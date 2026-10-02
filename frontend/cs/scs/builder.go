// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package scs

import (
	"fmt"
	"math/big"
	"reflect"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/circuitdefer"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"

	babybearr1cs "github.com/consensys/gnark/constraint/babybear"
	bls12377r1cs "github.com/consensys/gnark/constraint/bls12-377"
	bls12381r1cs "github.com/consensys/gnark/constraint/bls12-381"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	bw6761r1cs "github.com/consensys/gnark/constraint/bw6-761"
	grumpkinr1cs "github.com/consensys/gnark/constraint/grumpkin"
	koalabearr1cs "github.com/consensys/gnark/constraint/koalabear"
	"github.com/consensys/gnark/constraint/solver"
	tinyfieldr1cs "github.com/consensys/gnark/constraint/tinyfield"
)

// NewBuilder returns a new PLONKish/SparseR1CS builder which implements
// [frontend.API]. Additionally, this builder implements [frontend.Committer].
func NewBuilder[E constraint.Element](field *big.Int, config frontend.CompileConfig) (frontend.Builder[E], error) {
	return newBuilder[E](field, config), nil
}

type builder[E constraint.Element] struct {
	cs     constraint.SparseR1CS[E]
	config frontend.CompileConfig
	kvstore.Store

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[expr.Term[E]]struct{}

	// records multiplications constraint to avoid duplicates.
	// see mulConstraintExist(...)
	mMulInstructions map[uint64]int

	// same thing for addition gates
	// see addConstraintExist(...)
	mAddInstructions map[uint64]int

	// frequently used coefficients
	tOne, tMinusOne E

	genericGate                constraint.BlueprintID
	mulGate, addGate, boolGate constraint.BlueprintID
	batchInverseGate           constraint.BlueprintID

	// used to avoid repeated allocations
	bufL expr.LinearExpression[E]
	bufH []constraint.LinearExpression
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newBuilder[E constraint.Element](field *big.Int, config frontend.CompileConfig) *builder[E] {
	b := &builder[E]{
		mtBooleans:       make(map[expr.Term[E]]struct{}),
		mMulInstructions: make(map[uint64]int, config.Capacity/2),
		mAddInstructions: make(map[uint64]int, config.Capacity/2),
		config:           config,
		Store:            kvstore.New(),
		bufL:             make(expr.LinearExpression[E], 20),
	}
	// init hint buffer.
	_ = b.hintBuffer(256)

	curve := utils.FieldToCurve(field)

	switch bT := any(b).(type) {
	case *builder[constraint.U64]:
		switch curve {
		case ecc.BLS12_377:
			bT.cs = bls12377r1cs.NewSparseR1CS(config.Capacity)
		case ecc.BLS12_381:
			bT.cs = bls12381r1cs.NewSparseR1CS(config.Capacity)
		case ecc.BN254:
			bT.cs = bn254r1cs.NewSparseR1CS(config.Capacity)
		case ecc.BW6_761:
			bT.cs = bw6761r1cs.NewSparseR1CS(config.Capacity)
		default:
			if field.Cmp(ecc.GRUMPKIN.ScalarField()) == 0 {
				bT.cs = grumpkinr1cs.NewSparseR1CS(config.Capacity)
				break
			}
			panic("not implemented")
		}
	case *builder[constraint.U32]:
		switch curve {
		default:
			if field.Cmp(tinyfield.Modulus()) == 0 {
				bT.cs = tinyfieldr1cs.NewSparseR1CS(config.Capacity)
				break
			}
			if field.Cmp(babybear.Modulus()) == 0 {
				bT.cs = babybearr1cs.NewSparseR1CS(config.Capacity)
				break
			}
			if field.Cmp(koalabear.Modulus()) == 0 {
				bT.cs = koalabearr1cs.NewSparseR1CS(config.Capacity)
				break
			}
			panic("not implemented")
		}
	default:
		panic("invalid constraint.Element type")
	}

	b.tOne = b.cs.One()
	b.tMinusOne = b.cs.FromInterface(-1)

	b.genericGate = b.cs.AddBlueprint(&constraint.BlueprintGenericSparseR1C[E]{})
	b.mulGate = b.cs.AddBlueprint(&constraint.BlueprintSparseR1CMul[E]{})
	b.addGate = b.cs.AddBlueprint(&constraint.BlueprintSparseR1CAdd[E]{})
	b.boolGate = b.cs.AddBlueprint(&constraint.BlueprintSparseR1CBool[E]{})
	b.batchInverseGate = b.cs.AddBlueprint(&constraint.BlueprintBatchInverse[E]{})

	return b
}

func (builder *builder[E]) Field() *big.Int {
	return builder.cs.Field()
}

func (builder *builder[E]) FieldBitLen() int {
	return builder.cs.FieldBitLen()
}

// TODO @gbotrel doing a 2-step refactoring for now, frontend only. need to update constraint/SparseR1C.
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
type sparseR1C[E constraint.Element] struct {
	xa, xb, xc         int // wires
	qL, qR, qO, qM, qC E   // coefficients
	commitment         constraint.CommitmentConstraint
}

// a * b == c
func (builder *builder[E]) addMulGate(a, b, c expr.Term[E]) {
	qM := builder.cs.Mul(a.Coeff, b.Coeff)
	QM := builder.cs.AddCoeff(qM)

	builder.cs.AddSparseR1C(constraint.SparseR1C{
		XA: uint32(a.VID),
		XB: uint32(b.VID),
		XC: uint32(c.VID),
		QM: QM,
		QO: constraint.CoeffIdMinusOne,
	}, builder.mulGate)
}

// a + b + k == c
func (builder *builder[E]) addAddGate(a, b expr.Term[E], xc uint32, k E) {
	qL := builder.cs.AddCoeff(a.Coeff)
	qR := builder.cs.AddCoeff(b.Coeff)
	qC := builder.cs.AddCoeff(k)

	builder.cs.AddSparseR1C(constraint.SparseR1C{
		XA: uint32(a.VID),
		XB: uint32(b.VID),
		XC: xc,
		QL: qL,
		QR: qR,
		QC: qC,
		QO: constraint.CoeffIdMinusOne,
	}, builder.addGate)
}

func (builder *builder[E]) addBoolGate(c sparseR1C[E], debugInfo ...constraint.DebugInfo) {
	QL := builder.cs.AddCoeff(c.qL)
	QM := builder.cs.AddCoeff(c.qM)

	cID := builder.cs.AddSparseR1C(constraint.SparseR1C{
		XA: uint32(c.xa),
		QL: QL,
		QM: QM},
		builder.boolGate)
	if debug.Debug && len(debugInfo) == 1 {
		builder.cs.AttachDebugInfo(debugInfo[0], []int{cID})
	}
}

// addPlonkConstraint adds a sparseR1C to the underlying constraint system
func (builder *builder[E]) addPlonkConstraint(c sparseR1C[E], debugInfo ...constraint.DebugInfo) {
	QL := builder.cs.AddCoeff(c.qL)
	QR := builder.cs.AddCoeff(c.qR)
	QO := builder.cs.AddCoeff(c.qO)
	QM := builder.cs.AddCoeff(c.qM)
	QC := builder.cs.AddCoeff(c.qC)

	cID := builder.cs.AddSparseR1C(constraint.SparseR1C{
		XA: uint32(c.xa),
		XB: uint32(c.xb),
		XC: uint32(c.xc),
		QL: QL,
		QR: QR,
		QO: QO,
		QM: QM,
		QC: QC, Commitment: c.commitment}, builder.genericGate)
	if debug.Debug && len(debugInfo) == 1 {
		builder.cs.AttachDebugInfo(debugInfo[0], []int{cID})
	}
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (builder *builder[E]) newInternalVariable() expr.Term[E] {
	idx := builder.cs.AddInternalVariable()
	return expr.NewTerm(idx, builder.tOne)
}

// PublicVariable creates a new Public Variable
func (builder *builder[E]) PublicVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddPublicVariable(f.FullName())
	return expr.NewTerm(idx, builder.tOne)
}

// SecretVariable creates a new Secret Variable
func (builder *builder[E]) SecretVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddSecretVariable(f.FullName())
	return expr.NewTerm(idx, builder.tOne)
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (builder *builder[E]) reduce(l expr.LinearExpression[E]) expr.LinearExpression[E] {

	// ensure our linear expression is sorted, by visibility and by Variable ID
	sort.Sort(l)

	for i := 1; i < len(l); i++ {
		if l[i-1].VID == l[i].VID {
			// we have redundancy
			l[i-1].Coeff = builder.cs.Add(l[i-1].Coeff, l[i].Coeff)
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (builder *builder[E]) IsBoolean(v frontend.Variable) bool {
	if b, ok := builder.constantValue(v); ok {
		return (b.IsZero() || builder.cs.IsOne(b))
	}
	_, ok := builder.mtBooleans[v.(expr.Term[E])]
	return ok
}

// MarkBoolean sets (but do not constraint!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (builder *builder[E]) MarkBoolean(v frontend.Variable) {
	if _, ok := builder.constantValue(v); ok {
		if !builder.IsBoolean(v) {
			panic("MarkBoolean called a non-boolean constant")
		}
		return
	}
	builder.mtBooleans[v.(expr.Term[E])] = struct{}{}
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}

func (builder *builder[E]) Compile() (constraint.ConstraintSystemGeneric[E], error) {
	log := logger.Logger()
	log.Info().
		Int("nbConstraints", builder.cs.GetNbConstraints()).
		Msg("building constraint builder")

	// ensure all inputs and hints are constrained
	err := builder.cs.CheckUnconstrainedWires()
	if err != nil {
		log.Warn().Msg("circuit has unconstrained inputs")
		if !builder.config.IgnoreUnconstrainedInputs {
			return nil, err
		}
	}

	return builder.cs, nil
}

// ConstantValue returns the big.Int value of v and true if v is a constant, false otherwise
func (builder *builder[E]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	coeff, ok := builder.constantValue(v)
	if !ok {
		return nil, false
	}
	return builder.cs.ToBigInt(coeff), true
}

func (builder *builder[E]) constantValue(v frontend.Variable) (E, bool) {
	if vv, ok := v.(expr.Term[E]); ok {
		var zero E
		if vv.Coeff.IsZero() {
			return zero, true
		}
		return zero, false
	}
	return builder.cs.FromInterface(v), true
}

func (builder *builder[E]) hintBuffer(size int) []constraint.LinearExpression {
	if cap(builder.bufH) < size {
		builder.bufH = make([]constraint.LinearExpression, 2*size)
		for i := 0; i < len(builder.bufH); i++ {
			builder.bufH[i] = make(constraint.LinearExpression, 1)
		}
	}

	return builder.bufH[:size]
}

// NewHint initializes internal variables whose value will be evaluated using
// the provided hint function at run time from the inputs. Inputs must be either
// variables or convertible to *big.Int. The function returns an error if the
// number of inputs is not compatible with f.
//
// The hint function is provided at the proof creation time and is not embedded
// into the circuit. From the backend point of view, the variable returned by
// the hint function is equivalent to the user-supplied witness, but its actual
// value is assigned by the solver, not the caller.
//
// No new constraints are added to the newly created wire and must be added
// manually in the circuit. Failing to do so leads to solver failure.
func (builder *builder[E]) NewHint(f solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	return builder.newHint(f, solver.GetHintID(f), nbOutputs, inputs...)
}

func (builder *builder[E]) newHint(f solver.Hint, id solver.HintID, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	hintInputs := builder.hintBuffer(len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case expr.Term[E]:
			hintInputs[i][0] = builder.cs.MakeTerm(t.Coeff, t.VID)
		default:
			c := builder.cs.FromInterface(in)
			term := builder.cs.MakeTerm(c, 0)
			term.MarkConstant()
			hintInputs[i][0] = term
		}
	}

	internalVariables, err := builder.cs.AddSolverHint(f, id, hintInputs, nbOutputs)
	if err != nil {
		return nil, err
	}

	// make the variables
	res := make([]frontend.Variable, len(internalVariables))
	for i, idx := range internalVariables {
		res[i] = expr.NewTerm(idx, builder.tOne)
	}
	return res, nil

}

// returns in split into a slice of compiledTerm and the sum of all constants in in as a bigInt
func (builder *builder[E]) filterConstantSum(in []frontend.Variable) (expr.LinearExpression[E], E) {
	var res expr.LinearExpression[E]
	if len(in) <= cap(builder.bufL) {
		// we can use the temp buffer
		res = builder.bufL[:0]
	} else {
		res = make(expr.LinearExpression[E], 0, len(in))
	}

	var b E
	for i := 0; i < len(in); i++ {
		if c, ok := builder.constantValue(in[i]); ok {
			b = builder.cs.Add(b, c)
		} else {
			if inTerm := in[i].(expr.Term[E]); !inTerm.Coeff.IsZero() {
				// add only term if coefficient is not zero.
				res = append(res, in[i].(expr.Term[E]))
			}
		}
	}
	return res, b
}

// returns in split into a slice of compiledTerm and the product of all constants in in as a coeff
func (builder *builder[E]) filterConstantProd(in []frontend.Variable) (expr.LinearExpression[E], E) {
	var res expr.LinearExpression[E]
	if len(in) <= cap(builder.bufL) {
		// we can use the temp buffer
		res = builder.bufL[:0]
	} else {
		res = make(expr.LinearExpression[E], 0, len(in))
	}

	b := builder.tOne
	for i := 0; i < len(in); i++ {
		if c, ok := builder.constantValue(in[i]); ok {
			b = builder.cs.Mul(b, c)
		} else {
			res = append(res, in[i].(expr.Term[E]))
		}
	}
	return res, b
}

func (builder *builder[E]) splitSum(acc expr.Term[E], r expr.LinearExpression[E], k *E) expr.Term[E] {
	// floor case
	if len(r) == 0 {
		if k != nil {
			// we need to return acc + k
			o, found := builder.addConstraintExist(acc, expr.Term[E]{}, *k)
			if !found {
				o = builder.newInternalVariable()
				builder.addAddGate(acc, expr.Term[E]{}, uint32(o.VID), *k)
			}

			return o
		}
		return acc
	}

	// constraint to add: acc + r[0] (+ k) == o
	var qC E
	if k != nil {
		qC = *k
	}
	o, found := builder.addConstraintExist(acc, r[0], qC)
	if !found {
		o = builder.newInternalVariable()
		builder.addAddGate(acc, r[0], uint32(o.VID), qC)
	}

	return builder.splitSum(o, r[1:], nil)
}

// addConstraintExist check if we recorded a constraint in the form
// q1*xa + q2*xb + qC - xc == 0
//
// if we find one, this function returns the xc wire with the correct coefficients.
// if we don't, and no previous addition was recorded with xa and xb, add an entry in the map
// (this assumes that the caller will add a constraint just after this call if it's not found!)
//
// idea:
// 1. take (xa | (xb << 32)) as a identifier of an addition that used wires xa and xb.
// 2. look for an entry in builder.mAddConstraints for a previously added constraint that matches.
// 3. if so, check that the coefficients matches and we can re-use xc wire.
//
// limitations:
// 1. for efficiency, we just store the first addition that occurred with with xa and xb;
// so if we do 2*xa + 3*xb == c, then want to compute xa + xb == d multiple times, the compiler is
// not going to catch these duplicates.
// 2. this piece of code assumes some behavior from constraint/ package (like coeffIDs, or append-style
// constraint management)
func (builder *builder[E]) addConstraintExist(a, b expr.Term[E], k E) (expr.Term[E], bool) {
	// ensure deterministic combined identifier;
	if a.VID < b.VID {
		a, b = b, a
	}
	h := uint64(a.WireID()) | uint64(b.WireID()<<32)

	if iID, ok := builder.mAddInstructions[h]; ok {
		// if we do custom gates with slices in the constraint
		// should use a shared object here to avoid allocs.
		var c constraint.SparseR1C

		// seems likely we have a fit, let's double check
		inst := builder.cs.GetInstruction(iID)
		// we know the blueprint we added it.
		blueprint := constraint.BlueprintSparseR1CAdd[E]{}
		blueprint.DecompressSparseR1C(&c, inst)

		// qO == -1
		if a.WireID() == int(c.XB) {
			a, b = b, a // ensure a is in qL
		}

		tk := builder.cs.MakeTerm(k, 0)
		if tk.CoeffID() != int(c.QC) {
			// the constant part of the addition differs, no point going forward
			// since we will need to add a new constraint anyway.
			return expr.Term[E]{}, false
		}

		// check that the coeff matches
		qL := a.Coeff
		qR := b.Coeff
		ta := builder.cs.MakeTerm(qL, 0)
		tb := builder.cs.MakeTerm(qR, 0)
		if int(c.QL) != ta.CoeffID() || int(c.QR) != tb.CoeffID() {
			if !k.IsZero() {
				// may be for some edge cases we could avoid adding a constraint here.
				return expr.Term[E]{}, false
			}
			// we recorded an addition in the form q1*a + q2*b == c
			// we want to record a new one in the form q3*a + q4*b == n*c
			// question is; can we re-use c to avoid introducing a new wire & new constraint
			// this is possible only if n == q3/q1 == q4/q2, that is, q3q2 == q1q4
			q1 := builder.cs.GetCoefficient(int(c.QL))
			q2 := builder.cs.GetCoefficient(int(c.QR))
			q3 := qL
			q4 := qR
			q3 = builder.cs.Mul(q3, q2)
			q1 = builder.cs.Mul(q1, q4)
			if q1 == q3 {
				// no need to introduce a new constraint;
				// compute n, the coefficient for the output wire
				q2, ok = builder.cs.Inverse(q2)
				if !ok {
					// q2 is zero when a term cancelled out in reduce (e.g. x + y - y),
					// we can't compute n from it so we just add a new constraint.
					return expr.Term[E]{}, false
				}
				q2 = builder.cs.Mul(q2, q4)
				return expr.NewTerm(int(c.XC), q2), true
			}
			// we will need an additional constraint
			return expr.Term[E]{}, false
		}

		// we found the same constraint!
		return expr.NewTerm(int(c.XC), builder.tOne), true
	}
	// we are going to add this constraint, so we mark it.
	// ! assumes the caller add an instruction immediately  after the call to this function
	builder.mAddInstructions[h] = builder.cs.GetNbInstructions()
	return expr.Term[E]{}, false
}

// mulConstraintExist check if we recorded a constraint in the form
// qM*xa*xb - xc == 0
//
// if we find one, this function returns the xc wire with the correct coefficients.
// if we don't, and no previous multiplication was recorded with xa and xb, add an entry in the map
// (this assumes that the caller will add a constraint just after this call if it's not found!)
//
// idea:
// 1. take (xa | (xb << 32)) as a identifier of a multiplication that used wires xa and xb.
// 2. look for an entry in builder.mMulConstraints for a previously added constraint that matches.
// 3. if so, compute correct coefficient N for xc wire that matches qM'*xa*xb - N*xc == 0
//
// limitations:
// 1. this piece of code assumes some behavior from constraint/ package (like coeffIDs, or append-style
// constraint management)
func (builder *builder[E]) mulConstraintExist(a, b expr.Term[E]) (expr.Term[E], bool) {
	// ensure deterministic combined identifier;
	if a.VID < b.VID {
		a, b = b, a
	}
	h := uint64(a.WireID()) | uint64(b.WireID()<<32)

	if iID, ok := builder.mMulInstructions[h]; ok {
		// if we do custom gates with slices in the constraint
		// should use a shared object here to avoid allocs.
		var c constraint.SparseR1C

		// seems likely we have a fit, let's double check
		inst := builder.cs.GetInstruction(iID)
		// we know the blueprint we added it.
		blueprint := constraint.BlueprintSparseR1CMul[E]{}
		blueprint.DecompressSparseR1C(&c, inst)

		// qO == -1

		if a.WireID() == int(c.XB) {
			a, b = b, a // ensure a is in qL
		}

		// recompute the qM coeff and check that it matches;
		qM := builder.cs.Mul(a.Coeff, b.Coeff)
		tm := builder.cs.MakeTerm(qM, 0)
		if int(c.QM) != tm.CoeffID() {
			// so we wanted to compute
			// N * xC == qM*xA*xB
			// but found a constraint
			// xC == qM'*xA*xB
			// the coefficient for our resulting wire is different;
			// N = qM / qM'
			N := builder.cs.GetCoefficient(int(c.QM))
			N, ok := builder.cs.Inverse(N)
			if !ok {
				panic("div by 0") // sanity check.
			}
			N = builder.cs.Mul(N, qM)

			return expr.NewTerm(int(c.XC), N), true
		}

		// we found the exact same constraint
		return expr.NewTerm(int(c.XC), builder.tOne), true
	}

	// we are going to add this constraint, so we mark it.
	// ! assumes the caller add an instruction immediately  after the call to this function
	builder.mMulInstructions[h] = builder.cs.GetNbInstructions()
	return expr.Term[E]{}, false
}

func (builder *builder[E]) splitProd(acc expr.Term[E], r expr.LinearExpression[E]) expr.Term[E] {
	// floor case
	if len(r) == 0 {
		return acc
	}
	// we want to add a constraint such that acc * r[0] == o
	// let's check if we didn't already constrain a similar product
	o, found := builder.mulConstraintExist(acc, r[0])

	if !found {
		// constraint to add: acc * r[0] == o
		o = builder.newInternalVariable()
		builder.addMulGate(acc, r[0], o)
	}

	return builder.splitProd(o, r[1:])
}

// newDebugInfo this is temporary to restore debug logs
// something more like builder.sprintf("my message %le %lv", l0, l1)
// to build logs for both debug and println
// and append some program location.. (see other todo in debug_info.go)
func (builder *builder[E]) newDebugInfo(errName string, in ...interface{}) constraint.DebugInfo {
	for i := 0; i < len(in); i++ {
		// for inputs that are LinearExpressions or Term, we need to "Make" them in the backend.
		// TODO @gbotrel this is a duplicate effort with adding a constraint and should be taken care off

		switch t := in[i].(type) {
		case *expr.LinearExpression[E], expr.LinearExpression[E]:
			// shouldn't happen
		case expr.Term[E]:
			in[i] = builder.cs.MakeTerm(t.Coeff, t.VID)
		case *expr.Term[E]:
			in[i] = builder.cs.MakeTerm(t.Coeff, t.VID)
		case E:
			in[i] = builder.cs.String(t)
		case *E:
			in[i] = builder.cs.String(*t)
		}
	}

	return builder.cs.NewDebugInfo(errName, in...)

}

func (builder *builder[E]) Defer(cb func(frontend.API) error) {
	// in case the builder is wrapped implementing kvstore.Store methods then we
	// may put and retrieve deferred functions from different storages. We use
	// the unwrapped builder for storing deferred functions to avoid this issue.
	// See [callDeferred] function in frontend/compile.go
	compiler := builder.Compiler()
	circuitdefer.Put(compiler, cb)
}

// AddInstruction is used to add custom instructions to the constraint system.
func (builder *builder[E]) AddInstruction(bID constraint.BlueprintID, calldata []uint32) []uint32 {
	return builder.cs.AddInstruction(bID, calldata)
}

// AddBlueprint adds a custom blueprint to the constraint system.
func (builder *builder[E]) AddBlueprint(b constraint.Blueprint) constraint.BlueprintID {
	return builder.cs.AddBlueprint(b)
}

func (builder *builder[E]) InternalVariable(wireID uint32) frontend.Variable {
	return expr.NewTerm(int(wireID), builder.tOne)
}

// ToCanonicalVariable converts a frontend.Variable to a constraint system specific Variable
// ! Experimental: use in conjunction with constraint.CustomizableSystem
func (builder *builder[E]) ToCanonicalVariable(v frontend.Variable) frontend.CanonicalVariable {
	switch t := v.(type) {
	case expr.Term[E]:
		return builder.cs.MakeTerm(t.Coeff, t.VID)
	default:
		c := builder.cs.FromInterface(v)
		term := builder.cs.MakeTerm(c, 0)
		term.MarkConstant()
		return term
	}
}

// GetWireConstraints returns the pairs (constraintID, wireLocation) for the
// given wires in the compiled constraint system:
//   - constraintID is the index of the constraint in the constraint system.
//   - wireLocation is the location of the wire in the constraint (0=xA or 1=xB).
//
// If the argument addMissing is true, then the function will add a new
// constraint for each wire that is not found in the constraint system. This may
// happen when getting the constraint for a witness which is not used in
// constraints. Otherwise, when addMissing is false, the function returns an
// error if a wire is not found in the constraint system.
//
// The method only returns a single pair (constraintID, wireLocation) for every
// unique wire (removing duplicates). The order of the returned pairs is not the
// same as for the given arguments. It is however, deterministic order.
func (builder *builder[E]) GetWireConstraints(wires []frontend.Variable, addMissing bool) ([][2]int, error) {
	// construct a lookup table table for later quick access when iterating over instructions
	lookup := make(map[int]struct{})
	wireTerms := make([]expr.Term[E], len(wires)) // stores the term of each wire.
	for i, w := range wires {
		ww, ok := w.(expr.Term[E])
		if !ok {
			panic("input wire is not a Term")
		}
		lookup[ww.WireID()] = struct{}{}
		wireTerms[i] = ww
	}
	nbPub := builder.cs.GetNbPublicVariables()
	res := make([][2]int, 0, len(wires))
	iterator := builder.cs.GetSparseR1CIterator()
	for c, constraintIdx := iterator.Next(), 0; c != nil; c, constraintIdx = iterator.Next(), constraintIdx+1 {
		if _, ok := lookup[int(c.XA)]; ok {
			res = append(res, [2]int{nbPub + constraintIdx, 0})
			delete(lookup, int(c.XA))
		}
		if _, ok := lookup[int(c.XB)]; ok {
			res = append(res, [2]int{nbPub + constraintIdx, 1})
			delete(lookup, int(c.XB))
		}
		if _, ok := lookup[int(c.XC)]; ok {
			res = append(res, [2]int{nbPub + constraintIdx, 2})
			delete(lookup, int(c.XC))
		}
		if len(lookup) == 0 {
			// we can break early if we found constraints for all the wires
			break
		}
	}
	if addMissing {
		nbWitnessWires := builder.cs.GetNbPublicVariables() + builder.cs.GetNbSecretVariables()
		// It is important to iterate over wireTerms here as doing it over [lookup]
		// would result in a non-deterministic order of constraints.
		for _, ww := range wireTerms {

			if _, ok := lookup[ww.WireID()]; !ok {
				continue
			}

			k := ww.WireID()
			if k >= nbWitnessWires {
				return nil, fmt.Errorf("addMissing is true, but wire %d is not a witness", k)
			}
			constraintIdx := builder.cs.AddSparseR1C(constraint.SparseR1C{
				XA: uint32(k),
				XC: uint32(k),
				QL: constraint.CoeffIdOne,
				QO: constraint.CoeffIdMinusOne,
			}, builder.genericGate)

			res = append(res, [2]int{nbPub + constraintIdx, 0})
			delete(lookup, k)
		}
	}
	if len(lookup) > 0 {
		return nil, fmt.Errorf("constraint with wire not found in circuit")
	}
	return res, nil
}

// GetWiresConstraintExact works as [GetWireConstraints], but returns an
// exact wire for each constraint. That is if the caller passes the same wire
// several times at different positions in [vars], it will not deduplicate
// unlike [GetWireConstraints]. The function has also a different way to deal
// with constants and missing wires. If the same variabes is passed, then the
// same wire ID is returned. The function returns the first occurrence of the
// wire in the constraint system, by order of the constraints.
//
//   - If a variable is a constant. It will introduct an adhoc term and it will
//     be reused each time the constant appears.
//
//   - The function tolerates that a wire is missing if addMissing is true even
//     if the wire is not a witness element. This is allows supporting variables
//     that are constrained through hints only.
//
// For instance,
// ```
//
//	GetWiresConstraintsExact([]frontend.Variable{a, a, b, a, c}) => wa, wa, wb, wa, wc
//
// ```
//
// while,
//
// ```
//
//	GetWiresConstraints([]frontend.Variable{a, a, b, a, c}) => wa, wb, wc
//
// ```
func (builder *builder[E]) GetWiresConstraintExact(wires []frontend.Variable, addMissing bool) ([][2]int, error) {

	// wireIDsSet stores the indices of all the wires involved in the input.
	// We want to ensure that all the stored variables do corresponds to
	// canonical variables: therefore not to constants and not too terms
	// with a coeff different from 1. This may add constraints but has the
	// benefit of making it simpler to read the LRO values.
	//
	// wireIDsSetOrdered stores the same values as wireIDsSet but in order
	// of insertion. This is necessary to ensure the compilation is deterministic
	var (
		wireIDsSet = make(map[int]struct{})
		wireTerms  = make([]expr.Term[E], len(wires))

		// constantWiresMap registers the wires that we create to represent
		// the constants that appear in the input. It helps avoiding to
		// create too many unncessary adhoc terms for the same constant.
		constantWiresMap = make(map[E]expr.Term[E])
	)

	for i, w := range wires {
		ww, ok := w.(expr.Term[E])
		if !ok {
			// In the case of a Plonk circuit. It will only cover the case
			// where "w" was a constant. There, we can assume that this
			// condition and the next one are mutually exclusive.
			c := builder.cs.FromInterface(w)
			o, oWasFound := constantWiresMap[c]
			if !oWasFound {
				o = builder.newInternalVariable()
				constantWiresMap[c] = o
				builder.addAddGate(expr.Term[E]{}, expr.Term[E]{}, uint32(o.VID), c)
			}
			ww = o
		}

		if ww.Coeff != builder.tOne {
			o := builder.newInternalVariable()
			var zero E
			builder.addAddGate(ww, expr.Term[E]{}, uint32(o.VID), zero)
			ww = o
		}

		wireIDsSet[ww.VID] = struct{}{}
		wireTerms[i] = ww
	}

	// This loop attempts to find the wire IDs in the constraint system and
	// gives a localization for each. The loop removes items from [wireIDsSets]
	// when they are found. This will allow us to identify the wires that are
	// missing from the constraint system. This can happen when wires are
	// unconstrained.
	var (
		foundWireIDPosition = make(map[int][2]int)
		nbPub               = builder.cs.GetNbPublicVariables()
		iterator            = builder.cs.GetSparseR1CIterator()
	)

	for c, constraintIdx := iterator.Next(), 0; c != nil; c, constraintIdx = iterator.Next(), constraintIdx+1 {
		if _, ok := wireIDsSet[int(c.XA)]; ok {
			foundWireIDPosition[int(c.XA)] = [2]int{nbPub + constraintIdx, 0}
			delete(wireIDsSet, int(c.XA))
		}
		if _, ok := wireIDsSet[int(c.XB)]; ok {
			foundWireIDPosition[int(c.XB)] = [2]int{nbPub + constraintIdx, 1}
			delete(wireIDsSet, int(c.XB))
		}
		if _, ok := wireIDsSet[int(c.XC)]; ok {
			foundWireIDPosition[int(c.XC)] = [2]int{nbPub + constraintIdx, 2}
			delete(wireIDsSet, int(c.XC))
		}
		if len(wireIDsSet) == 0 {
			// we can break early if we found constraints for all the wires
			break
		}
	}

	if addMissing {
		for _, ww := range wireTerms {

			// The above loop removes the wireIDs from the set when they are
			// found. This means that a wireID is missing if and only if it
			// is still in [wireIDsSet].
			if _, isIndeedMissing := wireIDsSet[ww.VID]; !isIndeedMissing {
				continue
			}

			constraintIdx := builder.cs.AddSparseR1C(constraint.SparseR1C{
				XA: uint32(ww.VID),
				XC: uint32(ww.VID),
				QL: constraint.CoeffIdOne,
				QO: constraint.CoeffIdMinusOne,
			}, builder.genericGate)

			foundWireIDPosition[ww.VID] = [2]int{nbPub + constraintIdx, 0}
			delete(wireIDsSet, ww.VID)
		}
	}

	if len(wireIDsSet) > 0 {
		return nil, fmt.Errorf("wires not found in constraint system: %v", wireIDsSet)
	}

	res := make([][2]int, len(wires))
	for i, w := range wireTerms {
		res[i] = foundWireIDPosition[w.VID]
	}
	return res, nil
}
