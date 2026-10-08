// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package r1cs

import (
	"errors"
	"math/big"
	"reflect"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/circuitdefer"
	"github.com/consensys/gnark/internal/frontendtype"
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
	mamabearr1cs "github.com/consensys/gnark/constraint/mamabear"
	"github.com/consensys/gnark/constraint/solver"
	tinyfieldr1cs "github.com/consensys/gnark/constraint/tinyfield"
)

// NewBuilder returns a new R1CS builder which implements [frontend.API].
// Additionally, this builder also implements [frontend.Committer].
func NewBuilder[E constraint.Element](field *big.Int, config frontend.CompileConfig) (frontend.Builder[E], error) {
	return newBuilder[E](field, config), nil
}

type builder[E constraint.Element] struct {
	cs     constraint.R1CS[E]
	config frontend.CompileConfig
	kvstore.Store

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[[16]byte][]expr.LinearExpression[E]

	tOne        E
	eZero, eOne expr.LinearExpression[E]
	cZero, cOne constraint.LinearExpression

	// helps merge k sorted linear expressions
	heap minHeap

	// buffers used to do in place api.MAC
	mbuf1 expr.LinearExpression[E]
	mbuf2 expr.LinearExpression[E]

	genericGate      constraint.BlueprintID
	batchInverseGate constraint.BlueprintID
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newBuilder[E constraint.Element](field *big.Int, config frontend.CompileConfig) *builder[E] {
	macCapacity := 100
	if config.CompressThreshold != 0 {
		macCapacity = config.CompressThreshold
	}
	bldr := &builder[E]{
		mtBooleans: make(map[[16]byte][]expr.LinearExpression[E], config.Capacity/10),
		config:     config,
		heap:       make(minHeap, 0, 100),
		mbuf1:      make(expr.LinearExpression[E], 0, macCapacity),
		mbuf2:      make(expr.LinearExpression[E], 0, macCapacity),
		Store:      kvstore.New(),
	}

	// by default the circuit is given a public wire equal to 1

	curve := utils.FieldToCurve(field)

	switch bldrT := any(bldr).(type) {
	case *builder[constraint.U64]:
		switch curve {
		case ecc.BLS12_377:
			bldrT.cs = bls12377r1cs.NewR1CS(config.Capacity)
		case ecc.BLS12_381:
			bldrT.cs = bls12381r1cs.NewR1CS(config.Capacity)
		case ecc.BN254:
			bldrT.cs = bn254r1cs.NewR1CS(config.Capacity)
		case ecc.BW6_761:
			bldrT.cs = bw6761r1cs.NewR1CS(config.Capacity)
		default:
			if field.Cmp(ecc.GRUMPKIN.ScalarField()) == 0 {
				bldrT.cs = grumpkinr1cs.NewR1CS(config.Capacity)
				break
			}
			if field.Cmp(mamabear.Modulus()) == 0 {
				bldrT.cs = mamabearr1cs.NewR1CS(config.Capacity)
				break
			}
			panic("not implemented")
		}
	case *builder[constraint.U32]:
		switch curve {
		default:
			if field.Cmp(tinyfield.Modulus()) == 0 {
				bldrT.cs = tinyfieldr1cs.NewR1CS(config.Capacity)
				break
			}
			if field.Cmp(babybear.Modulus()) == 0 {
				bldrT.cs = babybearr1cs.NewR1CS(config.Capacity)
				break
			}
			if field.Cmp(koalabear.Modulus()) == 0 {
				bldrT.cs = koalabearr1cs.NewR1CS(config.Capacity)
				break
			}
			panic("not implemented")
		}
	default:
		panic("invalid constraint.Element type")
	}

	bldr.tOne = bldr.cs.One()
	bldr.cs.AddPublicVariable("1")

	bldr.genericGate = bldr.cs.AddBlueprint(&constraint.BlueprintGenericR1C{})
	bldr.batchInverseGate = bldr.cs.AddBlueprint(&constraint.BlueprintBatchInverse[E]{})

	var zero E
	bldr.eZero = expr.NewLinearExpression(0, zero)
	bldr.eOne = expr.NewLinearExpression(0, bldr.tOne)

	bldr.cOne = constraint.LinearExpression{constraint.Term{VID: 0, CID: constraint.CoeffIdOne}}
	bldr.cZero = constraint.LinearExpression{constraint.Term{VID: 0, CID: constraint.CoeffIdZero}}

	return bldr
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (builder *builder[E]) newInternalVariable() expr.LinearExpression[E] {
	idx := builder.cs.AddInternalVariable()
	return expr.NewLinearExpression(idx, builder.tOne)
}

// PublicVariable creates a new public Variable
func (builder *builder[E]) PublicVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddPublicVariable(f.FullName())
	return expr.NewLinearExpression(idx, builder.tOne)
}

// SecretVariable creates a new secret Variable
func (builder *builder[E]) SecretVariable(f schema.LeafInfo) frontend.Variable {
	idx := builder.cs.AddSecretVariable(f.FullName())
	return expr.NewLinearExpression(idx, builder.tOne)
}

// cstOne return the one constant
func (builder *builder[E]) cstOne() expr.LinearExpression[E] {
	return builder.eOne
}

// cstZero return the zero constant
func (builder *builder[E]) cstZero() expr.LinearExpression[E] {
	return builder.eZero
}

func (builder *builder[E]) isCstOne(c E) bool {
	return builder.cs.IsOne(c)
}

func (builder *builder[E]) Field() *big.Int {
	return builder.cs.Field()
}

func (builder *builder[E]) FieldBitLen() int {
	return builder.cs.FieldBitLen()
}

// newR1C clones the linear expression associated with the Variables (to avoid offsetting the ID multiple time)
// and return a R1C
func (builder *builder[E]) newR1C(l, r, o frontend.Variable) constraint.R1C {
	L := builder.getLinearExpression(l)
	R := builder.getLinearExpression(r)
	O := builder.getLinearExpression(o)

	// We want R (the B matrix) to have fewer variables to increase the chance
	// of infinity points in pk.G1.B / pk.G2.B during Groth16 setup,
	// which improves proving time. Therefore, we swap L and R if R has more terms.
	if len(R) > len(L) {
		L, R = R, L
	}

	return constraint.R1C{L: L, R: R, O: O}
}

func (builder *builder[E]) getLinearExpression(_l interface{}) constraint.LinearExpression {
	var L constraint.LinearExpression
	switch tl := _l.(type) {
	case expr.LinearExpression[E]:
		if len(tl) == 1 && tl[0].VID == 0 {
			if tl[0].Coeff.IsZero() {
				return builder.cZero
			} else if tl[0].Coeff == builder.tOne {
				return builder.cOne
			}
		}
		L = make(constraint.LinearExpression, 0, len(tl))
		for _, t := range tl {
			L = append(L, builder.cs.MakeTerm(t.Coeff, t.VID))
		}
	case constraint.LinearExpression:
		L = tl
	default:
		panic("invalid input for getLinearExpression") // sanity check
	}

	return L
}

// MarkBoolean sets (but do not **constraint**!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (builder *builder[E]) MarkBoolean(v frontend.Variable) {
	if b, ok := builder.constantValue(v); ok {
		if !(b.IsZero() || builder.isCstOne(b)) { // nolint QF1001
			panic("MarkBoolean called a non-boolean constant")
		}
		return
	}
	// v is a linear expression
	l := v.(expr.LinearExpression[E])
	sort.Sort(l)

	key := l.HashCode()
	list := builder.mtBooleans[key]
	list = append(list, l)
	builder.mtBooleans[key] = list
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (builder *builder[E]) IsBoolean(v frontend.Variable) bool {
	if b, ok := builder.constantValue(v); ok {
		return (b.IsZero() || builder.isCstOne(b))
	}
	// v is a linear expression
	l := v.(expr.LinearExpression[E])
	sort.Sort(l)

	key := l.HashCode()
	list, ok := builder.mtBooleans[key]
	if !ok {
		return false
	}

	for _, v := range list {
		if v.Equal(l) {
			return true
		}
	}
	return false
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}

// Compile constructs a rank-1 constraint system
func (builder *builder[E]) Compile() (constraint.ConstraintSystemGeneric[E], error) {
	// TODO if already compiled, return builder.cs object
	log := logger.Logger()
	log.Info().
		Int("nbConstraints", builder.cs.GetNbConstraints()).
		Msg("building constraint builder")

	// ensure all inputs and hints are constrained
	if err := builder.cs.CheckUnconstrainedWires(); err != nil {
		log.Warn().Msg("circuit has unconstrained inputs")
		if !builder.config.IgnoreUnconstrainedInputs {
			return nil, err
		}
	}

	return builder.cs, nil
}

// ConstantValue returns the big.Int value of v.
// Will panic if v.IsConstant() == false
func (builder *builder[E]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	coeff, ok := builder.constantValue(v)
	if !ok {
		return nil, false
	}
	return builder.cs.ToBigInt(coeff), true
}

func (builder *builder[E]) constantValue(v frontend.Variable) (E, bool) {
	var zero E
	if _v, ok := v.(expr.LinearExpression[E]); ok {
		assertIsSet(_v)
		switch len(_v) {
		case 0:
			// empty linear expression, this is a constant zero
			return zero, true
		case 1:
			// linear expression with one term, check if it is a constant
			if _v[0].Coeff == zero { // fast path for zero comparison to avoid overhead of calling IsZero
				return zero, true
			}
			if _v[0].WireID() != 0 { // public ONE WIRE
				return zero, false
			}
			return _v[0].Coeff, true
		default:
			// linear expression with more than one term. Here it is only constant in case all coefficients are zero.
			for _, t := range _v {
				if !t.Coeff.IsZero() {
					return zero, false
				}
			}
			// all coefficients are zero, this is a constant zero
			return zero, true
		}
	}
	return builder.cs.FromInterface(v), true
}

// toVariable will return (and allocate if necessary) a linearExpression from given value
//
// if input is already a linearExpression, does nothing
// else, attempts to convert input to a big.Int (see utils.FromInterface) and returns a toVariable linearExpression
func (builder *builder[E]) toVariable(input interface{}) expr.LinearExpression[E] {

	switch t := input.(type) {
	case expr.LinearExpression[E]:
		// this is already a "kwown" variable
		assertIsSet(t)
		return t
	case *expr.LinearExpression[E]:
		assertIsSet(*t)
		return *t
	case E:
		return expr.NewLinearExpression(0, t)
	case *E:
		return expr.NewLinearExpression(0, *t)
	default:
		// try to make it into a constant
		c := builder.cs.FromInterface(t)
		return expr.NewLinearExpression(0, c)
	}
}

// toVariables return frontend.Variable corresponding to inputs and the total size of the linear expressions
func (builder *builder[E]) toVariables(in ...frontend.Variable) ([]expr.LinearExpression[E], int) {
	r := make([]expr.LinearExpression[E], 0, len(in))
	s := 0
	e := func(i frontend.Variable) {
		v := builder.toVariable(i)
		r = append(r, v)
		s += len(v)
	}
	// e(i1)
	// e(i2)
	for i := 0; i < len(in); i++ {
		e(in[i])
	}
	return r, s
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
	return builder.newHint(f, solver.GetHintID(f), nbOutputs, inputs)
}

func (builder *builder[E]) NewHintForId(id solver.HintID, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	return builder.newHint(nil, id, nbOutputs, inputs)
}

func (builder *builder[E]) newHint(f solver.Hint, id solver.HintID, nbOutputs int, inputs []frontend.Variable) ([]frontend.Variable, error) {
	hintInputs := make([]constraint.LinearExpression, len(inputs))

	// TODO @gbotrel hint input pass
	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		if t, ok := in.(expr.LinearExpression[E]); ok {
			assertIsSet(t)
			hintInputs[i] = builder.getLinearExpression(t)
		} else {
			c := builder.cs.FromInterface(in)
			term := builder.cs.MakeTerm(c, 0)
			term.MarkConstant()
			hintInputs[i] = constraint.LinearExpression{term}
		}
	}

	internalVariables, err := builder.cs.AddSolverHint(f, id, hintInputs, nbOutputs)
	if err != nil {
		return nil, err
	}

	// make the variables
	res := make([]frontend.Variable, len(internalVariables))
	for i, idx := range internalVariables {
		res[i] = expr.NewLinearExpression(idx, builder.tOne)
	}
	return res, nil
}

// assertIsSet panics if the variable is unset
// this may happen if inside a Define we have
// var a variable
// cs.Mul(a, 1)
// since a was not in the circuit struct it is not a secret variable
func assertIsSet[E constraint.Element](l expr.LinearExpression[E]) {
	if len(l) == 0 {
		// errNoValue triggered when trying to access a variable that was not allocated
		errNoValue := errors.New("can't determine API input value")
		panic(errNoValue)
	}

	if debug.Debug {
		// frontend/ package must build linear expressions that are sorted.
		if !sort.IsSorted(l) {
			panic("unsorted linear expression")
		}
	}
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
		case *expr.LinearExpression[E]:
			in[i] = builder.getLinearExpression(*t)
		case expr.LinearExpression[E]:
			in[i] = builder.getLinearExpression(t)
		case expr.Term[E]:
			in[i] = builder.getLinearExpression(expr.LinearExpression[E]{t})
		case *expr.Term[E]:
			in[i] = builder.getLinearExpression(expr.LinearExpression[E]{*t})
		case E:
			in[i] = builder.cs.String(t)
		case *E:
			in[i] = builder.cs.String(*t)
		}
	}

	return builder.cs.NewDebugInfo(errName, in...)

}

// compress checks the length of the linear expression le and if it is larger or
// equal than CompressThreshold in the configuration, replaces it with a linear
// expression of one term. In that case it adds an equality constraint enforcing
// the correctness of the returned linear expression.
func (builder *builder[E]) compress(le expr.LinearExpression[E]) expr.LinearExpression[E] {
	if builder.config.CompressThreshold <= 0 || len(le) < builder.config.CompressThreshold {
		return le
	}

	one := builder.cstOne()
	t := builder.newInternalVariable()
	builder.cs.AddR1C(builder.newR1C(le, one, t), builder.genericGate)
	return t
}

func (builder *builder[E]) Defer(cb func(frontend.API) error) {
	// in case the builder is wrapped implementing kvstore.Store methods then we
	// may put and retrieve deferred functions from different storages. We use
	// the unwrapped builder for storing deferred functions to avoid this issue.
	// See [callDeferred] function in frontend/compile.go
	compiler := builder.Compiler()
	circuitdefer.Put(compiler, cb)
}

func (*builder[E]) FrontendType() frontendtype.Type {
	return frontendtype.R1CS
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
	return expr.NewLinearExpression(int(wireID), builder.tOne)
}

// ToCanonicalVariable converts a frontend.Variable to a constraint system specific Variable
// ! Experimental: use in conjunction with constraint.CustomizableSystem
func (builder *builder[E]) ToCanonicalVariable(in frontend.Variable) frontend.CanonicalVariable {
	if t, ok := in.(expr.LinearExpression[E]); ok {
		assertIsSet(t)
		return builder.getLinearExpression(t)
	} else {
		c := builder.cs.FromInterface(in)
		term := builder.cs.MakeTerm(c, 0)
		term.MarkConstant()
		return constraint.LinearExpression{term}
	}
}
