// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package scs

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/cs"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/frontendtype"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/std/math/bits"
)

func (builder *builder[E]) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	// separate the constant part from the variables
	vars, k := builder.filterConstantSum(append([]frontend.Variable{i1, i2}, in...))

	if len(vars) == 0 {
		// no variables, we return the constant.
		return builder.cs.ToBigInt(k)
	}

	vars = builder.reduce(vars)
	if k.IsZero() {
		return builder.splitSum(vars[0], vars[1:], nil)
	}
	// no constant we decompose the linear expressions in additions of 2 terms
	return builder.splitSum(vars[0], vars[1:], &k)
}

func (builder *builder[E]) MulAcc(a, b, c frontend.Variable) frontend.Variable {

	if fastTrack := builder.mulAccFastTrack(a, b, c); fastTrack != nil {
		return fastTrack
	}

	// TODO can we do better here to limit allocations?
	return builder.Add(a, builder.Mul(b, c))
}

// special case for when a/c is constant
// let a = a' * α, b = b' * β, c = c' * α
// then a + b * c = a' * α + (b' * c') (β * α)
// thus qL = a', qR = 0, qM = b'c'
func (builder *builder[E]) mulAccFastTrack(a, b, c frontend.Variable) frontend.Variable {
	var (
		aVar, bVar, cVar expr.Term[E]
		ok               bool
	)
	if aVar, ok = a.(expr.Term[E]); !ok {
		return nil
	}
	if bVar, ok = b.(expr.Term[E]); !ok {
		return nil
	}
	if cVar, ok = c.(expr.Term[E]); !ok {
		return nil
	}

	if aVar.VID == bVar.VID {
		bVar, cVar = cVar, bVar
	}

	if aVar.VID != cVar.VID {
		return nil
	}

	res := builder.newInternalVariable()
	var zero E
	builder.addPlonkConstraint(sparseR1C[E]{
		xa:         aVar.VID,
		xb:         bVar.VID,
		xc:         res.VID,
		qL:         aVar.Coeff,
		qR:         zero,
		qO:         builder.tMinusOne,
		qM:         builder.cs.Mul(bVar.Coeff, cVar.Coeff),
		qC:         zero,
		commitment: 0,
	})
	return res
}

func (builder *builder[E]) neg(in []frontend.Variable) []frontend.Variable {
	res := make([]frontend.Variable, len(in))

	for i := 0; i < len(in); i++ {
		res[i] = builder.Neg(in[i])
	}
	return res
}

func (builder *builder[E]) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	r := builder.neg(append([]frontend.Variable{i2}, in...))
	return builder.Add(i1, r[0], r[1:]...)
}

func (builder *builder[E]) Neg(i1 frontend.Variable) frontend.Variable {
	if n, ok := builder.constantValue(i1); ok {
		n = builder.cs.Neg(n)
		return builder.cs.ToBigInt(n)
	}
	v := i1.(expr.Term[E])
	v.Coeff = builder.cs.Neg(v.Coeff)
	return v
}

func (builder *builder[E]) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	vars, k := builder.filterConstantProd(append([]frontend.Variable{i1, i2}, in...))
	if len(vars) == 0 {
		return builder.cs.ToBigInt(k)
	}
	if k.IsZero() {
		return 0
	}
	for i := range vars {
		if vars[i].Coeff.IsZero() {
			return 0
		}
	}
	l := builder.mulConstant(vars[0], k)

	return builder.splitProd(l, vars[1:])
}

// returns t*m
func (builder *builder[E]) mulConstant(t expr.Term[E], m E) expr.Term[E] {
	t.Coeff = builder.cs.Mul(t.Coeff, m)
	return t
}

func (builder *builder[E]) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	c1, i1Constant := builder.constantValue(i1)
	c2, i2Constant := builder.constantValue(i2)

	if i1Constant && i2Constant {
		if c2.IsZero() {
			panic("inverse by constant(0)")
		}
		c2, _ = builder.cs.Inverse(c2)
		c2 = builder.cs.Mul(c2, c1)
		return builder.cs.ToBigInt(c2)
	}
	if i2Constant {
		if c2.IsZero() {
			panic("inverse by constant(0)")
		}
		c2, _ = builder.cs.Inverse(c2)
		return builder.mulConstant(i1.(expr.Term[E]), c2)
	}
	if i1Constant {
		res := builder.Inverse(i2)
		return builder.mulConstant(res.(expr.Term[E]), c1)
	}

	// res * i2 == i1
	res := builder.newInternalVariable()
	builder.addPlonkConstraint(sparseR1C[E]{
		xa: res.VID,
		xb: i2.(expr.Term[E]).VID,
		xc: i1.(expr.Term[E]).VID,
		qM: i2.(expr.Term[E]).Coeff,
		qO: builder.cs.Neg(i1.(expr.Term[E]).Coeff),
	})

	return res
}

func (builder *builder[E]) Div(i1, i2 frontend.Variable) frontend.Variable {
	// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
	builder.Inverse(i2)

	return builder.DivUnchecked(i1, i2)
}

func (builder *builder[E]) Inverse(i1 frontend.Variable) frontend.Variable {
	if c, ok := builder.constantValue(i1); ok {
		if c.IsZero() {
			panic("inverse by constant(0)")
		}
		c, _ = builder.cs.Inverse(c)
		return builder.cs.ToBigInt(c)
	}
	t := i1.(expr.Term[E])
	res := builder.newInternalVariable()

	// res * i1 - 1 == 0
	constraint := sparseR1C[E]{
		xa: res.VID,
		xb: t.VID,
		qM: t.Coeff,
		qC: builder.tMinusOne,
	}

	if debug.Debug {
		debug := builder.newDebugInfo("inverse", "1/", i1, " < ∞")
		builder.addPlonkConstraint(constraint, debug)
	} else {
		builder.addPlonkConstraint(constraint)
	}

	return res
}

// BatchInvert implements [frontend.BatchInverter]. It computes the modular
// inverse of each element in i1 using a single BlueprintBatchInverse instruction
// (one field inversion + O(n) multiplications) followed by n cheap verification
// constraints.
func (builder *builder[E]) BatchInvert(i1 []frontend.Variable) []frontend.Variable {
	n := len(i1)
	if n == 0 {
		return nil
	}

	res := make([]frontend.Variable, n)

	// Separate constants (computed inline) from variable inputs (handled by blueprint).
	type varEntry struct {
		outputIdx int
		inTerm    expr.Term[E]
	}
	varEntries := make([]varEntry, 0, n)
	for j, v := range i1 {
		if c, ok := builder.constantValue(v); ok {
			if c.IsZero() {
				panic("BatchInvert: cannot invert zero")
			}
			c, _ = builder.cs.Inverse(c)
			res[j] = builder.cs.ToBigInt(c)
			continue
		}
		varEntries = append(varEntries, varEntry{outputIdx: j, inTerm: v.(expr.Term[E])})
	}

	if len(varEntries) == 0 {
		return res
	}

	// Build calldata with LE encoding per input (single-term in SCS):
	// [totalSize, nVars, 1, coeffID_0, wireID_0, 1, coeffID_1, wireID_1, ...]
	nVars := len(varEntries)
	calldata := make([]uint32, 2, 2+3*nVars)
	calldata[0] = 0 // placeholder for totalSize
	calldata[1] = uint32(nVars)
	for _, e := range varEntries {
		calldata = append(calldata, 1, builder.cs.AddCoeff(e.inTerm.Coeff), uint32(e.inTerm.VID))
	}
	calldata[0] = uint32(len(calldata))

	outputWires := builder.cs.AddInstruction(builder.batchInverseGate, calldata)

	// For each variable input add a verification constraint: outWire * inTerm - 1 == 0
	for k, e := range varEntries {
		outTerm := expr.NewTerm(int(outputWires[k]), builder.tOne)
		builder.addPlonkConstraint(sparseR1C[E]{
			xa: outTerm.VID,
			xb: e.inTerm.VID,
			qM: e.inTerm.Coeff,
			qC: builder.tMinusOne,
		})
		res[e.outputIdx] = outTerm
	}

	return res
}

// ---------------------------------------------------------------------------------------------
// Bit operations

func (builder *builder[E]) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	// nbBits
	nbBits := builder.cs.FieldBitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	return bits.ToBinary(builder, i1, bits.WithNbDigits(nbBits))
}

func (builder *builder[E]) FromBinary(b ...frontend.Variable) frontend.Variable {
	return bits.FromBinary(builder, b)
}

func (builder *builder[E]) Xor(a, b frontend.Variable) frontend.Variable {
	// pre condition: a, b must be booleans
	builder.AssertIsBoolean(a)
	builder.AssertIsBoolean(b)

	_a, aConstant := builder.constantValue(a)
	_b, bConstant := builder.constantValue(b)

	// if both inputs are constants
	if aConstant && bConstant {
		b0 := 0
		b1 := 0
		if builder.cs.IsOne(_a) {
			b0 = 1
		}
		if builder.cs.IsOne(_b) {
			b1 = 1
		}
		return b0 ^ b1
	}

	// if one input is constant, ensure we put it in b.
	if aConstant {
		a, b = b, a
		bConstant = aConstant
		_b = _a
	}
	if bConstant {
		if _b.IsZero() {
			return a
		}

		res := builder.newInternalVariable()
		builder.MarkBoolean(res)
		xa := a.(expr.Term[E])
		// 1 - 2b
		qL := builder.tOne
		qL = builder.cs.Sub(qL, _b)
		qL = builder.cs.Sub(qL, _b)
		qL = builder.cs.Mul(qL, xa.Coeff)

		// (1-2b)a + b == res
		builder.addPlonkConstraint(sparseR1C[E]{
			xa: xa.VID,
			xc: res.VID,
			qL: qL,
			qO: builder.tMinusOne,
			qC: _b,
		})
		// builder.addPlonkConstraint(xa, xb, res, builder.st.CoeffID(oneMinusTwoB), constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdMinusOne, builder.st.CoeffID(_b))
		return res
	}

	res := builder.newInternalVariable()
	builder.MarkBoolean(res)
	xa := a.(expr.Term[E])
	xb := b.(expr.Term[E])

	// -a - b + 2ab + res == 0
	qM := builder.tOne
	qM = builder.cs.Add(qM, qM)
	qM = builder.cs.Mul(qM, xa.Coeff)
	qM = builder.cs.Mul(qM, xb.Coeff)

	qL := builder.cs.Neg(xa.Coeff)
	qR := builder.cs.Neg(xb.Coeff)

	builder.addPlonkConstraint(sparseR1C[E]{
		xa: xa.VID,
		xb: xb.VID,
		xc: res.VID,
		qL: qL,
		qR: qR,
		qO: builder.tOne,
		qM: qM,
	})
	// builder.addPlonkConstraint(xa, xb, res, constraint.CoeffIdMinusOne, constraint.CoeffIdMinusOne, constraint.CoeffIdTwo, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdZero)
	return res
}

func (builder *builder[E]) Or(a, b frontend.Variable) frontend.Variable {
	builder.AssertIsBoolean(a)
	builder.AssertIsBoolean(b)

	_a, aConstant := builder.constantValue(a)
	_b, bConstant := builder.constantValue(b)

	if aConstant && bConstant {
		if builder.cs.IsOne(_a) || builder.cs.IsOne(_b) {
			return 1
		}
		return 0
	}

	// if one input is constant, ensure we put it in b
	if aConstant {
		a, b = b, a
		_b = _a
		bConstant = aConstant
	}

	if bConstant {
		if builder.cs.IsOne(_b) {
			return 1
		} else {
			return a
		}
	}
	res := builder.newInternalVariable()
	builder.MarkBoolean(res)
	xa := a.(expr.Term[E])
	xb := b.(expr.Term[E])
	// -a - b + ab + res == 0

	qM := builder.cs.Mul(xa.Coeff, xb.Coeff)

	qL := builder.cs.Neg(xa.Coeff)
	qR := builder.cs.Neg(xb.Coeff)

	builder.addPlonkConstraint(sparseR1C[E]{
		xa: xa.VID,
		xb: xb.VID,
		xc: res.VID,
		qL: qL,
		qR: qR,
		qM: qM,
		qO: builder.tOne,
	})
	return res
}

func (builder *builder[E]) And(a, b frontend.Variable) frontend.Variable {
	builder.AssertIsBoolean(a)
	builder.AssertIsBoolean(b)
	res := builder.Mul(a, b)
	builder.MarkBoolean(res)
	return res
}

// ---------------------------------------------------------------------------------------------
// Conditionals

func (builder *builder[E]) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	_b, bConstant := builder.constantValue(b)

	if bConstant {
		if !builder.IsBoolean(b) {
			panic(fmt.Sprintf("%s should be 0 or 1", builder.cs.String(_b)))
		}
		if _b.IsZero() {
			return i2
		}
		return i1
	}

	// ensure the condition is a boolean
	builder.AssertIsBoolean(b)

	u := builder.Sub(i1, i2)
	l := builder.Mul(u, b)

	return builder.Add(l, i2)
}

func (builder *builder[E]) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	// ensure that bits are actually bits. Adds no constraints if the variables
	// are already constrained.
	builder.AssertIsBoolean(b0)
	builder.AssertIsBoolean(b1)

	c0, b0IsConstant := builder.constantValue(b0)
	c1, b1IsConstant := builder.constantValue(b1)

	if b0IsConstant && b1IsConstant {
		b0 := builder.cs.IsOne(c0)
		b1 := builder.cs.IsOne(c1)

		if !b0 && !b1 {
			return i0
		}
		if b0 && !b1 {
			return i1
		}
		if b0 && b1 {
			return i3
		}
		return i2
	}

	if b0IsConstant {
		if builder.cs.IsOne(c0) {
			return builder.Select(b1, i3, i1)
		}
		return builder.Select(b1, i2, i0)
	}
	if b1IsConstant {
		if builder.cs.IsOne(c1) {
			return builder.Select(b0, i3, i2)
		}
		return builder.Select(b0, i1, i0)
	}

	// two-bit lookup for the general case can be done with three constraints as
	// following:
	//    (1) (in3 - in2 - in1 + in0) * s1 = tmp1 - in1 + in0
	//    (2) tmp1 * s0 = tmp2
	//    (3) (in2 - in0) * s1 = RES - tmp2 - in0
	// the variables tmp1 and tmp2 are new internal variables and the variables
	// RES will be the returned result
	tmp1 := builder.Sub(i3, i2)
	tmp := builder.Sub(i0, i1)
	tmp1 = builder.Add(tmp1, tmp)
	tmp1 = builder.Mul(tmp1, b1)
	tmp1 = builder.Sub(tmp1, tmp) // (1) tmp1 = s1 * (in3 - in2 - in1 + in0) + in1 - in0
	tmp2 := builder.Mul(tmp1, b0) // (2) tmp2 = tmp1 * s0
	res := builder.Sub(i2, i0)
	res = builder.Mul(res, b1)
	res = builder.Add(res, tmp2, i0) // (3) res = (v2 - v0) * s1 + tmp2 + in0

	return res

}

func (builder *builder[E]) IsZero(i1 frontend.Variable) frontend.Variable {
	if a, ok := builder.constantValue(i1); ok {
		if a.IsZero() {
			return 1
		}
		return 0
	}

	// x = 1/a 				// in a hint (x == 0 if a == 0)
	// m = -a*x + 1         // constrain m to be 1 if a == 0
	// a * m = 0            // constrain m to be 0 if a != 0
	a := i1.(expr.Term[E])
	m := builder.newInternalVariable()

	// x = 1/a 				// in a hint (x == 0 if a == 0)
	x, err := builder.NewHint(solver.InvZeroHint, 1, a)
	if err != nil {
		// the function errs only if the number of inputs is invalid.
		panic(err)
	}

	// m = -a*x + 1         // constrain m to be 1 if a == 0
	// a*x + m - 1 == 0
	X := x[0].(expr.Term[E])
	builder.addPlonkConstraint(sparseR1C[E]{
		xa: a.VID,
		xb: X.VID,
		xc: m.VID,
		qM: a.Coeff,
		qO: builder.tOne,
		qC: builder.tMinusOne,
	})

	// a * m = 0            // constrain m to be 0 if a != 0
	builder.addPlonkConstraint(sparseR1C[E]{
		xa: a.VID,
		xb: m.VID,
		qM: a.Coeff,
	})

	builder.MarkBoolean(m)

	return m
}

func (builder *builder[E]) Cmp(i1, i2 frontend.Variable) frontend.Variable {

	nbBits := builder.cs.FieldBitLen()
	// in AssertIsLessOrEq we omitted comparison against modulus for the left
	// side as if `a+r<b` implies `a<b`, then here we compute the inequality
	// directly.
	bi1 := bits.ToBinary(builder, i1, bits.WithNbDigits(nbBits))
	bi2 := bits.ToBinary(builder, i2, bits.WithNbDigits(nbBits))

	var res frontend.Variable
	res = 0

	for i := builder.cs.FieldBitLen() - 1; i >= 0; i-- {
		iszeroi1 := builder.IsZero(bi1[i])
		iszeroi2 := builder.IsZero(bi2[i])

		i1i2 := builder.And(bi1[i], iszeroi2)
		i2i1 := builder.And(bi2[i], iszeroi1)

		n := builder.Select(i2i1, -1, 0)
		m := builder.Select(i1i2, 1, n)

		res = builder.Select(builder.IsZero(res), m, res)
	}
	return res
}

func (builder *builder[E]) Println(a ...frontend.Variable) {
	var log constraint.LogEntry

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		log.Caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	var sbb strings.Builder

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		if v, ok := arg.(expr.Term[E]); ok {

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, constraint.LinearExpression{builder.cs.MakeTerm(v.Coeff, v.VID)})
		} else {
			builder.printArg(&log, &sbb, arg)
		}
	}

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	log.Format = sbb.String()

	builder.cs.AddLog(log)
}

func (builder *builder[E]) printArg(log *constraint.LogEntry, sbb *strings.Builder, a frontend.Variable) {

	leafCount, err := schema.Walk(builder.Field(), a, tVariable, nil)
	count := leafCount.Public + leafCount.Secret

	// no variables in nested struct, we use fmt std print function
	if count == 0 || err != nil {
		if _, err = fmt.Fprint(sbb, a); err != nil {
			panic(err)
		}
		return
	}

	sbb.WriteByte('{')
	printer := func(f schema.LeafInfo, tValue reflect.Value) error {
		count--
		sbb.WriteString(f.FullName())
		sbb.WriteString(": ")
		sbb.WriteString("%s")
		if count != 0 {
			sbb.WriteString(", ")
		}

		v := tValue.Interface().(expr.Term[E])
		// we set limits to the linear expression, so that the log printer
		// can evaluate it before printing it
		log.ToResolve = append(log.ToResolve, constraint.LinearExpression{builder.cs.MakeTerm(v.Coeff, v.VID)})
		return nil
	}
	// ignoring error, printer() doesn't return errors
	_, _ = schema.Walk(builder.Field(), a, tVariable, printer)
	sbb.WriteByte('}')
}

func (builder *builder[E]) Compiler() frontend.Compiler {
	return builder
}

// AddPlonkCommitmentInputs registers variables to be committed to. The method
// iterates over the variables and adds constraints to indicate they are to be
// committed to. The method returns the list of constraint indexes corresponding
// to each input variable. Does not perform any deduplication or constant
// filtering.
//
// NB! This method does not create the commitment itself. The user must call the
// hint for computing the commitment value, registering the commitment output
// using [AddPlonkCommitmentOutputs]. Note: [AddPlonkCommitmentOutputs] already
// handles adding the commitment to the constraint system, so the user does not
// need to call [constraint.System.AddCommitment] separately.
//
// This method is not exposed in standard APIs - it is meant to be used
// externally for implementing wide commitments. We also use it internally in
// the [Commit] method.
func (builder *builder[E]) AddPlonkCommitmentInputs(inputs []frontend.Variable) []int {
	committed := make([]int, len(inputs))
	for i, vI := range inputs { // TODO @Tabaie Perf; If public, just hash it
		vINeg, ok := builder.Neg(vI).(expr.Term[E])
		if !ok {
			// in Commit method we already ensure that we only commit to
			// variables. If given input is not a variable, then it means there
			// is a bug.
			panic("only variables can be committed to")
		}
		committed[i] = builder.cs.GetNbConstraints()
		// a constraint to enforce consistency between the commitment and committed value
		// - v + comm(n) = 0
		builder.addPlonkConstraint(sparseR1C[E]{xa: vINeg.VID, qL: vINeg.Coeff, commitment: constraint.COMMITTED})
	}
	return committed
}

// AddPlonkCommitmentOutputs registers the outputs of a commitment. The method
// adds constraints to the constraint system to indicate that the outputs of a
// commitment will be provided at proof time. The method takes as input the list
// of constraint indexes corresponding to the committed variables and the list
// of output variables.
//
// This method is not exposed in standard APIs - it is meant to be used
// externally for implementing wide commitments. We also use it internally in
// the [Commit] method.
func (builder *builder[E]) AddPlonkCommitmentOutputs(committed []int, outs []frontend.Variable) error {
	commitmentConstraintIndex := builder.cs.GetNbConstraints()
	for _, out := range outs {
		outNeg, ok := builder.Neg(out).(expr.Term[E])
		if !ok {
			// the outputs come from a hint, so they must be variables. If not,
			// then it means there is a bug.
			panic("only variables can be commitment outputs")
		}
		// RHS will be provided by both prover and verifier independently, as for a public wire
		builder.addPlonkConstraint(sparseR1C[E]{xa: outNeg.VID, qL: outNeg.Coeff, commitment: constraint.COMMITMENT}) // value will be injected later
	}
	return builder.cs.AddCommitment(constraint.PlonkCommitment{
		CommitmentIndex: commitmentConstraintIndex,
		Committed:       committed,
		Width:           len(outs),
	})
}

func (builder *builder[E]) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	if smallfields.IsSmallField(builder.Field()) {
		return nil, fmt.Errorf("commitment not supported for small field %s", builder.Field())
	}

	commitments := builder.cs.GetCommitments().(constraint.PlonkCommitments)

	// we deduplicate the inputs. As we add a copy constraint for every
	// committed value, then a duplicated value would lead to excessive
	// constraints (resulting in duplicated constraints).
	dedup := make([]frontend.Variable, 1, len(v)+1)
	isCommitted := make(map[int]struct{})
	for _, vi := range v {
		viTerm, ok := vi.(expr.Term[E])
		if !ok {
			// constants (or other non-term variables) are not committed, so we skip them here
			continue
		}
		if viTerm.Coeff.IsZero() {
			// if the variable has a zero coefficient, then it is effectively a
			// constant and we don't need to commit to it, so we skip it here
			continue
		}
		if _, found := isCommitted[viTerm.VID]; found {
			// skip duplicated committed value
			continue
		}
		// we base the deduplication only on the variable ID ignoring the
		// coefficient. Indeed, committing to 2*x and x is the same as
		// committing to x only as it doesn't give prover any extra power in
		// predicting the commitment value.
		isCommitted[viTerm.VID] = struct{}{}
		dedup = append(dedup, vi)
	}

	if len(dedup) == 1 {
		// nothing to commit to
		return nil, fmt.Errorf("Commit called with no non-constant variables commit to")
	}

	committed := builder.AddPlonkCommitmentInputs(dedup[1:])

	dedup[0] = len(commitments) // commitment depth
	outs, err := builder.NewHint(cs.Bsb22CommitmentComputePlaceholder, 1, dedup...)
	if err != nil {
		return nil, err
	}
	outs = outs[:1]
	return outs[0], builder.AddPlonkCommitmentOutputs(committed, outs)
}

// EvaluatePlonkExpression in the form of res = qL.a + qR.b + qM.ab + qC
func (builder *builder[E]) EvaluatePlonkExpression(a, b frontend.Variable, qL, qR, qM, qC int) frontend.Variable {
	_, aConstant := builder.constantValue(a)
	_, bConstant := builder.constantValue(b)
	if aConstant || bConstant {
		return builder.Add(
			builder.Mul(a, qL),
			builder.Mul(b, qR),
			builder.Mul(a, b, qM),
			qC,
		)
	}

	res := builder.newInternalVariable()
	builder.addPlonkConstraint(sparseR1C[E]{
		xa: a.(expr.Term[E]).VID,
		xb: b.(expr.Term[E]).VID,
		xc: res.VID,
		qL: builder.cs.Mul(builder.cs.FromInterface(qL), a.(expr.Term[E]).Coeff),
		qR: builder.cs.Mul(builder.cs.FromInterface(qR), b.(expr.Term[E]).Coeff),
		qO: builder.tMinusOne,
		qM: builder.cs.Mul(builder.cs.FromInterface(qM), builder.cs.Mul(a.(expr.Term[E]).Coeff, b.(expr.Term[E]).Coeff)),
		qC: builder.cs.FromInterface(qC),
	})
	return res
}

// AddPlonkConstraint asserts qL.a + qR.b + qO.o + qM.ab + qC = 0
func (builder *builder[E]) AddPlonkConstraint(a, b, o frontend.Variable, qL, qR, qO, qM, qC int) {
	_, aConstant := builder.constantValue(a)
	_, bConstant := builder.constantValue(b)
	_, oConstant := builder.constantValue(o)
	if aConstant || bConstant || oConstant {
		builder.AssertIsEqual(
			builder.Add(
				builder.Mul(a, qL),
				builder.Mul(b, qR),
				builder.Mul(a, b, qM),
				builder.Mul(o, qO),
				qC,
			),
			0,
		)
		return
	}

	builder.addPlonkConstraint(sparseR1C[E]{
		xa: a.(expr.Term[E]).VID,
		xb: b.(expr.Term[E]).VID,
		xc: o.(expr.Term[E]).VID,
		qL: builder.cs.Mul(builder.cs.FromInterface(qL), a.(expr.Term[E]).Coeff),
		qR: builder.cs.Mul(builder.cs.FromInterface(qR), b.(expr.Term[E]).Coeff),
		qO: builder.cs.Mul(builder.cs.FromInterface(qO), o.(expr.Term[E]).Coeff),
		qM: builder.cs.Mul(builder.cs.FromInterface(qM), builder.cs.Mul(a.(expr.Term[E]).Coeff, b.(expr.Term[E]).Coeff)),
		qC: builder.cs.FromInterface(qC),
	})
}

func (*builder[E]) FrontendType() frontendtype.Type {
	return frontendtype.SCS
}
