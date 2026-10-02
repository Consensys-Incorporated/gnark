// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package scs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/std/math/bits"
)

// AssertIsEqual fails if i1 != i2
func (builder *builder[E]) AssertIsEqual(i1, i2 frontend.Variable) {

	c1, i1Constant := builder.constantValue(i1)
	c2, i2Constant := builder.constantValue(i2)

	if i1Constant && i2Constant {
		if c1 != c2 {
			panic("i1, i2 should be equal")
		}
		return
	}
	if i1Constant {
		i1, i2 = i2, i1
		i2Constant = i1Constant
		c2 = c1
	}
	if i2Constant {
		xa := i1.(expr.Term[E])
		c2 := builder.cs.Neg(c2)

		// xa - i2 == 0
		toAdd := sparseR1C[E]{
			xa: xa.VID,
			qL: xa.Coeff,
			qC: c2,
		}

		if debug.Debug {
			debug := builder.newDebugInfo("assertIsEqual", xa, "==", i2)
			builder.addPlonkConstraint(toAdd, debug)
		} else {
			builder.addPlonkConstraint(toAdd)
		}
		return
	}
	xa := i1.(expr.Term[E])
	xb := i2.(expr.Term[E])

	xb.Coeff = builder.cs.Neg(xb.Coeff)
	// xa - xb == 0
	toAdd := sparseR1C[E]{
		xa: xa.VID,
		xb: xb.VID,
		qL: xa.Coeff,
		qR: xb.Coeff,
	}

	if debug.Debug {
		xb.Coeff = builder.cs.Neg(xb.Coeff)
		debug := builder.newDebugInfo("assertIsEqual", xa, " == ", xb)
		builder.addPlonkConstraint(toAdd, debug)
	} else {
		builder.addPlonkConstraint(toAdd)
	}
}

// AssertIsDifferent fails if i1 == i2
func (builder *builder[E]) AssertIsDifferent(i1, i2 frontend.Variable) {
	s := builder.Sub(i1, i2)
	if c, ok := builder.constantValue(s); ok {
		if c.IsZero() {
			panic("AssertIsDifferent(x,x) will never be satisfied")
		}
	} else if t := s.(expr.Term[E]); t.Coeff.IsZero() {
		panic("AssertIsDifferent(x,x) will never be satisfied")
	}
	builder.Inverse(s)
}

// AssertIsBoolean fails if v ≠ 0 ∥ v ≠ 1
func (builder *builder[E]) AssertIsBoolean(i1 frontend.Variable) {
	if c, ok := builder.constantValue(i1); ok {
		if !(c.IsZero() || builder.cs.IsOne(c)) { // nolint QF1001
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", builder.cs.String(c)))
		}
		return
	}

	v := i1.(expr.Term[E])
	if builder.IsBoolean(v) {
		return
	}
	builder.MarkBoolean(v)

	// ensure v * (1 - v) == 0
	// that is v + -v*v == 0
	// qM = -v.Coeff*v.Coeff
	qM := builder.cs.Neg(v.Coeff)
	qM = builder.cs.Mul(qM, v.Coeff)
	toAdd := sparseR1C[E]{
		xa: v.VID,
		qL: v.Coeff,
		qM: qM,
	}
	if debug.Debug {
		debug := builder.newDebugInfo("assertIsBoolean", v, " == (0|1)")
		builder.addBoolGate(toAdd, debug)
	} else {
		builder.addBoolGate(toAdd)
	}

}

func (builder *builder[E]) AssertIsCrumb(i1 frontend.Variable) {
	if c, ok := builder.constantValue(i1); ok {
		if i, ok := builder.cs.Uint64(c); ok && i < 4 {
			return
		}
		panic(fmt.Sprintf("AssertIsCrumb constant input %s is not a crumb", builder.cs.String(c)))
	}

	// i1 (i1-1) (i1-2) (i1-3) = (i1² - 3i1) (i1² - 3i1 + 2)
	// take X := i1² - 3i1 and we get X (X+2) = 0

	// usually MulAcc is a composition in PLONK, unless we have the condition
	// a/c == const. This holds here so this is only a single constraint.
	x := builder.MulAcc(builder.Mul(-3, i1), i1, i1).(expr.Term[E])

	// usually bit assertions are defined in [std/math/bits] package, but we
	// already have it and want to keep it backwards compatible. By doing it
	// directly we can avoid a constraint as we do 2X + X^2 == 0 in a single
	// constraint.
	builder.addPlonkConstraint(sparseR1C[E]{
		xa: x.VID,
		xb: x.VID,
		qL: builder.cs.FromInterface(2),
		qM: builder.tOne,
	})
}

// AssertIsLessOrEqual fails if  v > bound
func (builder *builder[E]) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	cv, vConst := builder.constantValue(v)
	cb, bConst := builder.constantValue(bound)

	switch {
	case vConst && bConst: // both inputs are constants
		bv, bb := builder.cs.ToBigInt(cv), builder.cs.ToBigInt(cb)
		if bv.Cmp(bb) == 1 {
			panic(fmt.Sprintf("AssertIsLessOrEqual: %s > %s", bv.String(), bb.String()))
		}
		return
	case bConst: // bound is constant
		nbBits := builder.cs.FieldBitLen()
		vBits := bits.ToBinary(builder, v, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())
		builder.MustBeLessOrEqCst(vBits, builder.cs.ToBigInt(cb), v)
		return
	default:
		if b, ok := bound.(expr.Term[E]); ok {
			builder.mustBeLessOrEqVar(v, b)
		} else {
			panic(fmt.Sprintf("expected bound type expr.Term, got %T", bound))
		}
	}

}

func (builder *builder[E]) mustBeLessOrEqVar(a frontend.Variable, bound expr.Term[E]) {
	var debugInfo []constraint.DebugInfo
	if debug.Debug {
		debugInfo = []constraint.DebugInfo{builder.newDebugInfo("mustBeLessOrEq", a, " <= ", bound)}
	}

	nbBits := builder.cs.FieldBitLen()

	aBits := bits.ToBinary(builder, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs(), bits.OmitModulusCheck())
	boundBits := bits.ToBinary(builder, bound, bits.WithNbDigits(nbBits)) // enforces range check against modulus

	p := make([]frontend.Variable, nbBits+1)
	p[nbBits] = 1

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := builder.Mul(p[i+1], aBits[i])
		p[i] = builder.Select(boundBits[i], v, p[i+1])

		t := builder.Select(boundBits[i], 0, p[i+1])

		// (1 - t - ai) * ai == 0
		l := builder.Sub(1, t, aBits[i]).(expr.Term[E])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// → this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too

		if ai, ok := builder.constantValue(aBits[i]); ok {
			// a is constant; ensure l == 0
			l.Coeff = builder.cs.Mul(l.Coeff, ai)
			builder.addPlonkConstraint(sparseR1C[E]{
				xa: l.VID,
				qL: l.Coeff,
			}, debugInfo...)
		} else {
			// l * a[i] == 0
			builder.addPlonkConstraint(sparseR1C[E]{
				xa: l.VID,
				xb: aBits[i].(expr.Term[E]).VID,
				qM: l.Coeff,
			}, debugInfo...)
		}

	}

}

// MustBeLessOrEqCst asserts that value represented using its bit decomposition
// aBits is less or equal than constant bound. The method boolean constraints
// the bits in aBits, so the caller can provide unconstrained bits.
func (builder *builder[E]) MustBeLessOrEqCst(aBits []frontend.Variable, bound *big.Int, aForDebug frontend.Variable) {

	nbBits := builder.cs.FieldBitLen()
	if len(aBits) > nbBits {
		panic("more input bits than field bit length")
	}
	for i := len(aBits); i < nbBits; i++ {
		aBits = append(aBits, 0)
	}

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debugInfo info
	var debugInfo []constraint.DebugInfo
	if debug.Debug {
		debugInfo = []constraint.DebugInfo{builder.newDebugInfo("mustBeLessOrEq", aForDebug, " <= ", bound)}
	}

	// t trailing bits in the bound
	t := 0
	for i := 0; i < nbBits; i++ {
		if bound.Bit(i) == 0 {
			break
		}
		t++
	}

	p := make([]frontend.Variable, nbBits+1)
	// p[i] == 1 → a[j] == c[j] for all j ⩾ i
	p[nbBits] = 1

	for i := nbBits - 1; i >= t; i-- {
		if bound.Bit(i) == 0 {
			p[i] = p[i+1]
		} else {
			p[i] = builder.Mul(p[i+1], aBits[i])
		}
	}

	for i := nbBits - 1; i >= 0; i-- {

		if bound.Bit(i) == 0 {
			if c, ok := builder.constantValue(aBits[i]); ok {
				// skip trivially satisfied constraints for constant zero bits
				if !c.IsZero() {
					// (1 - p(i+1) - ai) * ai == 0 with ai constant
					builder.AssertIsEqual(builder.Mul(builder.Sub(1, p[i+1], aBits[i]), aBits[i]), 0)
				}
				continue
			}
			// (1 - p(i+1) - ai) * ai == 0
			l := builder.Sub(1, p[i+1], aBits[i]).(expr.Term[E])

			builder.addPlonkConstraint(sparseR1C[E]{
				xa: l.VID,
				xb: aBits[i].(expr.Term[E]).VID,
				qM: builder.tOne,
			}, debugInfo...)
		} else {
			builder.AssertIsBoolean(aBits[i])
		}
	}

}
