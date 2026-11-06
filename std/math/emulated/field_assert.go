package emulated

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/profile"
)

// enforceWidth enforces the width of the limbs to nbBits. The number of limbs
// must be exactly ceil(nbBits / BitsPerLimb()); it panics otherwise. All limbs
// except the last are range-checked to BitsPerLimb() bits; the last limb is
// range-checked to ((nbBits-1) % BitsPerLimb()) + 1 bits.
func (f *Field[T]) enforceWidth(a *Element[T], nbBits int) {
	bitsPerLimb := int(f.fParams.BitsPerLimb())
	expectedNbLimbs := (nbBits + bitsPerLimb - 1) / bitsPerLimb
	if _, aConst := f.constantValue(a); aConst {
		if len(a.Limbs) != expectedNbLimbs {
			panic("constant limb width doesn't match parametrized field")
		}
	}
	if len(a.Limbs) != expectedNbLimbs {
		panic("enforcing width element with inexact number of limbs")
	}

	for i := range a.Limbs {
		limbNbBits := bitsPerLimb
		if i == len(a.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((nbBits - 1) % bitsPerLimb) + 1
		}
		f.rangeCheck(a.Limbs[i], limbNbBits)
	}
}

// smallEnforceWidth enforces a custom bit width on an element via the small
// field optimization path. Unlike enforceWidth, each limb is range-checked
// to nbBits+overflow. The limb count must equal ceil(nbBits / BitsPerLimb()).
func (f *Field[T]) smallEnforceWidth(a *Element[T], nbBits int) {
	bitsPerLimb := int(f.fParams.BitsPerLimb())
	expectedNbLimbs := (nbBits + bitsPerLimb - 1) / bitsPerLimb
	if len(a.Limbs) != expectedNbLimbs {
		panic("enforcing width element with inexact number of limbs")
	}

	for i := range a.Limbs {
		limbNbBits := bitsPerLimb
		if i == len(a.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((nbBits - 1) % bitsPerLimb) + 1
		}
		f.rangeCheck(a.Limbs[i], limbNbBits+int(a.overflow))
	}
}

// AssertIsEqual ensures that a is equal to b modulo the modulus.
func (f *Field[T]) AssertIsEqual(a, b *Element[T]) {
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Mod(ba, f.fParams.Modulus())
		bb.Mod(bb, f.fParams.Modulus())
		if ba.Cmp(bb) != 0 {
			panic(fmt.Sprintf("%s != %s", ba, bb))
		}
		return
	}

	diff := f.Sub(b, a)
	f.checkZero(diff, nil)
}

// AssertIsLessOrEqual ensures that e is less or equal than a. For proper
// bitwise comparison first reduce the element using [Field.ReduceStrict].
func (f *Field[T]) AssertIsLessOrEqual(e, a *Element[T]) {
	// we omit conditional width assertion as is done in ToBits below

	// we usually require that the inputs are already reduced fully
	// (overflow=1). but in case we use small field parameters, we mostly
	// operate with a small overflow to optimize range checks. In this case we
	// allow both inputs to have small overflow. As we check binary check below anyway,
	// having small overflow is not an issue.
	//
	// when we emulate large fields, then f.smallAdditionalOverflow() returns 0, thus
	// we enforce that both inputs have overflow 0.
	if e.overflow > uint(f.smallAdditionalOverflow()) {
		panic("first input must have 0 overflow")
	}
	if a.overflow > uint(f.smallAdditionalOverflow()) {
		panic("second input must have 0 overflow")
	}
	eBits := f.ToBits(e)
	aBits := f.ToBits(a)
	f.assertIsLessOrEqualBits(eBits, aBits)

	profile.RecordOperation("emulated.AssertIsLessOrEqual", 4*(len(eBits)+len(aBits)))
}

// assertIsLessOrEqualBits asserts that the value represented by eBits is less
// or equal to the value represented by aBits. Both are in little-endian bit
// order. The slices are padded to the same length internally.
func (f *Field[T]) assertIsLessOrEqualBits(eBits, aBits []frontend.Variable) {
	padBits := func(xbits, ybits []frontend.Variable) []frontend.Variable {
		diff := len(xbits) - len(ybits)
		ybits = append(ybits, make([]frontend.Variable, diff)...)
		for i := len(ybits) - diff; i < len(ybits); i++ {
			ybits[i] = 0
		}
		return ybits
	}
	if len(eBits) > len(aBits) {
		aBits = padBits(eBits, aBits)
	} else {
		eBits = padBits(aBits, eBits)
	}
	p := make([]frontend.Variable, len(eBits)+1)
	p[len(eBits)] = 1
	for i := len(eBits) - 1; i >= 0; i-- {
		v := f.api.Mul(p[i+1], eBits[i])
		p[i] = f.api.Select(aBits[i], v, p[i+1])
		t := f.api.Select(aBits[i], 0, p[i+1])
		l := f.api.Sub(1, t, eBits[i])
		ll := f.api.Mul(l, eBits[i])
		f.api.AssertIsEqual(ll, 0)
	}
}

// AssertIsInRange ensures that a is less than the emulated modulus. When we
// call [Reduce] then we only ensure that the result is width-constrained, but
// not actually less than the modulus. This means that the actual value may be
// either x or x + p. For arithmetic it is sufficient, but for binary comparison
// it is not. For binary comparison the values have both to be below the
// modulus.
func (f *Field[T]) AssertIsInRange(a *Element[T]) {
	// short path - this element is already enforced to be less than the modulus
	if a.modReduced {
		return
	}
	// we omit conditional width assertion as is done in ToBits down the calling stack
	f.AssertIsLessOrEqual(a, f.modulusPrev())

	// set properties for the element so that we wouldn't duplicate check when
	// called again
	a.modReduced = true
	a.overflow = 0
}

// IsZero returns a boolean indicating if the element is strictly zero. The
// method internally reduces the element and asserts that the value is less than
// the modulus.
func (f *Field[T]) IsZero(a *Element[T]) frontend.Variable {
	// fast path - when the element is on zero limbs, then it is always zero
	if a.isStrictZero() {
		return 1
	}

	// to avoid using strict reduction (which is expensive as requires binary
	// assertion that value is less than modulus), we use ordinary reduction but
	// in this case the result can be either 0 or p (if it is zero).
	//
	// so we check that the reduced value limbs are either all zeros or
	// correspond to the modulus limbs.
	ca := f.Reduce(a)
	// Reduce can fold a constant input down to the canonical zero, which is
	// on zero limbs even when the input was not, and the checks below index
	// Limbs[0] unguarded. Reached e.g. by AddUnified(p, p), where q.X - p.X
	// constant-folds.
	if ca.isStrictZero() {
		return 1
	}
	p := f.Modulus()

	// we use two approaches for checking if the element is exactly zero. The
	// first approach is to check that every limb individually is zero. The
	// second approach is to check if the sum of all limbs is zero. Usually, we
	// cannot use this approach as we could have false positive due to overflow
	// in the native field. However, as the widths of the limbs are restricted,
	// then we can ensure in most cases that no overflows happen.

	// as ca is already reduced, then every limb overflow is already 0. Only
	// every addition adds a bit to the overflow.
	var res0 frontend.Variable
	totalOverflow := len(ca.Limbs) - 1
	if totalOverflow > int(f.maxOverflow()) {
		// the sums of limbs would overflow the native field. Use the first
		// approach instead.
		res0 = f.api.IsZero(ca.Limbs[0])
		for i := 1; i < len(ca.Limbs); i++ {
			res0 = f.api.Mul(res0, f.api.IsZero(ca.Limbs[i]))
		}
	} else {
		// default case, limbs sum does not overflow the native field
		limbSum := ca.Limbs[0]
		for i := 1; i < len(ca.Limbs); i++ {
			limbSum = f.api.Add(limbSum, ca.Limbs[i])
		}
		res0 = f.api.IsZero(limbSum)
	}
	// however, for checking if the element is p, we can not use the
	// optimization as we may have underflows. So we have to check every limb
	// individually.
	resP := f.api.IsZero(f.api.Sub(p.Limbs[0], ca.Limbs[0]))
	for i := 1; i < len(ca.Limbs); i++ {
		resP = f.api.Mul(resP, f.api.IsZero(f.api.Sub(p.Limbs[i], ca.Limbs[i])))
	}
	return f.api.Or(res0, resP)
}

// AssertIsDifferent asserts that a and b are different.
func (f *Field[T]) AssertIsDifferent(a, b *Element[T]) {
	// we skip conditional width checking as it is done in [Sub] below
	diff := f.Sub(a, b)
	diffIsZero := f.IsZero(diff)
	f.api.AssertIsEqual(diffIsZero, 0)
}

// // Cmp returns:
// //   - -1 if a < b
// //   - 0 if a = b
// //   - 1 if a > b
// //
// // The method internally reduces the element and asserts that the value is less
// // than the modulus.
// func (f *Field[T]) Cmp(a, b *Element[T]) frontend.Variable {
// 	ca := f.Reduce(a)
// 	f.AssertIsInRange(ca)
// 	cb := f.Reduce(b)
// 	f.AssertIsInRange(cb)
// 	var res frontend.Variable = 0
// 	for i := int(f.fParams.NbLimbs() - 1); i >= 0; i-- {
// 		lmbCmp := f.api.Cmp(ca.Limbs[i], cb.Limbs[i])
// 		res = f.api.Select(f.api.IsZero(res), lmbCmp, res)
// 	}
// 	return res
// }
