package emulated

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// ModMul computes a*b mod modulus. Instead of taking modulus as a constant
// parametrized by T, it is passed as an argument. This allows to use a variable
// modulus in the circuit. Type parameter T should be sufficiently big to fit a,
// b and modulus. Recommended to use [emparams.Mod1e512] or
// [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
//
// NB! known limitation: the modulus must be a witness or constant element which
// has not been operated on in-circuit, and must be strictly smaller than the
// modulus represented by T. Passing an element with non-zero overflow panics at
// compile time - the carry bounds for the multiplication check are derived from
// the limb width of the modulus, and we do not reduce it implicitly as that
// would silently change the modulus whenever it does not fit T. If reducing it
// is intended, wrap it in [Field.ReduceStrict] explicitly.
//
// The result is congruent to a·b modulo modulus but is not guaranteed to be the
// canonical representative in [0, modulus): it may be any value r' ≡ a·b (mod
// modulus) with r' < 2^(nbLimbs·bpl). For a canonical output (required before
// binary decomposition, comparison, or hashing), use [Field.ModMulCanonical] or
// reduce with [Field.assertLessThanModulus].
func (f *Field[T]) ModMul(a, b *Element[T], modulus *Element[T]) *Element[T] {
	f.checkModulus(modulus)
	// fast path when either of the inputs is zero then result is always zero
	if len(a.Limbs) == 0 || len(b.Limbs) == 0 {
		return f.Zero()
	}
	var target overflowError
	for nbReductions := 0; ; nbReductions++ {
		nextOverflow, err := f.mulPreCondReduced(a, b)
		if err == nil {
			return f.mulMod(a, b, nextOverflow, modulus)
		}
		if !errors.As(err, &target) {
			panic(err)
		}
		if nbReductions >= 2 {
			panic("internal error: custom-modulus multiplication does not fit after reducing both inputs")
		}
		if target.reduceRight {
			b = f.mulMod(b, f.One(), 0, modulus)
		} else {
			a = f.mulMod(a, f.One(), 0, modulus)
		}
	}
}

// ModMulCanonical computes a*b mod modulus and returns the canonical
// representative, asserted to be strictly smaller than modulus. It is
// functionally equivalent to [Field.ModMul] but additionally constrains the
// output to be unique, making it safe for binary decomposition, comparison, or
// hashing. This costs roughly one extra bit-comparison per call; prefer
// [Field.ModMul] for intermediate values in a chain and use this only where a
// canonical result is consumed.
func (f *Field[T]) ModMulCanonical(a, b *Element[T], modulus *Element[T]) *Element[T] {
	res := f.ModMul(a, b, modulus)
	f.assertLessThanModulus(res, modulus)
	return res
}

// ModAdd computes a+b mod modulus. Instead of taking modulus as a constant
// parametrized by T, it is passed as an argument. This allows to use a variable
// modulus in the circuit. Type parameter T should be sufficiently big to fit a,
// b and modulus. Recommended to use [emparams.Mod1e512] or
// [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
//
// NB! known limitation: the modulus must be a witness or constant element which
// has not been operated on in-circuit, and must be strictly smaller than the
// modulus represented by T. Passing an element with non-zero overflow panics at
// compile time - the carry bounds for the multiplication check are derived from
// the limb width of the modulus, and we do not reduce it implicitly as that
// would silently change the modulus whenever it does not fit T. If reducing it
// is intended, wrap it in [Field.ReduceStrict] explicitly.
func (f *Field[T]) ModAdd(a, b *Element[T], modulus *Element[T]) *Element[T] {
	f.checkModulus(modulus)
	// inlined version of [Field.reduceAndOp] which uses variable-modulus reduction
	var nextOverflow uint
	var err error
	var target overflowError
	for nextOverflow, err = f.addPreCond(a, b); errors.As(err, &target); nextOverflow, err = f.addPreCond(a, b) {
		if errors.As(err, &target) {
			if !target.reduceRight {
				a = f.mulMod(a, f.One(), 0, modulus)
			} else {
				b = f.mulMod(b, f.One(), 0, modulus)
			}
		}
	}
	res := f.add(a, b, nextOverflow)
	return res
}

func (f *Field[T]) modSub(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// like fixed modulus subtraction, but for sub padding need to use hint
	// instead of assuming T as a constant. And when doing as a hint, then need
	// to assert that the padding is a multiple of the modulus (done inside callSubPaddingHint)
	nextOverflow := max(b.overflow+1, a.overflow) + 1
	if nextOverflow > f.maxOverflow() {
		// TODO: in general we should handle it more gracefully, but this method
		// is only used in ModAssertIsEqual which in turn is only used in tests,
		// then for now we avoid automatic overflow handling (like we have for fixed modulus case).
		// We only panic here so that the user would know to manually handle the overflow.
		panic("next overflow would overflow the native field")
	}
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	padding := f.computeSubPaddingHint(b.overflow, uint(nbLimbs), modulus)
	for i := range limbs {
		limbs[i] = padding.Limbs[i]
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Sub(limbs[i], b.Limbs[i])
		}
	}
	res := f.newInternalElement(limbs, nextOverflow)
	return res
}

// ModAssertIsEqual asserts equality of a and b mod modulus. Instead of taking
// modulus as a constant parametrized by T, it is passed as an argument. This
// allows to use a variable modulus in the circuit. Type parameter T should be
// sufficiently big to fit a, b and modulus. Recommended to use
// [emparams.Mod1e512] or [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
//
// NB! known limitation: the modulus must be a witness or constant element which
// has not been operated on in-circuit, and must be strictly smaller than the
// modulus represented by T. Passing an element with non-zero overflow panics at
// compile time - the carry bounds for the multiplication check are derived from
// the limb width of the modulus, and we do not reduce it implicitly as that
// would silently change the modulus whenever it does not fit T. If reducing it
// is intended, wrap it in [Field.ReduceStrict] explicitly.
func (f *Field[T]) ModAssertIsEqual(a, b *Element[T], modulus *Element[T]) {
	f.checkModulus(modulus)
	// like fixed modulus AssertIsEqual, but uses current Sub implementation for
	// computing the diff
	diff := f.modSub(b, a, modulus)
	f.checkZero(diff, modulus)
}

// ModExp computes base^exp mod modulus. Instead of taking modulus as a constant
// parametrized by T, it is passed as an argument. This allows to use a variable
// modulus in the circuit. Type parameter T should be sufficiently big to fit
// base, exp and modulus. Recommended to use [emparams.Mod1e512] or
// [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
//
// NB! known limitation: the modulus must be a witness or constant element which
// has not been operated on in-circuit, and must be strictly smaller than the
// modulus represented by T. Passing an element with non-zero overflow panics at
// compile time - the carry bounds for the multiplication check are derived from
// the limb width of the modulus, and we do not reduce it implicitly as that
// would silently change the modulus whenever it does not fit T. If reducing it
// is intended, wrap it in [Field.ReduceStrict] explicitly.
//
// The implementation uses windowed exponentiation with window size 4, which
// reduces the number of multiplications compared to binary square-and-multiply.
//
// The result is the canonical representative: a single bound assertion
// (result < modulus) is applied to the final output, so it is safe to compare
// or decompose into bits. Intermediate multiplications use [Field.ModMul]
// without the canonicality assertion, keeping the per-call cost low.
func (f *Field[T]) ModExp(base, exp, modulus *Element[T]) *Element[T] {
	f.checkModulus(modulus)
	// fast path when the base is zero then result is always zero
	if len(base.Limbs) == 0 {
		return f.Zero()
	}

	const windowSize = 4
	const tableSize = 1 << windowSize // 16

	// Build precomputation table: table[i] = base^i for i in [0, 2^windowSize)
	table := make([]*Element[T], tableSize)
	table[0] = f.One()
	table[1] = base
	for i := 2; i < tableSize; i++ {
		table[i] = f.ModMul(table[i-1], base, modulus)
	}

	// Get exponent bits (LSB first). The exponent is reduced strictly first:
	// ToBits decomposes the raw limb value, so a non-canonical representation
	// (exp vs exp+p, both valid post-Reduce) would decompose to different bits
	// and produce a different result for the same in-circuit exponent value.
	expBts := f.ToBits(f.ReduceStrict(exp))
	n := len(expBts)

	// Pad to multiple of windowSize
	padding := (windowSize - (n % windowSize)) % windowSize
	paddedLen := n + padding

	// Process windows from MSB to LSB
	// expBts is LSB-first, so expBts[n-1] is MSB
	numWindows := paddedLen / windowSize

	// Initialize result with table lookup for the MSB window
	// MSB window (window 0) covers bits [(numWindows-1)*windowSize, numWindows*windowSize-1]
	// in the padded representation. Bits at indices >= n are padding zeros.
	msbWindowBits := make([]frontend.Variable, windowSize)
	msbBaseIdx := (numWindows - 1) * windowSize
	for i := 0; i < windowSize; i++ {
		actualIdx := msbBaseIdx + i
		if actualIdx < n {
			msbWindowBits[i] = expBts[actualIdx]
		} else {
			msbWindowBits[i] = 0
		}
	}
	res := f.tableLookup(table, msbWindowBits)

	// Process remaining windows
	for w := 1; w < numWindows; w++ {
		// Square windowSize times
		for i := 0; i < windowSize; i++ {
			res = f.ModMul(res, res, modulus)
		}

		// Extract window bits for this window
		// Window w covers bits from position (numWindows-1-w)*windowSize to (numWindows-w)*windowSize - 1
		// In the original LSB-first array
		windowBits := make([]frontend.Variable, windowSize)
		baseIdx := (numWindows - 1 - w) * windowSize
		for i := 0; i < windowSize; i++ {
			windowBits[i] = expBts[baseIdx+i]
		}

		// Table lookup and multiply
		selected := f.tableLookup(table, windowBits)
		res = f.ModMul(res, selected, modulus)
	}

	// Canonicalize the final output: assert it is strictly smaller than the
	// runtime modulus so the result is unique (safe for comparison, bit
	// decomposition, hashing). Only the returned value is constrained; the
	// intermediate ModMul results are allowed any representative.
	f.assertLessThanModulus(res, modulus)
	return res
}

// checkModulus asserts the invariant the variable-modulus carry bounds rely on:
// every limb of the modulus is at most [FieldParams.BitsPerLimb] bits wide. The
// bound on the k*p coefficients in [Field.mulCarryBound] is derived from that
// width, so a wider limb would make the bound unsound.
//
// For witness and constant moduli the width is enforced (respectively checked)
// where the modulus is used, in [Field.mulMod] and [Field.checkZero]. An element
// which has been operated on in-circuit instead carries the extra width in its
// overflow, and for those we fail at compile time. We deliberately do not reduce
// it for the caller: reducing would silently change the modulus whenever it does
// not fit T. See the note on the exported variable-modulus methods.
//
// The method adds no constraints.
func (f *Field[T]) checkModulus(modulus *Element[T]) {
	// populate the limbs in case the modulus was constructed in-circuit with
	// [ValueOf]. No-op for a witness element, which is initialized at witness
	// parsing time.
	modulus.Initialize(f.api.Compiler().Field())
	if modulus.overflow != 0 {
		panic(fmt.Sprintf("variable modulus has %d bits of overflow: the variable-modulus methods require a witness or constant modulus, see the method documentation", modulus.overflow))
	}
	if value, isConstant := f.constantValue(modulus); isConstant && value.Cmp(f.fParams.Modulus()) >= 0 {
		panic(fmt.Sprintf("variable modulus must be smaller than emulation modulus %s", f.fParams.Modulus()))
	}
}

// assertLessThanModulus asserts that e < modulus as integers, where modulus is
// a runtime (variable) modulus. mulMod only range-checks the remainder limbs to
// the width of T's modulus, so without this assertion the remainder may be any
// representative r' ≡ a·b (mod modulus) with r' < 2^(nbLimbs·bpl) — in
// particular r' = (a·b mod modulus) + modulus, which is non-canonical and breaks
// callers that rely on a unique representative (MODEXP, CRT reconstruction, bit
// decomposition, comparisons).
//
// The remainder returned by mulMod has zero overflow, and modulus is required to
// have zero overflow (see [Field.checkModulus]), so both can be decomposed into
// bits directly. The bound is modulus−1, computed as a constant-modulus strict
// reduction (exact, no wraparound: modulus−1 < modulus ≤ T's modulus).
func (f *Field[T]) assertLessThanModulus(e, modulus *Element[T]) {
	// fast path for constant modulus and constant element: check directly.
	if cv, ok := f.constantValue(e); ok {
		if mv, ok2 := f.constantValue(modulus); ok2 {
			if cv.Cmp(mv) >= 0 {
				panic(fmt.Sprintf("remainder %s is not canonical: not less than modulus %s", cv, mv))
			}
			return
		}
	}
	// modulusMinusOne = modulus - 1, strictly reduced against T's modulus. Since
	// modulus <= Modulus() (enforced for constants in checkModulus) and
	// modulus >= 1, modulus-1 is exact (no wraparound).
	modulusMinusOne := f.ReduceStrict(f.Sub(modulus, f.One()))
	f.AssertIsLessOrEqual(e, modulusMinusOne)
}

// tableLookup performs a selection to retrieve table[idx] where idx is the
// value represented by bits (LSB first). Uses Lookup2 for efficiency.
// Assumes len(table) == 16 and len(bits) == 4.
func (f *Field[T]) tableLookup(table []*Element[T], bits []frontend.Variable) *Element[T] {
	if len(table) != 16 || len(bits) != 4 {
		panic("tableLookup requires table of size 16 and 4 bits")
	}
	// For 4 bits selecting from 16 elements:
	// - bits[0], bits[1] select within groups of 4
	// - bits[2], bits[3] select which group

	// First level: use bits[0], bits[1] to reduce 16 -> 4
	level1 := make([]*Element[T], 4)
	for i := 0; i < 4; i++ {
		level1[i] = f.Lookup2(bits[0], bits[1],
			table[4*i+0], table[4*i+1], table[4*i+2], table[4*i+3])
	}

	// Second level: use bits[2], bits[3] to reduce 4 -> 1
	return f.Lookup2(bits[2], bits[3], level1[0], level1[1], level1[2], level1[3])
}
