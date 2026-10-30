package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/bits"
)

// ToBits returns the bit representation of the Element in little-endian (LSB
// first) order. The returned bits are constrained to be 0-1. The number of
// returned bits is nbLimbs*nbBits+overflow. To obtain the bits of the canonical
// representation of Element, use method [Field.ToBitsCanonical].
//
// The bit decomposition is cached in the Element to avoid redundant computation
// when the same element is decomposed multiple times.
func (f *Field[T]) ToBits(a *Element[T]) []frontend.Variable {
	// Save cached bits and overflow BEFORE enforceWidthConditional, which calls
	// Initialize and resets the cache for deterministic recompilation. This
	// matches the pattern used by modReduced flag.
	cachedBits := a.bitsDecomposition
	cachedOverflow := a.bitsOverflow

	f.enforceWidthConditional(a)
	ba, aConst := f.constantValue(a)
	if aConst {
		res := make([]frontend.Variable, f.fParams.BitsPerLimb()*f.fParams.NbLimbs())
		for i := range res {
			res[i] = ba.Bit(i)
		}
		return res
	}

	// Check if we had cached bits that are still valid (same overflow value).
	// Overflow can change (e.g., AssertIsInRange sets overflow=0), which affects
	// the bit count, so we must verify the cached bits match current overflow.
	if cachedBits != nil && cachedOverflow == a.overflow {
		// Restore cache and return a copy to prevent callers from mutating
		a.bitsDecomposition = cachedBits
		a.bitsOverflow = cachedOverflow
		res := make([]frontend.Variable, len(cachedBits))
		copy(res, cachedBits)
		return res
	}

	var carry frontend.Variable = 0
	var fullBits []frontend.Variable
	var limbBits []frontend.Variable
	for i := 0; i < len(a.Limbs); i++ {
		limbBits = bits.ToBinary(f.api, f.api.Add(a.Limbs[i], carry), bits.WithNbDigits(int(f.fParams.BitsPerLimb()+a.overflow)))
		fullBits = append(fullBits, limbBits[:f.fParams.BitsPerLimb()]...)
		if a.overflow > 0 {
			carry = bits.FromBinary(f.api, limbBits[f.fParams.BitsPerLimb():])
		}
	}
	fullBits = append(fullBits, limbBits[f.fParams.BitsPerLimb():f.fParams.BitsPerLimb()+a.overflow]...)

	// Cache the bits and overflow in the element for future use
	a.bitsDecomposition = fullBits
	a.bitsOverflow = a.overflow

	// Record operation for profiling
	profile.RecordOperation("emulated.ToBits", 4*len(fullBits))
	return fullBits
}

// ToBitsCanonical represents the unique bit representation in the canonical
// format (less that the modulus).
func (f *Field[T]) ToBitsCanonical(a *Element[T]) []frontend.Variable {
	nbBits := f.fParams.Modulus().BitLen()
	// when the modulus is a power of 2, then we can remove the most significant
	// bit as it is always zero.
	if f.fParams.Modulus().TrailingZeroBits() == uint(nbBits-1) {
		nbBits--
	}

	// Reduce the element first using strict reduction (always performs mulMod).
	// This ensures the value is actually reduced mod p, not just has overflow=0.
	ca := f.reduce(a, true)

	// Get bits of reduced element
	caBits := f.ToBits(ca)

	// Get bits of modulus-1 (this is cached as a constant, so ToBits is cheap)
	modPrev := f.modulusPrev()
	modPrevBits := f.ToBits(modPrev)

	// Assert that the reduced element is less than the modulus (ca <= modulus-1).
	// This avoids calling ToBits again on the same element (which is what
	// the original ReduceStrict + AssertIsInRange path would do).
	f.assertIsLessOrEqualBits(caBits, modPrevBits)

	profile.RecordOperation("emulated.ToBitsCanonical", 4*(len(caBits)+len(modPrevBits)))
	return caBits[:nbBits]
}

// FromBits returns a new Element given the bits is little-endian order.
func (f *Field[T]) FromBits(bs ...frontend.Variable) *Element[T] {
	nbLimbs := (uint(len(bs)) + f.fParams.BitsPerLimb() - 1) / f.fParams.BitsPerLimb()
	limbs := make([]frontend.Variable, nbLimbs)
	for i := uint(0); i < nbLimbs-1; i++ {
		limbs[i] = bits.FromBinary(f.api, bs[i*f.fParams.BitsPerLimb():(i+1)*f.fParams.BitsPerLimb()])
	}
	limbs[nbLimbs-1] = bits.FromBinary(f.api, bs[(nbLimbs-1)*f.fParams.BitsPerLimb():])
	// more bits than the modulus can encode 2p, 3p, ...: mark it as overflowed
	// so that Reduce reduces it (IsZero is only exact below 2p).
	var overflow uint
	if len(bs) > f.fParams.Modulus().BitLen() {
		overflow = 1
	}
	return f.newInternalElement(limbs, overflow)
}
