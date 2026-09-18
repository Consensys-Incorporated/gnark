package emulated

// ReduceWidth returns an element reduced by the modulus and constrained to have
// same length as the modulus. The output element has the same width as the
// modulus but may up to twice larger than the modulus).
//
// Does not mutate the input.
//
// In cases where the canonical representation of the element is required, use
// [Field.ReduceStrict].
func (f *Field[T]) Reduce(a *Element[T]) *Element[T] {
	ret := f.reduce(a, false)
	return ret
}

func (f *Field[T]) reduce(a *Element[T], strict bool) *Element[T] {
	f.enforceWidthConditional(a)
	if a.modReduced {
		// fast path - we are in the strict case and the element was just strictly reduced
		return a
	}
	if !strict && a.overflow == 0 {
		// fast path - we are in non-strict case and the element has no
		// overflow. We don't need to reduce now.
		return a
	}
	// rest of the cases:
	//   - in strict case and element was not recently reduced (even if it has no overflow)
	//   - in non-strict case and the element has overflow

	// Lazy operations can algebraically cancel variables and leave an element
	// which the compiler recognizes as constant while its conservative overflow
	// metadata remains non-zero. Fold it before entering the hint-based path.
	if ca, aConst := f.constantValue(a); aConst {
		return newConstElement[T](f.api.Compiler().Field(), ca, false)
	}
	// slow path - use hint to reduce value
	return f.mulMod(a, f.One(), 0, nil)
}

// ReduceStrict returns an element reduced by the modulus. The output element
// has the same width as the modulus and is guaranteed to be less than the
// modulus.
//
// Does not mutate the input.
//
// This method is useful when the canonical representation of the element is
// required. For example, when the element is used in bitwise operations. This
// means that the reduction is enforced even when the overflow of the element is
// 0, but it has not been strictly reduced before.
func (f *Field[T]) ReduceStrict(a *Element[T]) *Element[T] {
	ret := f.reduce(a, true)
	f.AssertIsInRange(ret)
	return ret
}
