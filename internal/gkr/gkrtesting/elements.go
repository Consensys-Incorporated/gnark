package gkrtesting

import (
	"fmt"
	"math/big"
)

// testElement is the part of a field element's API the test-vector helpers need.
type testElement[E any] interface {
	*E
	SetBigInt(*big.Int) *E
	Inverse(*E) *E
	Mul(*E, *E) *E
	Equal(*E) bool
	String() string
}

// SetElement parses value — a decimal or "num/den" string, or a JSON number — into a big.Rat,
// then sets z to its numerator divided by its denominator, via SetBigInt, Inverse and Mul.
func SetElement[E any, PE testElement[E]](z *E, value any) error {
	var r big.Rat
	switch v := value.(type) {
	case string:
		if _, ok := r.SetString(v); !ok {
			return fmt.Errorf("cannot parse %q", v)
		}
	case float64:
		asInt := int64(v)
		if float64(asInt) != v {
			return fmt.Errorf("cannot currently parse float")
		}
		r.SetFloat64(v)
	default:
		return fmt.Errorf("cannot parse value of type %T", value)
	}

	var denom E
	pz, pDenom := PE(z), PE(&denom)
	pz.SetBigInt(r.Num())
	pDenom.SetBigInt(r.Denom())
	pDenom.Inverse(pDenom)
	pz.Mul(pz, pDenom)
	return nil
}

// SliceToElementSlice parses each element of slice with SetElement.
func SliceToElementSlice[E any, PE testElement[E], T any](slice []T) ([]E, error) {
	elementSlice := make([]E, len(slice))
	for i, v := range slice {
		if err := SetElement[E, PE](&elementSlice[i], v); err != nil {
			return nil, err
		}
	}
	return elementSlice, nil
}

// SliceEquals returns an error describing the first difference between a and b, if any.
func SliceEquals[E any, PE testElement[E]](a, b []E) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if !PE(&a[i]).Equal(&b[i]) {
			return fmt.Errorf("at index %d: %s ≠ %s", i, PE(&a[i]).String(), PE(&b[i]).String())
		}
	}
	return nil
}

// PolynomialSliceEquals returns an error describing the first difference between a and b, if any.
func PolynomialSliceEquals[E any, PE testElement[E]](a, b [][]E) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if err := SliceEquals[E, PE](a[i], b[i]); err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}
	}
	return nil
}

// ToSlices converts a slice of slices of a named slice type to a slice of []T.
func ToSlices[T any, S ~[]T](slices []S) [][]T {
	res := make([][]T, len(slices))
	for i := range slices {
		res[i] = slices[i]
	}
	return res
}
