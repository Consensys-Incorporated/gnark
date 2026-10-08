package constraint

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/smallfields"
)

// U32 represents an element on a single uint32 limb
type U32 [1]uint32

// U64 represents an element on 6 uint64 limbs. This fits all scalar fields used
// in gnark-crypto. In concrete implementations, the backends may use less than
// 6 limbs if not necessary. Due to this, there is up to 50% overhead.
type U64 [6]uint64

// Element is a generic interface for all elements used in gnark. It is
// implemented by U32 and U64. The interface is used to provide a generic
// interface for all elements used in gnark.
type Element interface {
	U32 | U64
	// IsZero returns true if coefficient == 0
	IsZero() bool
	// Bytes return the Element as a big-endian byte slice The length of the
	// byte slice is 4 for U32 and 48 for U64. The byte slice is in big-endian
	// order.
	Bytes() []byte
}

// NewElement creates a new element from a byte slice. The byte slice must be in
// big-endian order. The length of the byte slice is 4 for U32 and 48 for U64.
// The byte slice is copied to the element. The element is returned as the type
// of the element passed as a parameter. The function panics if the byte slice
// is not the correct length or if the element type is not supported.
//
// We use this method instead of having a method on the parametric interface to
// avoid passing the pointer (mutable) parameter.
func NewElement[E Element](b []byte) E {
	var e E
	switch t := any(&e).(type) {
	case *U32:
		if len(b) != 4 {
			panic(fmt.Sprintf("wrong length, expected 4 got %d", len(b)))
		}
		t[0] = binary.BigEndian.Uint32(b[0:4])
	case *U64:
		if len(b) != 48 {
			panic(fmt.Sprintf("wrong length, expected 48 got %d", len(b)))
		}
		t[0] = binary.BigEndian.Uint64(b[40:48])
		t[1] = binary.BigEndian.Uint64(b[32:40])
		t[2] = binary.BigEndian.Uint64(b[24:32])
		t[3] = binary.BigEndian.Uint64(b[16:24])
		t[4] = binary.BigEndian.Uint64(b[8:16])
		t[5] = binary.BigEndian.Uint64(b[0:8])
	default:
		panic(fmt.Sprintf("unsupported type %T", t))
	}
	return e
}

// FitsElement returns true if the element fits in the given modulus. This can
// be used to type-switch in the implementation at runtime.
//
// Being a small field does not by itself imply U32: [U32] holds a single
// uint32, so a small field wider than that is represented in [U64] instead.
// mamabear is 49 bits and is the first such field.
func FitsElement[E Element](modulus *big.Int) bool {
	var e E
	switch any(e).(type) {
	case U32:
		return smallfields.IsSmallField(modulus) && modulus.BitLen() <= 32
	case U64:
		for _, c := range gnark.Curves() {
			if modulus.Cmp(c.ScalarField()) == 0 {
				return true
			}
		}
		if modulus.Cmp(ecc.GRUMPKIN.ScalarField()) == 0 {
			return true
		}
		// small fields too wide for U32
		return smallfields.IsSmallField(modulus) && modulus.BitLen() > 32
	default:
		panic("unsupported type")
	}
}

// IsZero returns true if coefficient == 0
func (z U64) IsZero() bool {
	return (z[5] | z[4] | z[3] | z[2] | z[1] | z[0]) == 0
}

// Bytes return the Element as a big-endian byte slice
func (z U64) Bytes() []byte {
	var b [48]byte
	binary.BigEndian.PutUint64(b[40:48], z[0])
	binary.BigEndian.PutUint64(b[32:40], z[1])
	binary.BigEndian.PutUint64(b[24:32], z[2])
	binary.BigEndian.PutUint64(b[16:24], z[3])
	binary.BigEndian.PutUint64(b[8:16], z[4])
	binary.BigEndian.PutUint64(b[0:8], z[5])
	return b[:]
}

// IsZero returns true if coefficient == 0
func (z U32) IsZero() bool {
	return (z[0]) == 0
}

// Bytes return the Element as a big-endian byte slice
func (z U32) Bytes() []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[0:4], z[0])
	return b[:]
}

// Field capability to perform arithmetic on Coeff
type Field[E Element] interface {
	FromInterface(interface{}) E
	ToBigInt(E) *big.Int
	Mul(a, b E) E
	Add(a, b E) E
	Sub(a, b E) E
	Neg(a E) E
	Inverse(a E) (E, bool)
	One() E
	IsOne(E) bool
	String(E) string
	Uint64(E) (uint64, bool)
}
