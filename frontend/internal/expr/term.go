package expr

import (
	"encoding/binary"

	"github.com/consensys/gnark/constraint"
	"golang.org/x/crypto/blake2b"
)

type Term[E constraint.Element] struct {
	VID   int
	Coeff E
}

func NewTerm[E constraint.Element](vID int, cID E) Term[E] {
	return Term[E]{Coeff: cID, VID: vID}
}

func (t *Term[E]) SetCoeff(c E) {
	t.Coeff = c
}

// TODO @gbotrel make that return a uint32
func (t Term[E]) WireID() int {
	return t.VID
}

// HashCode returns a collision resistant hash code identifier for the term.
func (t Term[E]) HashCode() [16]byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(t.VID)))

	switch coeff := any(t.Coeff).(type) {
	case constraint.U32:
		for i := range coeff {
			h.Write(binary.BigEndian.AppendUint32(nil, uint32(coeff[i])))
		}
	case constraint.U64W1:
		for i := range coeff {
			h.Write(binary.BigEndian.AppendUint64(nil, coeff[i]))
		}
	case constraint.U64:
		for i := range coeff {
			h.Write(binary.BigEndian.AppendUint64(nil, uint64(coeff[i])))
		}
	}
	crc := h.Sum(nil)
	return [16]byte(crc[:16])
}
