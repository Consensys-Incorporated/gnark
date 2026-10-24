package test

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/utils"
)

// modulus encapsulates field modulus and Montgomery conversion parameters
type modulus[E constraint.Element] struct {
	q        *big.Int
	rInv     *big.Int
	qInv     *big.Int // -q⁻¹ mod R, for Montgomery multiplication
	rMask    *big.Int // 2^logR - 1, for efficient mod R operation
	logR     uint
	bytesLen int
}

// newModulus creates a typed modulus and computes Montgomery parameters
func newModulus[E constraint.Element](q *big.Int) *modulus[E] {
	res := &modulus[E]{q: q}
	// The Montgomery radix follows the element type, not the size of the
	// modulus: the backing gnark-crypto field uses one limb of the element's
	// word width per limb of E.
	var e E
	switch any(e).(type) {
	case constraint.U32:
		res.logR = 32
		res.bytesLen = 4
	case constraint.U64W1:
		res.logR = 64
		res.bytesLen = 8
	case constraint.U64:
		nbBits := q.BitLen()
		nbLimbs := (nbBits + 63) / 64
		res.logR = uint(nbLimbs * 64)
		res.bytesLen = 48
	default:
		panic("unsupported type")
	}

	// Compute R = 2^logR
	r := new(big.Int).Lsh(big.NewInt(1), res.logR)

	// Compute R⁻¹ mod q
	res.rInv = new(big.Int).ModInverse(r, q)

	// Compute q⁻¹ mod R
	res.qInv = new(big.Int).ModInverse(q, r)

	// Compute qInv = -q⁻¹ mod R
	res.qInv.Sub(r, res.qInv)

	// Compute rMask = R - 1 = 2^logR - 1 for efficient mod R
	res.rMask = new(big.Int).Sub(r, big.NewInt(1))

	return res
}

// toMontBigInt extracts element bytes as Montgomery form big.Int (no conversion)
func (m *modulus[E]) toMontBigInt(f E) *big.Int {
	fBytes := f.Bytes()
	return new(big.Int).SetBytes(fBytes[:])
}

// montBigIntToElement converts Montgomery big.Int directly to element (no conversion)
func (m *modulus[E]) montBigIntToElement(mont *big.Int) E {
	bytes := mont.Bytes()
	if len(bytes) > m.bytesLen {
		panic("value too big")
	}
	paddedBytes := make([]byte, m.bytesLen)
	copy(paddedBytes[m.bytesLen-len(bytes):], bytes[:])
	return constraint.NewElement[E](paddedBytes[:])
}

// ToBigInt converts element (Montgomery form) to canonical big.Int
func (m *modulus[E]) ToBigInt(f E) *big.Int {
	x := m.toMontBigInt(f)
	x.Mul(x, m.rInv).Mod(x, m.q)
	return x
}

// bigIntToElement converts canonical big.Int to Montgomery form element
func (m *modulus[E]) bigIntToElement(b *big.Int) E {
	if b.Sign() == -1 {
		panic("negative value")
	}
	x := new(big.Int).Lsh(b, m.logR)
	x.Mod(x, m.q)
	return m.montBigIntToElement(x)
}

// blueprintSolver is a constraint.Solver that can be used to test a circuit
// it is a separate type to avoid method collisions with the engine.
type blueprintSolver[E constraint.Element] struct {
	internalVariables []*big.Int
	blueprints        []constraint.Blueprint
	*modulus[E]
}

// implements constraint.Solver

func (s *blueprintSolver[E]) SetValue(vID uint32, f E) {
	if int(vID) > len(s.internalVariables) {
		panic("out of bounds")
	}
	v := s.ToBigInt(f)
	s.internalVariables[vID].Set(v)
}

func (s *blueprintSolver[E]) GetValue(cID, vID uint32) E {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver[E]) GetCoeff(cID uint32) E {
	panic("not implemented in test.Engine")
}

func (s *blueprintSolver[E]) IsSolved(vID uint32) bool {
	panic("not implemented in test.Engine")
}

func (s *blueprintSolver[E]) GetBlueprint(id constraint.BlueprintID) constraint.Blueprint {
	return s.blueprints[id]
}

// implements constraint.Field

func (s *blueprintSolver[E]) FromInterface(i interface{}) E {
	b := utils.FromInterface(i)
	return s.bigIntToElement(&b)
}

func (s *blueprintSolver[E]) Mul(a, b E) E {
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)

	// Montgomery multiplication using REDC algorithm
	// Computes (a·R) · (b·R) / R mod q = a·b·R mod q

	// Step 1: t = a · b
	t := new(big.Int).Mul(ba, bb)

	// Step 2: m = (t · qInv) mod R
	// Since R = 2^logR, we use bit masking for mod R
	// Optimize: reduce t mod R first to make multiplication smaller
	m := new(big.Int).And(t, s.modulus.rMask)
	m.Mul(m, s.modulus.qInv)
	m.And(m, s.modulus.rMask)

	// Step 3: m = (t + m·q) / R
	m.Mul(m, s.modulus.q)
	m.Add(m, t)
	m.Rsh(m, s.modulus.logR) // divide by R = 2^logR

	// Step 4: Final reduction
	if m.Cmp(s.modulus.q) >= 0 {
		m.Sub(m, s.modulus.q)
	}

	return s.montBigIntToElement(m)
}

func (s *blueprintSolver[E]) Add(a, b E) E {
	// Addition works the same in Montgomery form: (a·R + b·R) mod m = (a+b)·R mod m
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Add(ba, bb).Mod(ba, s.modulus.q)
	return s.montBigIntToElement(ba)
}

func (s *blueprintSolver[E]) Sub(a, b E) E {
	// Subtraction works the same in Montgomery form: (a·R - b·R) mod m = (a-b)·R mod m
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Sub(ba, bb).Mod(ba, s.modulus.q)
	return s.montBigIntToElement(ba)
}

func (s *blueprintSolver[E]) Neg(a E) E {
	var zero E
	if a == zero {
		return zero
	}
	ba := s.toMontBigInt(a)
	ba.Sub(s.modulus.q, ba)
	return s.montBigIntToElement(ba)
}

func (s *blueprintSolver[E]) Inverse(a E) (E, bool) {
	var zero E
	if a == zero {
		return zero, false
	}
	// a is non-zero, so toMontBigInt(a) != 0 mod q (q prime), ModInverse always succeeds.
	r := s.toMontBigInt(a)
	r.ModInverse(r, s.modulus.q)
	r.Lsh(r, s.modulus.logR).
		Mod(r, s.modulus.q)
	return s.bigIntToElement(r), true
}

func (s *blueprintSolver[E]) One() E {
	b := new(big.Int).SetUint64(1)
	return s.bigIntToElement(b)
}
func (s *blueprintSolver[E]) IsOne(a E) bool {
	return a == s.One()
}

func (s *blueprintSolver[E]) String(a E) string {
	b := s.ToBigInt(a)
	return b.String()
}

func (s *blueprintSolver[E]) Uint64(a E) (uint64, bool) {
	b := s.ToBigInt(a)
	return b.Uint64(), b.IsUint64()
}

func (s *blueprintSolver[E]) Read(calldata []uint32) (E, int) {
	// Read canonical bytes from calldata, convert to Montgomery form element
	var r E
	var canonicalValue *big.Int
	var nWords int

	switch t := any(&r).(type) {
	case *constraint.U64:
		// Read canonical bytes from calldata
		for i := 0; i < len(r); i++ {
			index := i * 2
			t[i] = uint64(calldata[index])<<32 | uint64(calldata[index+1])
		}
		canonicalValue = new(big.Int).SetBytes(r.Bytes())
		nWords = len(r) * 2
	case *constraint.U64W1:
		t[0] = uint64(calldata[0])<<32 | uint64(calldata[1])
		canonicalValue = new(big.Int).SetUint64(t[0])
		nWords = 2
	case *constraint.U32:
		t[0] = uint32(calldata[0])
		canonicalValue = new(big.Int).SetUint64(uint64(t[0]))
		nWords = 1
	default:
		panic("unsupported type")
	}

	// Convert canonical to Montgomery and return as element
	return s.bigIntToElement(canonicalValue), nWords
}

// wrappedBigInt is a wrapper around big.Int to implement the frontend.CanonicalVariable interface
type wrappedBigInt[E constraint.Element] struct {
	*big.Int
	*modulus[E]
}

// Compress writes canonical bytes to calldata (no Montgomery conversion)
func (w wrappedBigInt[E]) Compress(to *[]uint32) {
	if w.Sign() == -1 {
		panic("negative value")
	}

	// Use montBigIntToElement to handle byte padding and type switching
	e := w.modulus.montBigIntToElement(w.Int)

	// Extract uint32 values from the element
	switch e := any(e).(type) {
	case constraint.U32:
		*to = append(*to, uint32(e[0]))
	case constraint.U64W1:
		*to = append(*to, uint32(e[0]>>32), uint32(e[0]&0xffffffff))
	case constraint.U64:
		// append the uint32 words to the slice
		for i := range e {
			*to = append(*to, uint32(e[i]>>32))
			*to = append(*to, uint32(e[i]&0xffffffff))
		}
	default:
		panic("unsupported type")
	}
}
