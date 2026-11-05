package emulated

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type ZeroCircuit[T FieldParams] struct {
	Var    Element[T]
	IsZero frontend.Variable `gnark:",public"`
}

func (c *ZeroCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.IsZero(&c.Var)
	f.api.AssertIsEqual(res, c.IsZero)
	return nil
}

func TestZeroCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	type T = BLS12381Fp
	var circuit, witness ZeroCircuit[T]
	{
		//Non-zero
		el := Element[T]{
			Limbs:    []frontend.Variable{0, 1, 0, 1, 0, 1},
			overflow: 0,
			internal: true,
		}
		witness.Var = el
		witness.IsZero = 0

		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}
	{
		//Zero
		el := Element[T]{
			Limbs:    []frontend.Variable{0, 0, 0, 0, 0, 0},
			overflow: 0,
			internal: true,
		}
		witness.Var = el
		witness.IsZero = 1

		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}
}

type FromBitsIsZeroCircuit[T FieldParams] struct {
	Bits   []frontend.Variable
	IsZero frontend.Variable
}

func (c *FromBitsIsZeroCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	el := f.FromBits(c.Bits...)
	api.AssertIsEqual(f.IsZero(el), c.IsZero)
	// the result is usable as any element of overflow 0
	f.AssertIsInRange(el)
	return nil
}

// FromBits over more bits than the modulus can encode 2p, 3p, ..., which are
// zero mod p. Covers the same limb count as the modulus (k·p) and twice as
// many limbs (p², p²+1), and AssertIsInRange on the result.
func TestFromBitsIsZeroMultipleOfModulus(t *testing.T) {
	testFromBitsIsZeroMultipleOfModulus[BN254Fp](t)
	testFromBitsIsZeroMultipleOfModulus[BLS12381Fp](t)
}

func testFromBitsIsZeroMultipleOfModulus[T FieldParams](t *testing.T) {
	var fp T
	p := fp.Modulus()
	limbBits := int(fp.NbLimbs() * fp.BitsPerLimb())
	assert := test.NewAssert(t)
	check := func(name string, nbBits int, v *big.Int) {
		bs := make([]frontend.Variable, nbBits)
		for i := range bs {
			bs[i] = v.Bit(i)
		}
		isZero := 0
		if new(big.Int).Mod(v, p).Sign() == 0 {
			isZero = 1
		}
		assert.Run(func(assert *test.Assert) {
			assert.CheckCircuit(&FromBitsIsZeroCircuit[T]{Bits: make([]frontend.Variable, nbBits)},
				test.WithValidAssignment(&FromBitsIsZeroCircuit[T]{Bits: bs, IsZero: isZero}),
				test.WithInvalidAssignment(&FromBitsIsZeroCircuit[T]{Bits: bs, IsZero: 1 - isZero}),
				test.WithCurves(testCurve), test.NoSerializationChecks(), test.NoProverChecks())
		}, testName[T](), name)
	}
	for k := int64(2); ; k++ {
		kp := new(big.Int).Mul(p, big.NewInt(k))
		if kp.BitLen() > limbBits {
			break
		}
		check(fmt.Sprintf("k=%d", k), limbBits, kp)
	}
	pp := new(big.Int).Mul(p, p)
	check("p^2", 2*limbBits, pp)
	check("p^2+1", 2*limbBits, pp.Add(pp, big.NewInt(1)))
}

// fromBitsPaddingCircuit asserts FromBits(Bits followed by Pad constant zeros)
// in range.
type fromBitsPaddingCircuit[T FieldParams] struct {
	Bits []frontend.Variable
	Pad  int `gnark:"-"`
}

func (c *fromBitsPaddingCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	bs := append([]frontend.Variable{}, c.Bits...)
	for i := 0; i < c.Pad; i++ {
		bs = append(bs, 0)
	}
	f.AssertIsInRange(f.FromBits(bs...))
	return nil
}

// Constant zeros on top of the modulus's bit length don't make FromBits
// reduce: the padding costs nothing and AssertIsInRange still rejects p.
// Compiled backends only: the test engine shows no constants.
func TestFromBitsConstantPadding(t *testing.T) {
	type T = BN254Fp
	p := T{}.Modulus()
	nbBits, pad := p.BitLen(), 2 // 256 bits, the modulus's limb count
	bitsOf := func(v *big.Int) []frontend.Variable {
		bs := make([]frontend.Variable, nbBits)
		for i := range bs {
			bs[i] = v.Bit(i)
		}
		return bs
	}
	for _, b := range []struct {
		name    string
		compile func(frontend.Circuit) (constraint.ConstraintSystem, error)
	}{
		{"r1cs", func(c frontend.Circuit) (constraint.ConstraintSystem, error) {
			return frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, c)
		}},
		{"scs", func(c frontend.Circuit) (constraint.ConstraintSystem, error) {
			return frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, c)
		}},
	} {
		plain, err := b.compile(&fromBitsPaddingCircuit[T]{Bits: make([]frontend.Variable, nbBits)})
		if err != nil {
			t.Fatal(err)
		}
		padded, err := b.compile(&fromBitsPaddingCircuit[T]{Bits: make([]frontend.Variable, nbBits), Pad: pad})
		if err != nil {
			t.Fatal(err)
		}
		if padded.GetNbConstraints() != plain.GetNbConstraints() {
			t.Errorf("%s: %d constraints with padding, %d without", b.name, padded.GetNbConstraints(), plain.GetNbConstraints())
		}
		solve := func(v *big.Int) error {
			w, err := frontend.NewWitness(&fromBitsPaddingCircuit[T]{Bits: bitsOf(v), Pad: pad}, testCurve.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			_, err = padded.Solve(w)
			return err
		}
		if err := solve(new(big.Int).Sub(p, big.NewInt(1))); err != nil {
			t.Errorf("%s: p-1 rejected: %v", b.name, err)
		}
		if err := solve(p); err == nil {
			t.Errorf("%s: p accepted: the padding made FromBits reduce", b.name)
		}
	}
}

type fromBitsSmallFieldCircuit struct {
	Bits []frontend.Variable
}

func (c *fromBitsSmallFieldCircuit) Define(api frontend.API) error {
	f, err := NewField[Goldilocks](api)
	if err != nil {
		return err
	}
	if x := f.FromBits(c.Bits...); x.overflow != 0 || len(x.Limbs) != 2 {
		return fmt.Errorf("FromBits(128 bits) reduced on a small field: overflow %d, %d limbs", x.overflow, len(x.Limbs))
	}
	return nil
}

// Small fields are left as they were: their reduction folds the limbs into
// one native value, which a wide input can wrap.
func TestFromBitsSmallFieldNotReduced(t *testing.T) {
	bs := make([]frontend.Variable, 128)
	for i := range bs {
		bs[i] = 1
	}
	if err := test.IsSolved(&fromBitsSmallFieldCircuit{Bits: make([]frontend.Variable, 128)}, &fromBitsSmallFieldCircuit{Bits: bs}, testCurve.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
