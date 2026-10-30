package emulated

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
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
	api.AssertIsEqual(f.IsZero(f.FromBits(c.Bits...)), c.IsZero)
	return nil
}

// FromBits over more bits than the modulus can encode 2p, 3p, ..., which are
// zero mod p. Covers the same limb count as the modulus (k·p) and twice as
// many limbs (p², p²+1).
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
