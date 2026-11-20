package emulated

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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

type IsZeroWideCircuit[T FieldParams] struct {
	Bits []frontend.Variable
}

func (c *IsZeroWideCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	_ = f.IsZero(f.FromBits(c.Bits...))
	return nil
}

func TestIsZeroWide(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &IsZeroWideCircuit[BN254Fr]{
		Bits: make([]frontend.Variable, 508),
	}
	witness := &IsZeroWideCircuit[BN254Fr]{
		Bits: make([]frontend.Variable, 508),
	}
	for i := range witness.Bits {
		witness.Bits[i] = 0
	}
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsZeroShortFalsePositiveCircuit[T FieldParams] struct {
	LowLimb frontend.Variable
}

func (c *IsZeroShortFalsePositiveCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	el := f.newInternalElement([]frontend.Variable{c.LowLimb}, 0)
	isZero := f.IsZero(el)
	api.AssertIsEqual(isZero, 0)
	return nil
}

func TestIsZeroShortFalsePositive(t *testing.T) {
	assert := test.NewAssert(t)
	lowLimb, _ := new(big.Int).SetString("ffffffff00000001", 16)
	circuit := &IsZeroShortFalsePositiveCircuit[BLS12381Fr]{}
	witness := &IsZeroShortFalsePositiveCircuit[BLS12381Fr]{
		LowLimb: lowLimb,
	}
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
