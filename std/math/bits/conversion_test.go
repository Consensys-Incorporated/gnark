package bits_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

type toBinaryCircuit struct {
	A          frontend.Variable
	B0, B1, B2 frontend.Variable
}

func (c *toBinaryCircuit) Define(api frontend.API) error {
	// binary decomposition
	nA := bits.FromBinary(api, []frontend.Variable{c.B0, c.B1, c.B2})

	api.AssertIsEqual(nA, c.A)

	// to binary
	b := bits.ToBinary(api, c.A, bits.WithNbDigits(3))
	api.AssertIsEqual(b[0], c.B0)
	api.AssertIsEqual(b[1], c.B1)
	api.AssertIsEqual(b[2], c.B2)

	return nil
}

func TestToBinary(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&toBinaryCircuit{},
		test.WithValidAssignment(&toBinaryCircuit{A: 5, B0: 1, B1: 0, B2: 1}),
		test.WithValidAssignment(&toBinaryCircuit{A: 3, B0: 1, B1: 1, B2: 0}),
		test.WithInvalidAssignment(&toBinaryCircuit{A: 8, B0: 0, B1: 0, B2: 0}),
		test.WithInvalidAssignment(&toBinaryCircuit{A: 10, B0: 0, B1: 1, B2: 0}),
	)

}

type toTernaryCircuit struct {
	A          frontend.Variable
	T0, T1, T2 frontend.Variable
}

func (c *toTernaryCircuit) Define(api frontend.API) error {
	// ternary decomposition
	nA := bits.FromTernary(api, []frontend.Variable{c.T0, c.T1, c.T2})

	api.AssertIsEqual(nA, c.A)

	// to ternary
	t := bits.ToTernary(api, c.A, bits.WithNbDigits(3))
	api.AssertIsEqual(t[0], c.T0)
	api.AssertIsEqual(t[1], c.T1)
	api.AssertIsEqual(t[2], c.T2)

	return nil
}

func TestToTernary(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&toTernaryCircuit{}, test.WithValidAssignment(&toTernaryCircuit{A: 5, T0: 2, T1: 1, T2: 0}))
}

type toBinaryCircuitConstantInput struct {
	A         frontend.Variable
	constantA *big.Int
	nbBits    int
}

func (c *toBinaryCircuitConstantInput) Define(api frontend.API) error {
	opts := []bits.BaseConversionOption{}
	if c.nbBits > 0 {
		opts = append(opts, bits.WithNbDigits(c.nbBits))
	}
	decomposedA := bits.ToBinary(api, c.A, opts...)
	constantA := new(big.Int).Set(c.constantA)
	if _, ok := api.Compiler().ConstantValue(constantA); !ok {
		// we work inside a test engine. It doesn't differentiate between a constant and a variable. We manually reduce for now.
		constantA.Mod(constantA, api.Compiler().Field())
	}
	decomposedAConstant := bits.ToBinary(api, constantA, opts...)
	if len(decomposedA) != len(decomposedAConstant) {
		return errors.New("decomposedA and decomposedAConstant must have the same length")
	}
	for i := 0; i < len(decomposedA); i++ {
		api.AssertIsEqual(decomposedA[i], decomposedAConstant[i])
	}

	return nil
}

func TestToBinaryConstantInput(t *testing.T) {
	assert := test.NewAssert(t)

	for _, v := range []int{0, 1, 2, 10, 100, 300} {
		assert.Run(func(assert *test.Assert) {
			val, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(v)))
			assert.NoError(err)
			assert.CheckCircuit(&toBinaryCircuitConstantInput{constantA: val, nbBits: v}, test.WithValidAssignment(&toBinaryCircuitConstantInput{A: val}))
		}, fmt.Sprintf("v=%d", v))
	}
}

type testFromBinaryCircuitConstantInput struct {
	Inputs           []*big.Int
	ThirdVariableBit frontend.Variable
	allConstant      bool
	Expected         frontend.Variable
}

func (c *testFromBinaryCircuitConstantInput) Define(api frontend.API) error {
	inps := make([]frontend.Variable, len(c.Inputs))
	for i, inp := range c.Inputs {
		inps[i] = inp
		// we also want to test the case where inside the constant inputs we have a variable
		if i == 2 && !c.allConstant {
			inps[i] = c.ThirdVariableBit
		}
	}
	res := bits.FromBinary(api, inps)
	api.AssertIsEqual(res, c.Expected)
	api.AssertIsEqual(c.Expected, c.Expected) // dummy constraint to overcome prover bug with 1 constraint
	return nil
}

func TestFromBinaryConstantInput(t *testing.T) {
	assert := test.NewAssert(t)

	for _, v := range []int{1, 2, 10, 100, 300} {
		val, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(v)))
		assert.NoError(err)

		bts := make([]*big.Int, v)
		for i := 0; i < v; i++ {
			bts[i] = new(big.Int).SetUint64(uint64(val.Bit(i)))
		}
		assert.Run(func(assert *test.Assert) {
			assert.Run(func(assert *test.Assert) {
				assert.CheckCircuit(&testFromBinaryCircuitConstantInput{
					Inputs:      bts,
					allConstant: true,
				},
					test.WithValidAssignment(&testFromBinaryCircuitConstantInput{
						ThirdVariableBit: 0,
						Expected:         val,
					}))
			}, "allconstant=true")
			if v > 2 {
				assert.Run(func(assert *test.Assert) {
					assert.CheckCircuit(&testFromBinaryCircuitConstantInput{
						Inputs:      bts,
						allConstant: false,
					},
						test.WithValidAssignment(&testFromBinaryCircuitConstantInput{
							Expected:         val,
							ThirdVariableBit: val.Bit(2),
						}))
				}, "allconstant=false")
			}
		}, fmt.Sprintf("v=%d", v))
	}
}

type testFromBinaryInvalidInput struct {
	ConstantInputs []*big.Int
	VariableInputs []frontend.Variable
	Variable       frontend.Variable
}

func (c *testFromBinaryInvalidInput) Define(api frontend.API) error {
	if len(c.ConstantInputs) != 0 {
		inps := make([]frontend.Variable, len(c.ConstantInputs))
		for i, inp := range c.ConstantInputs {
			inps[i] = inp
		}
		// test when constant inputs are not binary
		res := bits.FromBinary(api, inps)
		api.AssertIsDifferent(res, 0)
		// ensure we have at least two constraints to overcome PLONK prover bug with 1 constraint only
		api.AssertIsEqual(c.Variable, c.Variable)
		api.AssertIsEqual(c.Variable, c.Variable)
	} else {
		res := bits.FromBinary(api, c.VariableInputs)
		api.AssertIsDifferent(res, 0)
	}
	return nil
}

func TestFromBinaryInvalidInput(t *testing.T) {
	assert := test.NewAssert(t)

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testFromBinaryInvalidInput{
		ConstantInputs: []*big.Int{big.NewInt(2), big.NewInt(1)},
	})
	assert.Error(err)
	assert.CheckCircuit(&testFromBinaryInvalidInput{VariableInputs: make([]frontend.Variable, 2)}, test.WithInvalidAssignment(&testFromBinaryInvalidInput{
		VariableInputs: []frontend.Variable{2, 1},
		Variable:       big.NewInt(3),
	}))
}

type toBinaryUpperBoundCircuit struct {
	A     frontend.Variable
	bound *big.Int
}

func (c *toBinaryUpperBoundCircuit) Define(api frontend.API) error {
	bits.ToBinary(api, c.A, bits.WithUpperBound(c.bound))
	return nil
}

// The bound has to bind on its own, including when the digit count already
// keeps the value below the modulus. 100 is representable in the default number
// of digits, so only the bound can reject it.
func TestToBinaryUpperBound(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&toBinaryUpperBoundCircuit{bound: big.NewInt(100)},
		test.WithValidAssignment(&toBinaryUpperBoundCircuit{A: 0}),
		test.WithValidAssignment(&toBinaryUpperBoundCircuit{A: 99}),
		test.WithValidAssignment(&toBinaryUpperBoundCircuit{A: 100}),
		test.WithInvalidAssignment(&toBinaryUpperBoundCircuit{A: 101}),
		test.WithInvalidAssignment(&toBinaryUpperBoundCircuit{A: 255}),
	)
}

type toBinaryUpperBoundFewDigitsCircuit struct {
	A frontend.Variable
}

func (c *toBinaryUpperBoundFewDigitsCircuit) Define(api frontend.API) error {
	// WithNbDigits alone would skip the comparison entirely; the explicit bound
	// must still be enforced on top of it.
	bits.ToBinary(api, c.A, bits.WithNbDigits(8), bits.WithUpperBound(big.NewInt(100)))
	return nil
}

func TestToBinaryUpperBoundWithNbDigits(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&toBinaryUpperBoundFewDigitsCircuit{},
		test.WithValidAssignment(&toBinaryUpperBoundFewDigitsCircuit{A: 100}),
		test.WithInvalidAssignment(&toBinaryUpperBoundFewDigitsCircuit{A: 101}),
	)
}
