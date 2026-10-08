package emulated

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type WrapperCircuit struct {
	X1, X2, X3, X4, X5, X6 frontend.Variable
	Res                    frontend.Variable
}

func (c *WrapperCircuit) Define(api frontend.API) error {
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := api.Mul(c.X1, c.X1, c.X1)
	fx2 := api.Mul(5, c.X2)
	nom := api.Sub(c.X3, c.X4)
	denom := api.Add(c.X5, c.X6)
	free := api.Div(nom, denom)
	res := api.Add(x13, fx2, free)
	api.AssertIsEqual(res, c.Res)
	return nil
}

type ConstantCircuit struct {
}

func (c *ConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	{
		c1 := f.NewElement(42)
		b1, ok := f.constantValue(c1)
		if !ok {
			return errors.New("42 should be constant")
		}
		if !b1.IsUint64() || b1.Uint64() != 42 {
			return errors.New("42 != constant(42)")
		}
	}
	{
		m := f.Modulus()
		b1, ok := f.constantValue(m)
		if !ok {
			return errors.New("modulus should be constant")
		}
		if b1.Cmp(Secp256k1Fp{}.Modulus()) != 0 {
			return errors.New("modulus != constant(modulus)")
		}
	}

	return nil
}

func TestConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness ConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type MulConstantCircuit struct {
}

func (c *MulConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	c0 := f.NewElement(0)
	c1 := f.NewElement(0)
	c2 := f.NewElement(0)
	r := f.Mul(c0, c1)
	f.AssertIsEqual(r, c2)

	return nil
}

func TestMulConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness MulConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type SubConstantCircuit struct {
}

func (c *SubConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	c0 := f.NewElement(0)
	c1 := f.NewElement(0)
	c2 := f.NewElement(0)
	r := f.Sub(c0, c1)
	if r.overflow != 0 {
		return fmt.Errorf("overflow %d != 0", r.overflow)
	}
	f.AssertIsEqual(r, c2)

	return nil
}

func TestSubConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness SubConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type SmallMulConstantFastPathCircuit struct {
	Dummy frontend.Variable
}

func (c *SmallMulConstantFastPathCircuit) Define(api frontend.API) error {
	// duplicate constraints to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Dummy, c.Dummy)
	api.AssertIsEqual(c.Dummy, c.Dummy)
	f, err := NewField[Goldilocks](api)
	if err != nil {
		return err
	}
	res := f.Mul(f.One(), f.One())
	if res.overflow != 0 {
		return fmt.Errorf("mul overflow %d != 0", res.overflow)
	}
	if _, ok := f.constantValue(res); !ok {
		return fmt.Errorf("mul should be constant")
	}
	f.AssertIsEqual(res, f.One())
	return nil
}

func TestSmallMulConstantFastPathCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&SmallMulConstantFastPathCircuit{}, test.WithValidAssignment(&SmallMulConstantFastPathCircuit{Dummy: 1}), test.NoTestEngine())
}

type SmallMulNoReduceConstantFastPathCircuit struct {
	Dummy frontend.Variable
}

func (c *SmallMulNoReduceConstantFastPathCircuit) Define(api frontend.API) error {
	// duplicate constraints to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Dummy, c.Dummy)
	api.AssertIsEqual(c.Dummy, c.Dummy)
	f, err := NewField[Goldilocks](api)
	if err != nil {
		return err
	}
	res := f.MulNoReduce(f.NewElement(7), f.NewElement(9))
	if res.overflow != 0 {
		return fmt.Errorf("mulNoReduce overflow %d != 0", res.overflow)
	}
	if _, ok := f.constantValue(res); !ok {
		return fmt.Errorf("mulNoReduce should be constant")
	}
	f.AssertIsEqual(res, f.NewElement(63))
	return nil
}

func TestSmallMulNoReduceConstantFastPathCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&SmallMulNoReduceConstantFastPathCircuit{}, test.WithValidAssignment(&SmallMulNoReduceConstantFastPathCircuit{Dummy: 1}), test.NoTestEngine())
}

type DivConstantFastPathCircuit struct {
	Dummy frontend.Variable
}

func (c *DivConstantFastPathCircuit) Define(api frontend.API) error {
	// duplicate constraints to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Dummy, c.Dummy)
	api.AssertIsEqual(c.Dummy, c.Dummy)
	f, err := NewField[Goldilocks](api)
	if err != nil {
		return err
	}
	res := f.Div(f.NewElement(21), f.NewElement(3))
	if res.overflow != 0 {
		return fmt.Errorf("div overflow %d != 0", res.overflow)
	}
	if _, ok := f.constantValue(res); !ok {
		return fmt.Errorf("div should be constant")
	}
	f.AssertIsEqual(res, f.NewElement(7))
	return nil
}

func TestDivConstantFastPathCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&DivConstantFastPathCircuit{}, test.WithValidAssignment(&DivConstantFastPathCircuit{Dummy: 1}), test.NoTestEngine())
}

type InverseConstantFastPathCircuit struct {
	Dummy frontend.Variable
}

func (c *InverseConstantFastPathCircuit) Define(api frontend.API) error {
	// duplicate constraints to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Dummy, c.Dummy)
	api.AssertIsEqual(c.Dummy, c.Dummy)
	f, err := NewField[Goldilocks](api)
	if err != nil {
		return err
	}
	res := f.Inverse(f.NewElement(7))
	if res.overflow != 0 {
		return fmt.Errorf("inverse overflow %d != 0", res.overflow)
	}
	if _, ok := f.constantValue(res); !ok {
		return fmt.Errorf("inverse should be constant")
	}
	f.AssertIsEqual(f.Mul(res, f.NewElement(7)), f.One())
	return nil
}

func TestInverseConstantFastPathCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&InverseConstantFastPathCircuit{}, test.WithValidAssignment(&InverseConstantFastPathCircuit{Dummy: 1}), test.NoTestEngine())
}

type InverseShortElementCircuit struct {
	B        frontend.Variable
	Expected Element[Secp256k1Fp]
}

func (c *InverseShortElementCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	// the selected element is stored on a single limb
	x := f.Select(c.B, f.NewElement(3), f.NewElement(5))
	f.AssertIsEqual(f.Inverse(x), &c.Expected)
	return nil
}

func TestInverseShortElement(t *testing.T) {
	assert := test.NewAssert(t)
	var fp Secp256k1Fp
	for _, tc := range []struct {
		b int
		v int64
	}{{1, 3}, {0, 5}} {
		inv := new(big.Int).ModInverse(big.NewInt(tc.v), fp.Modulus())
		assignment := InverseShortElementCircuit{B: tc.b, Expected: ValueOf[Secp256k1Fp](inv)}
		assert.NoError(test.IsSolved(&InverseShortElementCircuit{}, &assignment, ecc.BN254.ScalarField()))
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		assert.NoError(err)
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &InverseShortElementCircuit{})
		assert.NoError(err)
		_, err = ccs.Solve(w)
		assert.NoError(err)
		ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &InverseShortElementCircuit{})
		assert.NoError(err)
		_, err = ccs.Solve(w)
		assert.NoError(err)
	}
}

type SqrtConstantFastPathCircuit struct {
	Dummy frontend.Variable
}

func (c *SqrtConstantFastPathCircuit) Define(api frontend.API) error {
	// duplicate constraints to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Dummy, c.Dummy)
	api.AssertIsEqual(c.Dummy, c.Dummy)
	f, err := NewField[Goldilocks](api)
	if err != nil {
		return err
	}
	res := f.Sqrt(f.NewElement(9))
	if res.overflow != 0 {
		return fmt.Errorf("sqrt overflow %d != 0", res.overflow)
	}
	if _, ok := f.constantValue(res); !ok {
		return fmt.Errorf("sqrt should be constant")
	}
	f.AssertIsEqual(f.Mul(res, res), f.NewElement(9))
	return nil
}

func TestSqrtConstantFastPathCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&SqrtConstantFastPathCircuit{}, test.WithValidAssignment(&SqrtConstantFastPathCircuit{Dummy: 1}), test.NoTestEngine())
}

type LargeMulConstantFastPathCircuit struct {
	Dummy frontend.Variable
}

func (c *LargeMulConstantFastPathCircuit) Define(api frontend.API) error {
	// duplicate constraints to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Dummy, c.Dummy)
	api.AssertIsEqual(c.Dummy, c.Dummy)
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	res := f.Mul(f.NewElement(7), f.NewElement(9))
	if res.overflow != 0 {
		return fmt.Errorf("mulLarge overflow %d != 0", res.overflow)
	}
	if _, ok := f.constantValue(res); !ok {
		return fmt.Errorf("mulLarge should be constant")
	}
	f.AssertIsEqual(res, f.NewElement(63))
	return nil
}

func TestLargeMulConstantFastPathCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&LargeMulConstantFastPathCircuit{}, test.WithValidAssignment(&LargeMulConstantFastPathCircuit{Dummy: 1}), test.NoTestEngine())
}
