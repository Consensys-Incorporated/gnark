package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type variableEquality[T FieldParams] struct {
	Modulus Element[T]
	A, B    Element[T]
}

func (c *variableEquality[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	f.ModAssertIsEqual(&c.A, &c.B, &c.Modulus)
	return nil
}

func TestVariableEquality(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	a := big.NewInt(10)
	b := new(big.Int).Add(a, modulus)
	circuit := &variableEquality[emparams.Mod1e512]{}
	assignment := &variableEquality[emparams.Mod1e512]{
		Modulus: ValueOf[emparams.Mod1e512](modulus),
		A:       ValueOf[emparams.Mod1e512](a),
		B:       ValueOf[emparams.Mod1e512](b),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableAddition[T FieldParams] struct {
	Modulus  Element[T]
	A, B     Element[T]
	Expected Element[T]
}

func (c *variableAddition[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModAdd(&c.A, &c.B, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableAddition(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	circuit := &variableAddition[emparams.Mod1e512]{}
	assignment := &variableAddition[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		A:        ValueOf[emparams.Mod1e512](10),
		B:        ValueOf[emparams.Mod1e512](20),
		Expected: ValueOf[emparams.Mod1e512](30),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableSubtraction[T FieldParams] struct {
	Modulus  Element[T]
	A, B     Element[T]
	Expected Element[T]
}

func (c *variableSubtraction[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.modSub(&c.A, &c.B, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableSubtraction(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	circuit := &variableSubtraction[emparams.Mod1e512]{}
	res := new(big.Int).Sub(modulus, big.NewInt(10))
	assignment := &variableSubtraction[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		A:        ValueOf[emparams.Mod1e512](10),
		B:        ValueOf[emparams.Mod1e512](20),
		Expected: ValueOf[emparams.Mod1e512](res),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableMultiplication[T FieldParams] struct {
	Modulus  Element[T]
	A, B     Element[T]
	Expected Element[T]
}

func (c *variableMultiplication[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModMul(&c.A, &c.B, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableMultiplication(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	a, _ := rand.Int(rand.Reader, modulus)
	b, _ := rand.Int(rand.Reader, modulus)
	exp := new(big.Int).Mul(a, b)
	exp.Mod(exp, modulus)
	circuit := &variableMultiplication[emparams.Mod1e512]{}
	assignment := &variableMultiplication[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		A:        ValueOf[emparams.Mod1e512](a),
		B:        ValueOf[emparams.Mod1e512](b),
		Expected: ValueOf[emparams.Mod1e512](exp),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableExp[T FieldParams] struct {
	Modulus  Element[T]
	Base     Element[T]
	Exp      Element[T]
	Expected Element[T]
}

func (c *variableExp[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModExp(&c.Base, &c.Exp, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableExp(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	base, _ := rand.Int(rand.Reader, modulus)
	exp, _ := rand.Int(rand.Reader, modulus)
	expected := new(big.Int).Exp(base, exp, modulus)
	circuit := &variableExp[emparams.Mod1e512]{}
	assignment := &variableExp[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		Base:     ValueOf[emparams.Mod1e512](base),
		Exp:      ValueOf[emparams.Mod1e512](exp),
		Expected: ValueOf[emparams.Mod1e512](expected),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestVariableExpEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)

	testCases := []struct {
		name           string
		base, exp, mod *big.Int
	}{
		{"small exponent", big.NewInt(2), big.NewInt(10), big.NewInt(1000)},
		{"zero exponent", big.NewInt(2), big.NewInt(0), big.NewInt(1000)},
		{"zero base", big.NewInt(0), big.NewInt(10), big.NewInt(1000)},
		{"base is one", big.NewInt(1), big.NewInt(12345), big.NewInt(1000)},
		{"small modulus", big.NewInt(7), big.NewInt(256), big.NewInt(13)},
		{"large base", new(big.Int).SetBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}), big.NewInt(3), big.NewInt(1000000007)},
		{"large exponent", big.NewInt(2), new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(1000000007)},
		{"large modulus", big.NewInt(12345), big.NewInt(67890), new(big.Int).Lsh(big.NewInt(1), 256)},
	}

	for _, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			expected := new(big.Int).Exp(tc.base, tc.exp, tc.mod)
			circuit := &variableExp[emparams.Mod1e512]{}
			assignment := &variableExp[emparams.Mod1e512]{
				Modulus:  ValueOf[emparams.Mod1e512](tc.mod),
				Base:     ValueOf[emparams.Mod1e512](tc.base),
				Exp:      ValueOf[emparams.Mod1e512](tc.exp),
				Expected: ValueOf[emparams.Mod1e512](expected),
			}
			err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
			assert.NoError(err)
		}, tc.name)
	}
}

type constantModulusCircuit[T FieldParams] struct {
	A, B                   Element[T]
	Mul, Add, Exp          Element[T]
	constModulus, constExp *big.Int
}

func (c *constantModulusCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	modulus := f.NewElement(c.constModulus)
	f.AssertIsEqual(f.ModMulCanonical(&c.A, &c.B, modulus), &c.Mul)
	f.ModAssertIsEqual(f.ModAdd(&c.A, &c.B, modulus), &c.Add, modulus)
	f.AssertIsEqual(f.ModExp(&c.A, f.NewElement(c.constExp), modulus), &c.Exp)
	return nil
}

// TestConstantModulus checks the variable-modulus methods with a constant
// modulus which fits in fewer limbs than the emulated parameters use.
func TestConstantModulus(t *testing.T) {
	testConstantModulus[emparams.Secp256k1Fp](t)
	testConstantModulus[emparams.Mod1e512](t)
}

func testConstantModulus[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	modulus := big.NewInt(1000003)
	exp := big.NewInt(65537)
	a, b := big.NewInt(123456), big.NewInt(654321)
	mul := new(big.Int).Mod(new(big.Int).Mul(a, b), modulus)
	add := new(big.Int).Mod(new(big.Int).Add(a, b), modulus)
	expRes := new(big.Int).Exp(a, exp, modulus)
	circuit := constantModulusCircuit[T]{constModulus: modulus, constExp: exp}
	assignment := constantModulusCircuit[T]{
		A:   ValueOf[T](a),
		B:   ValueOf[T](b),
		Mul: ValueOf[T](mul),
		Add: ValueOf[T](add),
		Exp: ValueOf[T](expRes),
	}
	assert.NoError(test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField()))
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	_, err = ccs.Solve(w)
	assert.NoError(err)
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	_, err = ccs.Solve(w)
	assert.NoError(err)
}
