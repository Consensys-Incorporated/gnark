package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
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

// variableExpConstZeroBase exercises [Field.ModExp] with a *structurally
// constant* zero base, i.e. the compile-time zero element returned by
// [Field.Zero] which carries no limbs at all. This is the input which takes the
// constant-folding fast path in ModExp; a witness element always carries
// NbLimbs() limbs and goes through the windowed ladder instead.
type variableExpConstZeroBase[T FieldParams] struct {
	Modulus  Element[T]
	Exp      Element[T]
	Expected Element[T]
}

func (c *variableExpConstZeroBase[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModExp(f.Zero(), &c.Exp, &c.Modulus)
	// the expected results are 0 or 1, both canonical, so we can compare
	// directly instead of modulo the variable modulus.
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

// TestVariableExpConstZeroBase pins 0^0 == 1 for the constant-zero base. The
// first case regressed: the fast path used to return zero for *every*
// exponent, but x^0 == 1 for all x including x == 0 (matching the EVM MODEXP
// specification and Go's [big.Int.Exp] / Python's pow).
func TestVariableExpConstZeroBase(t *testing.T) {
	assert := test.NewAssert(t)

	testCases := []struct {
		name     string
		exp, mod *big.Int
		expected *big.Int
	}{
		{"zero exponent", big.NewInt(0), big.NewInt(7), big.NewInt(1)},
		{"one exponent", big.NewInt(1), big.NewInt(7), big.NewInt(0)},
		{"five exponent", big.NewInt(5), big.NewInt(7), big.NewInt(0)},
		// modulo 1 everything is 0, including 0^0; the fast path must agree
		// with the general path here.
		{"zero exponent mod one", big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		{"one exponent mod one", big.NewInt(1), big.NewInt(1), big.NewInt(0)},
	}

	for _, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			// cross-check the expectation against the reference implementation
			assert.Equal(0, new(big.Int).Exp(big.NewInt(0), tc.exp, tc.mod).Cmp(tc.expected))
			circuit := &variableExpConstZeroBase[emparams.Mod1e512]{}
			assignment := &variableExpConstZeroBase[emparams.Mod1e512]{
				Modulus:  ValueOf[emparams.Mod1e512](tc.mod),
				Exp:      ValueOf[emparams.Mod1e512](tc.exp),
				Expected: ValueOf[emparams.Mod1e512](tc.expected),
			}
			err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
			assert.NoError(err)
		}, tc.name)
	}
}

// TestVariableExpWitnessZeroBase is a regression guard for the general
// (windowed ladder) path: a *witness* zero base must keep returning 1 for a
// zero exponent. This already holds on master and must not change.
func TestVariableExpWitnessZeroBase(t *testing.T) {
	assert := test.NewAssert(t)
	mod := big.NewInt(7)
	circuit := &variableExp[emparams.Mod1e512]{}
	assignment := &variableExp[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](mod),
		Base:     ValueOf[emparams.Mod1e512](0),
		Exp:      ValueOf[emparams.Mod1e512](0),
		Expected: ValueOf[emparams.Mod1e512](1),
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
