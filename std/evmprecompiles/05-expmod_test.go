package evmprecompiles

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type expmodCircuit struct {
	Base      emulated.Element[emparams.Mod1e4096]
	Exp       emulated.Element[emparams.Mod1e4096]
	Mod       emulated.Element[emparams.Mod1e4096]
	Result    emulated.Element[emparams.Mod1e4096]
	edgeCases bool
}

func (c *expmodCircuit) Define(api frontend.API) error {
	res := Expmod(api, &c.Base, &c.Exp, &c.Mod)
	f, err := emulated.NewField[emparams.Mod1e4096](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	if c.edgeCases {
		// cannot use ModAssertIsEqual for edge cases. But the output is either
		// 0 or 1 so can use AssertIsEqual
		f.AssertIsEqual(res, &c.Result)
	} else {
		// for random case need to use ModAssertIsEqual
		f.ModAssertIsEqual(&c.Result, res, &c.Mod)
	}
	return nil
}

func testInstance(edgeCases bool, base, exp, modulus, result *big.Int) error {
	circuit := &expmodCircuit{edgeCases: edgeCases}
	assignment := &expmodCircuit{
		Base:   emulated.ValueOf[emparams.Mod1e4096](base),
		Exp:    emulated.ValueOf[emparams.Mod1e4096](exp),
		Mod:    emulated.ValueOf[emparams.Mod1e4096](modulus),
		Result: emulated.ValueOf[emparams.Mod1e4096](result),
	}
	return test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
}

func TestRandomInstance(t *testing.T) {
	assert := test.NewAssert(t)
	expBits := []int{256, 512, 1024, 2048, 4096}
	if testing.Short() {
		expBits = []int{256, 512}
	}
	for _, bits := range expBits {
		assert.Run(func(assert *test.Assert) {
			modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits))
			base, _ := rand.Int(rand.Reader, modulus)
			exp, _ := rand.Int(rand.Reader, modulus)
			res := new(big.Int).Exp(base, exp, modulus)
			err := testInstance(false, base, exp, modulus, res)
			assert.NoError(err)
		}, fmt.Sprintf("random-%d", bits))
	}
}

func TestEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	testCases := []struct {
		base, exp, modulus, result *big.Int
	}{
		{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},     // 0^0 = 0 mod 0
		{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},     // 0^0 = 0 mod 1
		{big.NewInt(0), big.NewInt(0), big.NewInt(123), big.NewInt(1)},   // 0^0 = 1 mod 123
		{big.NewInt(123), big.NewInt(123), big.NewInt(0), big.NewInt(0)}, // 123^123 = 0 mod 0
		{big.NewInt(123), big.NewInt(123), big.NewInt(0), big.NewInt(0)}, // 123^123 = 0 mod 1
		{big.NewInt(0), big.NewInt(123), big.NewInt(123), big.NewInt(0)}, // 0^123 = 0 mod 123
		{big.NewInt(123), big.NewInt(0), big.NewInt(123), big.NewInt(1)}, // 123^0 = 1 mod 123
	}
	if testing.Short() {
		testCases = testCases[:2]
	}
	for i, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			err := testInstance(true, tc.base, tc.exp, tc.modulus, tc.result)
			assert.NoError(err)
		}, fmt.Sprintf("edge-%d", i))
	}
}

// expmodConstZeroBaseCircuit specialises [Expmod] with a compile-time constant
// zero base (as an out-of-tree caller hardcoding base = 0 would). This takes
// the constant-folding fast path inside [emulated.Field.ModExp], which a
// witness base never reaches.
type expmodConstZeroBaseCircuit struct {
	Exp    emulated.Element[emparams.Mod1e4096]
	Mod    emulated.Element[emparams.Mod1e4096]
	Result emulated.Element[emparams.Mod1e4096]
}

func (c *expmodConstZeroBaseCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emparams.Mod1e4096](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	res := Expmod(api, f.Zero(), &c.Exp, &c.Mod)
	// results here are always 0 or 1, both canonical
	f.AssertIsEqual(res, &c.Result)
	return nil
}

// TestEdgeCasesConstZeroBase pins the interaction between the constant-zero
// base fast path and the isOneOrZeroMod folding done by [Expmod]: 0^0 is 1,
// except modulo 0 or 1 where everything is 0.
func TestEdgeCasesConstZeroBase(t *testing.T) {
	assert := test.NewAssert(t)
	testCases := []struct {
		exp, modulus, result *big.Int
	}{
		{big.NewInt(0), big.NewInt(7), big.NewInt(1)}, // 0^0 = 1 mod 7
		{big.NewInt(1), big.NewInt(7), big.NewInt(0)}, // 0^1 = 0 mod 7
		{big.NewInt(0), big.NewInt(1), big.NewInt(0)}, // 0^0 = 0 mod 1
		{big.NewInt(0), big.NewInt(0), big.NewInt(0)}, // 0^0 = 0 mod 0
	}
	for i, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			circuit := &expmodConstZeroBaseCircuit{}
			assignment := &expmodConstZeroBaseCircuit{
				Exp:    emulated.ValueOf[emparams.Mod1e4096](tc.exp),
				Mod:    emulated.ValueOf[emparams.Mod1e4096](tc.modulus),
				Result: emulated.ValueOf[emparams.Mod1e4096](tc.result),
			}
			err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
			assert.NoError(err)
		}, fmt.Sprintf("edge-constzero-%d", i))
	}
}
