package selector

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type muxCircuit struct {
	Sel      frontend.Variable
	Input    []frontend.Variable
	Expected frontend.Variable
}

func (c *muxCircuit) Define(api frontend.API) error {

	out := Mux(api, c.Sel, c.Input...)
	api.AssertIsEqual(out, c.Expected)

	return nil
}

// The output of this circuit is ignored and the only way its proof can fail is by providing invalid inputs.
type ignoredOutputMuxCircuit struct {
	SEL        frontend.Variable
	I0, I1, I2 frontend.Variable
}

func (c *ignoredOutputMuxCircuit) Define(api frontend.API) error {
	// We ignore the output
	_ = Mux(api, c.SEL, c.I0, c.I1, c.I2)

	return nil
}

func testMux(assert *test.Assert, len int, sel int) {
	// seed the random generator with the current time. Good enough for tests.
	rng := rand.New(rand.NewPCG(uint64(time.Now().Unix()), 1)) //nolint G404
	circuit := &muxCircuit{
		Input: make([]frontend.Variable, len),
	}

	inputs := make([]frontend.Variable, len)
	for i := 0; i < len; i++ {
		inputs[i] = frontend.Variable(rng.Uint64())
	}
	// out-range invalid selector
	outRangeSel := uint64(len) + rng.Uint64N(100)
	opts := []test.TestingOption{
		test.WithValidAssignment(&muxCircuit{
			Sel:      sel,
			Input:    inputs,
			Expected: inputs[sel],
		}),
		test.WithInvalidAssignment(&muxCircuit{
			Sel:      outRangeSel,
			Input:    inputs,
			Expected: sel,
		}),
	}

	// in-range invalid selector
	if len > 1 {
		invalidSel := rng.Uint64N(uint64(len))
		for invalidSel == uint64(sel) {
			invalidSel = rng.Uint64N(uint64(len))
		}
		opts = append(opts, test.WithInvalidAssignment(&muxCircuit{
			Sel:      invalidSel,
			Input:    inputs,
			Expected: sel,
		}))
	}

	assert.CheckCircuit(circuit, opts...)
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)

	for len := 0; len < 9; len++ {
		for sel := 0; sel < len+1; sel++ {
			assert.Run(func(assert *test.Assert) {
				testMux(assert, len+1, sel)
			}, fmt.Sprintf("len=%d/sel=%d", len+1, sel))
		}
	}

	assert.CheckCircuit(&ignoredOutputMuxCircuit{},
		test.WithValidAssignment(&ignoredOutputMuxCircuit{SEL: 0, I0: 0, I1: 1, I2: 2}),
		test.WithValidAssignment(&ignoredOutputMuxCircuit{SEL: 2, I0: 0, I1: 1, I2: 2}),
		test.WithInvalidAssignment(&ignoredOutputMuxCircuit{SEL: 3, I0: 0, I1: 1, I2: 2}),
		test.WithInvalidAssignment(&ignoredOutputMuxCircuit{SEL: -1, I0: 0, I1: 1, I2: 2}),
	)

}

// Map tests:
type mapCircuit struct {
	SEL            frontend.Variable
	K0, K1, K2, K3 frontend.Variable
	V0, V1, V2, V3 frontend.Variable
	OUT            frontend.Variable
}

func (c *mapCircuit) Define(api frontend.API) error {

	out := Map(api, c.SEL,
		[]frontend.Variable{c.K0, c.K1, c.K2, c.K3},
		[]frontend.Variable{c.V0, c.V1, c.V2, c.V3})

	api.AssertIsEqual(out, c.OUT)

	return nil
}

type ignoredOutputMapCircuit struct {
	SEL    frontend.Variable
	K0, K1 frontend.Variable
	V0, V1 frontend.Variable
}

func (c *ignoredOutputMapCircuit) Define(api frontend.API) error {

	_ = Map(api, c.SEL,
		[]frontend.Variable{c.K0, c.K1},
		[]frontend.Variable{c.V0, c.V1})

	return nil
}

func TestMap(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 100,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 0,
		})

	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 222,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 2,
		})

	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 333,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	// Duplicated key, success:
	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 333,
			K0:  222, K1: 222, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	// Duplicated key, UNDEFINED behavior: (with our hint implementation it fails)
	assert.ProverFailed(&mapCircuit{},
		&mapCircuit{
			SEL: 333,
			K0:  100, K1: 111, K2: 333, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	assert.ProverFailed(&mapCircuit{},
		&mapCircuit{
			SEL: 77,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	assert.ProverFailed(&mapCircuit{},
		&mapCircuit{
			SEL: 111,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 2,
		})

	// Ignoring the circuit's output:
	assert.ProverSucceeded(&ignoredOutputMapCircuit{},
		&ignoredOutputMapCircuit{SEL: 5,
			K0: 5, K1: 7,
			V0: 10, V1: 11,
		})

	assert.ProverFailed(&ignoredOutputMapCircuit{},
		&ignoredOutputMapCircuit{SEL: 5,
			K0: 5, K1: 5,
			V0: 10, V1: 11,
		})

	assert.ProverFailed(&ignoredOutputMapCircuit{},
		&ignoredOutputMapCircuit{SEL: 6,
			K0: 5, K1: 7,
			V0: 10, V1: 11,
		})

}

type constSelectorCircuit struct {
	Inputs []frontend.Variable
	Sel    *big.Int
}

func (c *constSelectorCircuit) Define(api frontend.API) error {
	Mux(api, c.Sel, c.Inputs...)
	return nil
}

// TestMuxConstantSelectorOutOfRange checks that out-of-range constant selectors
// are rejected, including values that would be truncated by big.Int.Int64().
func TestMuxConstantSelectorOutOfRange(t *testing.T) {
	assert := test.NewAssert(t)
	for _, sel := range []*big.Int{
		big.NewInt(3),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)), // Int64() == 1
	} {
		circuit := &constSelectorCircuit{Inputs: []frontend.Variable{0, 1, 2}, Sel: sel}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.ErrorContains(err, "out of bounds", "sel=%s", sel)
	}
}
