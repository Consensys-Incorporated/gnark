package selector

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

// constSelectorCircuit uses a compile-time constant selector (a *big.Int, not a
// witness wire) to exercise the constant-folding fast path of [Mux].
type constSelectorCircuit struct {
	Inputs   []frontend.Variable
	Expected frontend.Variable
	Sel      *big.Int // compile-time constant selector; intentionally not a witness
}

func (c *constSelectorCircuit) Define(api frontend.API) error {
	out := Mux(api, c.Sel, c.Inputs...)
	api.AssertIsEqual(out, c.Expected)
	return nil
}

// TestMuxConstantSelector checks that [Mux] correctly range-checks a
// compile-time constant selector.
//
// math/big.Int.Int64() truncates silently for values outside the int64 range.
// A value like 2^64+1 is a perfectly valid constant for fields such as BN254,
// but s.Int64() would return 1, aliasing the selector to a valid index and
// silently folding the circuit to the wrong input instead of rejecting it. The
// out-of-range cases must therefore make the compiler panic (constant folding
// must not succeed) rather than being silently accepted.
func TestMuxConstantSelector(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()

	n := 5

	// In-range constant selectors must fold to the right input, on both the test
	// engine and the real compilers.
	for _, sel := range []int64{0, int64(n - 1)} {
		sel := sel
		assert.Run(func(assert *test.Assert) {
			inputs := make([]frontend.Variable, n)
			for i := range inputs {
				inputs[i] = i
			}
			circuit := &constSelectorCircuit{
				Inputs:   inputs,
				Expected: inputs[sel],
				Sel:      big.NewInt(sel),
			}
			err := test.IsSolved(circuit, circuit, field, test.SetAllVariablesAsConstants())
			assert.NoError(err)
			mustCompileSucceed(assert, circuit)
		}, fmt.Sprintf("in-range sel=%d", sel))
	}

	// Out-of-range constant selectors must be rejected. 2^63 and 2^64+1 are valid
	// non-negative field elements; n (== len(inputs)) is just past the last index.
	// All of them must make [Mux] panic at compile time rather than alias to a
	// valid index.
	outOfRange := []*big.Int{
		big.NewInt(int64(n)),
		new(big.Int).Lsh(big.NewInt(1), 63),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)),
	}
	for i, sel := range outOfRange {
		sel := sel
		assert.Run(func(assert *test.Assert) {
			inputs := make([]frontend.Variable, n)
			for j := range inputs {
				inputs[j] = j
			}
			circuit := &constSelectorCircuit{
				Inputs:   inputs,
				Expected: 0, // never reached; Mux must panic first
				Sel:      sel,
			}
			// The test engine recovers the compile-time panic as an error. We
			// check the message to ensure it is the out-of-bounds rejection and
			// not a downstream assertion mismatch.
			err := test.IsSolved(circuit, circuit, field, test.SetAllVariablesAsConstants())
			assert.Error(err)
			if err != nil {
				assert.True(strings.Contains(err.Error(), "out of bounds"),
					"expected out-of-bounds panic, got: %v", err)
			}
			// The real compilers must also reject the out-of-range constant. This
			// is the authoritative regression check: the buggy code would accept
			// 2^64+1 and silently fold to a wrong input.
			mustCompileFail(assert, circuit)
		}, fmt.Sprintf("out-of-range #%d", i))
	}
}

// mustCompileSucceed compiles the circuit with both supported backends over the
// BN254 scalar field and fails the test if compilation does not succeed.
func mustCompileSucceed(assert *test.Assert, circuit frontend.Circuit) {
	field := ecc.BN254.ScalarField()
	for _, nb := range []struct {
		name    string
		builder frontend.NewBuilder
	}{
		{"r1cs", r1cs.NewBuilder[constraint.U64]},
		{"scs", scs.NewBuilder[constraint.U64]},
	} {
		nb := nb
		func() {
			defer func() {
				if r := recover(); r != nil {
					assert.Fail(fmt.Sprintf("unexpected panic compiling %s: %v", nb.name, r))
				}
			}()
			_, err := frontend.Compile(field, nb.builder, circuit)
			assert.NoError(err, "compiling %s", nb.name)
		}()
	}
}

// mustCompileFail compiles the circuit with both supported backends over the
// BN254 scalar field and fails the test if compilation succeeds. A constant
// selector that is out of range must make [Mux] panic at compile time.
func mustCompileFail(assert *test.Assert, circuit frontend.Circuit) {
	field := ecc.BN254.ScalarField()
	for _, nb := range []struct {
		name    string
		builder frontend.NewBuilder
	}{
		{"r1cs", r1cs.NewBuilder[constraint.U64]},
		{"scs", scs.NewBuilder[constraint.U64]},
	} {
		nb := nb
		failed := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					failed = true
				}
			}()
			_, err := frontend.Compile(field, nb.builder, circuit)
			if err != nil {
				failed = true
			}
		}()
		assert.True(failed, "expected %s compilation to fail for out-of-range constant selector, but it succeeded", nb.name)
	}
}
