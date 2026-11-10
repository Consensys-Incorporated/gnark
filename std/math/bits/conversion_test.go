package bits_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
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
	// bind ThirdVariableBit also when all inputs are constant. This also keeps
	// the circuit above one constraint.
	api.AssertIsBoolean(c.ThirdVariableBit)
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

type testFromBinaryInvalidConstantInput struct {
	ConstantInputs []*big.Int
}

func (c *testFromBinaryInvalidConstantInput) Define(api frontend.API) error {
	inps := make([]frontend.Variable, len(c.ConstantInputs))
	for i, inp := range c.ConstantInputs {
		inps[i] = inp
	}
	// test when constant inputs are not binary
	res := bits.FromBinary(api, inps)
	api.AssertIsDifferent(res, 0)
	return nil
}

type testFromBinaryInvalidVariableInput struct {
	VariableInputs []frontend.Variable
}

func (c *testFromBinaryInvalidVariableInput) Define(api frontend.API) error {
	res := bits.FromBinary(api, c.VariableInputs)
	api.AssertIsDifferent(res, 0)
	return nil
}

func TestFromBinaryInvalidInput(t *testing.T) {
	assert := test.NewAssert(t)

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testFromBinaryInvalidConstantInput{
		ConstantInputs: []*big.Int{big.NewInt(2), big.NewInt(1)},
	})
	assert.Error(err)
	assert.CheckCircuit(&testFromBinaryInvalidVariableInput{VariableInputs: make([]frontend.Variable, 2)}, test.WithInvalidAssignment(&testFromBinaryInvalidVariableInput{
		VariableInputs: []frontend.Variable{2, 1},
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

// --- canonicity of the decomposition against a malicious prover ---------------
//
// A malicious prover controls the hint output, so the circuit must reject any
// digit vector that is not the canonical decomposition of v. For a full-width
// decomposition the digit range exceeds the native modulus, so the digits of
// v+p (and, on BN254, v+2p) also satisfy Σ base**i · d_i == v in the field.
// Only an explicit canonicity bound rejects them. See PR #836 for the binary
// precedent.

type fullWidthDecompCircuit struct {
	V       frontend.Variable `gnark:",public"`
	ternary bool
}

func (c *fullWidthDecompCircuit) Define(api frontend.API) error {
	if c.ternary {
		bits.ToTernary(api, c.V)
	} else {
		bits.ToBinary(api, c.V)
	}
	// dummy constraints to avoid degenerate single-constraint systems
	api.AssertIsEqual(c.V, c.V)
	api.AssertIsEqual(c.V, c.V)
	return nil
}

// hintIDByName looks up a registered hint by the suffix of its qualified name.
// The hints we want to override are unexported, so we cannot pass the function
// value to solver.GetHintID directly from this (external) test package.
func hintIDByName(t *testing.T, suffix string) solver.HintID {
	t.Helper()
	for _, h := range solver.GetRegisteredHints() {
		if strings.HasSuffix(solver.GetHintName(h), suffix) {
			return solver.GetHintID(h)
		}
	}
	t.Fatalf("hint %q not registered", suffix)
	return 0
}

// shiftedDigitsHint returns a malicious hint emitting the base-`base` digits of
// inputs[0] + shift instead of those of inputs[0].
func shiftedDigitsHint(base int, shift *big.Int) solver.Hint {
	return func(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
		n := new(big.Int).Add(inputs[0], shift)
		digits := n.Text(base)
		i := 0
		for j := len(digits) - 1; j >= 0 && i < len(results); j-- {
			results[i].SetUint64(uint64(digits[j] - '0'))
			i++
		}
		for ; i < len(results); i++ {
			results[i].SetUint64(0)
		}
		return nil
	}
}

func solveWithHint(t *testing.T, field *big.Int, ternary bool, v *big.Int, override solver.Option) error {
	t.Helper()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &fullWidthDecompCircuit{ternary: ternary})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	w, err := frontend.NewWitness(&fullWidthDecompCircuit{V: v}, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	opts := []solver.Option{}
	if override != nil {
		opts = append(opts, override)
	}
	_, err = ccs.Solve(w, opts...)
	return err
}

var canonicityCurves = []ecc.ID{ecc.BN254, ecc.BLS12_381, ecc.BW6_761, ecc.BLS12_377}

// TestToTernaryNonCanonical asserts that the full-width ternary decomposition
// rejects the digits of v+k·p for every k >= 1 that still fits in the digit
// range.
func TestToTernaryNonCanonical(t *testing.T) {
	v := big.NewInt(12345)
	nTritsID := hintIDByName(t, "nTrits")
	for _, cid := range canonicityCurves {
		field := cid.ScalarField()
		// how many extra representations does this field admit?
		nbBits := field.BitLen()
		nbTrits := int(float64(nbBits)/math.Log2(3.0)) + 1
		capacity := new(big.Int).Exp(big.NewInt(3), big.NewInt(int64(nbTrits)), nil)
		for k := int64(1); ; k++ {
			shift := new(big.Int).Mul(big.NewInt(k), field)
			if new(big.Int).Add(v, shift).Cmp(capacity) >= 0 {
				break
			}
			t.Run(fmt.Sprintf("%s/v+%dp", cid, k), func(t *testing.T) {
				err := solveWithHint(t, field, true, v, solver.OverrideHint(nTritsID, shiftedDigitsHint(3, shift)))
				if err == nil {
					t.Fatalf("TERNARY EXPLOIT: solver ACCEPTED digits of v+%dp as digits of v=%s", k, v)
				}
				t.Logf("rejected as expected: %v", err)
			})
		}
	}
}

// TestToBinaryNonCanonical is the control: the binary path already rejects this
// attack (PR #836), which shows the harness itself is sound.
func TestToBinaryNonCanonical(t *testing.T) {
	v := big.NewInt(12345)
	nBitsID := hintIDByName(t, "nBits")
	for _, cid := range canonicityCurves {
		field := cid.ScalarField()
		shift := new(big.Int).Set(field)
		if new(big.Int).Add(v, shift).BitLen() > field.BitLen() {
			continue
		}
		t.Run(cid.String(), func(t *testing.T) {
			err := solveWithHint(t, field, false, v, solver.OverrideHint(nBitsID, shiftedDigitsHint(2, shift)))
			if err == nil {
				t.Fatal("BINARY EXPLOIT: solver accepted digits of v+p")
			}
			t.Logf("rejected as expected: %v", err)
		})
	}
}

// TestToTernaryCanonicalHonest is the completeness counterpart: the honest
// full-width decomposition must still solve on every supported curve.
func TestToTernaryCanonicalHonest(t *testing.T) {
	for _, cid := range canonicityCurves {
		field := cid.ScalarField()
		t.Run(cid.String(), func(t *testing.T) {
			vals := []*big.Int{
				big.NewInt(0),
				big.NewInt(1),
				big.NewInt(12345),
				new(big.Int).Sub(field, big.NewInt(1)), // the bound itself
				new(big.Int).Sub(field, big.NewInt(2)),
				new(big.Int).Rsh(field, 1),
			}
			for i := 0; i < 20; i++ {
				r, err := rand.Int(rand.Reader, field)
				if err != nil {
					t.Fatal(err)
				}
				vals = append(vals, r)
			}
			for _, v := range vals {
				if err := solveWithHint(t, field, true, v, nil); err != nil {
					t.Fatalf("honest decomposition of %s failed: %v", v, err)
				}
			}
		})
	}
}

type toTernaryUpperBoundCircuit struct {
	A     frontend.Variable
	bound *big.Int
}

func (c *toTernaryUpperBoundCircuit) Define(api frontend.API) error {
	bits.ToTernary(api, c.A, bits.WithUpperBound(c.bound))
	return nil
}

func TestToTernaryUpperBound(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&toTernaryUpperBoundCircuit{bound: big.NewInt(100)},
		test.WithValidAssignment(&toTernaryUpperBoundCircuit{A: 0}),
		test.WithValidAssignment(&toTernaryUpperBoundCircuit{A: 99}),
		test.WithValidAssignment(&toTernaryUpperBoundCircuit{A: 100}),
		test.WithInvalidAssignment(&toTernaryUpperBoundCircuit{A: 101}),
		test.WithInvalidAssignment(&toTernaryUpperBoundCircuit{A: 255}),
	)
}

type toTernaryNbDigitsCircuit struct {
	A        frontend.Variable
	nbDigits int
}

func (c *toTernaryNbDigitsCircuit) Define(api frontend.API) error {
	bits.ToTernary(api, c.A, bits.WithNbDigits(c.nbDigits))
	api.AssertIsEqual(c.A, c.A)
	return nil
}

// TestToTernaryNbDigits checks that a narrow decomposition still binds (its
// digit range is below the modulus, so no extra canonicity check is needed and
// none is emitted) and that padding beyond the full width returns zeros.
func TestToTernaryNbDigits(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&toTernaryNbDigitsCircuit{nbDigits: 3},
		test.WithValidAssignment(&toTernaryNbDigitsCircuit{A: 26}),
		test.WithInvalidAssignment(&toTernaryNbDigitsCircuit{A: 27}),
	)

	// the narrow case must not emit the comparison at all
	nbBits := ecc.BN254.ScalarField().BitLen()
	nbTrits := int(float64(nbBits)/math.Log2(3.0)) + 1
	narrow, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &toTernaryNbDigitsCircuit{nbDigits: nbTrits - 1})
	assert.NoError(err)
	full, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &toTernaryNbDigitsCircuit{nbDigits: nbTrits})
	assert.NoError(err)
	// narrow has one digit less (3 constraints) and no comparison at all
	assert.True(full.GetNbConstraints() > narrow.GetNbConstraints()+3,
		"full width must pay for the canonicity check, narrow must not: %d vs %d", full.GetNbConstraints(), narrow.GetNbConstraints())

	// over-wide decomposition pads with zeros and still solves
	assert.CheckCircuit(&toTernaryNbDigitsCircuit{nbDigits: nbTrits + 5},
		test.WithValidAssignment(&toTernaryNbDigitsCircuit{A: 12345}),
		test.WithCurves(ecc.BN254),
	)
}
