package emulated

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/test"
)

func nnaHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHint(nativeInputs, nativeOutputs, func(mod *big.Int, inputs, outputs []*big.Int) error {
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, mod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, mod)
		outputs[0].Set(res)
		return nil
	})
}

type hintCircuit[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    Element[T]
}

func (c *hintCircuit[T]) Define(api frontend.API) error {
	field, err := NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHint(nnaHint, 1, &c.Nominator, &c.Denominator)
	if err != nil {
		return err
	}
	field.AssertIsEqual(res[0], &c.Expected)
	return nil
}

func testHint[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := hintCircuit[T]{}
	witness := hintCircuit[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    ValueOf[T](c),
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithSolverOpts(solver.WithHints(nnaHint)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestHint(t *testing.T) {
	testHint[Goldilocks](t)
	testHint[Secp256k1Fp](t)
	testHint[BN254Fp](t)
}

func nativeInputHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nonnativeMod *big.Int, inputs, outputs []*big.Int) error {
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, nonnativeMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, nonnativeMod)
		outputs[0].Set(res)
		return nil
	})
}

type hintNativeInputCircuit[T FieldParams] struct {
	Nominator   frontend.Variable
	Denominator frontend.Variable
	Expected    Element[T]
}

func (c *hintNativeInputCircuit[T]) Define(api frontend.API) error {
	field, err := NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHintWithNativeInput(nativeInputHint, 1, c.Nominator, c.Denominator)
	if err != nil {
		return err
	}
	field.AssertIsEqual(res[0], &c.Expected)
	return nil
}

func testHintNativeInput[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, testCurve.ScalarField())
	b, _ := rand.Int(rand.Reader, testCurve.ScalarField())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := hintNativeInputCircuit[T]{}
	witness := hintNativeInputCircuit[T]{
		Nominator:   a,
		Denominator: b,
		Expected:    ValueOf[T](c),
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(testCurve), test.WithSolverOpts(solver.WithHints(nativeInputHint)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestHintNativeInput(t *testing.T) {
	testHintNativeInput[Goldilocks](t)
	testHintNativeInput[Secp256k1Fp](t)
	testHintNativeInput[BN254Fp](t)
}

func nativeOutputHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHintWithNativeOutput(nativeInputs, nativeOutputs, func(nonnativeMod *big.Int, inputs, outputs []*big.Int) error {
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, nativeMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, nativeMod)
		outputs[0].Set(res)
		return nil
	})
}

type hintNativeOutputCircuit[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    frontend.Variable
}

func (c *hintNativeOutputCircuit[T]) Define(api frontend.API) error {
	field, err := NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHintWithNativeOutput(nativeOutputHint, 1, &c.Nominator, &c.Denominator)
	if err != nil {
		return err
	}
	api.AssertIsEqual(res[0], c.Expected)
	api.AssertIsDifferent(c.Expected, 0)
	return nil
}

func testHintNativeOutput[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, testCurve.ScalarField())
	c.Mul(c, a)
	c.Mod(c, testCurve.ScalarField())

	circuit := hintNativeOutputCircuit[T]{}
	witness := hintNativeOutputCircuit[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    c,
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(testCurve), test.WithSolverOpts(solver.WithHints(nativeOutputHint)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestHintNativeOutput(t *testing.T) {
	testHintNativeOutput[Goldilocks](t)
	testHintNativeOutput[Secp256k1Fp](t)
	testHintNativeOutput[BN254Fp](t)
}

func hintNativeInNativeOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		inputs, outputs := ctx.NativeInputsOutputs()
		if len(inputs) != 2 || len(outputs) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(inputs), len(outputs))
		}
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, mod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, mod)
		outputs[0].Set(res)
		return nil
	})
}

type genericHintCircuitNativeInNativeOut[T FieldParams] struct {
	Nominator   frontend.Variable
	Denominator frontend.Variable
	Expected    frontend.Variable
}

func (c *genericHintCircuitNativeInNativeOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNative, outEm, err := f.NewHintGeneric(hintNativeInNativeOut, 1, 0, []frontend.Variable{c.Nominator, c.Denominator}, nil)
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNative) != 1 {
		return fmt.Errorf("expected 1 native output, got %d", len(outNative))
	}
	if len(outEm) != 0 {
		return fmt.Errorf("expected 0 emulated outputs, got %d", len(outEm))
	}
	api.AssertIsEqual(outNative[0], c.Expected)
	// duplicate constraint to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Expected, c.Expected)
	return nil
}

func testGenericHintNativeInNativeOut[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	b, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	c := new(big.Int).ModInverse(b, ecc.BN254.ScalarField())
	c.Mul(c, a)
	c.Mod(c, ecc.BN254.ScalarField())

	circuit := genericHintCircuitNativeInNativeOut[T]{}
	witness := genericHintCircuitNativeInNativeOut[T]{
		Nominator:   a,
		Denominator: b,
		Expected:    c,
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.WithSolverOpts(solver.WithHints(hintNativeInNativeOut)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestGenericHintNativeInNativeOut(t *testing.T) {
	testGenericHintNativeInNativeOut[Goldilocks](t)
	testGenericHintNativeInNativeOut[Secp256k1Fp](t)
	testGenericHintNativeInNativeOut[BN254Fp](t)
}

func hintNativeInEmulatedOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		emulatedMod := moduli[0]
		nativeInputs, _ := ctx.NativeInputsOutputs()
		_, emulatedOut := ctx.InputsOutputs(emulatedMod)
		if len(nativeInputs) != 2 || len(emulatedOut) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(nativeInputs), len(emulatedOut))
		}
		nominator := nativeInputs[0]
		denominator := nativeInputs[1]
		res := new(big.Int).ModInverse(denominator, emulatedMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, emulatedMod)
		emulatedOut[0].Set(res)
		return nil
	})
}

type genericHintCircuitNativeInEmulatedOut[T FieldParams] struct {
	Nominator   frontend.Variable
	Denominator frontend.Variable
	Expected    Element[T]
}

func (c *genericHintCircuitNativeInEmulatedOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNative, outEm, err := f.NewHintGeneric(hintNativeInEmulatedOut, 0, 1, []frontend.Variable{c.Nominator, c.Denominator}, nil)
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNative) != 0 {
		return fmt.Errorf("expected 0 native outputs, got %d", len(outNative))
	}
	if len(outEm) != 1 {
		return fmt.Errorf("expected 1 emulated output, got %d", len(outEm))
	}
	f.AssertIsEqual(outEm[0], &c.Expected)
	return nil
}

func testGenericHintNativeInEmulatedOut[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	b, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := genericHintCircuitNativeInEmulatedOut[T]{}
	witness := genericHintCircuitNativeInEmulatedOut[T]{
		Nominator:   a,
		Denominator: b,
		Expected:    ValueOf[T](c),
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.WithSolverOpts(solver.WithHints(hintNativeInEmulatedOut)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestGenericHintNativeInEmulatedOut(t *testing.T) {
	testGenericHintNativeInEmulatedOut[Goldilocks](t)
	testGenericHintNativeInEmulatedOut[Secp256k1Fp](t)
	testGenericHintNativeInEmulatedOut[BN254Fp](t)
}

func hintEmulatedInEmulatedOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		emulatedMod := moduli[0]
		emulatedIn, emulatedOut := ctx.InputsOutputs(emulatedMod)
		if len(emulatedIn) != 2 || len(emulatedOut) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(emulatedIn), len(emulatedOut))
		}
		nominator := emulatedIn[0]
		denominator := emulatedIn[1]
		res := new(big.Int).ModInverse(denominator, emulatedMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, emulatedMod)
		emulatedOut[0].Set(res)
		return nil
	})
}

type genericHintCircuitEmulatedInEmulatedOut[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    Element[T]
}

func (c *genericHintCircuitEmulatedInEmulatedOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNat, outEm, err := f.NewHintGeneric(hintEmulatedInEmulatedOut, 0, 1, nil, []*Element[T]{&c.Nominator, &c.Denominator})
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNat) != 0 {
		return fmt.Errorf("expected 0 native outputs, got %d", len(outNat))
	}
	if len(outEm) != 1 {
		return fmt.Errorf("expected 1 emulated output, got %d", len(outEm))
	}
	f.AssertIsEqual(outEm[0], &c.Expected)
	return nil
}

func testGenericHintEmulatedInEmulatedOut[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := genericHintCircuitEmulatedInEmulatedOut[T]{}
	witness := genericHintCircuitEmulatedInEmulatedOut[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    ValueOf[T](c),
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithSolverOpts(solver.WithHints(hintEmulatedInEmulatedOut)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestGenericHintEmulatedInEmulatedOut(t *testing.T) {
	testGenericHintEmulatedInEmulatedOut[Goldilocks](t)
	testGenericHintEmulatedInEmulatedOut[Secp256k1Fp](t)
	testGenericHintEmulatedInEmulatedOut[BN254Fp](t)
}

func hintEmulatedInNativeOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		nativeMod, emulatedMod := ctx.NativeModulus(), moduli[0]
		_, nativeOut := ctx.NativeInputsOutputs()
		emulatedIn, _ := ctx.InputsOutputs(emulatedMod)
		if len(emulatedIn) != 2 || len(nativeOut) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(emulatedIn), len(nativeOut))
		}
		nominator := emulatedIn[0]
		denominator := emulatedIn[1]
		res := new(big.Int).ModInverse(denominator, nativeMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, nativeMod)
		nativeOut[0].Set(res)
		return nil
	})
}

type genericHintCircuitEmulatedInNativeOut[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    frontend.Variable
}

func (c *genericHintCircuitEmulatedInNativeOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNat, outEm, err := f.NewHintGeneric(hintEmulatedInNativeOut, 1, 0, nil, []*Element[T]{&c.Nominator, &c.Denominator})
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNat) != 1 {
		return fmt.Errorf("expected 1 native output, got %d", len(outNat))
	}
	if len(outEm) != 0 {
		return fmt.Errorf("expected 0 emulated outputs, got %d", len(outEm))
	}
	api.AssertIsEqual(outNat[0], c.Expected)
	// duplicate constraint to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Expected, c.Expected)
	return nil
}

func testGenericHintEmulatedInNativeOut[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, ecc.BN254.ScalarField())
	c.Mul(c, a)
	c.Mod(c, ecc.BN254.ScalarField())
	circuit := genericHintCircuitEmulatedInNativeOut[T]{}
	witness := genericHintCircuitEmulatedInNativeOut[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    c,
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.WithSolverOpts(solver.WithHints(hintEmulatedInNativeOut)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestGenericHintEmulatedInNativeOut(t *testing.T) {
	testGenericHintEmulatedInNativeOut[Goldilocks](t)
	testGenericHintEmulatedInNativeOut[Secp256k1Fp](t)
	testGenericHintEmulatedInNativeOut[BN254Fp](t)
}

func crossfieldHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHintContext(nativeMod, nativeInputs, nativeOutputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expected 2 moduli, got %d", len(moduli))
		}
		emulatedMod1, emulatedMod2 := moduli[0], moduli[1]
		nativeInputs, nativeOutputs := ctx.NativeInputsOutputs()
		emulatedInputs1, emulatedOutputs1 := ctx.InputsOutputs(emulatedMod1)
		emulatedInputs2, emulatedOutputs2 := ctx.InputsOutputs(emulatedMod2)
		if len(nativeInputs) != 2 || len(nativeOutputs) != 1 ||
			len(emulatedInputs1) != 2 || len(emulatedOutputs1) != 1 ||
			len(emulatedInputs2) != 2 || len(emulatedOutputs2) != 1 {
			return errors.New("unexpected number of inputs or outputs")
		}
		res := new(big.Int)
		res.Mul(res, nativeInputs[0])
		res.Mul(res, nativeInputs[1])
		res.Mod(res, emulatedInputs1[0])
		res.Mul(res, emulatedInputs1[1])
		res.Mul(res, emulatedInputs2[0])
		res.Mul(res, emulatedInputs2[1])
		nativeOutputs[0].Mod(res, nativeMod)
		emulatedOutputs1[0].Mod(res, emulatedMod1)
		emulatedOutputs2[0].Mod(res, emulatedMod2)
		return nil
	})
}

type crossfieldHintCircuit[T1, T2 FieldParams] struct {
	A, B              frontend.Variable
	C, D              Element[T1]
	E, F              Element[T2]
	ExpectedNative    frontend.Variable
	ExpectedEmulated1 Element[T1]
	ExpectedEmulated2 Element[T2]
}

func (c *crossfieldHintCircuit[T1, T2]) Define(api frontend.API) error {
	f1, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field T1: %w", err)
	}
	f2, err := NewField[T2](api)
	if err != nil {
		return fmt.Errorf("new field T2: %w", err)
	}
	outNative, outEm1, outEm2, err := NewVarGenericHint(api,
		1, 1, 1,
		[]frontend.Variable{c.A, c.B},
		[]*Element[T1]{&c.C, &c.D},
		[]*Element[T2]{&c.E, &c.F},
		crossfieldHint)
	if err != nil {
		return fmt.Errorf("new cross field hint: %w", err)
	}
	api.AssertIsEqual(outNative[0], c.ExpectedNative)
	f1.AssertIsEqual(outEm1[0], &c.ExpectedEmulated1)
	f2.AssertIsEqual(outEm2[0], &c.ExpectedEmulated2)
	return nil
}

func testCrossFieldHint[T1, T2 FieldParams](t *testing.T) {
	var fr1 T1
	var fr2 T2
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	b, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	c, _ := rand.Int(rand.Reader, fr1.Modulus())
	d, _ := rand.Int(rand.Reader, fr1.Modulus())
	e, _ := rand.Int(rand.Reader, fr2.Modulus())
	f, _ := rand.Int(rand.Reader, fr2.Modulus())
	res := new(big.Int)
	res.Mul(res, a)
	res.Mul(res, b)
	res.Mod(res, c)
	res.Mul(res, d)
	res.Mul(res, e)
	res.Mul(res, f)
	res1 := new(big.Int).Mod(res, ecc.BN254.ScalarField())
	res2 := new(big.Int).Mod(res, fr1.Modulus())
	res3 := new(big.Int).Mod(res, fr2.Modulus())
	circuit := crossfieldHintCircuit[T1, T2]{}
	witness := crossfieldHintCircuit[T1, T2]{
		A:                 a,
		B:                 b,
		C:                 ValueOf[T1](c),
		D:                 ValueOf[T1](d),
		E:                 ValueOf[T2](e),
		F:                 ValueOf[T2](f),
		ExpectedNative:    res1,
		ExpectedEmulated1: ValueOf[T1](res2),
		ExpectedEmulated2: ValueOf[T2](res3),
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254), test.WithSolverOpts(solver.WithHints(crossfieldHint)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestCrossFieldHint(t *testing.T) {
	testCrossFieldHint[Goldilocks, Secp256k1Fp](t)
	testCrossFieldHint[Goldilocks, BN254Fp](t)
	testCrossFieldHint[Secp256k1Fp, Goldilocks](t)
	testCrossFieldHint[Secp256k1Fp, BN254Fp](t)
	testCrossFieldHint[BN254Fp, Goldilocks](t)
	testCrossFieldHint[BN254Fp, Secp256k1Fp](t)
}

func matchingFieldHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		nativeMod, emulatedMod := ctx.NativeModulus(), moduli[0]
		nativeInputs, nativeOutputs := ctx.NativeInputsOutputs()
		emulatedInputs, emulatedOutputs := ctx.InputsOutputs(emulatedMod)
		if len(nativeInputs) != 2 || len(nativeOutputs) != 1 ||
			len(emulatedInputs) != 2 || len(emulatedOutputs) != 1 {
			return errors.New("unexpected number of inputs or outputs")
		}
		res1 := new(big.Int).Mul(nativeInputs[0], nativeInputs[1])
		res1.Mod(res1, nativeMod)
		res2 := new(big.Int).Mul(emulatedInputs[0], emulatedInputs[1])
		res2.Mod(res2, emulatedMod)
		nativeOutputs[0].Mod(res1, nativeMod)
		emulatedOutputs[0].Mod(res2, emulatedMod)
		return nil
	})
}

type matchingFieldHintCircuit[T FieldParams] struct {
	A, B             frontend.Variable
	C, D             Element[T]
	ExpectedNative   frontend.Variable
	ExpectedEmulated Element[T]
}

func (c *matchingFieldHintCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNative, outEm, err := f.NewHintGeneric(matchingFieldHint, 1, 1, []frontend.Variable{c.A, c.B}, []*Element[T]{&c.C, &c.D})
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNative) != 1 {
		return fmt.Errorf("expected 1 native output, got %d", len(outNative))
	}
	if len(outEm) != 1 {
		return fmt.Errorf("expected 1 emulated output, got %d", len(outEm))
	}
	api.AssertIsEqual(outNative[0], c.ExpectedNative)
	f.AssertIsEqual(outEm[0], &c.ExpectedEmulated)
	return nil
}

func testMatchingFieldHint[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c, _ := rand.Int(rand.Reader, fr.Modulus())
	d, _ := rand.Int(rand.Reader, fr.Modulus())
	res1 := new(big.Int).Mod(new(big.Int).Mul(a, b), fr.Modulus())
	res2 := new(big.Int).Mod(new(big.Int).Mul(c, d), fr.Modulus())

	circuit := matchingFieldHintCircuit[T]{}
	witness := matchingFieldHintCircuit[T]{
		A:                a,
		B:                b,
		C:                ValueOf[T](c),
		D:                ValueOf[T](d),
		ExpectedNative:   res1,
		ExpectedEmulated: ValueOf[T](res2),
	}
	// the inputs are only passed to the hint, which does not constrain them;
	// the circuit checks the hint plumbing and asserts nothing that reads them.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(utils.FieldToCurve(fr.Modulus())), test.WithSolverOpts(solver.WithHints(matchingFieldHint)), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestMatchingFieldHint(t *testing.T) {
	testMatchingFieldHint[BN254Fr](t)
	testMatchingFieldHint[BLS12381Fr](t)
}

func hintSquareAllInputs(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		nativeInputs, nativeOutputs := ctx.NativeInputsOutputs()
		if len(nativeInputs) != len(nativeOutputs) {
			return fmt.Errorf("expected same number of native inputs and outputs, got %d inputs and %d outputs", len(nativeInputs), len(nativeOutputs))
		}
		for i := range nativeOutputs {
			nativeOutputs[i].Mul(nativeInputs[i], nativeInputs[i])
			nativeOutputs[i].Mod(nativeOutputs[i], ctx.NativeModulus())
		}
		for _, m := range ctx.EmulatedModuli() {
			emulatedInputs, emulatedOutputs := ctx.InputsOutputs(m)
			if len(emulatedInputs) != len(emulatedOutputs) {
				return fmt.Errorf("expected same number of emulated inputs and outputs for modulus %s, got %d inputs and %d outputs", m.String(), len(emulatedInputs), len(emulatedOutputs))
			}
			for i := range emulatedOutputs {
				emulatedOutputs[i].Mul(emulatedInputs[i], emulatedInputs[i])
				emulatedOutputs[i].Mod(emulatedOutputs[i], m)
			}
		}

		return nil
	})
}

type customRangeCheckHintCircuit1[T1 FieldParams] struct {
	NativeIn         [2]frontend.Variable
	Emulated1In      [2]Element[T1]
	rangeCheckAmount map[int]int
}

func (c *customRangeCheckHintCircuit1[T1]) Define(api frontend.API) error {
	f, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	// request 2 native and 2 emulated outputs, with a range check option
	outNat, outEm, err := f.NewHintGeneric(hintSquareAllInputs, 2, 2, c.NativeIn[:], []*Element[T1]{&c.Emulated1In[0], &c.Emulated1In[1]},
		WithHintOutputRangeCheckBits(c.rangeCheckAmount))
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	for i := range outNat {
		api.AssertIsDifferent(outNat[i], c.NativeIn[i])
	}
	for i := range outEm {
		f.AssertIsDifferent(outEm[i], &c.Emulated1In[i])
	}
	return nil
}

func TestCustomRangeCheckHint(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := customRangeCheckHintCircuit1[Secp256k1Fp]{
		rangeCheckAmount: map[int]int{1: 8, 3: 8},
	}
	witness := customRangeCheckHintCircuit1[Secp256k1Fp]{
		NativeIn:    [2]frontend.Variable{3, 4},
		Emulated1In: [2]Element[Secp256k1Fp]{ValueOf[Secp256k1Fp](5), ValueOf[Secp256k1Fp](6)},
	}
	invalidWitness := customRangeCheckHintCircuit1[Secp256k1Fp]{
		NativeIn:    [2]frontend.Variable{1 << 7, 1 << 6},
		Emulated1In: [2]Element[Secp256k1Fp]{ValueOf[Secp256k1Fp](1 << 7), ValueOf[Secp256k1Fp](1 << 6)},
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.WithHints(hintSquareAllInputs)))
}

// varGenericHintCircuit exercises [NewVarGenericHint] which operates over the
// native field and two distinct emulated fields. We reuse hintSquareAllInputs
// which iterates over the native field and all emulated moduli. Note that the
// two emulated fields must use distinct moduli (and distinct from the native
// modulus), as the hint context looks up inputs/outputs by modulus value.
type varGenericHintCircuit[T1, T2 FieldParams] struct {
	NativeIn         [2]frontend.Variable
	Emulated1In      [2]Element[T1]
	Emulated2In      [2]Element[T2]
	rangeCheckAmount map[int]int
}

func (c *varGenericHintCircuit[T1, T2]) Define(api frontend.API) error {
	f1, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field 1: %w", err)
	}
	f2, err := NewField[T2](api)
	if err != nil {
		return fmt.Errorf("new field 2: %w", err)
	}
	outNat, outEm1, outEm2, err := NewVarGenericHint(api, 2, 2, 2,
		c.NativeIn[:],
		[]*Element[T1]{&c.Emulated1In[0], &c.Emulated1In[1]},
		[]*Element[T2]{&c.Emulated2In[0], &c.Emulated2In[1]},
		hintSquareAllInputs,
		WithHintOutputRangeCheckBits(c.rangeCheckAmount),
	)
	if err != nil {
		return fmt.Errorf("new var generic hint: %w", err)
	}
	for i := range outNat {
		api.AssertIsDifferent(outNat[i], c.NativeIn[i])
	}
	for i := range outEm1 {
		f1.AssertIsDifferent(outEm1[i], &c.Emulated1In[i])
	}
	for i := range outEm2 {
		f2.AssertIsDifferent(outEm2[i], &c.Emulated2In[i])
	}
	return nil
}

func TestVarGenericHint(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := varGenericHintCircuit[Secp256k1Fp, BLS12381Fr]{
		rangeCheckAmount: map[int]int{0: 8, 2: 8, 4: 8},
	}
	witness := varGenericHintCircuit[Secp256k1Fp, BLS12381Fr]{
		NativeIn:    [2]frontend.Variable{3, 4},
		Emulated1In: [2]Element[Secp256k1Fp]{ValueOf[Secp256k1Fp](5), ValueOf[Secp256k1Fp](6)},
		Emulated2In: [2]Element[BLS12381Fr]{ValueOf[BLS12381Fr](7), ValueOf[BLS12381Fr](8)},
	}
	invalidWitness := varGenericHintCircuit[Secp256k1Fp, BLS12381Fr]{
		NativeIn:    [2]frontend.Variable{1 << 32, 1 << 8},
		Emulated1In: [2]Element[Secp256k1Fp]{ValueOf[Secp256k1Fp](1 << 32), ValueOf[Secp256k1Fp](1 << 8)},
		Emulated2In: [2]Element[BLS12381Fr]{ValueOf[BLS12381Fr](1 << 32), ValueOf[BLS12381Fr](1 << 8)},
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.WithHints(hintSquareAllInputs)))
}

// zeroBitsHintCircuit exercises the bits==0 range check option, which disables
// range checking (same as bits<0). The hint outputs are returned as-is, not
// forced to zero, and no range check constraints are emitted.
type zeroBitsHintCircuit[T1 FieldParams] struct {
	NativeIn    frontend.Variable
	Emulated1In Element[T1]
}

func (c *zeroBitsHintCircuit[T1]) Define(api frontend.API) error {
	f, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	// output index 0 is the native output, index 1 is the emulated output; both
	// with bits==0, i.e. no range check.
	outNat, outEm, err := f.NewHintGeneric(hintSquareAllInputs, 1, 1, []frontend.Variable{c.NativeIn}, []*Element[T1]{&c.Emulated1In},
		WithHintOutputRangeCheckBits(map[int]int{0: 0, 1: 0}))
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	// the actual hint outputs are returned (not forced to zero) and are usable.
	nRes := api.Mul(c.NativeIn, c.NativeIn)
	api.AssertIsEqual(outNat[0], nRes)
	emRes := f.Mul(&c.Emulated1In, &c.Emulated1In)
	f.AssertIsEqual(outEm[0], emRes)
	return nil
}

func TestZeroBitsHint(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := zeroBitsHintCircuit[Secp256k1Fp]{}
	witness := zeroBitsHintCircuit[Secp256k1Fp]{
		NativeIn:    5,
		Emulated1In: ValueOf[Secp256k1Fp](6),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.WithHints(hintSquareAllInputs)))
}

// multiLimbRangeCheckHintCircuit exercises a positive bits range check that
// spans multiple limbs. Secp256k1Fp uses 64-bit limbs, so 130 bits requires 3
// limbs and exercises packLimbsWithWidth across a limb boundary (unlike the
// 8-bit single-limb case in TestCustomRangeCheckHint).
type multiLimbRangeCheckHintCircuit[T1 FieldParams] struct {
	Emulated1In [1]Element[T1]
}

func (c *multiLimbRangeCheckHintCircuit[T1]) Define(api frontend.API) error {
	f, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	_, outEm, err := f.NewHintGeneric(hintSquareAllInputs, 0, 1, nil, []*Element[T1]{&c.Emulated1In[0]},
		WithHintOutputRangeCheckBits(map[int]int{0: 130}))
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	f.AssertIsDifferent(outEm[0], &c.Emulated1In[0])
	return nil
}

func TestMultiLimbRangeCheckHint(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := multiLimbRangeCheckHintCircuit[Secp256k1Fp]{}
	// valid: (2^60)^2 = 2^120 < 2^130.
	validIn := new(big.Int).Lsh(big.NewInt(1), 60)
	// invalid: (2^66)^2 = 2^132 >= 2^130, so the range check fails.
	invalidIn := new(big.Int).Lsh(big.NewInt(1), 66)
	witness := multiLimbRangeCheckHintCircuit[Secp256k1Fp]{
		Emulated1In: [1]Element[Secp256k1Fp]{ValueOf[Secp256k1Fp](validIn)},
	}
	invalidWitness := multiLimbRangeCheckHintCircuit[Secp256k1Fp]{
		Emulated1In: [1]Element[Secp256k1Fp]{ValueOf[Secp256k1Fp](invalidIn)},
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.WithHints(hintSquareAllInputs)))
}

// badIndexHintCircuit requests a single emulated output (output index 0) but
// allows the test to supply an arbitrary range check index map to exercise the
// validation in applyHintOptions.
type badIndexHintCircuit[T1 FieldParams] struct {
	In  Element[T1]
	idx map[int]int
}

func (c *badIndexHintCircuit[T1]) Define(api frontend.API) error {
	f, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	_, _, err = f.NewHintGeneric(hintSquareAllInputs, 0, 1, nil, []*Element[T1]{&c.In},
		WithHintOutputRangeCheckBits(c.idx))
	return err
}

func TestHintRangeCheckOptionValidation(t *testing.T) {
	assert := test.NewAssert(t)
	// out-of-range index: only one output exists (index 0), index 5 is invalid.
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&badIndexHintCircuit[Secp256k1Fp]{idx: map[int]int{5: 8}})
	assert.Error(err, "expected error for out-of-range output range check index")
	// negative index is invalid.
	_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&badIndexHintCircuit[Secp256k1Fp]{idx: map[int]int{-1: 8}})
	assert.Error(err, "expected error for negative output range check index")
}
