package test

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

type hintCircuit struct {
	A, B frontend.Variable
}

func (circuit *hintCircuit) Define(api frontend.API) error {
	res, err := api.Compiler().NewHint(bits.GetHints()[0], 1, circuit.A, 3)
	if err != nil {
		return fmt.Errorf("IthBit circuitA 3: %w", err)
	}
	a3b := res[0]
	res, err = api.Compiler().NewHint(bits.GetHints()[0], 1, circuit.A, 25)
	if err != nil {
		return fmt.Errorf("IthBit circuitA 25: %w", err)
	}
	a25b := res[0]

	res, err = api.Compiler().NewHint(solver.InvZeroHint, 1, circuit.A)
	if err != nil {
		return fmt.Errorf("IsZero CircuitA: %w", err)
	}
	aInvZero := res[0]

	res, err = api.Compiler().NewHint(solver.InvZeroHint, 1, circuit.B)
	if err != nil {
		return fmt.Errorf("IsZero, CircuitB")
	}
	bInvZero := res[0]

	// good witness
	expectedA := big.NewInt(8)
	expectedA.ModInverse(expectedA, api.Compiler().Field())

	api.AssertIsEqual(aInvZero, expectedA)
	api.AssertIsEqual(bInvZero, 0) // b == 0, invZero(b) == 0
	api.AssertIsEqual(a3b, 1)
	api.AssertIsEqual(a25b, 0)

	return nil
}

func TestBuiltinHints(t *testing.T) {
	for _, curve := range gnark.Curves() {
		if err := IsSolved(&hintCircuit{}, &hintCircuit{
			A: (0b1000),
			B: (0),
		}, curve.ScalarField()); err != nil {
			t.Fatal(err)
		}

		if err := IsSolved(&hintCircuit{}, &hintCircuit{
			A: (0b10),
			B: (1),
		}, curve.ScalarField()); err == nil {
			t.Fatal("witness shouldn't solve circuit")
		}
	}

}

var isDeferCalled bool

type EmptyCircuit struct {
	X frontend.Variable
}

func (c *EmptyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 0)
	api.Compiler().Defer(func(api frontend.API) error {
		isDeferCalled = true
		return nil
	})
	return nil
}

func TestPreCompileHook(t *testing.T) {
	c := &EmptyCircuit{}
	w := &EmptyCircuit{
		X: 0,
	}
	isDeferCalled = false
	err := IsSolved(c, w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if !isDeferCalled {
		t.Error("callback not called")
	}
}

type divUncheckedZeroCircuit struct {
	Case divUncheckedCase `gnark:"-"`
	A    frontend.Variable
	B    frontend.Variable
}

func (c *divUncheckedZeroCircuit) Define(api frontend.API) error {
	var res frontend.Variable
	switch c.Case {
	case divUncheckedVarVar:
		res = api.DivUnchecked(c.A, c.B)
	case divUncheckedVarConst:
		res = api.DivUnchecked(c.A, 0)
	case divUncheckedConstVar:
		res = api.DivUnchecked(0, c.B)
	case divUncheckedConstConst:
		res = api.DivUnchecked(0, 0)
	default:
		return fmt.Errorf("unknown case %d", c.Case)
	}
	api.AssertIsEqual(res, 0)
	return nil
}

type divUncheckedCase uint8

const (
	divUncheckedVarVar divUncheckedCase = iota
	divUncheckedVarConst
	divUncheckedConstVar
	divUncheckedConstConst
)

// squareHint returns x^2 for the first input.
func squareHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Mul(inputs[0], inputs[0])
	return nil
}

// zeroHint always returns 0.
func zeroHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].SetUint64(0)
	return nil
}

type squareHintCircuit struct {
	X       frontend.Variable
	XSquare frontend.Variable
}

func (c *squareHintCircuit) Define(api frontend.API) error {
	res, err := api.Compiler().NewHint(squareHint, 1, c.X)
	if err != nil {
		return err
	}
	api.AssertIsEqual(res[0], c.XSquare)
	return nil
}

func TestHintReplacement(t *testing.T) {
	field := ecc.BN254.ScalarField()

	t.Run("without replacement", func(t *testing.T) {
		err := IsSolved(
			&squareHintCircuit{},
			&squareHintCircuit{X: 3, XSquare: 9},
			field,
		)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("with replacement", func(t *testing.T) {
		err := IsSolved(
			&squareHintCircuit{},
			&squareHintCircuit{X: 3, XSquare: 0},
			field,
			WithReplacementHint(solver.GetHintID(squareHint), zeroHint),
		)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestDivUncheckedZeroPanicsInEngine(t *testing.T) {
	tests := []struct {
		name string
		mode divUncheckedCase
	}{
		{name: "var_var", mode: divUncheckedVarVar},
		{name: "var_const", mode: divUncheckedVarConst},
		{name: "const_var", mode: divUncheckedConstVar},
		{name: "const_const", mode: divUncheckedConstConst},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := IsSolved(&divUncheckedZeroCircuit{Case: tc.mode}, &divUncheckedZeroCircuit{
				Case: tc.mode,
				A:    0,
				B:    0,
			}, ecc.BN254.ScalarField())
			if err == nil {
				t.Fatal("expected test engine to fail on DivUnchecked(0, 0)")
			}
			if !strings.Contains(err.Error(), "DivUnchecked(0, 0) called") {
				t.Fatalf("expected explicit DivUnchecked(0, 0) error, got %v", err)
			}
		})
	}
}

type lessOrEqCstCircuit struct {
	X frontend.Variable
}

func (c *lessOrEqCstCircuit) Define(api frontend.API) error {
	cmper, ok := api.Compiler().(interface {
		MustBeLessOrEqCst(aBits []frontend.Variable, bound *big.Int, aForDebug frontend.Variable)
	})
	if !ok {
		return fmt.Errorf("compiler does not implement MustBeLessOrEqCst")
	}
	cmper.MustBeLessOrEqCst(api.ToBinary(c.X, 3), big.NewInt(5), c.X)
	return nil
}

func TestMustBeLessOrEqCstToBinaryBits(t *testing.T) {
	assert := NewAssert(t)
	assert.CheckCircuit(&lessOrEqCstCircuit{},
		WithValidAssignment(&lessOrEqCstCircuit{X: 4}),
		WithValidAssignment(&lessOrEqCstCircuit{X: 5}),
		WithInvalidAssignment(&lessOrEqCstCircuit{X: 6}),
	)
}
