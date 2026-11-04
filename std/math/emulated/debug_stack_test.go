package emulated

import (
	"fmt"
	"math/big"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// The non-native multiplication checks are performed in a deferred callback
// after the circuit is defined. With the debug build tag, a failing check
// should still point to the line in the circuit definition where the failing
// operation was called, as the native API does.

// nextLine returns the line number following the call to nextLine.
func nextLine() int {
	_, _, line, _ := runtime.Caller(1)
	return line + 1
}

type debugStackCircuit struct {
	A, B, C Element[emparams.Secp256k1Fp]

	// nested calls the failing assertion from a helper function instead of
	// directly in Define.
	nested bool
	// lines where the failing assertion is called (in Define and the helper)
	defineLine, helperLine *int
}

func (c *debugStackCircuit) assertProduct(f *Field[emparams.Secp256k1Fp], a, b, expected *Element[emparams.Secp256k1Fp]) {
	ab := f.Mul(a, b)
	*c.helperLine = nextLine()
	f.AssertIsEqual(ab, expected)
}

func (c *debugStackCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.Secp256k1Fp](api)
	if err != nil {
		return err
	}
	// a passing check created before the failing one
	f.AssertIsEqual(f.Add(&c.A, &c.B), f.Add(&c.B, &c.A))
	if c.nested {
		*c.defineLine = nextLine()
		c.assertProduct(f, &c.A, &c.B, &c.C)
	} else {
		ab := f.Mul(&c.A, &c.B)
		*c.defineLine = nextLine()
		f.AssertIsEqual(ab, &c.C)
	}
	// a passing check created after the failing one
	f.AssertIsEqual(f.Mul(&c.A, &c.A), f.Mul(&c.A, &c.A))
	return nil
}

func newDebugStackCircuit(nested bool) (circuit, assignment *debugStackCircuit) {
	circuit = &debugStackCircuit{nested: nested, defineLine: new(int), helperLine: new(int)}
	assignment = &debugStackCircuit{
		A: ValueOf[emparams.Secp256k1Fp](3),
		B: ValueOf[emparams.Secp256k1Fp](5),
		C: ValueOf[emparams.Secp256k1Fp](16), // 3*5 != 16
	}
	return
}

// requireLocation checks that the error is attributed to the failing assertion
// in the circuit definition instead of the deferred callback.
func requireLocation(t *testing.T, err error, circuit *debugStackCircuit) {
	t.Helper()
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "(*debugStackCircuit).Define")
	require.Contains(t, msg, fmt.Sprintf("debug_stack_test.go:%d", *circuit.defineLine))
	if circuit.nested {
		require.Contains(t, msg, "(*debugStackCircuit).assertProduct")
		require.Contains(t, msg, fmt.Sprintf("debug_stack_test.go:%d", *circuit.helperLine))
	}
	require.NotContains(t, msg, "performDeferredChecks")
}

func TestDebugStackTestEngine(t *testing.T) {
	if !debug.Debug {
		t.Skip("the call stack of non-native operations is only recorded with the debug build tag")
	}
	// koalabear uses the extension field path for the deferred checks.
	for _, field := range []*big.Int{ecc.BN254.ScalarField(), koalabear.Modulus()} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("field=%s/nested=%t", field.String()[:6], nested), func(t *testing.T) {
				circuit, assignment := newDebugStackCircuit(nested)
				err := test.IsSolved(circuit, assignment, field)
				requireLocation(t, err, circuit)
			})
		}
	}
}

func TestDebugStackSolver(t *testing.T) {
	if !debug.Debug {
		t.Skip("the call stack of non-native operations is only recorded with the debug build tag")
	}
	for _, builder := range []struct {
		name    string
		builder frontend.NewBuilder
	}{
		{"r1cs", r1cs.NewBuilder[constraint.U64]},
		{"scs", scs.NewBuilder[constraint.U64]},
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", builder.name, nested), func(t *testing.T) {
				circuit, assignment := newDebugStackCircuit(nested)
				ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder.builder, circuit)
				require.NoError(t, err)
				w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
				require.NoError(t, err)
				_, err = ccs.Solve(w)
				requireLocation(t, err, circuit)
			})
		}
	}
}

func TestDebugStackValidWitness(t *testing.T) {
	// recording the call stack must not change the result for valid
	// witnesses, with or without the debug build tag.
	assert := test.NewAssert(t)
	for _, nested := range []bool{false, true} {
		circuit, assignment := newDebugStackCircuit(nested)
		assignment.C = ValueOf[emparams.Secp256k1Fp](15)
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254), test.NoProverChecks())
	}
}
