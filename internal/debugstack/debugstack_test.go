package debugstack_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/debugstack"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// deferredCheckCircuit records the call stack when Define runs and performs
// the actual assertion only in a deferred callback, as gadgets batching their
// checks do.
type deferredCheckCircuit struct {
	A, B frontend.Variable

	attribute bool
	line      *int // pointer as the test engine clones the circuit
}

func (c *deferredCheckCircuit) Define(api frontend.API) error {
	pcs := make([]uintptr, 32)
	_, _, line, _ := runtime.Caller(0)
	n := runtime.Callers(1, pcs) // the operation is "defined" on this line
	*c.line = line + 1
	pcs = pcs[:n]
	if !c.attribute {
		pcs = nil
	}
	api.Compiler().Defer(func(api frontend.API) error {
		debugstack.Run(api, pcs, func() {
			api.AssertIsEqual(c.A, c.B)
		})
		return nil
	})
	return nil
}

func TestRunTestEngine(t *testing.T) {
	// the test engine implements attribution independently of the debug tag.
	for _, attribute := range []bool{false, true} {
		t.Run(fmt.Sprintf("attribute=%t", attribute), func(t *testing.T) {
			circuit := &deferredCheckCircuit{attribute: attribute, line: new(int)}
			err := test.IsSolved(circuit, &deferredCheckCircuit{A: 1, B: 2}, ecc.BN254.ScalarField())
			require.Error(t, err)
			require.Contains(t, err.Error(), "[assertIsEqual] 1 == 2")
			defineSite := fmt.Sprintf("debugstack_test.go:%d", *circuit.line)
			if attribute {
				require.Contains(t, err.Error(), defineSite)
				require.Contains(t, err.Error(), "(*deferredCheckCircuit).Define")
			} else {
				require.NotContains(t, err.Error(), defineSite)
			}
			// valid witness is not affected
			require.NoError(t, test.IsSolved(&deferredCheckCircuit{attribute: attribute, line: new(int)}, &deferredCheckCircuit{A: 2, B: 2}, ecc.BN254.ScalarField()))
		})
	}
}
