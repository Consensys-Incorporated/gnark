package gkrtesting

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/stretchr/testify/require"
)

// ResultReadTwiceGate is a gate of two inputs, x and y, computing p + x + p with p = x·y.
func ResultReadTwiceGate(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	p := api.Mul(in[0], in[1])
	return api.Add(p, in[0], p)
}

// CheckEvaluators compiles the gates of MiMCCircuit, Poseidon2Circuit and ResultReadTwiceGate for
// field, and requires the evaluators newEvaluator returns to agree, on random inputs, with the gate
// functions evaluated by gkrcore.FieldAPI over the prime subfield, embedded into E by SetBigInt.
func CheckEvaluators[E comparable, PE interface {
	*E
	SetBigInt(*big.Int) *E
}](t *testing.T, field gkr.Field, newEvaluator func(gkr.GateBytecode) func(...E) *E) {

	type gate struct {
		f    gkr.GateFunction
		nbIn int
	}
	gates := []gate{{ResultReadTwiceGate, 2}}
	for _, circuit := range []gkrcore.RawCircuit{MiMCCircuit(3), Poseidon2Circuit(2, 2)} {
		for _, wire := range circuit {
			if wire.Gate != nil {
				gates = append(gates, gate{wire.Gate, len(wire.Inputs)})
			}
		}
	}

	reference := &gkrcore.FieldAPI{Field: gkr.PrimeField(field.Modulus)}
	for gateI, g := range gates {
		compiled, err := gkrcore.CompileGateFunction(g.f, g.nbIn, field)
		require.NoError(t, err)
		evaluator := newEvaluator(compiled.Evaluate)

		for range 2 {
			vars := make([]frontend.Variable, g.nbIn)
			in := make([]E, g.nbIn)
			for i := range vars {
				x, err := rand.Int(rand.Reader, field.Modulus)
				require.NoError(t, err)
				vars[i] = x
				PE(&in[i]).SetBigInt(x)
			}
			var want E
			PE(&want).SetBigInt(g.f(reference, vars...).([]*big.Int)[0])
			require.True(t, *evaluator(in...) == want, "gate %d", gateI)
		}
	}
}
