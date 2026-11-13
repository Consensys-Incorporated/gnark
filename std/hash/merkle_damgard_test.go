package hash_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/test"
)

type mulAddCompressor struct{ api frontend.API }

func (c mulAddCompressor) Compress(a, b frontend.Variable) frontend.Variable {
	return c.api.Mul(c.api.Add(a, b), a)
}

type mdSetStateCircuit struct {
	IV, S, X, Expected frontend.Variable
}

func (c *mdSetStateCircuit) Define(api frontend.API) error {
	h := hash.NewMerkleDamgardHasher(api, mulAddCompressor{api}, c.IV)
	if err := h.SetState([]frontend.Variable{c.S}); err != nil {
		return err
	}
	h.Write(c.X)
	api.AssertIsEqual(h.Sum(), c.Expected)

	// the state was already set, so setting it again must be refused
	if err := h.SetState([]frontend.Variable{c.S}); err == nil {
		panic("SetState succeeded on a hasher that is not in its initial state")
	}
	h.Reset()
	return h.SetState([]frontend.Variable{c.S})
}

// The IV is a circuit variable here; under the R1CS builder it is a slice-backed
// linear expression, which cannot be compared with ==.
func TestMerkleDamgardSetStateVariableIV(t *testing.T) {
	assignment := &mdSetStateCircuit{IV: 3, S: 5, X: 7, Expected: 60}
	test.NewAssert(t).CheckCircuit(&mdSetStateCircuit{}, test.WithValidAssignment(assignment),
		test.WithCurves(ecc.BN254), test.NoFuzzing(), test.NoSerializationChecks(), test.NoProverChecks())
}
