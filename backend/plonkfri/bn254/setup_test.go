package plonkfri_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"

	plonkfri "github.com/consensys/gnark/backend/plonkfri/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// squareMulCircuit proves knowledge of X, Y such that X^2 * Y = Out.
// Same toy circuit used throughout the design discussion in PROJECT.md
// (x=3, y=2, out=18), kept here so the two stay in sync.
type squareMulCircuit struct {
	X   frontend.Variable
	Y   frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *squareMulCircuit) Define(api frontend.API) error {
	t := api.Mul(c.X, c.X)
	out := api.Mul(t, c.Y)
	api.AssertIsEqual(out, c.Out)
	return nil
}

// TestSetupSmoke is a Phase 0 smoke test: it only checks that Setup runs to
// completion against today's constraint/bn254 and produces structurally
// sane keys. It does not prove or verify anything yet -- prove.go/verify.go
// don't exist on this branch yet.
func TestSetupSmoke(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &squareMulCircuit{})
	assert.NoError(err)

	sparseR1CS, ok := ccs.(*cs.SparseR1CS)
	assert.True(ok, "expected a *cs.SparseR1CS constraint system")

	pk, vk, err := plonkfri.Setup(sparseR1CS)
	assert.NoError(err)
	assert.NotNil(pk)
	assert.NotNil(vk)

	// ProvingKey embeds its VerifyingKey (per the struct's doc comment) --
	// Setup must return the very same object, not a copy.
	assert.Same(vk, pk.Vk)

	// one public input (Out); the small domain must be a power of two at
	// least as big as nbConstraints+nbPublic.
	assert.Equal(uint64(1), vk.NbPublicVariables)
	assert.True(vk.Size >= uint64(sparseR1CS.GetNbConstraints()+1))
	assert.True(vk.Size&(vk.Size-1) == 0, "domain size must be a power of two, got %d", vk.Size)
	assert.False(vk.Generator.IsZero())

	// the permutation must cover all 3*size wire slots (l||r||o).
	assert.Len(pk.Permutation, 3*int(vk.Size))

	// every setup polynomial must have actually gone through FRI's
	// BuildProofOfProximity -- a real proof has at least one folding round.
	for i, pp := range vk.Qpp {
		assert.NotEmpty(pp.Rounds, "Qpp[%d] has no rounds -- selector polynomial was not committed", i)
	}
	for i, pp := range vk.Spp {
		assert.NotEmpty(pp.Rounds, "Spp[%d] has no rounds -- permutation polynomial was not committed", i)
	}
	for i, pp := range vk.Idpp {
		assert.NotEmpty(pp.Rounds, "Idpp[%d] has no rounds -- identity polynomial was not committed", i)
	}
}
