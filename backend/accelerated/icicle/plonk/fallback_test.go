//go:build !icicle

package plonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	accel_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

type fallbackCircuit struct {
	A, B frontend.Variable `gnark:",public"`
	Res  frontend.Variable
}

func (c *fallbackCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Res)
	return nil
}

// TestCPUFallback checks that, when compiled without the 'icicle' build tag,
// the package degrades gracefully to the native CPU PLONK prover instead of
// panicking.
func TestCPUFallback(t *testing.T) {
	assert := test.NewAssert(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &fallbackCircuit{})
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)

	pk, vk, err := accel_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	assignment := fallbackCircuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	proof, err := accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	err = accel_plonk.Verify(proof, vk, pw)
	assert.NoError(err)
}
