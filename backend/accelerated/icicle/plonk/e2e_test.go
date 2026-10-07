//go:build icicle

package plonk_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	accel_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

const largeCircuitSize = 1 << 12

var errNoCommitter = errors.New("builder does not implement frontend.Committer")

// largeCircuit is a sequential x = x² + a recurrence, padded with a BSB22
// commitment so that the commitment path of the GPU prover is exercised
// (production circuits using std/rangecheck always carry one).
type largeCircuit struct {
	A   frontend.Variable `gnark:",public"`
	Res frontend.Variable
}

func (c *largeCircuit) Define(api frontend.API) error {
	x := c.A
	for i := 0; i < largeCircuitSize; i++ {
		x = api.Add(api.Mul(x, x), c.A)
	}
	api.AssertIsEqual(x, c.Res)
	committer, ok := api.(frontend.Committer)
	if !ok {
		return errNoCommitter
	}
	cm, err := committer.Commit(x, c.A)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cm, 0)
	return nil
}

// TestEndToEndLargeCircuit runs a full accelerated setup -> GPU prove ->
// verify cycle on every supported curve, with a circuit large enough
// (2^12+ constraints) to exercise the chunked-MSM and NTT paths.
func TestEndToEndLargeCircuit(t *testing.T) {
	for _, curveID := range []ecc.ID{ecc.BN254, ecc.BLS12_377, ecc.BLS12_381, ecc.BW6_761} {
		t.Run(curveID.String(), func(t *testing.T) {
			assert := test.NewAssert(t)

			ccs, err := frontend.Compile(curveID.ScalarField(), scs.NewBuilder, &largeCircuit{})
			assert.NoError(err)
			t.Logf("nb constraints: %d", ccs.GetNbConstraints())

			srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
			assert.NoError(err)

			iciPK, iciVK, err := accel_plonk.Setup(ccs, srs, srsLagrange)
			assert.NoError(err)

			// compute the expected result with the same recurrence
			mod := curveID.ScalarField()
			a := big.NewInt(3)
			x := big.NewInt(3)
			for i := 0; i < largeCircuitSize; i++ {
				x.Mul(x, x)
				x.Add(x, a)
				x.Mod(x, mod)
			}

			assignment := largeCircuit{A: a, Res: x}
			w, err := frontend.NewWitness(&assignment, curveID.ScalarField())
			assert.NoError(err)
			pw, err := w.Public()
			assert.NoError(err)

			proof, err := accel_plonk.Prove(ccs, iciPK, w)
			assert.NoError(err)
			err = accel_plonk.Verify(proof, iciVK, pw)
			assert.NoError(err)
		})
	}
}
