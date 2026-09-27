package plonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

type unmarshalSolidityCircuit struct {
	X       frontend.Variable `gnark:",public"`
	Y       frontend.Variable
	withCmt bool
}

func (c *unmarshalSolidityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.Y, c.Y), c.X)
	if c.withCmt {
		cmt, err := api.(frontend.Committer).Commit(c.Y)
		if err != nil {
			return err
		}
		api.AssertIsDifferent(cmt, 0)
	}
	return nil
}

func TestUnmarshalSolidity(t *testing.T) {
	for _, withCmt := range []bool{false, true} {
		assert := require.New(t)

		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &unmarshalSolidityCircuit{withCmt: withCmt})
		assert.NoError(err)
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
		assert.NoError(err)
		pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
		assert.NoError(err)

		w, err := frontend.NewWitness(&unmarshalSolidityCircuit{X: 9, Y: 3, withCmt: withCmt}, ecc.BN254.ScalarField())
		assert.NoError(err)
		pw, err := w.Public()
		assert.NoError(err)
		p, err := plonk.Prove(ccs, pk, w)
		assert.NoError(err)

		proof := p.(*plonk_bn254.Proof)
		nbCommits := len(proof.Bsb22Commitments)
		got := plonk_bn254.UnmarshalSolidity(proof.MarshalSolidity(), nbCommits)
		assert.Len(got.BatchedProof.ClaimedValues, len(proof.BatchedProof.ClaimedValues))

		// the claimed value of the linearised polynomial is not part of the
		// solidity encoding
		got.BatchedProof.ClaimedValues[0] = proof.BatchedProof.ClaimedValues[0]
		assert.NoError(plonk_bn254.Verify(&got, vk.(*plonk_bn254.VerifyingKey), pw.Vector().(fr.Vector)))
	}
}
