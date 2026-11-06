package test

import (
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/test/solcheck"
)

// solidityVerification checks that the exported solidity contract can verify the proof
// and that the proof is valid.
// It uses the test/solcheck package, see test.WithSolidity option.
func (assert *Assert) solidityVerification(b backend.ID, c ecc.ID, vk solidity.VerifyingKey,
	proof any,
	validPublicWitness witness.Witness,
	opts []solidity.ExportOption,
) {
	if !SolcCheck {
		// we return, we don't have the solidity check build tag defined
		return
	}
	var nbPubWit int
	switch c {
	case ecc.BN254:
		nbPubWit = len(validPublicWitness.Vector().(fr_bn254.Vector))
	case ecc.BLS12_381:
		nbPubWit = len(validPublicWitness.Vector().(fr_bls12381.Vector))
	default:
		panic("solidity verification not implemented for this curve: " + c.String())
	}
	if nbPubWit == 0 {
		assert.Log("skipping solidity tests for zero public witness length")
		return
	}

	if assert.b != nil {
		assert.b.Helper()
	} else {
		assert.t.Helper()
	}

	// make temp dir
	tmpDir, err := os.MkdirTemp("", "gnark-solidity-check*")
	assert.NoError(err)
	defer os.RemoveAll(tmpDir)

	// export solidity contract
	fSolidity, err := os.Create(filepath.Join(tmpDir, "gnark_verifier.sol"))
	assert.NoError(err)

	err = vk.ExportSolidity(fSolidity, opts...)
	assert.NoError(err)

	err = fSolidity.Close()
	assert.NoError(err)

	// compile the contract and generate the Go bindings
	assert.NoError(solcheck.Generate(tmpDir, "gnark_verifier.sol"))

	// proof to solidity calldata
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}

	// public witness to bytes
	bPublicWitness, err := validPublicWitness.MarshalBinary()
	assert.NoError(err)
	// that's quite dirty...
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	bPublicWitness = bPublicWitness[12:]

	// verify proof on a simulated geth backend
	err = solcheck.Verify(tmpDir, solcheck.Proof{
		Backend:      b,
		Curve:        c,
		Proof:        _proof.MarshalSolidity(),
		PublicInputs: bPublicWitness,
		// len(vk.K) - 1 == len(publicWitness) + len(commitments)
		NbCommitments: vk.NbPublicWitness() - nbPubWit,
	})
	assert.NoError(err)
}
