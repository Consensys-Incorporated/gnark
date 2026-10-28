// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fiatshamir

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type FiatShamirCircuit struct {
	Bindings   [3][4]frontend.Variable `gnark:",public"`
	Challenges [3]frontend.Variable    `gnark:",secret"`
}

func (circuit *FiatShamirCircuit) Define(api frontend.API) error {

	// create the hash function
	hSnark, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// New transcript with 3 challenges to be derived
	tsSnark := NewTranscript(api, &hSnark, []string{"alpha", "beta", "gamma"})

	// Bind challenges
	if err := tsSnark.Bind("alpha", circuit.Bindings[0][:]); err != nil {
		return err
	}
	if err := tsSnark.Bind("beta", circuit.Bindings[1][:]); err != nil {
		return err
	}
	if err := tsSnark.Bind("gamma", circuit.Bindings[2][:]); err != nil {
		return err
	}

	// derive challenges
	var challenges [3]frontend.Variable
	challenges[0], err = tsSnark.ComputeChallenge("alpha")
	if err != nil {
		return err
	}

	challenges[1], err = tsSnark.ComputeChallenge("beta")
	if err != nil {
		return err
	}
	challenges[2], err = tsSnark.ComputeChallenge("gamma")
	if err != nil {
		return err
	}

	// // check equality between expected values
	api.AssertIsEqual(challenges[0], circuit.Challenges[0])
	api.AssertIsEqual(challenges[1], circuit.Challenges[1])
	api.AssertIsEqual(challenges[2], circuit.Challenges[2])

	return nil
}

func TestFiatShamir(t *testing.T) {
	var err error
	assert := test.NewAssert(t)

	testData := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BW6_761:   hash.MIMC_BW6_761,
	}

	// compute the witness for each curve
	for curveID, h := range testData {

		// instantiate the hash and the transcript in plain go
		ts := fiatshamir.NewTranscript(h.New(), "alpha", "beta", "gamma")

		var bindings [3][4]*big.Int
		for i := 0; i < 3; i++ {
			for j := 0; j < 4; j++ {
				bindings[i][j], err = rand.Int(rand.Reader, curveID.ScalarField())
				assert.NoError(err)
			}
		}
		frSize := utils.ByteLen(curveID.ScalarField())
		buf := make([]byte, frSize)
		for i := 0; i < 4; i++ {
			err := ts.Bind("alpha", bindings[0][i].FillBytes(buf))
			assert.NoError(err)
			err = ts.Bind("beta", bindings[1][i].FillBytes(buf))
			assert.NoError(err)
			err = ts.Bind("gamma", bindings[2][i].FillBytes(buf))
			assert.NoError(err)
		}

		var expectedChallenges [3][]byte
		var err error
		expectedChallenges[0], err = ts.ComputeChallenge("alpha")
		assert.NoError(err)
		expectedChallenges[1], err = ts.ComputeChallenge("beta")
		assert.NoError(err)
		expectedChallenges[2], err = ts.ComputeChallenge("gamma")
		assert.NoError(err)

		// instantiate the circuit with provided inputs
		var witness FiatShamirCircuit

		for i := 0; i < 3; i++ {
			for j := 0; j < 4; j++ {
				witness.Bindings[i][j] = bindings[i][j]
			}
			witness.Challenges[i] = expectedChallenges[i]
		}

		assert.SolvingSucceeded(&FiatShamirCircuit{}, &witness, test.WithCurves(curveID))
	}

}

func BenchmarkCompile(b *testing.B) {
	// create an empty cs
	var circuit FiatShamirCircuit

	var ccs constraint.ConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	}
	b.Log(ccs.GetNbConstraints())
}
