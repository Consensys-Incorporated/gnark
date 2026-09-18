// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package eddsa

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

// Forge signature: S → S + order
func forge(id tedwards.ID, sig []byte) ([]byte, error) {

	forged := make([]byte, len(sig))
	copy(forged, sig)

	var offset int
	switch id {
	case tedwards.BN254:
		offset = 32
	case tedwards.BLS12_381:
		offset = 32
	case tedwards.BLS12_381_BANDERSNATCH:
		offset = 32
	case tedwards.BLS12_377:
		offset = 32
	case tedwards.BW6_761:
		offset = 48
	default:
		panic("not implemented")
	}

	s := new(big.Int).SetBytes(sig[offset:])
	params, err := twistededwards.GetCurveParams(id)
	if err != nil {
		return nil, err
	}
	s.Add(s, params.Order)

	sizeS := len(sig) - offset
	buf := make([]byte, sizeS)
	copy(buf[sizeS-len(s.Bytes()):], s.Bytes())

	copy(forged[offset:], buf)
	return forged, nil
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, tedwards.BN254},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{hash.MIMC_BLS12_377, tedwards.BLS12_377},
		{hash.MIMC_BW6_761, tedwards.BW6_761},
	}

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed)) //#nosec G404 -- This is a false positive

	for _, conf := range confs {

		snarkField, err := twistededwards.GetSnarkField(conf.curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)

		// generate parameters for the signatures
		privKey, err := eddsa.New(conf.curve, randomness)
		assert.NoError(err, "generating eddsa key pair")

		// pick a message to sign
		var msg big.Int
		msg.Rand(randomness, snarkField)
		t.Log("msg to sign", msg.String())
		msgDataUnpadded := msg.Bytes()
		msgData := make([]byte, len(snarkField.Bytes()))
		copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)

		// generate signature
		signature, err := privKey.Sign(msgData, conf.hash.New())
		assert.NoError(err, "signing message")

		// check if there is no problem in the signature
		pubKey := privKey.Public()
		checkSig, err := pubKey.Verify(signature, msgData, conf.hash.New())
		assert.NoError(err, "verifying signature")
		assert.True(checkSig, "signature verification failed")

		// create and compile the circuit for signature verification
		var circuit eddsaCircuit
		circuit.curveID = conf.curve

		var validWitness eddsaCircuit
		validWitness.Message = msg
		validWitness.PublicKey.Assign(conf.curve, pubKey.Bytes())
		validWitness.Signature.Assign(conf.curve, signature)

		var invalidWitness eddsaCircuit
		invalidMsg := new(big.Int)
		invalidMsg.Rand(randomness, snarkField)
		invalidWitness.Message = invalidMsg
		invalidWitness.PublicKey.Assign(conf.curve, pubKey.Bytes())
		invalidWitness.Signature.Assign(conf.curve, signature)

		var invalidWitnessOverflow eddsaCircuit
		invalidWitnessOverflow.Message = msg
		invalidWitnessOverflow.PublicKey.Assign(conf.curve, pubKey.Bytes())
		forgedSig, err := forge(conf.curve, signature)
		assert.NoError(err, "forging signature")
		invalidWitnessOverflow.Signature.Assign(conf.curve, forgedSig)

		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithInvalidAssignment(&invalidWitnessOverflow),
			test.WithCurves(snarkCurve))

	}

}
