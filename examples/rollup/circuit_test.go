// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package rollup

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type circuitSignature Circuit

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (t *circuitSignature) Define(api frontend.API) error {
	if err := (*Circuit)(t).postInit(api); err != nil {
		return err
	}
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	return verifyTransferSignature(api, t.Transfers[0], hFunc)
}

func TestCircuitSignature(t *testing.T) {

	const nbAccounts = 10

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// verifies the signature of the transfer
	assert := test.NewAssert(t)

	var signatureCircuit circuitSignature
	for i := 0; i < BatchSizeCircuit; i++ {
		signatureCircuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
		signatureCircuit.MerkleProofReceiverAfter[i].Path = make([]frontend.Variable, depth)
		signatureCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		signatureCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	assert.ProverSucceeded(&signatureCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

type circuitInclusionProof Circuit

func (t *circuitInclusionProof) Define(api frontend.API) error {

	hashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	t.MerkleProofReceiverBefore[0].VerifyProof(api, &hashFunc, t.LeafReceiver[0])
	t.MerkleProofReceiverAfter[0].VerifyProof(api, &hashFunc, t.LeafReceiver[0])
	t.MerkleProofSenderBefore[0].VerifyProof(api, &hashFunc, t.LeafSender[0])
	t.MerkleProofSenderAfter[0].VerifyProof(api, &hashFunc, t.LeafSender[0])

	return nil
}

func TestCircuitInclusionProof(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(16)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// verifies the proofs of inclusion of the transfer
	assert := test.NewAssert(t)

	// we allocate the slices of the circuit before compiling it
	var inclusionProofCircuit circuitInclusionProof
	for i := 0; i < BatchSizeCircuit; i++ {
		inclusionProofCircuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
		inclusionProofCircuit.MerkleProofReceiverAfter[i].Path = make([]frontend.Variable, depth)
		inclusionProofCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		inclusionProofCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	assert.ProverSucceeded(
		&inclusionProofCircuit,
		&operator.witnesses,
		test.WithCurves(ecc.BN254),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()),
		test.WithBackends(backend.GROTH16))

}

type circuitUpdateAccount Circuit

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (t *circuitUpdateAccount) Define(api frontend.API) error {

	if err := (*Circuit)(t).postInit(api); err != nil {
		return err
	}

	verifyAccountUpdated(api, t.SenderAccountsBefore[0], t.ReceiverAccountsBefore[0],
		t.SenderAccountsAfter[0], t.ReceiverAccountsAfter[0], t.Transfers[0].Amount)
	return nil
}

func TestCircuitUpdateAccount(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)

	var updateAccountCircuit circuitUpdateAccount
	(*Circuit)(&updateAccountCircuit).allocateSlicesMerkleProofs()

	assert.ProverSucceeded(&updateAccountCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

func TestCircuitFull(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	// verifies the proofs of inclusion of the transfer

	var rollupCircuit Circuit
	for i := 0; i < BatchSizeCircuit; i++ {
		rollupCircuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofReceiverAfter[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	// TODO full circuit has some unconstrained inputs, that's odd.
	assert.ProverSucceeded(
		&rollupCircuit,
		&operator.witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

}
