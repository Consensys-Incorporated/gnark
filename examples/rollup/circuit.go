// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package rollup

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	nbAccounts       = 16 // 16 accounts so we know that the proof length is 5
	depth            = 5  // size of the inclusion proofs
	BatchSizeCircuit = 1  // nbTransfers to batch in a proof
)

// Circuit "toy" rollup circuit where an operator can generate a proof that he processed
// some transactions
type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	// list of accounts involved before update and their public keys
	SenderAccountsBefore   [BatchSizeCircuit]AccountConstraints
	ReceiverAccountsBefore [BatchSizeCircuit]AccountConstraints
	PublicKeysSender       [BatchSizeCircuit]eddsa.PublicKey

	// list of accounts involved after update and their public keys
	SenderAccountsAfter   [BatchSizeCircuit]AccountConstraints
	ReceiverAccountsAfter [BatchSizeCircuit]AccountConstraints
	PublicKeysReceiver    [BatchSizeCircuit]eddsa.PublicKey

	// list of transactions
	Transfers [BatchSizeCircuit]TransferConstraints

	// list of proofs corresponding to sender and receiver accounts
	MerkleProofReceiverBefore [BatchSizeCircuit]merkle.MerkleProof
	MerkleProofReceiverAfter  [BatchSizeCircuit]merkle.MerkleProof
	MerkleProofSenderBefore   [BatchSizeCircuit]merkle.MerkleProof
	MerkleProofSenderAfter    [BatchSizeCircuit]merkle.MerkleProof
	LeafReceiver              [BatchSizeCircuit]frontend.Variable
	LeafSender                [BatchSizeCircuit]frontend.Variable

	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashesBefore [BatchSizeCircuit]frontend.Variable `gnark:",public"`
	RootHashesAfter  [BatchSizeCircuit]frontend.Variable `gnark:",public"`
}

// AccountConstraints accounts encoded as constraints
type AccountConstraints struct {
	Index   frontend.Variable // index in the tree
	Nonce   frontend.Variable // nb transactions done so far from this account
	Balance frontend.Variable
	PubKey  eddsa.PublicKey `gnark:"-"`
}

// TransferConstraints transfer encoded as constraints
type TransferConstraints struct {
	Amount         frontend.Variable
	Nonce          frontend.Variable `gnark:"-"`
	SenderPubKey   eddsa.PublicKey   `gnark:"-"`
	ReceiverPubKey eddsa.PublicKey   `gnark:"-"`
	Signature      eddsa.Signature
}

func (circuit *Circuit) postInit(api frontend.API) error {

	for i := 0; i < BatchSizeCircuit; i++ {

		// setting the sender accounts before update
		circuit.SenderAccountsBefore[i].PubKey = circuit.PublicKeysSender[i]

		// setting the sender accounts after update
		circuit.SenderAccountsAfter[i].PubKey = circuit.PublicKeysSender[i]

		// setting the receiver accounts before update
		circuit.ReceiverAccountsBefore[i].PubKey = circuit.PublicKeysReceiver[i]

		// setting the receiver accounts after update
		circuit.ReceiverAccountsAfter[i].PubKey = circuit.PublicKeysReceiver[i]

		// setting the transfers
		circuit.Transfers[i].Nonce = circuit.SenderAccountsBefore[i].Nonce
		circuit.Transfers[i].SenderPubKey = circuit.PublicKeysSender[i]
		circuit.Transfers[i].ReceiverPubKey = circuit.PublicKeysReceiver[i]

		// allocate the slices for the Merkle proofs
		// circuit.allocateSlicesMerkleProofs()

	}
	return nil
}

func (circuit *Circuit) allocateSlicesMerkleProofs() {

	for i := 0; i < BatchSizeCircuit; i++ {
		// allocating slice for the Merkle paths
		circuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofReceiverAfter[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

}

// Define declares the circuit's constraints
func (circuit *Circuit) Define(api frontend.API) error {

	if err := circuit.postInit(api); err != nil {
		return err
	}
	// hash function for the merkle proof and the eddsa signature
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verifications of:
	// - Merkle proofs of the accounts
	// - the signatures
	// - accounts' balance consistency
	for i := 0; i < BatchSizeCircuit; i++ {

		// the root hashes of the Merkle path must match the public ones given in the circuit
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofReceiverBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofSenderBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofReceiverAfter[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofSenderAfter[i].RootHash)

		// the leafs of the Merkle proofs must match the index of the accounts
		api.AssertIsEqual(circuit.ReceiverAccountsBefore[i].Index, circuit.LeafReceiver[i])
		api.AssertIsEqual(circuit.ReceiverAccountsAfter[i].Index, circuit.LeafReceiver[i])
		api.AssertIsEqual(circuit.SenderAccountsBefore[i].Index, circuit.LeafSender[i])
		api.AssertIsEqual(circuit.SenderAccountsAfter[i].Index, circuit.LeafSender[i])

		// verify the inclusion proofs
		circuit.MerkleProofReceiverBefore[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		circuit.MerkleProofSenderBefore[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])
		circuit.MerkleProofReceiverAfter[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		circuit.MerkleProofSenderAfter[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])

		// verify the transaction transfer
		err := verifyTransferSignature(api, circuit.Transfers[i], hFunc)
		if err != nil {
			return err
		}

		// update the accounts
		verifyAccountUpdated(api, circuit.SenderAccountsBefore[i], circuit.ReceiverAccountsBefore[i], circuit.SenderAccountsAfter[i], circuit.ReceiverAccountsAfter[i], circuit.Transfers[i].Amount)
	}

	return nil
}

// verifyTransferSignature ensures that the signature of the transfer is valid
func verifyTransferSignature(api frontend.API, t TransferConstraints, hFunc mimc.MiMC) error {

	// Reset the hash state!
	hFunc.Reset()

	// the signature is on h(nonce ∥ amount ∥ senderpubKey (x&y) ∥ receiverPubkey(x&y))
	hFunc.Write(t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)
	htransfer := hFunc.Sum()

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	hFunc.Reset()
	err = eddsa.Verify(curve, t.Signature, htransfer, t.SenderPubKey, &hFunc)
	if err != nil {
		return err
	}
	return nil
}

func verifyAccountUpdated(api frontend.API, from, to, fromUpdated, toUpdated AccountConstraints, amount frontend.Variable) {

	// ensure that nonce is correctly updated
	nonceUpdated := api.Add(from.Nonce, 1)
	api.AssertIsEqual(nonceUpdated, fromUpdated.Nonce)
	api.AssertIsEqual(to.Nonce, toUpdated.Nonce)

	// ensures that the amount is less than the balance
	api.AssertIsLessOrEqual(amount, from.Balance)

	// ensure that balance is correctly updated
	fromBalanceUpdated := api.Sub(from.Balance, amount)
	api.AssertIsEqual(fromBalanceUpdated, fromUpdated.Balance)

	toBalanceUpdated := api.Add(to.Balance, amount)
	api.AssertIsEqual(toBalanceUpdated, toUpdated.Balance)

}
