// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package rollup

import (
	"bytes"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

var hFunc = mimc.NewMiMC()

// BatchSize size of a batch of transactions to put in a snark
var BatchSize = 10

// Queue queue for storing the transfers (fixed size queue)
type Queue struct {
	listTransfers chan Transfer
}

// NewQueue creates a new queue, BatchSizeCircuit is the capacity
func NewQueue(BatchSizeCircuit int) Queue {
	resChan := make(chan Transfer, BatchSizeCircuit)
	var res Queue
	res.listTransfers = resChan
	return res
}

// Operator represents a rollup operator
type Operator struct {
	State      []byte            // list of accounts: index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY, each chunk is 256 bits
	HashState  []byte            // Hashed version of the state, each chunk is 256bits: ... ∥ H(index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY)) ∥ ...
	AccountMap map[string]uint64 // hashmap of all available accounts (the key is the account.pubkey.X), the value is the index of the account in the state
	nbAccounts int               // number of accounts managed by this operator
	h          hash.Hash         // hash function used to build the Merkle Tree
	q          Queue             // queue of transfers
	batch      int               // current number of transactions in a batch
	witnesses  Circuit           // witnesses for the snark circuit
}

// NewOperator creates a new operator.
// nbAccounts is the number of accounts managed by this operator, h is the hash function for the merkle proofs
func NewOperator(nbAccounts int) Operator {

	res := Operator{}

	// create a list of empty accounts
	res.State = make([]byte, SizeAccount*nbAccounts)

	// initialize hash of the state
	res.HashState = make([]byte, hFunc.Size()*nbAccounts)
	for i := 0; i < nbAccounts; i++ {
		hFunc.Reset()
		_, _ = hFunc.Write(res.State[i*SizeAccount : i*SizeAccount+SizeAccount])
		s := hFunc.Sum([]byte{})
		copy(res.HashState[i*hFunc.Size():(i+1)*hFunc.Size()], s)
	}

	res.AccountMap = make(map[string]uint64)
	res.nbAccounts = nbAccounts
	res.h = hFunc
	res.q = NewQueue(BatchSize)
	res.batch = 0
	return res
}

// readAccount reads the account located at index i
func (o *Operator) readAccount(i uint64) (Account, error) {

	var res Account
	err := Deserialize(&res, o.State[int(i)*SizeAccount:int(i)*SizeAccount+SizeAccount])
	if err != nil {
		return res, err
	}
	return res, nil
}

// updateState updates the state according to transfer
// numTransfer is the number of the transfer currently handled (between 0 and BatchSizeCircuit)
func (o *Operator) updateState(t Transfer, numTransfer int) error {

	var posSender, posReceiver uint64
	var ok bool

	// ext := strconv.Itoa(numTransfer)
	segmentSize := o.h.Size()

	// read sender's account
	b := t.senderPubKey.A.X.Bytes()
	if posSender, ok = o.AccountMap[string(b[:])]; !ok {
		return ErrNonExistingAccount
	}
	senderAccount, err := o.readAccount(posSender)
	if err != nil {
		return err
	}
	if senderAccount.index != posSender {
		return ErrIndexConsistency
	}

	// read receiver's account
	b = t.receiverPubKey.A.X.Bytes()
	if posReceiver, ok = o.AccountMap[string(b[:])]; !ok {
		return ErrNonExistingAccount
	}
	receiverAccount, err := o.readAccount(posReceiver)
	if err != nil {
		return err
	}
	if receiverAccount.index != posReceiver {
		return ErrIndexConsistency
	}

	// set witnesses for the leaves
	o.witnesses.LeafReceiver[numTransfer] = posReceiver
	o.witnesses.LeafSender[numTransfer] = posSender

	// set witnesses for the public keys
	o.witnesses.PublicKeysSender[numTransfer].A.X = senderAccount.pubKey.A.X
	o.witnesses.PublicKeysSender[numTransfer].A.Y = senderAccount.pubKey.A.Y
	o.witnesses.PublicKeysReceiver[numTransfer].A.X = receiverAccount.pubKey.A.X
	o.witnesses.PublicKeysReceiver[numTransfer].A.Y = receiverAccount.pubKey.A.Y

	// set witnesses for the accounts before update
	o.witnesses.SenderAccountsBefore[numTransfer].Index = senderAccount.index
	o.witnesses.SenderAccountsBefore[numTransfer].Nonce = senderAccount.nonce
	o.witnesses.SenderAccountsBefore[numTransfer].Balance = senderAccount.balance

	o.witnesses.ReceiverAccountsBefore[numTransfer].Index = receiverAccount.index
	o.witnesses.ReceiverAccountsBefore[numTransfer].Nonce = receiverAccount.nonce
	o.witnesses.ReceiverAccountsBefore[numTransfer].Balance = receiverAccount.balance

	//  Set witnesses for the proof of inclusion of sender and receivers account before update
	var buf bytes.Buffer
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	merkleRootBefore, proofInclusionSenderBefore, numLeaves, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posSender)
	if err != nil {
		return err
	}

	// verify the proof in plain go...
	merkletree.VerifyProof(o.h, merkleRootBefore, proofInclusionSenderBefore, posSender, numLeaves)

	buf.Reset() // the buffer needs to be reset
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	_, proofInclusionReceiverBefore, _, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posReceiver)
	if err != nil {
		return err
	}
	o.witnesses.RootHashesBefore[numTransfer] = merkleRootBefore
	o.witnesses.MerkleProofReceiverBefore[numTransfer].RootHash = merkleRootBefore
	o.witnesses.MerkleProofSenderBefore[numTransfer].RootHash = merkleRootBefore

	for i := 0; i < len(proofInclusionSenderBefore); i++ {
		o.witnesses.MerkleProofReceiverBefore[numTransfer].Path[i] = proofInclusionReceiverBefore[i]
		o.witnesses.MerkleProofSenderBefore[numTransfer].Path[i] = proofInclusionSenderBefore[i]
	}

	// set witnesses for the transfer
	o.witnesses.Transfers[numTransfer].Amount = t.amount
	o.witnesses.Transfers[numTransfer].Signature.R.X = t.signature.R.X
	o.witnesses.Transfers[numTransfer].Signature.R.Y = t.signature.R.Y
	o.witnesses.Transfers[numTransfer].Signature.S = t.signature.S[:]

	// verifying the signature. The msg is the hash (o.h) of the transfer
	// nonce ∥ amount ∥ senderpubKey(x&y) ∥ receiverPubkey(x&y)
	resSig, err := t.Verify(o.h)
	if err != nil {
		return err
	}
	if !resSig {
		return ErrWrongSignature
	}

	// checks if the amount is correct
	var bAmount, bBalance big.Int
	receiverAccount.balance.BigInt(&bBalance)
	t.amount.BigInt(&bAmount)
	if bAmount.Cmp(&bBalance) == 1 {
		return ErrAmountTooHigh
	}

	// check if the nonce is correct
	if t.nonce != senderAccount.nonce {
		return ErrNonce
	}

	// update balances
	senderAccount.balance.Sub(&senderAccount.balance, &t.amount)
	receiverAccount.balance.Add(&receiverAccount.balance, &t.amount)

	// update the nonce of the sender
	senderAccount.nonce++

	// set the witnesses for the account after update
	o.witnesses.ReceiverAccountsAfter[numTransfer].Index = receiverAccount.index
	o.witnesses.ReceiverAccountsAfter[numTransfer].Nonce = receiverAccount.nonce
	o.witnesses.ReceiverAccountsAfter[numTransfer].Balance = receiverAccount.balance

	o.witnesses.SenderAccountsAfter[numTransfer].Index = senderAccount.index
	o.witnesses.SenderAccountsAfter[numTransfer].Nonce = senderAccount.nonce
	o.witnesses.SenderAccountsAfter[numTransfer].Balance = senderAccount.balance

	// update the state of the operator
	copy(o.State[int(posSender)*SizeAccount:], senderAccount.Serialize())
	o.h.Reset()
	_, _ = o.h.Write(senderAccount.Serialize())
	bufSender := o.h.Sum([]byte{})
	copy(o.HashState[int(posSender)*o.h.Size():(int(posSender)+1)*o.h.Size()], bufSender)

	copy(o.State[int(posReceiver)*SizeAccount:], receiverAccount.Serialize())
	o.h.Reset()
	_, _ = o.h.Write(receiverAccount.Serialize())
	bufReceiver := o.h.Sum([]byte{})
	copy(o.HashState[int(posReceiver)*o.h.Size():(int(posReceiver)+1)*o.h.Size()], bufReceiver)

	//  Set witnesses for the proof of inclusion of sender and receivers account after update
	buf.Reset()
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	merkleRootAfter, proofInclusionSenderAfter, _, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posSender)
	if err != nil {
		return err
	}
	// merkleProofHelperSenderAfter := merkle.GenerateProofHelper(proofInclusionSenderAfter, posSender, numLeaves)

	buf.Reset() // the buffer needs to be reset
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	_, proofInclusionReceiverAfter, _, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posReceiver)
	if err != nil {
		return err
	}
	// merkleProofHelperReceiverAfter := merkle.GenerateProofHelper(proofInclusionReceiverAfter, posReceiver, numLeaves)

	o.witnesses.RootHashesAfter[numTransfer] = merkleRootAfter
	o.witnesses.MerkleProofReceiverAfter[numTransfer].RootHash = merkleRootAfter
	o.witnesses.MerkleProofSenderAfter[numTransfer].RootHash = merkleRootAfter

	for i := 0; i < len(proofInclusionSenderAfter); i++ {
		o.witnesses.MerkleProofReceiverAfter[numTransfer].Path[i] = proofInclusionReceiverAfter[i]
		o.witnesses.MerkleProofSenderAfter[numTransfer].Path[i] = proofInclusionSenderAfter[i]
	}

	return nil
}
