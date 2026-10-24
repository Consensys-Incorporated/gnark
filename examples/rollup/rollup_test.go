// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package rollup

import (
	"hash"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

// The tests in the package are for the rollup in plain go only, there is no snark circuits
// involved here.

func TestOperatorReadAccount(t *testing.T) {

	// create operator with 10 accounts
	operator, _ := createOperator(10)

	// check if the account read from the operator is correct
	for i := 0; i < 10; i++ {
		opAccount, err := operator.readAccount(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		acc, _ := createAccount(i)

		compareAccount(t, acc, opAccount)

	}

}

func TestSignTransfer(t *testing.T) {

	var amount uint64

	// create operator with 10 accounts
	operator, userKeys := createOperator(10)

	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it (the hash used for signing is the hash function of the operator)
	amount = 10
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// verify correct signature
	_, err = transfer.Sign(userKeys[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}
	res, err := transfer.Verify(operator.h)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifying transaction with the correct key should work")
	}

	// verify wrong signature
	_, err = transfer.Sign(userKeys[1], operator.h)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transfer.Verify(operator.h)
	if err == nil {
		t.Fatal("Verifying transaction signed with the wrong key should output an error")
	}
}

func TestOperatorUpdateAccount(t *testing.T) {

	var amount uint64

	// create operator with 10 accounts
	operator, userKeys := createOperator(10)

	// get info on the parties
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount = 10
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)
	transfer.Sign(userKeys[0], operator.h)

	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// read the updated accounts of the sender and receiver and check if they are updated correctly
	newSender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	newReceiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}
	var frAmount fr.Element
	frAmount.SetUint64(amount)

	sender.nonce++
	sender.balance.Sub(&sender.balance, &frAmount)
	receiver.balance.Add(&receiver.balance, &frAmount)

	compareAccount(t, newSender, sender)
	compareHashAccount(t, operator.HashState[0:operator.h.Size()], newSender, operator.h)

	compareAccount(t, newReceiver, receiver)
	compareHashAccount(t, operator.HashState[operator.h.Size():2*operator.h.Size()], newReceiver, operator.h)
}

func createAccount(i int) (Account, eddsa.PrivateKey) {

	var acc Account
	var rnd fr.Element
	var privkey eddsa.PrivateKey

	// create account, the i-th account has a balance of 20+i
	acc.index = uint64(i)
	acc.nonce = uint64(i)
	acc.balance.SetUint64(uint64(i) + 20)
	rnd.SetUint64(uint64(i))
	src := rand.NewSource(int64(i))
	r := rand.New(src) //#nosec G404

	pkey, err := eddsa.GenerateKey(r)
	if err != nil {
		panic(err)
	}
	privkey = *pkey

	acc.pubKey = privkey.PublicKey

	return acc, privkey
}

// Returns a newly created operator and the private keys of the associated accounts
func createOperator(nbAccounts int) (Operator, []eddsa.PrivateKey) {

	operator := NewOperator(nbAccounts)

	operator.witnesses.allocateSlicesMerkleProofs()

	userAccounts := make([]eddsa.PrivateKey, nbAccounts)

	// randomly fill the accounts
	for i := 0; i < nbAccounts; i++ {

		acc, privkey := createAccount(i)

		// fill the index map of the operator
		b := acc.pubKey.A.X.Bytes()
		operator.AccountMap[string(b[:])] = acc.index

		// fill user accounts list
		userAccounts[i] = privkey
		baccount := acc.Serialize()

		copy(operator.State[SizeAccount*i:], baccount)

		// create the list of hashes of account
		operator.h.Reset()
		operator.h.Write(acc.Serialize())
		buf := operator.h.Sum([]byte{})
		copy(operator.HashState[operator.h.Size()*i:], buf)
	}

	return operator, userAccounts

}

func compareAccount(t *testing.T, acc1, acc2 Account) {

	if acc1.index != acc2.index {
		t.Fatal("Incorrect index")
	}
	if acc1.nonce != acc2.nonce {
		t.Fatal("Incorrect nonce")
	}
	if !acc1.balance.Equal(&acc2.balance) {
		t.Fatal("Incorrect balance")
	}
	if !acc1.pubKey.A.X.Equal(&acc2.pubKey.A.X) {
		t.Fatal("Incorrect public key (X)")
	}
	if !acc1.pubKey.A.Y.Equal(&acc2.pubKey.A.Y) {
		t.Fatal("Incorrect public key (Y)")
	}

}

func compareHashAccount(t *testing.T, h []byte, acc Account, hFunc hash.Hash) {

	hFunc.Reset()
	_, err := hFunc.Write(acc.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	res := hFunc.Sum([]byte{})
	if len(res) != len(h) {
		t.Fatal("Error comparing hashes (different lengths)")
	}
	for i := 0; i < len(res); i++ {
		if res[i] != h[i] {
			t.Fatal("Error comparing hashes (different content)")
		}
	}
}
