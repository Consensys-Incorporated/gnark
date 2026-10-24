// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package rollup

import (
	"testing"
)

func TestAccount(t *testing.T) {

	var acc Account
	acc.Reset()
	acc.balance.SetString("1900")
	acc.nonce = 1
	acc.index = 2

	serializedAccount := acc.Serialize()
	var deserializedAccount Account
	err := Deserialize(&deserializedAccount, serializedAccount)
	if err != nil {
		t.Fatal(err)
	}

	// check each field
	if deserializedAccount.index != acc.index {
		t.Fatal("error deserializing index")
	}
	if deserializedAccount.nonce != acc.nonce {
		t.Fatal("error deserializing nonce")
	}
	if !deserializedAccount.balance.Equal(&acc.balance) {
		t.Fatal("error deserializing balance")
	}
	if !deserializedAccount.pubKey.A.X.Equal(&acc.pubKey.A.X) {
		t.Fatal("error deserializing pub key X")
	}
	if !deserializedAccount.pubKey.A.Y.Equal(&acc.pubKey.A.Y) {
		t.Fatal("error deserializing pub key Y")
	}

	// check invalid size
	serializedAccount = append(serializedAccount, 0x00)

	err = Deserialize(&deserializedAccount, serializedAccount)
	if err == nil {
		t.Fatal("Deserializing byte slice with wrong size should raise an error")
	}

}
