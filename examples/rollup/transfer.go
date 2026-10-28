// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package rollup

import (
	"hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

// Transfer describe a rollup transfer
type Transfer struct {
	nonce          uint64
	amount         fr.Element
	senderPubKey   eddsa.PublicKey
	receiverPubKey eddsa.PublicKey
	signature      eddsa.Signature // signature of the sender's account
}

// NewTransfer creates a new transfer (to be signed)
func NewTransfer(amount uint64, from, to eddsa.PublicKey, nonce uint64) Transfer {

	var res Transfer

	res.nonce = nonce
	res.amount.SetUint64(amount)
	res.senderPubKey = from
	res.receiverPubKey = to

	return res
}

// Sign signs a transaction
func (t *Transfer) Sign(priv eddsa.PrivateKey, h hash.Hash) (eddsa.Signature, error) {

	h.Reset()
	//var frNonce, msg fr.Element
	var frNonce fr.Element

	// serializing transfer. The signature is on h(nonce ∥ amount ∥ senderpubKey (x&y) ∥ receiverPubkey(x&y))
	// (each pubkey consist of 2 chunks of 256bits)
	frNonce.SetUint64(t.nonce)
	b := frNonce.Bytes()
	_, _ = h.Write(b[:])
	b = t.amount.Bytes()
	_, _ = h.Write(b[:])
	b = t.senderPubKey.A.X.Bytes()
	_, _ = h.Write(b[:])
	b = t.senderPubKey.A.Y.Bytes()
	_, _ = h.Write(b[:])
	b = t.receiverPubKey.A.X.Bytes()
	_, _ = h.Write(b[:])
	b = t.receiverPubKey.A.Y.Bytes()
	_, _ = h.Write(b[:])
	msg := h.Sum([]byte{})
	//msg.SetBytes(bmsg)

	sigBin, err := priv.Sign(msg, hFunc)
	if err != nil {
		return eddsa.Signature{}, err
	}
	var sig eddsa.Signature
	if _, err := sig.SetBytes(sigBin); err != nil {
		return eddsa.Signature{}, err
	}
	t.signature = sig
	return sig, nil
}

// Verify verifies the signature of the transfer.
// The message to sign is the hash (o.h) of the account.
func (t *Transfer) Verify(h hash.Hash) (bool, error) {

	h.Reset()
	//var frNonce, msg fr.Element
	var frNonce fr.Element

	// serializing transfer. The msg to sign is
	// nonce ∥ amount ∥ senderpubKey(x&y) ∥ receiverPubkey(x&y)
	// (each pubkey consist of 2 chunks of 256bits)
	frNonce.SetUint64(t.nonce)
	b := frNonce.Bytes()
	_, _ = h.Write(b[:])
	b = t.amount.Bytes()
	_, _ = h.Write(b[:])
	b = t.senderPubKey.A.X.Bytes()
	_, _ = h.Write(b[:])
	b = t.senderPubKey.A.Y.Bytes()
	_, _ = h.Write(b[:])
	b = t.receiverPubKey.A.X.Bytes()
	_, _ = h.Write(b[:])
	b = t.receiverPubKey.A.Y.Bytes()
	_, _ = h.Write(b[:])
	msg := h.Sum([]byte{})
	//msg.SetBytes(bmsg)

	// verification of the signature
	resSig, err := t.senderPubKey.Verify(t.signature.Bytes(), msg, hFunc)
	if err != nil {
		return false, err
	}
	if !resSig {
		return false, ErrWrongSignature
	}
	return true, nil
}
