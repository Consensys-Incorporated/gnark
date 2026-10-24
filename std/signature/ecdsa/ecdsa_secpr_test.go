package ecdsa

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func TestEcdsaP256PreHashed(t *testing.T) {

	// generate parameters
	privKey, _ := cryptoecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	msgHash := sha256.Sum256(msg)
	sigBin, _ := privKey.Sign(rand.Reader, msgHash[:], nil)

	// check that the signature is correct
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sigBin)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		panic("invalid sig")
	}
	flag := cryptoecdsa.Verify(&publicKey, msgHash[:], r, s)
	if !flag {
		t.Errorf("can't verify signature")
	}

	circuit := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{}
	witness := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{
		Sig: Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		Msg: emulated.ValueOf[emulated.P256Fr](msgHash[:]),
		Pub: PublicKey[emulated.P256Fp, emulated.P256Fr]{
			// The deprecation of PublicKey.X/Y (Go 1.26) is about *modifying*
			// the raw coordinates, which can produce invalid keys. Here they are
			// only read, to build the circuit witness for a key that crypto/ecdsa
			// itself generated and verified above.
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X), //nolint:staticcheck // SA1019: read-only, see above
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y), //nolint:staticcheck // SA1019: read-only, see above
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

func TestEcdsaP384PreHashed(t *testing.T) {

	// generate parameters
	privKey, _ := cryptoecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	msgHash := sha512.Sum384(msg)
	sigBin, _ := privKey.Sign(rand.Reader, msgHash[:], nil)

	// check that the signature is correct
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sigBin)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		panic("invalid sig")
	}
	flag := cryptoecdsa.Verify(&publicKey, msgHash[:], r, s)
	if !flag {
		t.Errorf("can't verify signature")
	}

	circuit := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{}
	witness := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{
		Sig: Signature[emulated.P384Fr]{
			R: emulated.ValueOf[emulated.P384Fr](r),
			S: emulated.ValueOf[emulated.P384Fr](s),
		},
		Msg: emulated.ValueOf[emulated.P384Fr](msgHash[:]),
		Pub: PublicKey[emulated.P384Fp, emulated.P384Fr]{
			// The deprecation of PublicKey.X/Y (Go 1.26) is about *modifying*
			// the raw coordinates, which can produce invalid keys. Here they are
			// only read, to build the circuit witness for a key that crypto/ecdsa
			// itself generated and verified above.
			X: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.X), //nolint:staticcheck // SA1019: read-only, see above
			Y: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.Y), //nolint:staticcheck // SA1019: read-only, see above
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
