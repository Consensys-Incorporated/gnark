package ecdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	fp_secp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig Signature[S]
	Msg emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}

func TestEcdsaPreHashed(t *testing.T) {

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	sigBin, _ := privKey.Sign(msg, nil)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, nil)
	if !flag {
		t.Errorf("can't verify signature")
	}

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	hash := ecdsa.HashToInt(msg)

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestEcdsaSHA256(t *testing.T) {

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (sha256)")
	md := sha256.New()
	sigBin, _ := privKey.Sign(msg, md)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, md)
	if !flag {
		t.Errorf("can't verify signature")
	}

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	// compute the hash of the message as an integer
	dataToHash := make([]byte, len(msg))
	copy(dataToHash[:], msg[:])
	md.Reset()
	md.Write(dataToHash[:])
	hramBin := md.Sum(nil)
	hash := ecdsa.HashToInt(hramBin)

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestEcdsaPreHashedZeroHash(t *testing.T) {
	assert := test.NewAssert(t)

	privKey, err := ecdsa.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to generate ecdsa key")
	publicKey := privKey.PublicKey

	msg := []byte{}
	sigBin, err := privKey.Sign(msg, nil)
	assert.NoError(err, "failed to sign message")

	flag, err := publicKey.Verify(sigBin, msg, nil)
	assert.NoError(err, "failed to verify signature")
	assert.True(flag, "can't verify signature")

	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	hash := ecdsa.HashToInt(msg)
	assert.Zero(hash.Sign(), "expected zero pre-hash")

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// Example how to verify the signature inside the circuit.
func ExamplePublicKey_Verify() {
	api := frontend.API(nil) // provider by the builder
	r, s := 0x01, 0x02       // usually given in the witness
	pubx, puby := 0x03, 0x04 // usually given in the witness
	m := 0x1337              // usually given in the witness

	// can be done in or out-circuit.
	Sig := Signature[emulated.Secp256k1Fr]{
		R: emulated.ValueOf[emulated.Secp256k1Fr](r),
		S: emulated.ValueOf[emulated.Secp256k1Fr](s),
	}
	Msg := emulated.ValueOf[emulated.Secp256k1Fr](m)
	Pub := PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
	}
	// signature verification assertion is done in-circuit
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &Msg, &Sig)
}

// Example how to create a valid signature for secp256k1
func ExamplePublicKey_Verify_create() {

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)

	// sign
	msg := []byte("testing ECDSA")
	md := sha256.New()
	sigBin, _ := privKey.Sign(msg, md)

	pubx := privKey.PublicKey.A.X
	puby := privKey.PublicKey.A.Y

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)

	// can continue in the PublicKey Verify example
	_, _, _, _, _ = sig.R, sig.S, msg, pubx, puby
}

type EcdsaIsValidCircuit[T, S emulated.FieldParams] struct {
	Sig     Signature[S]
	Msg     emulated.Element[S]
	Pub     PublicKey[T, S]
	IsValid frontend.Variable `gnark:",public"`
}

func (c *EcdsaIsValidCircuit[T, S]) Define(api frontend.API) error {
	verified := c.Pub.IsValid(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	api.AssertIsEqual(verified, c.IsValid)
	return nil
}

func TestEcdsaPublicKeyIsValid(t *testing.T) {
	assert := test.NewAssert(t)
	// generate parameters
	privKey, err := ecdsa.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to generate ecdsa key")
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	sigBin, err := privKey.Sign(msg, nil)
	assert.NoError(err, "failed to sign message")

	// check that the signature is correct
	flag, err := publicKey.Verify(sigBin, msg, nil)
	assert.NoError(err, "failed to verify signature")
	assert.True(flag, "can't verify signature")

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	hash := ecdsa.HashToInt(msg)

	circuit := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}

	assert.Run(func(assert *test.Assert) {
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 1,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=valid")

	assert.Run(func(assert *test.Assert) {
		r, err := rand.Int(rand.Reader, fr_secp256k1.Modulus())
		assert.NoError(err, "failed to generate random r")
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-r")

	assert.Run(func(assert *test.Assert) {
		s, err := rand.Int(rand.Reader, fr_secp256k1.Modulus())
		assert.NoError(err, "failed to generate random r")
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-s")

	assert.Run(func(assert *test.Assert) {
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](0),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=zero-r")

	assert.Run(func(assert *test.Assert) {
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](0),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=zero-s")

	assert.Run(func(assert *test.Assert) {
		hash := ecdsa.HashToInt([]byte("invalid message"))
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-msg")

	assert.Run(func(assert *test.Assert) {
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](0),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=zero-pub")

	assert.Run(func(assert *test.Assert) {
		privKey, err := ecdsa.GenerateKey(rand.Reader)
		assert.NoError(err, "failed to generate ecdsa key")
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-pub")
}

// TestEcdsaNonceXAboveOrder checks the case where the x-coordinate of the nonce
// point R is in [n, p). ECDSA defines r = R.x mod n, so such a signature carries
// r = R.x - n and must be accepted.
func TestEcdsaNonceXAboveOrder(t *testing.T) {
	assert := test.NewAssert(t)
	n := fr_secp256k1.Modulus()
	_, g := secp256k1.Generators()

	// find a curve point R with x = n + k < p
	var R secp256k1.G1Affine
	for k := int64(1); ; k++ {
		var X, Y, rhs fp_secp256k1.Element
		X.SetBigInt(new(big.Int).Add(n, big.NewInt(k)))
		rhs.Square(&X).Mul(&rhs, &X).Add(&rhs, new(fp_secp256k1.Element).SetUint64(7))
		if Y.Sqrt(&rhs) == nil {
			continue
		}
		R.X, R.Y = X, Y
		break
	}
	var rx big.Int
	R.X.BigInt(&rx)
	assert.True(rx.Cmp(n) >= 0, "R.x must be larger than the group order")
	r := new(big.Int).Sub(&rx, n) // r = R.x mod n
	s := big.NewInt(12345)
	msg := []byte("testing ECDSA with R.x >= n")
	hash := ecdsa.HashToInt(msg)

	// public key Q = r^{-1} (s*R - m*G), so that s^{-1}(m*G + r*Q) = R
	var sR, mG, Q secp256k1.G1Affine
	sR.ScalarMultiplication(&R, s)
	mG.ScalarMultiplication(&g, hash)
	mG.Neg(&mG)
	Q.Add(&sR, &mG)
	Q.ScalarMultiplication(&Q, new(big.Int).ModInverse(r, n))

	// the native implementation accepts the signature
	var sig ecdsa.Signature
	r.FillBytes(sig.R[:])
	s.FillBytes(sig.S[:])
	flag, err := (&ecdsa.PublicKey{A: Q}).Verify(sig.Bytes(), msg, nil)
	assert.NoError(err, "failed to verify signature")
	assert.True(flag, "can't verify signature")

	pub := PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](Q.X),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](Q.Y),
	}
	witnessSig := func(r *big.Int) Signature[emulated.Secp256k1Fr] {
		return Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		}
	}

	assert.Run(func(assert *test.Assert) {
		circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
		witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: witnessSig(r),
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: pub,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "valid signature rejected by Verify")
	}, "verify")

	assert.Run(func(assert *test.Assert) {
		circuit := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig:     witnessSig(r),
			Msg:     emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub:     pub,
			IsValid: 1,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "valid signature rejected by IsValid")
	}, "isvalid")

	assert.Run(func(assert *test.Assert) {
		// a different r must still be rejected
		circuit := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig:     witnessSig(new(big.Int).Add(r, big.NewInt(1))),
			Msg:     emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub:     pub,
			IsValid: 0,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "wrong r must be reported as invalid")
	}, "wrong-r")
}
