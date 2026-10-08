package evmprecompiles

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestSignForRecoverCorrectness(t *testing.T) {
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	_, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	var sig ecdsa.Signature
	r.FillBytes(sig.R[:fr.Bytes])
	s.FillBytes(sig.S[:fr.Bytes])
	sigM := sig.Bytes()
	ok, err := pk.Verify(sigM, msg, nil)
	if err != nil {
		t.Fatal("verify", err)
	}
	if !ok {
		t.Fatal("not verified")
	}
}

func TestECRecoverGeneratorCommitment(t *testing.T) {
	assert := test.NewAssert(t)

	// Use k=1 and d=1, so the ECDSA commitment is R=G. This forces r=G.x,
	// which is a degenerate input for incomplete JointScalarMulBase.
	_, generator := secp256k1.Generators()
	msgDigest := sha256.Sum256([]byte("ecrecover regression: r = G.x"))
	msgHash := ecdsa.HashToInt(msgDigest[:])
	r := generator.X.BigInt(new(big.Int))
	s := new(big.Int).Add(msgHash, r)
	s.Mod(s, fr.Modulus())
	if s.Sign() == 0 {
		t.Fatal("constructed zero s")
	}
	v := uint(generator.Y.BigInt(new(big.Int)).Bit(0))

	var pk ecdsa.PublicKey
	err := pk.RecoverFrom(msgDigest[:], v, r, s)
	assert.NoError(err)

	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](msgHash),
		V:         v + 27,
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ecrecoverCircuit struct {
	Message   emulated.Element[emulated.Secp256k1Fr]
	V         frontend.Variable
	R         emulated.Element[emulated.Secp256k1Fr]
	S         emulated.Element[emulated.Secp256k1Fr]
	Strict    frontend.Variable
	IsFailure frontend.Variable
	Expected  sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

func (c *ecrecoverCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	res := ECRecover(api, c.Message, c.V, c.R, c.S, c.Strict, c.IsFailure)
	curve.AssertIsEqual(&c.Expected, res)
	return nil
}

func testRoutineECRecover(t *testing.T, forceLargeS bool) (circ, wit *ecrecoverCircuit) {
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))

	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	// SignForRecover always returns s < r_mod/2. But in the tests we want
	// to check that the circuit fails when s > r_mod/2 in strict mode.
	if forceLargeS {
		// first we make s large
		s.Sub(fr.Modulus(), s)
		// but we also have to swap the sign of the recovered public key
		v ^= 1
	}

	strict := 1
	if forceLargeS {
		strict = 0
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    strict,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	return &circuit, &witness
}

func TestECRecoverCircuitShortStrict(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortLax(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, true)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))
	var circuit, witness *ecrecoverCircuit
	circuit, witness = testRoutineECRecover(t, true)
	witness.Strict = 1
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
}

func TestECRecoverCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	_, witness2 := testRoutineECRecover(t, true)

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(witness),
		test.WithValidAssignment(witness2),
		test.WithCurves(ecc.BN254, ecc.BLS12_377),
		test.NoProverChecks(),
	)
}

func TestECRecoverQNR(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	_, err := sk.SetBytes([]byte{0x80, 0x95, 0xb4, 0x19, 0x78, 0xe3, 0x7c, 0xb2, 0x44, 0x76, 0xd3, 0x76, 0x90, 0x87, 0x33, 0x61, 0x89, 0xcf, 0xac, 0xc2, 0x60, 0x2d, 0xf9, 0x83, 0xcc, 0xb5, 0xb2, 0x5c, 0x84, 0xe9, 0x41, 0x76, 0x7e, 0xe7, 0x47, 0x4b, 0x89, 0xbb, 0x50, 0xe0, 0x6, 0xf6, 0x11, 0x25, 0xf2, 0xe8, 0xf7, 0xb2, 0x59, 0x9d, 0xa8, 0x7, 0x48, 0x2b, 0x6d, 0x8c, 0x3e, 0x28, 0x5, 0x93, 0xf8, 0x5c, 0xcc, 0xc9, 0xe, 0x40, 0x3d, 0x19, 0x13, 0xad, 0x7f, 0xc1, 0x63, 0x93, 0x71, 0xb6, 0x8d, 0x3d, 0x43, 0x7a, 0x7f, 0x8, 0x9f, 0xaa, 0x8f, 0xc, 0xf6, 0xf8, 0x5, 0xad, 0xaf, 0x23, 0x93, 0x34, 0x97, 0xba})
	assert.NoError(err)
	msg := []byte("test")
	v := 1
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 1,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](0),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECRecoverQNRWoFailure(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	_, err := sk.SetBytes([]byte{0x80, 0x95, 0xb4, 0x19, 0x78, 0xe3, 0x7c, 0xb2, 0x44, 0x76, 0xd3, 0x76, 0x90, 0x87, 0x33, 0x61, 0x89, 0xcf, 0xac, 0xc2, 0x60, 0x2d, 0xf9, 0x83, 0xcc, 0xb5, 0xb2, 0x5c, 0x84, 0xe9, 0x41, 0x76, 0x7e, 0xe7, 0x47, 0x4b, 0x89, 0xbb, 0x50, 0xe0, 0x6, 0xf6, 0x11, 0x25, 0xf2, 0xe8, 0xf7, 0xb2, 0x59, 0x9d, 0xa8, 0x7, 0x48, 0x2b, 0x6d, 0x8c, 0x3e, 0x28, 0x5, 0x93, 0xf8, 0x5c, 0xcc, 0xc9, 0xe, 0x40, 0x3d, 0x19, 0x13, 0xad, 0x7f, 0xc1, 0x63, 0x93, 0x71, 0xb6, 0x8d, 0x3d, 0x43, 0x7a, 0x7f, 0x8, 0x9f, 0xaa, 0x8f, 0xc, 0xf6, 0xf8, 0x5, 0xad, 0xaf, 0x23, 0x93, 0x34, 0x97, 0xba})
	assert.NoError(err)
	msg := []byte("test")
	v := 1
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](0),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

func TestECRecoverInfinity(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	var err error
	pk := sk.Public().(*ecdsa.PublicKey)
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 1,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECRecoverInfinityWoFailure(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	var err error
	pk := sk.Public().(*ecdsa.PublicKey)
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

func TestInvalidFailureTag(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	witness.IsFailure = 1
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
	_, witness2 := testRoutineECRecover(t, true)
	witness2.IsFailure = 1
	err = test.IsSolved(circuit, witness2, ecc.BN254.ScalarField())
	assert.Error(err)
}

func TestLargeV(t *testing.T) {
	assert := test.NewAssert(t)
	var pk ecdsa.PublicKey
	msg := []byte("test")
	var rE, sE fr.Element
	r, s := new(big.Int), new(big.Int)
	for _, v := range []uint{2, 3} {
		for {
			rE.SetRandom()
			sE.SetRandom()
			rE.BigInt(r)
			sE.BigInt(s)
			if err := pk.RecoverFrom(msg, v, r, s); errors.Is(err, ecdsa.ErrNoSqrtR) {
				continue
			} else {
				assert.NoError(err)
				break
			}
		}
		circuit := ecrecoverCircuit{}
		witness := ecrecoverCircuit{
			Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
			V:         v + 27, // EVM constant
			R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
			S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
			Strict:    0,
			IsFailure: 0,
			Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
			},
		}
		err := test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
		assert.Error(err)
	}
}

func TestOverKoalabear(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, koalabear.Modulus())
	assert.NoError(err)
}

// TestOverMamabear is the koalabear test over the other small native field.
// mamabear is 49 bits rather than 31, so the emulated arithmetic this circuit
// is built from packs its limbs differently.
func TestOverMamabear(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, mamabear.Modulus())
	assert.NoError(err)
}
