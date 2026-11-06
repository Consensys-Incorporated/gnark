package evmprecompiles

import (
	"bytes"
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256r1/ecdsa"
	fr_secp256r1 "github.com/consensys/gnark-crypto/ecc/secp256r1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type p256verifyCircuit struct {
	MsgHash  emulated.Element[emulated.P256Fr]
	R        emulated.Element[emulated.P256Fr]
	S        emulated.Element[emulated.P256Fr]
	Qx, Qy   emulated.Element[emulated.P256Fp]
	Expected frontend.Variable
}

func (c *p256verifyCircuit) Define(api frontend.API) error {
	res := P256Verify(api, &c.MsgHash, &c.R, &c.S, &c.Qx, &c.Qy)
	api.AssertIsEqual(c.Expected, res)
	return nil
}

func TestP256VerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	// key generation
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	// signing
	msg := []byte("test")
	sigBuf, err := sk.Sign(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	// verification
	verified, err := sk.PublicKey.Verify(sigBuf, msg, nil)
	if err != nil {
		t.Fatal("verify", err)
	}
	// marshalling
	var sig ecdsa.Signature
	sig.SetBytes(sigBuf[:])
	hash := ecdsa.HashToInt(msg)
	expected := 0
	if verified {
		expected = 1
	}

	circuit := p256verifyCircuit{}
	witness := p256verifyCircuit{
		MsgHash:  emulated.ValueOf[emulated.P256Fr](hash),
		R:        emulated.ValueOf[emulated.P256Fr](sig.R[:]),
		S:        emulated.ValueOf[emulated.P256Fr](sig.S[:]),
		Qx:       emulated.ValueOf[emulated.P256Fp](pk.A.X),
		Qy:       emulated.ValueOf[emulated.P256Fp](pk.A.Y),
		Expected: expected,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestP256VerifyMockedArithmetization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	assert := test.NewAssert(t)
	data, err := os.ReadFile("test_vectors/p256verify_vectors.json")
	assert.NoError(err, "read vectors.json")

	var vecs []vector
	err = json.Unmarshal(data, &vecs)
	assert.NoError(err, "unmarshal vectors")
	for _, v := range vecs {
		assert.Run(func(assert *test.Assert) {
			isValid, h, r, s, qx, qy, err := mockedArithmetization(&v)
			// this means that the arithmetization detected an error.
			// lets compare that the test case also assumed an error
			tcVerified := expectedBool(v.Expected)
			if err != nil && tcVerified {
				// arithmetization said test case failed, but test case indicates success
				assert.Fail("supposed successful verification but arithmetization failed: %v", err)
			}
			assert.Equal(isValid, tcVerified, "mismatch between arithmetization and test case")
			if err != nil {
				return
			}
			// this means that the arithmetization has filtered the input. We won't be calling the circuit
			// in this case.
			expectedRes := 0
			if isValid {
				expectedRes = 1
			}
			witness := p256verifyCircuit{
				MsgHash:  emulated.ValueOf[emulated.P256Fr](h),
				R:        emulated.ValueOf[emulated.P256Fr](*r),
				S:        emulated.ValueOf[emulated.P256Fr](*s),
				Qx:       emulated.ValueOf[emulated.P256Fp](qx),
				Qy:       emulated.ValueOf[emulated.P256Fp](qy),
				Expected: expectedRes,
			}
			err = test.IsSolved(&p256verifyCircuit{}, &witness, ecc.BN254.ScalarField())
			assert.NoError(err)

		}, v.Name)
	}
}

// --- utils
type vector struct {
	Name     string `json:"Name,omitempty"`
	Input    string `json:"Input"`
	Expected string `json:"Expected"`
}

// mockedArithmetization performs the checks what the arithmetization would
// perform. It returns a boolean indicating if the signature is valid or not and
// and an error if the test case would fail already at the arithmetization
// level.
func mockedArithmetization(testcase *vector) (isValid bool, h []byte, r, s *big.Int, qx, qy []byte, err error) {
	// arithmetization checks:
	// * Input length: Input MUST be exactly 160 bytes !!!!
	// * Signature component bounds: Both r and s MUST satisfy 0 < r < n and 0 < s < n !!!
	// * Public key bounds: Both qx and qy MUST satisfy 0 ≤ qx < p and 0 ≤ qy < p !!!
	// * Point validity: The point (qx, qy) MUST satisfy the curve equation qy^2 ≡ qx^3 + a*qx + b (mod p) !!!
	// * Point not at infinity: The point (qx, qy) MUST NOT be the point at infinity (represented as (0, 0)) !!!

	// 1. first check the input length:
	raw, err := hex.DecodeString(testcase.Input)
	if err != nil {
		return
	}
	if len(raw) != 160 {
		err = errors.New("input length check failed: invalid input length")
		return
	}
	h = raw[0:32]
	r = new(big.Int).SetBytes(raw[32:64])
	s = new(big.Int).SetBytes(raw[64:96])
	qx = raw[96:128]
	qy = raw[128:160]
	// 2. check signature component bounds
	modFr := fr_secp256r1.Modulus()
	if r.Sign() <= 0 || r.Cmp(modFr) >= 0 {
		err = errors.New("r out of bounds")
		return
	}
	if s.Sign() <= 0 || s.Cmp(modFr) >= 0 {
		err = errors.New("s out of bounds")
		return
	}
	// 3. the public key bounds, the point validity and the point-at-infinity checks are all
	// performed by the parser
	pk, err := cryptoecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, raw[96:160]...))
	if err != nil {
		err = fmt.Errorf("public key check failed: %w", err)
		return
	}
	// if we reached this point, all arithmetization checks passed. Now check
	// signature validity
	ok := cryptoecdsa.Verify(pk, h, r, s)
	if !ok {
		return
	}
	isValid = true
	return
}

func expectedBool(s string) bool {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	one := make([]byte, 32)
	one[31] = 1
	return bytes.Equal(raw, one)
}
