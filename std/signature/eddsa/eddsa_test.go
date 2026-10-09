// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package eddsa

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

// Forge signature: S → S + order
func forge(id tedwards.ID, sig []byte) ([]byte, error) {

	forged := make([]byte, len(sig))
	copy(forged, sig)

	var offset int
	switch id {
	case tedwards.BN254:
		offset = 32
	case tedwards.BLS12_381:
		offset = 32
	case tedwards.BLS12_381_BANDERSNATCH:
		offset = 32
	case tedwards.BLS12_377:
		offset = 32
	case tedwards.BW6_761:
		offset = 48
	default:
		panic("not implemented")
	}

	s := new(big.Int).SetBytes(sig[offset:])
	params, err := twistededwards.GetCurveParams(id)
	if err != nil {
		return nil, err
	}
	s.Add(s, params.Order)

	sizeS := len(sig) - offset
	buf := make([]byte, sizeS)
	copy(buf[sizeS-len(s.Bytes()):], s.Bytes())

	copy(forged[offset:], buf)
	return forged, nil
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, tedwards.BN254},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{hash.MIMC_BLS12_377, tedwards.BLS12_377},
		{hash.MIMC_BW6_761, tedwards.BW6_761},
	}

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed)) //#nosec G404 -- This is a false positive

	for _, conf := range confs {

		snarkField, err := twistededwards.GetSnarkField(conf.curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)

		// generate parameters for the signatures
		privKey, err := eddsa.New(conf.curve, randomness)
		assert.NoError(err, "generating eddsa key pair")

		// pick a message to sign
		var msg big.Int
		msg.Rand(randomness, snarkField)
		t.Log("msg to sign", msg.String())
		msgDataUnpadded := msg.Bytes()
		msgData := make([]byte, len(snarkField.Bytes()))
		copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)

		// generate signature
		signature, err := privKey.Sign(msgData, conf.hash.New())
		assert.NoError(err, "signing message")

		// check if there is no problem in the signature
		pubKey := privKey.Public()
		checkSig, err := pubKey.Verify(signature, msgData, conf.hash.New())
		assert.NoError(err, "verifying signature")
		assert.True(checkSig, "signature verification failed")

		// create and compile the circuit for signature verification
		var circuit eddsaCircuit
		circuit.curveID = conf.curve

		var validWitness eddsaCircuit
		validWitness.Message = msg
		validWitness.PublicKey.Assign(conf.curve, pubKey.Bytes())
		validWitness.Signature.Assign(conf.curve, signature)

		var invalidWitness eddsaCircuit
		invalidMsg := new(big.Int)
		invalidMsg.Rand(randomness, snarkField)
		invalidWitness.Message = invalidMsg
		invalidWitness.PublicKey.Assign(conf.curve, pubKey.Bytes())
		invalidWitness.Signature.Assign(conf.curve, signature)

		var invalidWitnessOverflow eddsaCircuit
		invalidWitnessOverflow.Message = msg
		invalidWitnessOverflow.PublicKey.Assign(conf.curve, pubKey.Bytes())
		forgedSig, err := forge(conf.curve, signature)
		assert.NoError(err, "forging signature")
		invalidWitnessOverflow.Signature.Assign(conf.curve, forgedSig)

		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithInvalidAssignment(&invalidWitnessOverflow),
			test.WithCurves(snarkCurve))

	}

}

func TestEddsaSmallOrderPublicKey(t *testing.T) {
	// For a small-order public key A, the term [H(R,A,M)]A vanishes after
	// cofactor clearing, so S=1, R=G satisfies the verification equation for
	// any message. Such keys must be rejected.
	assert := test.NewAssert(t)

	confs := []struct {
		hash  hash.Hash
		curve tedwards.ID
	}{
		{hash.MIMC_BN254, tedwards.BN254},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{hash.MIMC_BLS12_377, tedwards.BLS12_377},
		{hash.MIMC_BW6_761, tedwards.BW6_761},
	}

	randomness := rand.New(rand.NewSource(time.Now().Unix())) //#nosec G404 -- This is a false positive

	for _, conf := range confs {
		snarkField, err := twistededwards.GetSnarkField(conf.curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)
		params, err := twistededwards.GetCurveParams(conf.curve)
		assert.NoError(err)

		// honest signature, so that the circuit has a valid assignment
		privKey, err := eddsa.New(conf.curve, randomness)
		assert.NoError(err)
		msgData := make([]byte, len(snarkField.Bytes()))
		signature, err := privKey.Sign(msgData, conf.hash.New())
		assert.NoError(err)
		var validWitness eddsaCircuit
		validWitness.Message = 0
		validWitness.PublicKey.Assign(conf.curve, privKey.Public().Bytes())
		validWitness.Signature.Assign(conf.curve, signature)

		minusOne := new(big.Int).Sub(snarkField, big.NewInt(1))
		smallOrderKeys := []twistededwards.Point{
			{X: 0, Y: 1},        // identity
			{X: 0, Y: minusOne}, // order 2
		}

		opts := []test.TestingOption{
			test.WithValidAssignment(&validWitness),
			test.WithCurves(snarkCurve),
		}
		for _, A := range smallOrderKeys {
			opts = append(opts, test.WithInvalidAssignment(&eddsaCircuit{
				PublicKey: PublicKey{A: A},
				Signature: Signature{
					R: twistededwards.Point{X: params.Base[0], Y: params.Base[1]},
					S: 1,
				},
				Message: 42,
			}))
		}

		// off-curve points must be rejected: the in-circuit group formulas use
		// unchecked divisions which are undefined for off-curve inputs. (1,1)
		// satisfies a*x²+y² = 1+d*x²y² only if a == d, which holds for no
		// twisted Edwards curve.
		offCurve := twistededwards.Point{X: 1, Y: 1}
		opts = append(opts,
			test.WithInvalidAssignment(&eddsaCircuit{ // off-curve A
				PublicKey: PublicKey{A: offCurve},
				Signature: validWitness.Signature,
				Message:   42,
			}),
			test.WithInvalidAssignment(&eddsaCircuit{ // off-curve R
				PublicKey: validWitness.PublicKey,
				Signature: Signature{R: offCurve, S: 1},
				Message:   42,
			}),
		)

		var circuit eddsaCircuit
		circuit.curveID = conf.curve
		assert.CheckCircuit(&circuit, opts...)
	}
}

func TestEddsaMixedOrderPublicKey(t *testing.T) {
	// Mixed-order public keys A' = [sk]G + T (T a torsion point) are accepted
	// in-circuit: the small-order check only requires [cofactor]A' ≠ O, and
	// the torsion component of the verification equation vanishes after
	// cofactor clearing. This deliberate divergence from gnark-crypto's
	// native verification (which requires full subgroup membership) means one
	// secret key corresponds to up to cofactor distinct accepted public keys.
	// This test pins the behavior: signatures crafted with the same secret
	// key verify for both A and A'.
	assert := test.NewAssert(t)

	confs := []struct {
		hash  hash.Hash
		curve tedwards.ID
	}{
		{hash.MIMC_BN254, tedwards.BN254},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{hash.MIMC_BLS12_377, tedwards.BLS12_377},
		{hash.MIMC_BW6_761, tedwards.BW6_761},
	}

	randomness := rand.New(rand.NewSource(time.Now().Unix())) //#nosec G404 -- This is a false positive

	for _, conf := range confs {
		snarkField, err := twistededwards.GetSnarkField(conf.curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)
		params, err := twistededwards.GetCurveParams(conf.curve)
		assert.NoError(err)

		// secret key and its prime-order public key A = [sk]G
		sk := new(big.Int).Rand(randomness, params.Order)
		base := bigPoint{params.Base[0], params.Base[1]}
		A := base.scalarMul(sk, params, snarkField)

		// A' = A + T for the order-2 point T = (0, -1) is a mixed-order key:
		// [cofactor]A' = [cofactor]A ≠ O, so it passes the small-order check.
		minusOne := new(big.Int).Sub(snarkField, big.NewInt(1))
		mixedA := A.add(bigPoint{big.NewInt(0), minusOne}, params, snarkField)

		// craft a signature under sk for each key; both must verify
		r := new(big.Int).Rand(randomness, params.Order)
		R := base.scalarMul(r, params, snarkField)
		msg := big.NewInt(42)

		opts := []test.TestingOption{test.WithCurves(snarkCurve)}
		for _, key := range []bigPoint{A, mixedA} {
			// h = H(R, key, M), mirroring the in-circuit hash input order
			hFunc := conf.hash.New()
			for _, v := range []*big.Int{R.x, R.y, key.x, key.y, msg} {
				buf := make([]byte, len(snarkField.Bytes()))
				vb := v.Bytes()
				copy(buf[len(buf)-len(vb):], vb)
				_, err := hFunc.Write(buf)
				assert.NoError(err)
			}
			h := new(big.Int).SetBytes(hFunc.Sum(nil))
			S := new(big.Int).Mul(h, sk)
			S.Add(S, r).Mod(S, params.Order)

			opts = append(opts, test.WithValidAssignment(&eddsaCircuit{
				PublicKey: PublicKey{A: twistededwards.Point{X: key.x, Y: key.y}},
				Signature: Signature{
					R: twistededwards.Point{X: R.x, Y: R.y},
					S: S,
				},
				Message: msg,
			}))
		}

		var circuit eddsaCircuit
		circuit.curveID = conf.curve
		assert.CheckCircuit(&circuit, opts...)
	}
}

// bigPoint is an affine point on a twisted Edwards curve
// a·x² + y² = 1 + d·x²·y² over the snark scalar field, for native test
// arithmetic.
type bigPoint struct {
	x, y *big.Int
}

// add returns p + q using the twisted Edwards addition formulas.
func (p bigPoint) add(q bigPoint, params *twistededwards.CurveParams, field *big.Int) bigPoint {
	x1y2 := new(big.Int).Mul(p.x, q.y)
	y1x2 := new(big.Int).Mul(p.y, q.x)
	x1x2 := new(big.Int).Mul(p.x, q.x)
	y1y2 := new(big.Int).Mul(p.y, q.y)
	dxy := new(big.Int).Mul(params.D, x1x2)
	dxy.Mul(dxy, y1y2).Mod(dxy, field)

	// x = (x1y2 + y1x2) / (1 + d·x1x2y1y2)
	num := new(big.Int).Add(x1y2, y1x2)
	num.Mod(num, field)
	den := new(big.Int).Add(big.NewInt(1), dxy)
	den.Mod(den, field)
	x := new(big.Int).ModInverse(den, field)
	x.Mul(x, num).Mod(x, field)

	// y = (y1y2 - a·x1x2) / (1 - d·x1x2y1y2)
	num.Mul(params.A, x1x2)
	num.Sub(y1y2, num).Mod(num, field)
	den.Sub(big.NewInt(1), dxy).Mod(den, field)
	y := new(big.Int).ModInverse(den, field)
	y.Mul(y, num).Mod(y, field)

	return bigPoint{x, y}
}

// scalarMul returns [s]p via double-and-add.
func (p bigPoint) scalarMul(s *big.Int, params *twistededwards.CurveParams, field *big.Int) bigPoint {
	res := bigPoint{big.NewInt(0), big.NewInt(1)} // identity
	base := p
	for i := range s.BitLen() {
		if s.Bit(i) == 1 {
			res = res.add(base, params, field)
		}
		base = base.add(base, params, field)
	}
	return res
}
