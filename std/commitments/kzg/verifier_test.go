package kzg

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

const (
	kzgSize        = 128
	polynomialSize = 100
	nbPolynomials  = 5
)

type KZGVerificationCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GTEl algebra.GtElementT] struct {
	VerifyingKey[G1El, G2El]
	Commitment[G1El]
	OpeningProof[FR, G1El]
	Point emulated.Element[FR]
}

func (c *KZGVerificationCircuit[FR, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	if err := verifier.CheckOpeningProof(c.Commitment, c.OpeningProof, c.Point, c.VerifyingKey); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGVerificationEmulated(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bn254.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bn254.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bn254.Element
	point.SetRandom()
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bn254.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bn254.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bn254.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}, test.WithValidAssignment(&assignment))
}

func TestKZGVerificationEmulated2(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12381.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	check := func(assert *test.Assert, f fr_bls12381.Vector, point fr_bls12381.Element) {
		com, err := kzg_bls12381.Commit(f, srs.Pk)
		assert.NoError(err)
		proof, err := kzg_bls12381.Open(f, point, srs.Pk)
		assert.NoError(err)
		if err = kzg_bls12381.Verify(&com, &proof, point, srs.Vk); err != nil {
			t.Fatal("verify proof", err)
		}
		wCmt, err := ValueOfCommitment[sw_bls12381.G1Affine](com)
		assert.NoError(err)
		wVk, err := ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine](srs.Vk)
		assert.NoError(err)
		wProof, err := ValueOfOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine](proof)
		assert.NoError(err)
		wPt, err := ValueOfScalar[sw_bls12381.ScalarField](point)
		assert.NoError(err)

		assignment := KZGVerificationCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
			VerifyingKey: wVk,
			Commitment:   wCmt,
			OpeningProof: wProof,
			Point:        wPt,
		}
		assert.CheckCircuit(&KZGVerificationCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{}, test.WithValidAssignment(&assignment))
	}

	assert.Run(func(assert *test.Assert) {
		f := make(fr_bls12381.Vector, polynomialSize)
		f.MustSetRandom()
		var point fr_bls12381.Element
		point.MustSetRandom()
		check(assert, f, point)
	})
	assert.Run(func(assert *test.Assert) {
		f := make(fr_bls12381.Vector, polynomialSize)
		var point fr_bls12381.Element
		point.MustSetRandom()
		check(assert, f, point)
	}, "case=zero_polynomial")
	assert.Run(func(assert *test.Assert) {
		f := make(fr_bls12381.Vector, polynomialSize)
		f.MustSetRandom()
		var point fr_bls12381.Element
		point.SetZero()
		check(assert, f, point)
	}, "case=zero_point")
	assert.Run(func(assert *test.Assert) {
		f := make(fr_bls12381.Vector, polynomialSize)
		f.MustSetRandom()
		f[0].SetZero()
		var point fr_bls12381.Element
		point.SetZero()
		check(assert, f, point)
	}, "case=zero_first_coeff_zero_point")
}

func TestKZGVerificationEmulated3(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BW6_761.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bw6761.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bw6761.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bw6761.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bw6761.Element
	point.SetRandom()
	proof, err := kzg_bw6761.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bw6761.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bw6761.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bw6761.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestKZGVerificationTwoChain(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12377.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12377.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12377.Element
	point.SetRandom()
	proof, err := kzg_bls12377.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12377.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12377.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bls12377.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}

	assert.CheckCircuit(&KZGVerificationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_761))
}

type KZGBatcheVerificationMultiPointCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GTEl algebra.GtElementT] struct {
	Vk          VerifyingKey[G1El, G2El]
	Commitments []Commitment[G1El]
	Proofs      []OpeningProof[FR, G1El]
	Points      []emulated.Element[FR]
}

func (c *KZGBatcheVerificationMultiPointCircuit[FR, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	if err := verifier.BatchVerifyMultiPoints(c.Commitments, c.Proofs, c.Points, c.Vk); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGBatchVerificationMultiPointsTwoChain(t *testing.T) {

	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	// sample random polynomials, random points

	f := make([][]fr_bls12377.Element, nbPolynomials)
	points := make([]fr_bls12377.Element, nbPolynomials)
	proofs := make([]kzg_bls12377.OpeningProof, nbPolynomials)
	commitments := make([]kzg_bls12377.Digest, nbPolynomials)
	for i := 0; i < nbPolynomials; i++ {
		f[i] = make([]fr_bls12377.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			f[i][j].SetRandom()
		}

		commitments[i], err = kzg_bls12377.Commit(f[i], srs.Pk)
		assert.NoError(err)

		points[i].SetRandom()
		proofs[i], err = kzg_bls12377.Open(f[i], points[i], srs.Pk)
		assert.NoError(err)
	}

	if err = kzg_bls12377.BatchVerifyMultiPoints(commitments, proofs, points, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	var assignment KZGBatcheVerificationMultiPointCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	assignment.Commitments = make([]Commitment[sw_bls12377.G1Affine], nbPolynomials)
	assignment.Proofs = make([]OpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine], nbPolynomials)
	assignment.Points = make([]emulated.Element[sw_bls12377.ScalarField], nbPolynomials)
	for i := 0; i < nbPolynomials; i++ {
		wCmt, err := ValueOfCommitment[sw_bls12377.G1Affine](commitments[i])
		assert.NoError(err)
		wProof, err := ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](proofs[i])
		assert.NoError(err)
		wPt, err := ValueOfScalar[sw_bls12377.ScalarField](points[i])
		assert.NoError(err)
		assignment.Commitments[i] = wCmt
		assignment.Proofs[i] = wProof
		assignment.Points[i] = wPt
	}
	wVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine](srs.Vk)
	assert.NoError(err)
	assignment.Vk = wVk

	var circuit KZGBatcheVerificationMultiPointCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	circuit.Commitments = make([]Commitment[sw_bls12377.G1Affine], nbPolynomials)
	circuit.Proofs = make([]OpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine], nbPolynomials)
	circuit.Points = make([]emulated.Element[sw_bls12377.ScalarField], nbPolynomials)

	assert.CheckCircuit(
		&circuit,
		test.WithValidAssignment(&assignment),
		test.WithCurves(ecc.BW6_761),
	)
}

func TestValueOfCommitment(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bn254.Generators()
		assignment, err := ValueOfCommitment[sw_bn254.G1Affine](G1)
		assert.NoError(err)
		_ = assignment
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bls12377.Generators()
		assignment, err := ValueOfCommitment[sw_bls12377.G1Affine](G1)
		assert.NoError(err)
		_ = assignment
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bls12381.Generators()
		assignment, err := ValueOfCommitment[sw_bls12381.G1Affine](G1)
		assert.NoError(err)
		_ = assignment
	}, "bls12381")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bw6761.Generators()
		assignment, err := ValueOfCommitment[sw_bw6761.G1Affine](G1)
		assert.NoError(err)
		_ = assignment
	}, "bw6761")
}

func TestValueOfOpeningProof(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bn254.Generators()
		var value, point fr_bn254.Element
		value.SetRandom()
		point.SetRandom()
		proof := kzg_bn254.OpeningProof{
			H:            G1,
			ClaimedValue: value,
		}
		assignment, err := ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](proof)
		assert.NoError(err)
		_ = assignment
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bls12377.Generators()
		var value, point fr_bls12377.Element
		value.SetRandom()
		point.SetRandom()
		proof := kzg_bls12377.OpeningProof{
			H:            G1,
			ClaimedValue: value,
		}
		assignment, err := ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](proof)
		assert.NoError(err)
		_ = assignment
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bls12381.Generators()
		var value, point fr_bls12381.Element
		value.SetRandom()
		point.SetRandom()
		proof := kzg_bls12381.OpeningProof{
			H:            G1,
			ClaimedValue: value,
		}
		assignment, err := ValueOfOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine](proof)
		assert.NoError(err)
		_ = assignment
	}, "bls12381")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bw6761.Generators()
		var value, point fr_bw6761.Element
		value.SetRandom()
		point.SetRandom()
		proof := kzg_bw6761.OpeningProof{
			H:            G1,
			ClaimedValue: value,
		}
		assignment, err := ValueOfOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine](proof)
		assert.NoError(err)
		_ = assignment
	}, "bw6761")
}

func TestValueOfSRS(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		_, _, _, G2 := bn254.Generators()
		vk := kzg_bn254.VerifyingKey{
			G2: [2]bn254.G2Affine{G2, G2},
		}
		assignment, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
		assert.NoError(err)
		_ = assignment
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		_, _, _, G2 := bls12377.Generators()
		vk := kzg_bls12377.VerifyingKey{
			G2: [2]bls12377.G2Affine{G2, G2},
		}
		assignment, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine](vk)
		assert.NoError(err)
		_ = assignment
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		_, _, _, G2 := bls12381.Generators()
		vk := kzg_bls12381.VerifyingKey{
			G2: [2]bls12381.G2Affine{G2, G2},
		}
		assignment, err := ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine](vk)
		assert.NoError(err)
		_ = assignment
	}, "bls12381")
	assert.Run(func(assert *test.Assert) {
		_, _, _, G2 := bw6761.Generators()
		vk := kzg_bw6761.VerifyingKey{
			G2: [2]bw6761.G2Affine{G2, G2},
		}
		assignment, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine](vk)
		assert.NoError(err)
		_ = assignment
	}, "bw6761")
}

type FoldProofTest[FR emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Point                emulated.Element[FR]
	Digests              [10]Commitment[G1El]
	BatchOpeningProof    BatchOpeningProof[FR, G1El]
	ExpectedFoldedProof  OpeningProof[FR, G1El]
	ExpectedFoldedDigest Commitment[G1El]
}

func (c *FoldProofTest[FR, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}

	foldedProof, foldedDigests, err := verifier.FoldProof(c.Digests[:], c.BatchOpeningProof, c.Point)
	if err != nil {
		return err
	}

	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return err
	}

	curve.AssertIsEqual(&foldedDigests.G1El, &c.ExpectedFoldedDigest.G1El)
	curve.AssertIsEqual(&foldedProof.Quotient, &c.ExpectedFoldedProof.Quotient)

	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&foldedProof.ClaimedValue, &c.ExpectedFoldedProof.ClaimedValue)

	return nil
}
func TestFoldProof(t *testing.T) {

	assert := test.NewAssert(t)

	// prepare test data
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	var polynomials [10][]fr_bn254.Element
	var coms [10]kzg_bn254.Digest
	for i := 0; i < 10; i++ {
		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			polynomials[i][j].SetRandom()
		}
		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
		assert.NoError(err)
	}

	var point fr_bn254.Element
	point.SetRandom()
	var target big.Int
	target.SetUint64(1)
	nbBits := ecc.BLS12_381.ScalarField().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))
	h, err := recursion.NewShort(ecc.BLS12_381.ScalarField(), &target)
	assert.NoError(err)

	batchOpeningProof, err := kzg_bn254.BatchOpenSinglePoint(polynomials[:], coms[:], point, h, srs.Pk)
	assert.NoError(err)

	foldedProofs, foldedDigest, err := kzg_bn254.FoldProof(coms[:], &batchOpeningProof, point, h)
	assert.NoError(err)

	// prepare witness
	wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
	assert.NoError(err)
	var wDigests [10]Commitment[sw_bn254.G1Affine]
	for i := 0; i < 10; i++ {
		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](coms[i])
		assert.NoError(err)
	}
	wBatchOpeningProof, err := ValueOfBatchOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](batchOpeningProof)
	assert.NoError(err)
	wExpectedFoldedProof, err := ValueOfOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](foldedProofs)
	assert.NoError(err)
	wExpectedFoldedDigest, err := ValueOfCommitment[sw_bn254.G1Affine](foldedDigest)
	assert.NoError(err)

	assignment := FoldProofTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Point:                wPoint,
		Digests:              wDigests,
		BatchOpeningProof:    wBatchOpeningProof,
		ExpectedFoldedProof:  wExpectedFoldedProof,
		ExpectedFoldedDigest: wExpectedFoldedDigest,
	}

	var circuit FoldProofTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	circuit.BatchOpeningProof.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], 10)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

}

type BatchVerifySinglePointTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Vk                VerifyingKey[G1El, G2El]
	Point             emulated.Element[S]
	Digests           [10]Commitment[G1El]
	BatchOpeningProof BatchOpeningProof[S, G1El]
}

func (c *BatchVerifySinglePointTest[S, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	if err := verifier.BatchVerifySinglePoint(c.Digests[:], c.BatchOpeningProof, c.Point, c.Vk); err != nil {
		return fmt.Errorf("batch verify single point: %w", err)
	}

	return nil
}

func TestBatchVerifySinglePoint(t *testing.T) {

	assert := test.NewAssert(t)

	// prepare test data
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	var polynomials [10][]fr_bn254.Element
	var coms [10]kzg_bn254.Digest
	for i := 0; i < 10; i++ {
		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			polynomials[i][j].SetRandom()
		}
		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
		assert.NoError(err)
	}

	// random point at which the polynomials are evaluated
	var point fr_bn254.Element
	point.SetRandom()

	// build short hash, we pick a number one byte less than the snark field...
	var target big.Int
	target.SetUint64(1)
	nbBits := ecc.BLS12_381.ScalarField().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))
	h, err := recursion.NewShort(ecc.BLS12_381.ScalarField(), &target)
	assert.NoError(err)

	batchOpeningProof, err := kzg_bn254.BatchOpenSinglePoint(polynomials[:], coms[:], point, h, srs.Pk)
	assert.NoError(err)

	err = kzg_bn254.BatchVerifySinglePoint(coms[:], &batchOpeningProof, point, h, srs.Vk)
	assert.NoError(err)

	// prepare witness
	wVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
	assert.NoError(err)
	var wDigests [10]Commitment[sw_bn254.G1Affine]
	for i := 0; i < 10; i++ {
		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](coms[i])
		assert.NoError(err)
	}
	wBatchOpeningProof, err := ValueOfBatchOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](batchOpeningProof)
	assert.NoError(err)

	assignment := BatchVerifySinglePointTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk:                wVk,
		Point:             wPoint,
		Digests:           wDigests,
		BatchOpeningProof: wBatchOpeningProof,
	}

	var circuit BatchVerifySinglePointTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	circuit.BatchOpeningProof.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], 10)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

}

type BatchVerifyMultiPointsTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Vk      VerifyingKey[G1El, G2El]
	Digests [4]Commitment[G1El]
	Proofs  [4]OpeningProof[S, G1El]
	Points  [4]emulated.Element[S]
}

func (circuit *BatchVerifyMultiPointsTest[S, G1El, G2El, GTEl]) Define(api frontend.API) error {

	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}

	if err := verifier.BatchVerifyMultiPoints(circuit.Digests[:], circuit.Proofs[:], circuit.Points[:], circuit.Vk); err != nil {
		return fmt.Errorf("batch verify multi points: %w", err)
	}

	return nil
}

func TestBatchVerifyMultiPoints(t *testing.T) {

	assert := test.NewAssert(t)

	// prepare test data
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	var polynomials [4][]fr_bn254.Element
	var coms [4]kzg_bn254.Digest
	for i := 0; i < 4; i++ {
		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			polynomials[i][j].SetRandom()
		}
		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
		assert.NoError(err)
	}

	// random points at which the polynomials are evaluated
	var points [4]fr_bn254.Element
	for i := 0; i < 4; i++ {
		points[i].SetRandom()
	}

	// build opening proofs
	var openingProofs [4]kzg_bn254.OpeningProof
	for i := 0; i < 4; i++ {
		openingProofs[i], err = kzg_bn254.Open(polynomials[i], points[i], srs.Pk)
		assert.NoError(err)
	}

	// check that the proofs are correct
	err = kzg_bn254.BatchVerifyMultiPoints(coms[:], openingProofs[:], points[:], srs.Vk)
	assert.NoError(err)

	// prepare witness
	wVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	var wDigests [4]Commitment[sw_bn254.G1Affine]
	var wPoints [4]emulated.Element[emulated.BN254Fr]
	var wOpeningProofs [4]OpeningProof[emulated.BN254Fr, sw_bn254.G1Affine]
	for i := 0; i < 4; i++ {
		wPoints[i], err = ValueOfScalar[emulated.BN254Fr](points[i])
		assert.NoError(err)
		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](coms[i])
		assert.NoError(err)
		wOpeningProofs[i], err = ValueOfOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](openingProofs[i])
		assert.NoError(err)
	}

	assignment := BatchVerifyMultiPointsTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk:      wVk,
		Points:  wPoints,
		Digests: wDigests,
		Proofs:  wOpeningProofs,
	}

	var circuit BatchVerifyMultiPointsTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

}

type KZGVerificationConstantVkCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GTEl algebra.GtElementT] struct {
	vk VerifyingKey[G1El, G2El] `gnark:"-"` // override visibility for sub-definitions
	Commitment[G1El]
	OpeningProof[FR, G1El]
	Point emulated.Element[FR]
}

func (c *KZGVerificationConstantVkCircuit[FR, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	if err := verifier.CheckOpeningProof(c.Commitment, c.OpeningProof, c.Point, c.vk); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGVerificationEmulated3ConstantVk(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BW6_761.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bw6761.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bw6761.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bw6761.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bw6761.Element
	point.SetRandom()
	proof, err := kzg_bw6761.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bw6761.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bw6761.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bw6761.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationConstantVkCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationConstantVkCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		vk: wVk,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestKZGVerificationEmulated3Precomputed(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BW6_761.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bw6761.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bw6761.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bw6761.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bw6761.Element
	point.SetRandom()
	proof, err := kzg_bw6761.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bw6761.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bw6761.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bw6761.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		VerifyingKey: PlaceholderVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine](),
	}
	// the fixed G2 points come with precomputed lines, so Pair never reads their
	// coordinates nor the addition lines at the zero bits of the loop counter.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestKZGVerificationEmulatedConstantVk(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bn254.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bn254.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bn254.Element
	point.SetRandom()
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bn254.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bn254.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bn254.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationConstantVkCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationConstantVkCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		vk: wVk,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestKZGVerificationEmulatedPrecomputed(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bn254.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bn254.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bn254.Element
	point.SetRandom()
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bn254.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bn254.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bn254.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](),
	}
	// the fixed G2 points come with precomputed lines, so Pair never reads their
	// coordinates nor the addition lines at the zero bits of the loop counter.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestKZGVerificationEmulated2ConstantVk(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12381.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12381.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12381.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12381.Element
	point.SetRandom()
	proof, err := kzg_bls12381.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12381.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12381.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bls12381.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationConstantVkCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationConstantVkCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		vk: wVk,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func TestKZGVerificationEmulated2Precomputed(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12381.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12381.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12381.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12381.Element
	point.SetRandom()
	proof, err := kzg_bls12381.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12381.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12381.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bls12381.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine](),
	}
	// the fixed G2 points come with precomputed lines, so Pair never reads their
	// coordinates nor the addition lines at the zero bits of the loop counter.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestKZGVerificationTwoChainPrecomputed(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12377.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12377.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12377.Element
	point.SetRandom()
	proof, err := kzg_bls12377.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12377.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12377.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bls12377.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine](),
	}
	// the fixed G2 points come with precomputed lines, so Pair never reads their
	// coordinates nor the addition lines at the zero bits of the loop counter.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_761), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

func TestKZGVerificationTwoChainConstantVk(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12377.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12377.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12377.Element
	point.SetRandom()
	proof, err := kzg_bls12377.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12377.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12377.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine](srs.Vk)
	assert.NoError(err)
	wPt, err := ValueOfScalar[sw_bls12377.ScalarField](point)
	assert.NoError(err)

	assignment := KZGVerificationConstantVkCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationConstantVkCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		vk: wVk,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_761))
}
