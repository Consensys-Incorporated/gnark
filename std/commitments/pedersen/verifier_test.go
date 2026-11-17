package pedersen

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fp_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	ped_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/pedersen"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	ped_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	ped_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fp_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	ped_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/pedersen"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// assertCommitmentCircuit calls AssertCommitment with no options, exercising
// the default (no-option) verification path.
type assertCommitmentCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Commitment Commitment[G1El]
	Pok        KnowledgeProof[G1El]
	Vk         VerifyingKey[G2El]
}

func (c *assertCommitmentCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}
	return verifier.AssertCommitment(c.Commitment, c.Pok, c.Vk)
}

// ---------------------------------------------------------------------------
// BN254
// ---------------------------------------------------------------------------

func bn254PedersenInstance(t *testing.T) (bn254.G1Affine, bn254.G1Affine, *ped_bn254.VerifyingKey) {
	t.Helper()
	_, _, g1gen, _ := bn254.Generators()
	basis := []bn254.G1Affine{g1gen}
	pk, vk, err := ped_bn254.Setup([][]bn254.G1Affine{basis})
	if err != nil {
		t.Fatal(err)
	}
	var one fr_bn254.Element
	one.SetOne()
	values := [][]fr_bn254.Element{{one}}
	cmt, err := pk[0].Commit(values[0])
	if err != nil {
		t.Fatal(err)
	}
	pok, err := pk[0].ProveKnowledge(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return cmt, pok, &vk
}

func TestPedersenForgeryBN254(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, vk := bn254PedersenInstance(t)

	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G2Affine](vk)
	assert.NoError(err)

	// off-curve points with y == 0: every Miller line evaluates to 1, so the
	// pairing check is trivially satisfied unless the points are validated.
	var forgedC, forgedPok bn254.G1Affine
	forgedC.X.SetUint64(12345)
	forgedC.Y.SetZero()
	forgedPok.X.SetUint64(67890)
	forgedPok.Y.SetZero()

	c, err := ValueOfCommitment[sw_bn254.G1Affine](forgedC)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bn254.G1Affine](forgedPok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk: circuitVk,
	}
	assignment := &assertCommitmentCircuit[emparams.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Commitment: c,
		Pok:        p,
		Vk:         circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.Error(err, "forged commitment with y=0 must be rejected")
}

func TestPedersenHonestBN254(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bn254PedersenInstance(t)

	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G2Affine](vk)
	assert.NoError(err)
	c, err := ValueOfCommitment[sw_bn254.G1Affine](cmt)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bn254.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk: circuitVk,
	}
	assignment := &assertCommitmentCircuit[emparams.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Commitment: c,
		Pok:        p,
		Vk:         circuitVk,
	}
	assert.NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
}

// ---------------------------------------------------------------------------
// BLS12-381
// ---------------------------------------------------------------------------

func bls12381PedersenInstance(t *testing.T) (bls12381.G1Affine, bls12381.G1Affine, *ped_bls12381.VerifyingKey) {
	t.Helper()
	_, _, g1gen, _ := bls12381.Generators()
	basis := []bls12381.G1Affine{g1gen}
	pk, vk, err := ped_bls12381.Setup([][]bls12381.G1Affine{basis})
	if err != nil {
		t.Fatal(err)
	}
	var one fr_bls12381.Element
	one.SetOne()
	values := [][]fr_bls12381.Element{{one}}
	cmt, err := pk[0].Commit(values[0])
	if err != nil {
		t.Fatal(err)
	}
	pok, err := pk[0].ProveKnowledge(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return cmt, pok, &vk
}

func TestPedersenForgeryBLS12381(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, vk := bls12381PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bls12381.G2Affine](vk)
	assert.NoError(err)

	var forgedC, forgedPok bls12381.G1Affine
	forgedC.X.SetUint64(12345)
	forgedC.Y.SetZero()
	forgedPok.X.SetUint64(67890)
	forgedPok.Y.SetZero()

	c, err := ValueOfCommitment[sw_bls12381.G1Affine](forgedC)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bls12381.G1Affine](forgedPok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.Error(err, "forged commitment with y=0 must be rejected")
}

func TestPedersenHonestBLS12381(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bls12381PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bls12381.G2Affine](vk)
	assert.NoError(err)
	c, err := ValueOfCommitment[sw_bls12381.G1Affine](cmt)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bls12381.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	assert.NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
}

// ---------------------------------------------------------------------------
// BW6-761
// ---------------------------------------------------------------------------

func bw6761PedersenInstance(t *testing.T) (bw6761.G1Affine, bw6761.G1Affine, *ped_bw6761.VerifyingKey) {
	t.Helper()
	_, _, g1gen, _ := bw6761.Generators()
	basis := []bw6761.G1Affine{g1gen}
	pk, vk, err := ped_bw6761.Setup([][]bw6761.G1Affine{basis})
	if err != nil {
		t.Fatal(err)
	}
	var one fr_bw6761.Element
	one.SetOne()
	values := [][]fr_bw6761.Element{{one}}
	cmt, err := pk[0].Commit(values[0])
	if err != nil {
		t.Fatal(err)
	}
	pok, err := pk[0].ProveKnowledge(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return cmt, pok, &vk
}

func TestPedersenForgeryBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, vk := bw6761PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G2Affine](vk)
	assert.NoError(err)

	var forgedC, forgedPok bw6761.G1Affine
	forgedC.X.SetUint64(12345)
	forgedC.Y.SetZero()
	forgedPok.X.SetUint64(67890)
	forgedPok.Y.SetZero()

	c, err := ValueOfCommitment[sw_bw6761.G1Affine](forgedC)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bw6761.G1Affine](forgedPok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BW6761Fr, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BW6761Fr, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.Error(err, "forged commitment with y=0 must be rejected")
}

func TestPedersenHonestBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bw6761PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G2Affine](vk)
	assert.NoError(err)
	c, err := ValueOfCommitment[sw_bw6761.G1Affine](cmt)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bw6761.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BW6761Fr, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BW6761Fr, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	assert.NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
}

// ---------------------------------------------------------------------------
// BLS12-377 (native, in BW6-761)
// ---------------------------------------------------------------------------

func bls12377PedersenInstance(t *testing.T) (bls12377.G1Affine, bls12377.G1Affine, *ped_bls12377.VerifyingKey) {
	t.Helper()
	_, _, g1gen, _ := bls12377.Generators()
	basis := []bls12377.G1Affine{g1gen}
	pk, vk, err := ped_bls12377.Setup([][]bls12377.G1Affine{basis})
	if err != nil {
		t.Fatal(err)
	}
	var one fr_bls12377.Element
	one.SetOne()
	values := [][]fr_bls12377.Element{{one}}
	cmt, err := pk[0].Commit(values[0])
	if err != nil {
		t.Fatal(err)
	}
	pok, err := pk[0].ProveKnowledge(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return cmt, pok, &vk
}

func TestPedersenForgeryBLS12377(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, vk := bls12377PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G2Affine](vk)
	assert.NoError(err)

	var forgedC, forgedPok bls12377.G1Affine
	forgedC.X.SetUint64(12345)
	forgedC.Y.SetZero()
	forgedPok.X.SetUint64(67890)
	forgedPok.Y.SetZero()

	c, err := ValueOfCommitment[sw_bls12377.G1Affine](forgedC)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bls12377.G1Affine](forgedPok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BLS12377Fr, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BLS12377Fr, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BW6_761.ScalarField())
	assert.Error(err, "forged commitment with y=0 must be rejected")
}

func TestPedersenHonestBLS12377(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bls12377PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G2Affine](vk)
	assert.NoError(err)
	c, err := ValueOfCommitment[sw_bls12377.G1Affine](cmt)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bls12377.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BLS12377Fr, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BLS12377Fr, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	assert.NoError(test.IsSolved(circuit, assignment, ecc.BW6_761.ScalarField()))
}

// ---------------------------------------------------------------------------
// On-curve, out-of-subgroup forgeries
//
// The (x, 0) forgeries above are off the curve, so an on-curve check alone
// would reject them. The tests below pin the *subgroup* half of AssertIsOnG1:
// the forged commitment is a genuine point of E(Fp) outside the prime-order
// subgroup G1. It is cmt + T with T = [r]P' for a curve point P'; T lies in the
// cofactor part, which pairs to 1, so the forgery pairs exactly like cmt and
// the honest proof of knowledge still goes through.
//
// There is no BN254 counterpart: BN254 has G1 cofactor 1, so every curve point
// is in G1 and no such forgery exists.
// ---------------------------------------------------------------------------

// cofactorPointBLS12377 returns a nonzero point of the BLS12-377 G1 cofactor
// part: [r]P' for the first small-x curve point P'. It is on the curve, outside
// G1, and pairs to 1.
func cofactorPointBLS12377(t *testing.T) bls12377.G1Affine {
	t.Helper()
	a, b := bls12377.CurveCoefficients()
	var p, tt bls12377.G1Affine
	var x, ysq, ax, y fp_bls12377.Element
	for i := uint64(1); i < 1000; i++ {
		x.SetUint64(i)
		ysq.Square(&x)
		ysq.Mul(&ysq, &x)
		ax.Mul(&a, &x)
		ysq.Add(&ysq, &ax)
		ysq.Add(&ysq, &b)
		if y.Sqrt(&ysq) == nil {
			continue
		}
		p.X, p.Y = x, y
		if !p.IsOnCurve() {
			continue
		}
		tt.ScalarMultiplication(&p, fr_bls12377.Modulus())
		if !tt.IsInfinity() {
			return tt
		}
	}
	t.Fatal("no cofactor point found")
	return tt
}

// cofactorPointBLS12381 is cofactorPointBLS12377 for BLS12-381.
func cofactorPointBLS12381(t *testing.T) bls12381.G1Affine {
	t.Helper()
	a, b := bls12381.CurveCoefficients()
	var p, tt bls12381.G1Affine
	var x, ysq, ax, y fp_bls12381.Element
	for i := uint64(1); i < 1000; i++ {
		x.SetUint64(i)
		ysq.Square(&x)
		ysq.Mul(&ysq, &x)
		ax.Mul(&a, &x)
		ysq.Add(&ysq, &ax)
		ysq.Add(&ysq, &b)
		if y.Sqrt(&ysq) == nil {
			continue
		}
		p.X, p.Y = x, y
		if !p.IsOnCurve() {
			continue
		}
		tt.ScalarMultiplication(&p, fr_bls12381.Modulus())
		if !tt.IsInfinity() {
			return tt
		}
	}
	t.Fatal("no cofactor point found")
	return tt
}

// cofactorPointBW6761 is cofactorPointBLS12377 for BW6-761.
func cofactorPointBW6761(t *testing.T) bw6761.G1Affine {
	t.Helper()
	a, b := bw6761.CurveCoefficients()
	var p, tt bw6761.G1Affine
	var x, ysq, ax, y fp_bw6761.Element
	for i := uint64(1); i < 1000; i++ {
		x.SetUint64(i)
		ysq.Square(&x)
		ysq.Mul(&ysq, &x)
		ax.Mul(&a, &x)
		ysq.Add(&ysq, &ax)
		ysq.Add(&ysq, &b)
		if y.Sqrt(&ysq) == nil {
			continue
		}
		p.X, p.Y = x, y
		if !p.IsOnCurve() {
			continue
		}
		tt.ScalarMultiplication(&p, fr_bw6761.Modulus())
		if !tt.IsInfinity() {
			return tt
		}
	}
	t.Fatal("no cofactor point found")
	return tt
}

func TestPedersenForgeryOutOfSubgroupBLS12377(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bls12377PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G2Affine](vk)
	assert.NoError(err)

	tt := cofactorPointBLS12377(t)
	var forged bls12377.G1Affine
	forged.Add(&cmt, &tt)
	assert.True(forged.IsOnCurve(), "forgery must be on the curve")
	assert.False(forged.IsInSubGroup(), "forgery must be outside G1")
	// oracle: the native gnark-crypto verifier rejects it (subgroup check).
	assert.Error(vk.Verify(forged, pok), "native verifier must reject the forgery")

	c, err := ValueOfCommitment[sw_bls12377.G1Affine](forged)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bls12377.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BLS12377Fr, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BLS12377Fr, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BW6_761.ScalarField())
	assert.Error(err, "on-curve out-of-subgroup commitment must be rejected")
}

func TestPedersenForgeryOutOfSubgroupBLS12381(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bls12381PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bls12381.G2Affine](vk)
	assert.NoError(err)

	tt := cofactorPointBLS12381(t)
	var forged bls12381.G1Affine
	forged.Add(&cmt, &tt)
	assert.True(forged.IsOnCurve(), "forgery must be on the curve")
	assert.False(forged.IsInSubGroup(), "forgery must be outside G1")
	// oracle: the native gnark-crypto verifier rejects it (subgroup check).
	assert.Error(vk.Verify(forged, pok), "native verifier must reject the forgery")

	c, err := ValueOfCommitment[sw_bls12381.G1Affine](forged)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bls12381.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.Error(err, "on-curve out-of-subgroup commitment must be rejected")
}

func TestPedersenForgeryOutOfSubgroupBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	cmt, pok, vk := bw6761PedersenInstance(t)
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G2Affine](vk)
	assert.NoError(err)

	tt := cofactorPointBW6761(t)
	var forged bw6761.G1Affine
	forged.Add(&cmt, &tt)
	assert.True(forged.IsOnCurve(), "forgery must be on the curve")
	assert.False(forged.IsInSubGroup(), "forgery must be outside G1")
	// oracle: the native gnark-crypto verifier rejects it (subgroup check).
	assert.Error(vk.Verify(forged, pok), "native verifier must reject the forgery")

	c, err := ValueOfCommitment[sw_bw6761.G1Affine](forged)
	assert.NoError(err)
	p, err := ValueOfKnowledgeProof[sw_bw6761.G1Affine](pok)
	assert.NoError(err)

	circuit := &assertCommitmentCircuit[emparams.BW6761Fr, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{Vk: circuitVk}
	assignment := &assertCommitmentCircuit[emparams.BW6761Fr, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		Commitment: c, Pok: p, Vk: circuitVk,
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.Error(err, "on-curve out-of-subgroup commitment must be rejected")
}
