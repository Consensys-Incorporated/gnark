package pedersen

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	ped_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/pedersen"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	ped_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	ped_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
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
