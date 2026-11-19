package evmprecompiles

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
)

// The two fixed circuits below replace the one-sided
// [ECPairMillerLoopAndFinalExpCheck] (see GHSA-76v9-555f-fpfh): the caller
// selects the one matching the precompile's (public) return value.

type ecPairFinalExpSuccessCircuit struct {
	Acc sw_bn254.GTEl
	P   sw_bn254.G1Affine
	Q   sw_bn254.G2Affine
}

func (c *ecPairFinalExpSuccessCircuit) Define(api frontend.API) error {
	return ECPairMillerLoopAndFinalExpCheckSuccess(api, &c.Acc, &c.P, &c.Q)
}

type ecPairFinalExpFailureCircuit struct {
	Acc sw_bn254.GTEl
	P   sw_bn254.G1Affine
	Q   sw_bn254.G2Affine
}

func (c *ecPairFinalExpFailureCircuit) Define(api frontend.API) error {
	return ECPairMillerLoopAndFinalExpCheckFailure(api, &c.Acc, &c.P, &c.Q)
}

// bnPairInputs returns an accumulator holding the Miller loop of (p, q) in the
// convention of [sw_bn254.Pairing.MillerLoopAndMul], together with the last
// pair. With last = -p the two-pair product is 1; with last = p it is not.
func bnPairInputs(t *testing.T) (acc bn254.GT, p, np bn254.G1Affine, q bn254.G2Affine) {
	t.Helper()
	_, _, g1, g2 := bn254.Generators()
	s1, err := rand.Int(rand.Reader, bn254.ID.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := rand.Int(rand.Reader, bn254.ID.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	p.ScalarMultiplication(&g1, s1)
	q.ScalarMultiplication(&g2, s2)
	np.Neg(&p)

	lines := bn254.PrecomputeLines(q)
	acc, err = bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{p},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines},
	)
	if err != nil {
		t.Fatal(err)
	}
	return acc, p, np, q
}

func TestECPairMillerLoopAndFinalExpCheckSuccessCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	acc, p, np, q := bnPairInputs(t)

	ok, err := bn254.PairingCheck([]bn254.G1Affine{p, np}, []bn254.G2Affine{q, q})
	assert.NoError(err)
	assert.True(ok)

	// e(p,q)·e(-p,q) == 1 : the success circuit must be satisfiable.
	assert.NoError(test.IsSolved(&ecPairFinalExpSuccessCircuit{}, &ecPairFinalExpSuccessCircuit{
		Acc: sw_bn254.NewGTEl(acc),
		P:   sw_bn254.NewG1Affine(np),
		Q:   sw_bn254.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))

	// e(p,q)·e(p,q) != 1 : the success circuit must be unsatisfiable.
	ok, err = bn254.PairingCheck([]bn254.G1Affine{p, p}, []bn254.G2Affine{q, q})
	assert.NoError(err)
	assert.False(ok)
	assert.Error(test.IsSolved(&ecPairFinalExpSuccessCircuit{}, &ecPairFinalExpSuccessCircuit{
		Acc: sw_bn254.NewGTEl(acc),
		P:   sw_bn254.NewG1Affine(p),
		Q:   sw_bn254.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))
}

func TestECPairMillerLoopAndFinalExpCheckFailureCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	acc, p, np, q := bnPairInputs(t)

	// e(p,q)·e(p,q) != 1 : the failure circuit must be satisfiable.
	assert.NoError(test.IsSolved(&ecPairFinalExpFailureCircuit{}, &ecPairFinalExpFailureCircuit{
		Acc: sw_bn254.NewGTEl(acc),
		P:   sw_bn254.NewG1Affine(p),
		Q:   sw_bn254.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))

	// e(p,q)·e(-p,q) == 1 : the failure circuit must be unsatisfiable. This is
	// the direction that [ECPairMillerLoopAndFinalExpCheck] fails to enforce.
	assert.Error(test.IsSolved(&ecPairFinalExpFailureCircuit{}, &ecPairFinalExpFailureCircuit{
		Acc: sw_bn254.NewGTEl(acc),
		P:   sw_bn254.NewG1Affine(np),
		Q:   sw_bn254.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))
}

type ecPairBLSFinalExpSuccessCircuit struct {
	Acc sw_bls12381.GTEl
	P   sw_bls12381.G1Affine
	Q   sw_bls12381.G2Affine
}

func (c *ecPairBLSFinalExpSuccessCircuit) Define(api frontend.API) error {
	return ECPairBLSMillerLoopAndFinalExpCheckSuccess(api, &c.Acc, &c.P, &c.Q)
}

type ecPairBLSFinalExpFailureCircuit struct {
	Acc sw_bls12381.GTEl
	P   sw_bls12381.G1Affine
	Q   sw_bls12381.G2Affine
}

func (c *ecPairBLSFinalExpFailureCircuit) Define(api frontend.API) error {
	return ECPairBLSMillerLoopAndFinalExpCheckFailure(api, &c.Acc, &c.P, &c.Q)
}

// blsPairInputs is the BLS12-381 analogue of bnPairInputs. Note that
// [sw_bls12381.Pairing.MillerLoopAndMul] conjugates the Miller loop output
// before accumulating it (negative seed), so the accumulator holds the
// conjugate of the gnark-crypto Miller loop.
func blsPairInputs(t *testing.T) (acc bls12381.GT, p, np bls12381.G1Affine, q bls12381.G2Affine) {
	t.Helper()
	_, _, g1, g2 := bls12381.Generators()
	s1, err := rand.Int(rand.Reader, bls12381.ID.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := rand.Int(rand.Reader, bls12381.ID.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	p.ScalarMultiplication(&g1, s1)
	q.ScalarMultiplication(&g2, s2)
	np.Neg(&p)

	lines := bls12381.PrecomputeLines(q)
	ml, err := bls12381.MillerLoopFixedQ(
		[]bls12381.G1Affine{p},
		[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{lines},
	)
	if err != nil {
		t.Fatal(err)
	}
	acc.Conjugate(&ml)
	return acc, p, np, q
}

func TestECPairBLSMillerLoopAndFinalExpCheckSuccessCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	acc, p, np, q := blsPairInputs(t)

	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{p, np}, []bls12381.G2Affine{q, q})
	assert.NoError(err)
	assert.True(ok)

	assert.NoError(test.IsSolved(&ecPairBLSFinalExpSuccessCircuit{}, &ecPairBLSFinalExpSuccessCircuit{
		Acc: sw_bls12381.NewGTEl(acc),
		P:   sw_bls12381.NewG1Affine(np),
		Q:   sw_bls12381.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))

	ok, err = bls12381.PairingCheck([]bls12381.G1Affine{p, p}, []bls12381.G2Affine{q, q})
	assert.NoError(err)
	assert.False(ok)
	assert.Error(test.IsSolved(&ecPairBLSFinalExpSuccessCircuit{}, &ecPairBLSFinalExpSuccessCircuit{
		Acc: sw_bls12381.NewGTEl(acc),
		P:   sw_bls12381.NewG1Affine(p),
		Q:   sw_bls12381.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))
}

func TestECPairBLSMillerLoopAndFinalExpCheckFailureCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	acc, p, np, q := blsPairInputs(t)

	assert.NoError(test.IsSolved(&ecPairBLSFinalExpFailureCircuit{}, &ecPairBLSFinalExpFailureCircuit{
		Acc: sw_bls12381.NewGTEl(acc),
		P:   sw_bls12381.NewG1Affine(p),
		Q:   sw_bls12381.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))

	assert.Error(test.IsSolved(&ecPairBLSFinalExpFailureCircuit{}, &ecPairBLSFinalExpFailureCircuit{
		Acc: sw_bls12381.NewGTEl(acc),
		P:   sw_bls12381.NewG1Affine(np),
		Q:   sw_bls12381.NewG2Affine(q),
	}, ecc.BN254.ScalarField()))
}
