package sw_bls12381

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type tripleCircuit struct {
	In, Res G1Affine
}

func (c *tripleCircuit) Define(api frontend.API) error {
	g1, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1 struct: %w", err)
	}
	res := g1.triple(&c.In)
	g1.AssertIsEqual(res, &c.Res)
	return nil
}

type tripleCircuitConsistency struct {
	In G1Affine
}

func (c *tripleCircuitConsistency) Define(api frontend.API) error {
	g1, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1 struct: %w", err)
	}
	res1 := g1.triple(&c.In)
	res2 := g1.double(&c.In)
	res2 = g1.add(res2, &c.In)
	g1.AssertIsEqual(res1, res2)
	return nil
}

func TestTripleG1(t *testing.T) {
	assert := test.NewAssert(t)
	in, _ := randomG1G2Affines()
	var res bls12381.G1Affine
	res.Double(&in).Add(&res, &in)
	witness := tripleCircuit{
		In:  NewG1Affine(in),
		Res: NewG1Affine(res),
	}
	err := test.IsSolved(&tripleCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	witness2 := tripleCircuitConsistency{
		In: NewG1Affine(in),
	}
	err = test.IsSolved(&tripleCircuitConsistency{}, &witness2, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type assertIsOnG1Circuit struct {
	P G1Affine
}

func (c *assertIsOnG1Circuit) Define(api frontend.API) error {
	g1, err := NewG1(api)
	if err != nil {
		return err
	}
	g1.AssertIsOnG1(&c.P)
	return nil
}

func onG1Witness(p bls12381.G1Affine) *assertIsOnG1Circuit {
	return &assertIsOnG1Circuit{P: G1Affine{
		X: emulated.ValueOf[BaseField](p.X),
		Y: emulated.ValueOf[BaseField](p.Y),
	}}
}

// randomCurvePoint returns a uniformly random point of E(Fp). The G1 cofactor
// is ~2^126, so such a point is essentially never in the prime-order subgroup.
func randomCurvePoint() bls12381.G1Affine {
	var four fp_bls12381.Element
	four.SetUint64(4)
	for {
		var x, y2 fp_bls12381.Element
		x.SetRandom()
		y2.Square(&x).Mul(&y2, &x).Add(&y2, &four)
		if y2.Legendre() != 1 {
			continue
		}
		var y fp_bls12381.Element
		y.Sqrt(&y2)
		p := bls12381.G1Affine{X: x, Y: y}
		if p.IsOnCurve() {
			return p
		}
	}
}

func TestAssertIsOnG1(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bls12381.Generators()

	// Completeness: genuine subgroup points, and the (0,0) infinity encoding.
	for i := 0; i < 3; i++ {
		var q bls12381.G1Affine
		q.ScalarMultiplication(&g, big.NewInt(int64(4242421+i*104729)))
		assert.True(q.IsInSubGroup())
		assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithValidAssignment(onG1Witness(q)),
			test.WithCurves(ecc.BN254), test.NoProverChecks())
	}
	var infinity bls12381.G1Affine
	assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithValidAssignment(onG1Witness(infinity)),
		test.WithCurves(ecc.BN254), test.NoProverChecks())

	// Soundness: the rational 3-torsion point (0,2), a subgroup point shifted
	// by it, and uniformly random off-subgroup curve points.
	var t0 bls12381.G1Affine
	t0.X.SetZero()
	t0.Y.SetUint64(2)
	assert.True(t0.IsOnCurve())
	assert.False(t0.IsInSubGroup())
	assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithInvalidAssignment(onG1Witness(t0)),
		test.WithCurves(ecc.BN254), test.NoProverChecks())

	var tainted bls12381.G1Affine
	tainted.ScalarMultiplication(&g, big.NewInt(424242))
	tainted.Add(&tainted, &t0)
	assert.True(tainted.IsOnCurve())
	assert.False(tainted.IsInSubGroup())
	assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithInvalidAssignment(onG1Witness(tainted)),
		test.WithCurves(ecc.BN254), test.NoProverChecks())

	for i := 0; i < 3; i++ {
		p := randomCurvePoint()
		if p.IsInSubGroup() {
			continue
		}
		assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithInvalidAssignment(onG1Witness(p)),
			test.WithCurves(ecc.BN254), test.NoProverChecks())
	}

	// A point that is not on the curve at all must also be rejected.
	notOnCurve := randomCurvePoint()
	notOnCurve.Y.Add(&notOnCurve.Y, &fp_bls12381.Element{1})
	assert.False(notOnCurve.IsOnCurve())
	assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithInvalidAssignment(onG1Witness(notOnCurve)),
		test.WithCurves(ecc.BN254), test.NoProverChecks())
}
