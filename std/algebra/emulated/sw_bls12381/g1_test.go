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

// curvePointAtX returns the point of E(Fp): y² = x³ + 4 with the given small
// integer x-coordinate and the canonical square root as y.
//
// The off-subgroup inputs here are built deterministically rather than sampled,
// so a failure is reproducible and no candidate can be silently skipped for
// landing in the subgroup. (sw_emulated's randomBLS12381CurvePoint samples
// instead, because its check is statistical — it asserts [c]P lands in G1 over
// many random P. The two are not interchangeable, so neither is a copy of the
// other.)
func curvePointAtX(t *testing.T, x uint64) bls12381.G1Affine {
	t.Helper()
	var xe, y2 fp_bls12381.Element
	xe.SetUint64(x)
	y2.Square(&xe).Mul(&y2, &xe).Add(&y2, new(fp_bls12381.Element).SetUint64(4))
	if y2.Legendre() != 1 {
		t.Fatalf("x = %d is not the x-coordinate of a curve point", x)
	}
	var y fp_bls12381.Element
	y.Sqrt(&y2)
	p := bls12381.G1Affine{X: xe, Y: y}
	if !p.IsOnCurve() {
		t.Fatalf("constructed point at x = %d is not on the curve", x)
	}
	return p
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

	// Generic off-subgroup curve points, carrying torsion in both the n-part
	// and the 3-part of the cofactor rather than only the 3-torsion above.
	for _, x := range []uint64{4, 5, 6} {
		p := curvePointAtX(t, x)
		assert.False(p.IsInSubGroup(), "x=%d should be off-subgroup", x)
		assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithInvalidAssignment(onG1Witness(p)),
			test.WithCurves(ecc.BN254), test.NoProverChecks())
	}

	// A point that is not on the curve at all must also be rejected.
	notOnCurve := curvePointAtX(t, 4)
	notOnCurve.Y.Add(&notOnCurve.Y, &fp_bls12381.Element{1})
	assert.False(notOnCurve.IsOnCurve())
	assert.CheckCircuit(&assertIsOnG1Circuit{}, test.WithInvalidAssignment(onG1Witness(notOnCurve)),
		test.WithCurves(ecc.BN254), test.NoProverChecks())
}
