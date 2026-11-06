// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// thirdRootOneG2 = (thirdRootOneG1)² ∈ Fp. Mirrors
// gnark-crypto/ecc/bls12-377/bls12-377.go:111. The G2 GLV endomorphism is
// (X, Y) → (ω²·X, Y) acting on E2 coordinates.
var bls12377G2ThirdRootOne = func() fp.Element {
	var omega fp.Element
	omega.SetString(bls12377G1ThirdRootOne)
	var omegaSq fp.Element
	omegaSq.Square(&omega)
	return omegaSq
}()

type g2AddUnifiedTest struct {
	P, Q g2AffP
	R    g2AffP `gnark:",public"`
}

func (circuit *g2AddUnifiedTest) Define(api frontend.API) error {
	got := circuit.P
	got.AddUnified(api, circuit.Q)
	got.AssertIsEqual(api, circuit.R)
	return nil
}

// TestG2AddUnifiedCubeRootEdgeCase: j=0 incompleteness regression on G2.
// Q = -Φ_G2(P) = (ω²·P.X, -P.Y) satisfies y_P + y_Q = 0 with P ≠ -Q. The old
// formula returned ([0,0],[0,0]) — soundness break.
func TestG2AddUnifiedCubeRootEdgeCase(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, _, P := bls12377.Generators()

	// Q.X = ω²·P.X (component-wise multiplication of E2 by Fp scalar)
	var Q bls12377.G2Affine
	Q.X.A0.Mul(&P.X.A0, &bls12377G2ThirdRootOne)
	Q.X.A1.Mul(&P.X.A1, &bls12377G2ThirdRootOne)
	Q.Y.A0.Neg(&P.Y.A0)
	Q.Y.A1.Neg(&P.Y.A1)

	// Sanity checks
	assert.True(P.Y.A0.Cmp(new(fp.Element).Neg(&Q.Y.A0)) == 0, "y_P+y_Q ≠ 0 (A0)")
	assert.True(P.Y.A1.Cmp(new(fp.Element).Neg(&Q.Y.A1)) == 0, "y_P+y_Q ≠ 0 (A1)")
	assert.False(P.X.A0.Equal(&Q.X.A0) && P.X.A1.Equal(&Q.X.A1), "P=−Q")

	var Rjac bls12377.G2Jac
	Rjac.FromAffine(&P)
	var Qjac bls12377.G2Jac
	Qjac.FromAffine(&Q)
	Rjac.AddAssign(&Qjac)
	var R bls12377.G2Affine
	R.FromJacobian(&Rjac)
	assert.False(R.IsInfinity(), "expected finite sum")

	witness := g2AddUnifiedTest{}
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)
	witness.R.Assign(&R)

	assert.CheckCircuit(&g2AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG2AddUnifiedRandom: generic case.
func TestG2AddUnifiedRandom(t *testing.T) {
	_a := randomPointG2()
	_b := randomPointG2()
	var p, q bls12377.G2Affine
	p.FromJacobian(&_a)
	q.FromJacobian(&_b)

	var sum bls12377.G2Jac
	sum.Set(&_a).AddAssign(&_b)
	var r bls12377.G2Affine
	r.FromJacobian(&sum)

	witness := g2AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&q)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g2AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG2AddUnifiedDoubling: q = p → 2p.
func TestG2AddUnifiedDoubling(t *testing.T) {
	_a := randomPointG2()
	var p bls12377.G2Affine
	p.FromJacobian(&_a)
	var doubled bls12377.G2Jac
	doubled.Set(&_a).DoubleAssign()
	var r bls12377.G2Affine
	r.FromJacobian(&doubled)

	witness := g2AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&p)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g2AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG2AddUnifiedInverse: q = -p → ([0,0],[0,0]).
func TestG2AddUnifiedInverse(t *testing.T) {
	_a := randomPointG2()
	var p bls12377.G2Affine
	p.FromJacobian(&_a)
	var q bls12377.G2Affine
	q.X = p.X
	q.Y.A0.Neg(&p.Y.A0)
	q.Y.A1.Neg(&p.Y.A1)

	var r bls12377.G2Affine
	// expected: identity
	r.X.A0.SetZero()
	r.X.A1.SetZero()
	r.Y.A0.SetZero()
	r.Y.A1.SetZero()

	witness := g2AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&q)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g2AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}
