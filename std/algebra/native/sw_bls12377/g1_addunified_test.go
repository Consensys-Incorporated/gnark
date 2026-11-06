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

// thirdRootOneG1 of BLS12-377 G1 (fp constant; cube root of 1 in Fp). Mirrors
// gnark-crypto/ecc/bls12-377/bls12-377.go:110.
const bls12377G1ThirdRootOne = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"

type g1AddUnifiedTest struct {
	P, Q G1Affine
	R    G1Affine `gnark:",public"`
}

func (circuit *g1AddUnifiedTest) Define(api frontend.API) error {
	got := circuit.P
	got.AddUnified(api, circuit.Q)
	got.AssertIsEqual(api, circuit.R)
	return nil
}

// TestG1AddUnifiedCubeRootEdgeCase exercises the j=0 incompleteness case that
// the old Brier–Joye AddUnified got wrong: pick Q = -Φ(P) so that
// y_P + y_Q = 0 with P ≠ -Q. The correct sum is a finite non-zero point;
// the old code returned (0, 0) (infinity), a soundness break.
func TestG1AddUnifiedCubeRootEdgeCase(t *testing.T) {
	assert := test.NewAssert(t)

	// P = G1 generator
	_, _, P, _ := bls12377.Generators()

	// Q = -Φ(P) = (ω·P.x, -P.y)
	var omega fp.Element
	omega.SetString(bls12377G1ThirdRootOne)
	var Q bls12377.G1Affine
	Q.X.Mul(&P.X, &omega)
	Q.Y.Neg(&P.Y)

	// Sanity: y_P + y_Q = 0 and P ≠ -Q
	var ySum fp.Element
	ySum.Add(&P.Y, &Q.Y)
	assert.True(ySum.IsZero(), "test setup wrong: y_P+y_Q≠0")
	assert.False(P.X.Equal(&Q.X), "test setup wrong: P=−Q")

	// Correct R = P + Q computed natively.
	var Rjac bls12377.G1Jac
	Rjac.FromAffine(&P)
	var Qjac bls12377.G1Jac
	Qjac.FromAffine(&Q)
	Rjac.AddAssign(&Qjac)
	var R bls12377.G1Affine
	R.FromJacobian(&Rjac)
	assert.False(R.IsInfinity(), "expected finite sum but got infinity")

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)
	witness.R.Assign(&R)

	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG1AddUnifiedInfinityP: p=(0,0) → result=q.
func TestG1AddUnifiedInfinityP(t *testing.T) {
	_a := randomPointG1()
	var q bls12377.G1Affine
	q.FromJacobian(&_a)

	witness := g1AddUnifiedTest{}
	witness.P.X = 0
	witness.P.Y = 0
	witness.Q.Assign(&q)
	witness.R.Assign(&q)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG1AddUnifiedInverse: q = -p → result=(0,0).
func TestG1AddUnifiedInverse(t *testing.T) {
	_a := randomPointG1()
	var p bls12377.G1Affine
	p.FromJacobian(&_a)
	var q bls12377.G1Affine
	q.X = p.X
	q.Y.Neg(&p.Y)

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&q)
	witness.R.X = 0
	witness.R.Y = 0

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG1AddUnifiedDoubling: q = p → result = 2p.
func TestG1AddUnifiedDoubling(t *testing.T) {
	_a := randomPointG1()
	var p bls12377.G1Affine
	p.FromJacobian(&_a)
	var doubled bls12377.G1Jac
	doubled.Set(&_a).DoubleAssign()
	var r bls12377.G1Affine
	r.FromJacobian(&doubled)

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&p)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}

// TestG1AddUnifiedRandom: generic case, two random distinct non-inverse points.
func TestG1AddUnifiedRandom(t *testing.T) {
	_a := randomPointG1()
	_b := randomPointG1()
	var p, q bls12377.G1Affine
	p.FromJacobian(&_a)
	q.FromJacobian(&_b)

	var sum bls12377.G1Jac
	sum.Set(&_a).AddAssign(&_b)
	var r bls12377.G1Affine
	r.FromJacobian(&sum)

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&q)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BW6_761))
}
