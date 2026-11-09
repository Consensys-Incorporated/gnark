// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_grumpkin

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// thirdRootOneG1 of Grumpkin G1. Mirrors gnark-crypto/ecc/grumpkin/grumpkin.go:76.
const grumpkinG1ThirdRootOne = "4407920970296243842393367215006156084916469457145843978461"

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

// TestG1AddUnifiedCubeRootEdgeCase: j=0 incompleteness regression. Q = -Φ(P)
// has y_P + y_Q = 0 with P ≠ -Q; old code returned (0,0) — soundness break.
func TestG1AddUnifiedCubeRootEdgeCase(t *testing.T) {
	assert := test.NewAssert(t)

	_, P := grumpkin.Generators()

	var omega fp.Element
	omega.SetString(grumpkinG1ThirdRootOne)
	var Q grumpkin.G1Affine
	Q.X.Mul(&P.X, &omega)
	Q.Y.Neg(&P.Y)

	var ySum fp.Element
	ySum.Add(&P.Y, &Q.Y)
	assert.True(ySum.IsZero(), "test setup wrong: y_P+y_Q≠0")
	assert.False(P.X.Equal(&Q.X), "test setup wrong: P=−Q")

	var Rjac grumpkin.G1Jac
	Rjac.FromAffine(&P)
	var Qjac grumpkin.G1Jac
	Qjac.FromAffine(&Q)
	Rjac.AddAssign(&Qjac)
	var R grumpkin.G1Affine
	R.FromJacobian(&Rjac)
	assert.False(R.IsInfinity(), "expected finite sum")

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)
	witness.R.Assign(&R)

	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254))
}

// TestG1AddUnifiedInfinityP: p=(0,0) → result=q.
func TestG1AddUnifiedInfinityP(t *testing.T) {
	_a := randomPointG1()
	var q grumpkin.G1Affine
	q.FromJacobian(&_a)

	witness := g1AddUnifiedTest{}
	witness.P.X = 0
	witness.P.Y = 0
	witness.Q.Assign(&q)
	witness.R.Assign(&q)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254))
}

// TestG1AddUnifiedInverse: q = -p → result=(0,0).
func TestG1AddUnifiedInverse(t *testing.T) {
	_a := randomPointG1()
	var p grumpkin.G1Affine
	p.FromJacobian(&_a)
	var q grumpkin.G1Affine
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
		test.WithCurves(ecc.BN254))
}

// TestG1AddUnifiedDoubling: q = p → result = 2p.
func TestG1AddUnifiedDoubling(t *testing.T) {
	_a := randomPointG1()
	var p grumpkin.G1Affine
	p.FromJacobian(&_a)
	var doubled grumpkin.G1Jac
	doubled.Set(&_a).DoubleAssign()
	var r grumpkin.G1Affine
	r.FromJacobian(&doubled)

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&p)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254))
}

// TestG1AddUnifiedRandom: generic case.
func TestG1AddUnifiedRandom(t *testing.T) {
	_a := randomPointG1()
	_b := randomPointG1()
	var p, q grumpkin.G1Affine
	p.FromJacobian(&_a)
	q.FromJacobian(&_b)

	var sum grumpkin.G1Jac
	sum.Set(&_a).AddAssign(&_b)
	var r grumpkin.G1Affine
	r.FromJacobian(&sum)

	witness := g1AddUnifiedTest{}
	witness.P.Assign(&p)
	witness.Q.Assign(&q)
	witness.R.Assign(&r)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&g1AddUnifiedTest{},
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254))
}
