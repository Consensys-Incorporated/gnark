// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/test"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// -------------------------------------------------------------------------------------------------
// Add affine

type g2AddAssignAffine struct {
	A, B g2AffP
	C    g2AffP `gnark:",public"`
}

func (circuit *g2AddAssignAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddAssignAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	_b := randomPointG2()
	var a, b, c bls12377.G2Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g2AddAssignAffine

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// DoubleAndAdd affine

type g2DoubleAndAddAffine struct {
	A, B g2AffP
	C    g2AffP `gnark:",public"`
}

func (circuit *g2DoubleAndAddAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.DoubleAndAdd(api, &circuit.A, &circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAndAddAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	_b := randomPointG2()
	var a, b, c bls12377.G2Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g2DoubleAndAddAffine

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	_a.Double(&_a).AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Double affine

type g2DoubleAffine struct {
	A g2AffP
	C g2AffP `gnark:",public"`
}

func (circuit *g2DoubleAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.Double(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	var a, c bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2DoubleAffine

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Scalar multiplication

type g2constantScalarMul struct {
	A g2AffP
	C g2AffP `gnark:",public"`
	R *big.Int
}

func (circuit *g2constantScalarMul) Define(api frontend.API) error {
	expected := g2AffP{}
	expected.constScalarMul(api, circuit.A, circuit.R, algopts.WithIncompleteArithmetic())
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConstantScalarMulG2(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a, c bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2constantScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	br := new(big.Int)
	r.BigInt(br)
	// br is a circuit parameter
	circuit.R = br
	_a.ScalarMultiplication(&_a, br)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type g2constantScalarMulEdgeCases struct {
	A g2AffP
	R *big.Int
}

func (circuit *g2constantScalarMulEdgeCases) Define(api frontend.API) error {
	expected1 := g2AffP{}
	expected2 := g2AffP{}
	zero := fields_bls12377.E2{A0: 0, A1: 0}
	infinity := g2AffP{X: zero, Y: zero}
	expected1.constScalarMul(api, circuit.A, big.NewInt(0))
	expected2.constScalarMul(api, infinity, circuit.R)
	expected1.AssertIsEqual(api, infinity)
	expected2.AssertIsEqual(api, infinity)
	return nil
}

func TestConstantScalarMulG2EdgeCases(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2constantScalarMulEdgeCases
	var r fr.Element
	_, _ = r.SetRandom()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	br := new(big.Int)
	r.BigInt(br)
	// br is a circuit parameter
	circuit.R = br

	assert := test.NewAssert(t)
	// a constant scalar folds the point away, leaving its wires unreferenced.
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

type g2varScalarMul struct {
	A g2AffP
	C g2AffP `gnark:",public"`
	R frontend.Variable
}

func (circuit *g2varScalarMul) Define(api frontend.API) error {
	expected := g2AffP{}
	expected.varScalarMul(api, circuit.A, circuit.R, algopts.WithIncompleteArithmetic())
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestVarScalarMulG2(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a, c bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2varScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type g2varScalarMulEdgeCases struct {
	A g2AffP
	R frontend.Variable
}

func (circuit *g2varScalarMulEdgeCases) Define(api frontend.API) error {
	expected1 := g2AffP{}
	expected2 := g2AffP{}
	zero := fields_bls12377.E2{A0: 0, A1: 0}
	infinity := g2AffP{X: zero, Y: zero}
	expected1.varScalarMul(api, circuit.A, 0)
	expected2.varScalarMul(api, infinity, circuit.R)
	expected1.AssertIsEqual(api, infinity)
	expected2.AssertIsEqual(api, infinity)
	return nil
}

func TestVarScalarMulG2EdgeCases(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2varScalarMulEdgeCases
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// assign the inputs
	witness.A.Assign(&a)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type g2ScalarMul struct {
	A    g2AffP
	C    g2AffP `gnark:",public"`
	Rvar frontend.Variable
	Rcon fr.Element
}

func (circuit *g2ScalarMul) Define(api frontend.API) error {
	var expected, expected2 g2AffP
	expected.ScalarMul(api, circuit.A, circuit.Rvar)
	expected.AssertIsEqual(api, circuit.C)
	expected2.ScalarMul(api, circuit.A, circuit.Rcon)
	expected2.AssertIsEqual(api, circuit.C)
	return nil
}

func TestScalarMulG2(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a, c bls12377.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2ScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	witness.Rvar = r.String()
	circuit.Rcon = r
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761), test.NoProverChecks())
}

type g2varScalarMulBase struct {
	C g2AffP `gnark:",public"`
	R frontend.Variable
}

func (circuit *g2varScalarMulBase) Define(api frontend.API) error {
	expected := g2AffP{}
	expected.ScalarMulBase(api, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestVarScalarMulBaseG2(t *testing.T) {
	var c bls12377.G2Affine
	_, gJac, _, _ := bls12377.Generators()

	// create the cs
	var circuit, witness g2varScalarMulBase
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// compute the result
	var br big.Int
	gJac.ScalarMultiplication(&gJac, r.BigInt(&br))
	c.FromJacobian(&gJac)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

func randomPointG2() bls12377.G2Jac {
	_, p2, _, _ := bls12377.Generators()

	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p2.ScalarMultiplication(&p2, r1.BigInt(&b))
	return p2
}
