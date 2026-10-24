// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

//--------------------------------------------------------------------
// test

type fp6Add struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Add) Define(api frontend.API) error {
	expected := E6{}
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	var circuit, witness fp6Add

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6Sub struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Sub) Define(api frontend.API) error {
	expected := E6{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	var circuit, witness fp6Sub

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6Mul struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Mul) Define(api frontend.API) error {
	expected := E6{}

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	var circuit, witness fp6Mul

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6MulVariants struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6MulVariants) Define(api frontend.API) error {
	expected1 := E6{}
	expected2 := E6{}

	expected1.mulKaratsubaOverKaratsuba(api, circuit.A, circuit.B)
	expected2.mulToom3OverKaratsuba(api, circuit.A, circuit.B)

	expected1.AssertIsEqual(api, circuit.C)
	expected2.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulVariantsFp6(t *testing.T) {

	var circuit, witness fp6MulVariants

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6MulBy01 struct {
	A      E6
	C0, C1 E2
	C      E6 `gnark:",public"`
}

func (circuit *fp6MulBy01) Define(api frontend.API) error {
	expected := circuit.A
	expected.MulBy01(api, circuit.C0, circuit.C1)
	expected.AssertIsEqual(api, circuit.C)

	return nil
}

func TestMulFp6By01(t *testing.T) {

	var circuit, witness fp6MulBy01
	// witness values
	var a, c bls12377.E6
	var C0, C1 bls12377.E2
	_, _ = a.SetRandom()
	_, _ = C0.SetRandom()
	_, _ = C1.SetRandom()
	c.Set(&a)
	c.MulBy01(&C0, &C1)

	witness.A.Assign(&a)
	witness.C0.Assign(&C0)
	witness.C1.Assign(&C1)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type fp6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6MulByNonResidue) Define(api frontend.API) error {
	expected := E6{}

	expected.MulByNonResidue(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByNonResidueFp6(t *testing.T) {

	var circuit, witness fp6MulByNonResidue

	// witness values
	var a, c bls12377.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type fp6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6Inverse) Define(api frontend.API) error {
	expected := E6{}

	expected.Inverse(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp6(t *testing.T) {

	var circuit, witness fp6Inverse

	// witness values
	var a, c bls12377.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type e6Div struct {
	A, B, C E6
}

func (circuit *e6Div) Define(api frontend.API) error {
	var expected E6

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp6(t *testing.T) {

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e6Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&e6Div{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type e6IsEqual struct {
	A, B E6
	Eq   frontend.Variable `gnark:",public"`
}

func (circuit *e6IsEqual) Define(api frontend.API) error {
	isEqual := circuit.A.IsEqual(api, circuit.B)
	api.AssertIsEqual(isEqual, circuit.Eq)
	return nil
}

func TestE6IsEqual(t *testing.T) {

	// witness values
	var a, b bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()

	var witness, witness2 e6IsEqual
	witness.A.Assign(&a)
	witness.B.Assign(&a)
	witness.Eq = 1

	witness2.A.Assign(&a)
	witness2.B.Assign(&b)
	witness2.Eq = 0

	assert := test.NewAssert(t)
	assert.CheckCircuit(&e6IsEqual{}, test.WithValidAssignment(&witness), test.WithValidAssignment(&witness2), test.WithCurves(ecc.BW6_761))
}
