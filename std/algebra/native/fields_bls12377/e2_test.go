// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	var expected E2
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	var witness e2Add
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&e2Add{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	var expected E2
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	var witness e2Sub
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&e2Sub{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	var expected E2

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	var witness e2Mul
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&e2Mul{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type e2Div struct {
	A, B, C E2
}

func (circuit *e2Div) Define(api frontend.API) error {
	var expected E2

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e2Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&e2Div{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type fp2MulByFp struct {
	A E2
	B frontend.Variable
	C E2 `gnark:",public"`
}

func (circuit *fp2MulByFp) Define(api frontend.API) error {
	expected := E2{}
	expected.MulByFp(api, circuit.A, circuit.B)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByFpFp2(t *testing.T) {

	var circuit, witness fp2MulByFp

	// witness values
	var a, c bls12377.E2
	var b fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)

	witness.A.Assign(&a)
	witness.B = (fr.Element)(b)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type fp2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Conjugate) Define(api frontend.API) error {
	expected := E2{}
	expected.Conjugate(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConjugateFp2(t *testing.T) {

	var circuit, witness fp2Conjugate

	// witness values
	var a, c bls12377.E2
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Inverse) Define(api frontend.API) error {

	expected := E2{}
	expected.Inverse(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp2(t *testing.T) {

	var circuit, witness fp2Inverse

	// witness values
	var a, c bls12377.E2
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type fp2IsEqual struct {
	A      E2
	B      E2                `gnark:",public"`
	Result frontend.Variable `gnark:",public"`
}

func (c *fp2IsEqual) Define(api frontend.API) error {
	res := c.A.IsEqual(api, c.B)
	api.AssertIsEqual(res, c.Result)
	return nil
}

func TestIsEqualFp2(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, validWitness, validWitness2 fp2IsEqual
	var a bls12377.E2
	var b bls12377.E2
	a.SetRandom()
	b.SetRandom()

	validWitness.A.Assign(&a)
	validWitness.B.Assign(&a)
	validWitness.Result = 1

	validWitness2.A.Assign(&a)
	validWitness2.B.Assign(&b)
	validWitness2.Result = 0

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&validWitness), test.WithValidAssignment(&validWitness2), test.WithCurves(ecc.BW6_761))
}
