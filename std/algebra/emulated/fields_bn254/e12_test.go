package fields_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type e12Convert struct {
	A E12
}

func (circuit *e12Convert) Define(api frontend.API) error {
	e := NewExt12(api)
	tower := e.ToTower(&circuit.A)
	expected := e.FromTower(tower)
	e.AssertIsEqual(expected, &circuit.A)
	return nil
}

func TestConvertFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a bn254.E12
	_, _ = a.SetRandom()

	witness := e12Convert{
		A: FromE12(&a),
	}

	err := test.IsSolved(&e12Convert{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Add struct {
	A, B, C E12
}

func (circuit *e12Add) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e12Add{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Sub struct {
	A, B, C E12
}

func (circuit *e12Sub) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e12Sub{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Mul struct {
	A, B, C E12
}

func (circuit *e12Mul) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e12Mul{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e12Div{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Square struct {
	A, C E12
}

func (circuit *e12Square) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e12Square{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12SquareGS struct {
	A, C E12
}

func (circuit *e12SquareGS) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.CyclotomicSquareGS(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareGSFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.Square(&a)

	witness := e12SquareGS{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12SquareGS{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Conjugate) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness := e12Conjugate{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Inverse) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e12Inverse{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type Frobenius struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *Frobenius) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Frobenius(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobenius(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.Frobenius(&a)

	witness := Frobenius{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&Frobenius{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FrobeniusSquare struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *FrobeniusSquare) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.FrobeniusSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusSquare(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.FrobeniusSquare(&a)

	witness := FrobeniusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&FrobeniusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FrobeniusCube struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *FrobeniusCube) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.FrobeniusCube(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusCube(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.FrobeniusCube(&a)

	witness := FrobeniusCube{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&FrobeniusCube{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12MulBy01379 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *e12MulBy01379) Define(api frontend.API) error {
	e := NewExt12(api)
	res := e.MulBy01379(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy01379(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bn254.E12
	_, _ = a.SetRandom()
	var one, b, c bn254.E2
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy034(&one, &b, &c)

	witness := e12MulBy01379{
		A: FromE12(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12MulBy01379{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Mul01379By01379 struct {
	A, B E2 `gnark:",public"`
	C, D E2 `gnark:",public"`
	W    E12
}

func (circuit *e12Mul01379By01379) Define(api frontend.API) error {
	e := NewExt12(api)
	res := e.Mul01379By01379(&circuit.A, &circuit.B, &circuit.C, &circuit.D)
	e.AssertIsEqual(
		&E12{*res[0], *res[1], *res[2], *res[3], *res[4], *e.fp.Zero(), *res[5], *res[6], *res[7], *res[8], *res[9], *e.fp.Zero()},
		&circuit.W,
	)
	return nil
}

func TestFp12Mul01379By01379(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var one, a, b, c, d bn254.E2
	one.SetOne()
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	_, _ = d.SetRandom()
	prod := Mul034By034(&one, &a, &b, &one, &c, &d)
	var w bn254.E12
	w.C0.B0.Set(&prod[0])
	w.C0.B1.Set(&prod[1])
	w.C0.B2.Set(&prod[2])
	w.C1.B0.Set(&prod[3])
	w.C1.B1.Set(&prod[4])
	w.C1.B2.SetZero()

	witness := e12Mul01379By01379{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		D: FromE2(&d),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12Mul01379By01379{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Expt struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Expt) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Expt(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestFp12Expt(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.Expt(&a)
	witness := e12Expt{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// utils
// Mul034By034 multiplication of sparse element (c0,0,0,c3,c4,0) by sparse element (d0,0,0,d3,d4,0)
func Mul034By034(d0, d3, d4, c0, c3, c4 *bn254.E2) [5]bn254.E2 {
	var z00, tmp, x0, x3, x4, x04, x03, x34 bn254.E2
	x0.Mul(c0, d0)
	x3.Mul(c3, d3)
	x4.Mul(c4, d4)
	tmp.Add(c0, c4)
	x04.Add(d0, d4).
		Mul(&x04, &tmp).
		Sub(&x04, &x0).
		Sub(&x04, &x4)
	tmp.Add(c0, c3)
	x03.Add(d0, d3).
		Mul(&x03, &tmp).
		Sub(&x03, &x0).
		Sub(&x03, &x3)
	tmp.Add(c3, c4)
	x34.Add(d3, d4).
		Mul(&x34, &tmp).
		Sub(&x34, &x3).
		Sub(&x34, &x4)

	z00.MulByNonResidue(&x4).
		Add(&z00, &x0)

	return [5]bn254.E2{z00, x3, x34, x03, x04}
}

type e12AliasAndSemiSparse struct {
	A          E12
	E3, E4     E2
	C3, C4     E2
	SqExpected E12
	WExpected  E12
}

func (circuit *e12AliasAndSemiSparse) Define(api frontend.API) error {
	e := NewExt12(api)
	// Mul(&A, &A) self-aliasing must match Square(&A)
	aliasSq := e.Mul(&circuit.A, &circuit.A)
	directSq := e.Square(&circuit.A)
	e.AssertIsEqual(aliasSq, &circuit.SqExpected)
	e.AssertIsEqual(directSq, &circuit.SqExpected)

	semi := e.Mul01379By01379(&circuit.E3, &circuit.E4, &circuit.C3, &circuit.C4)
	w := e.MulBy012346789(&circuit.A, semi)
	e.AssertIsEqual(w, &circuit.WExpected)
	return nil
}

func TestFp12AliasSemiSparseAndSmallField(t *testing.T) {
	assert := test.NewAssert(t)
	var a, sq, w bn254.E12
	_, _ = a.SetRandom()
	sq.Square(&a)

	var one, e3, e4, c3, c4 bn254.E2
	one.SetOne()
	_, _ = e3.SetRandom()
	_, _ = e4.SetRandom()
	_, _ = c3.SetRandom()
	_, _ = c4.SetRandom()

	w.Set(&a)
	w.MulBy034(&one, &e3, &e4)
	w.MulBy034(&one, &c3, &c4)

	mkWitness := func() *e12AliasAndSemiSparse {
		return &e12AliasAndSemiSparse{
			A:          FromE12(&a),
			E3:         FromE2(&e3),
			E4:         FromE2(&e4),
			C3:         FromE2(&c3),
			C4:         FromE2(&c4),
			SqExpected: FromE12(&sq),
			WExpected:  FromE12(&w),
		}
	}

	for _, builder := range []frontend.NewBuilder{r1cs.NewBuilder[constraint.U64], scs.NewBuilder[constraint.U64]} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &e12AliasAndSemiSparse{})
		assert.NoError(err)
		wt, err := frontend.NewWitness(mkWitness(), ecc.BN254.ScalarField())
		assert.NoError(err)
		assert.NoError(ccs.IsSolved(wt))
	}

	// Verify over small scalar fields (BabyBear / KoalaBear, extensionApi != nil).
	assert.CheckCircuit(
		&e12AliasAndSemiSparse{},
		test.WithValidAssignment(mkWitness()),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck(),
	)
}
