package fields_bls12381

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
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
	var a bls12381.E12
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
	var a, b, c bls12381.E12
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
	var a, b, c bls12381.E12
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
	var a, b, c bls12381.E12
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
	var a, c bls12381.E12
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
	var a, c bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bls12381.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.CyclotomicSquare(&a)

	witness := e12SquareGS{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12SquareGS{}, &witness, ecc.BN254.ScalarField())
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
	var a, b, c bls12381.E12
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
	var a, c bls12381.E12
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
	var a, c bls12381.E12
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
	var a, c bls12381.E12
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
	var a, c bls12381.E12
	_, _ = a.SetRandom()

	c.FrobeniusSquare(&a)

	witness := FrobeniusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&FrobeniusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Expt struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Expt) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.ExptNeg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestFp12Expt(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E12
	_, _ = a.SetRandom()

	var xGen big.Int
	xGen.SetString("15132376222941642752", 10)
	c.Exp(a, &xGen)
	witness := e12Expt{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12ExptGS struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12ExptGS) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.ExptGS(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestFp12ExptGS(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bls12381.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.Expt(&a)
	witness := e12ExptGS{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12ExptGS{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12MulBy02368 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *e12MulBy02368) Define(api frontend.API) error {
	e := NewExt12(api)
	res := e.MulBy02368(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy02368(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bls12381.E12
	_, _ = a.SetRandom()
	var one, b, c bls12381.E2
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy014(&b, &c, &one)

	witness := e12MulBy02368{
		A: FromE12(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12MulBy02368{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12BLS12AliasAndSemiSparse struct {
	A          E12
	C00, C10   E2
	C01, C11   E2
	SqExpected E12
	WExpected  E12
}

func (circuit *e12BLS12AliasAndSemiSparse) Define(api frontend.API) error {
	e := NewExt12(api)
	aliasSq := e.Mul(&circuit.A, &circuit.A)
	directSq := e.Square(&circuit.A)
	e.AssertIsEqual(aliasSq, &circuit.SqExpected)
	e.AssertIsEqual(directSq, &circuit.SqExpected)

	w := e.Mul02368By02368ThenMul(&circuit.A, &circuit.C00, &circuit.C10, &circuit.C01, &circuit.C11)
	e.AssertIsEqual(w, &circuit.WExpected)
	return nil
}

func TestFp12AliasSemiSparseAndSmallField(t *testing.T) {
	assert := test.NewAssert(t)
	var a, sq, w bls12381.E12
	_, _ = a.SetRandom()
	sq.Square(&a)

	var one, c00, c10, c01, c11 bls12381.E2
	one.SetOne()
	_, _ = c00.SetRandom()
	_, _ = c10.SetRandom()
	_, _ = c01.SetRandom()
	_, _ = c11.SetRandom()

	w.Set(&a)
	w.MulBy014(&c00, &c10, &one)
	w.MulBy014(&c01, &c11, &one)

	mkWitness := func() *e12BLS12AliasAndSemiSparse {
		return &e12BLS12AliasAndSemiSparse{
			A:          FromE12(&a),
			C00:        FromE2(&c00),
			C10:        FromE2(&c10),
			C01:        FromE2(&c01),
			C11:        FromE2(&c11),
			SqExpected: FromE12(&sq),
			WExpected:  FromE12(&w),
		}
	}

	for _, builder := range []frontend.NewBuilder{r1cs.NewBuilder[constraint.U64], scs.NewBuilder[constraint.U64]} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &e12BLS12AliasAndSemiSparse{})
		assert.NoError(err)
		wt, err := frontend.NewWitness(mkWitness(), ecc.BN254.ScalarField())
		assert.NoError(err)
		assert.NoError(ccs.IsSolved(wt))
	}

	// Verify over small scalar fields (BabyBear / KoalaBear, extensionApi != nil).
	assert.CheckCircuit(
		&e12BLS12AliasAndSemiSparse{},
		test.WithValidAssignment(mkWitness()),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck(),
	)
}
