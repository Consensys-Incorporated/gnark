package fields_bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fp_bn "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type E12 struct {
	A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11 baseEl
}

type Ext12 struct {
	*Ext2
	api frontend.API
	fp  *curveF
}

func NewExt12(api frontend.API) *Ext12 {
	fp, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		panic(err)
	}
	return &Ext12{
		Ext2: NewExt2(api),
		api:  api,
		fp:   fp,
	}
}

func (e Ext12) Zero() *E12 {
	zero := e.fp.Zero()
	return &E12{
		A0:  *zero,
		A1:  *zero,
		A2:  *zero,
		A3:  *zero,
		A4:  *zero,
		A5:  *zero,
		A6:  *zero,
		A7:  *zero,
		A8:  *zero,
		A9:  *zero,
		A10: *zero,
		A11: *zero,
	}
}

func (e Ext12) One() *E12 {
	one := e.fp.One()
	zero := e.fp.Zero()
	return &E12{
		A0:  *one,
		A1:  *zero,
		A2:  *zero,
		A3:  *zero,
		A4:  *zero,
		A5:  *zero,
		A6:  *zero,
		A7:  *zero,
		A8:  *zero,
		A9:  *zero,
		A10: *zero,
		A11: *zero,
	}
}

func (e Ext12) Neg(x *E12) *E12 {
	a0 := e.fp.Neg(&x.A0)
	a1 := e.fp.Neg(&x.A1)
	a2 := e.fp.Neg(&x.A2)
	a3 := e.fp.Neg(&x.A3)
	a4 := e.fp.Neg(&x.A4)
	a5 := e.fp.Neg(&x.A5)
	a6 := e.fp.Neg(&x.A6)
	a7 := e.fp.Neg(&x.A7)
	a8 := e.fp.Neg(&x.A8)
	a9 := e.fp.Neg(&x.A9)
	a10 := e.fp.Neg(&x.A10)
	a11 := e.fp.Neg(&x.A11)

	return &E12{
		A0:  *a0,
		A1:  *a1,
		A2:  *a2,
		A3:  *a3,
		A4:  *a4,
		A5:  *a5,
		A6:  *a6,
		A7:  *a7,
		A8:  *a8,
		A9:  *a9,
		A10: *a10,
		A11: *a11,
	}
}

func (e Ext12) Add(x, y *E12) *E12 {
	a0 := e.fp.Add(&x.A0, &y.A0)
	a1 := e.fp.Add(&x.A1, &y.A1)
	a2 := e.fp.Add(&x.A2, &y.A2)
	a3 := e.fp.Add(&x.A3, &y.A3)
	a4 := e.fp.Add(&x.A4, &y.A4)
	a5 := e.fp.Add(&x.A5, &y.A5)
	a6 := e.fp.Add(&x.A6, &y.A6)
	a7 := e.fp.Add(&x.A7, &y.A7)
	a8 := e.fp.Add(&x.A8, &y.A8)
	a9 := e.fp.Add(&x.A9, &y.A9)
	a10 := e.fp.Add(&x.A10, &y.A10)
	a11 := e.fp.Add(&x.A11, &y.A11)

	return &E12{
		A0:  *a0,
		A1:  *a1,
		A2:  *a2,
		A3:  *a3,
		A4:  *a4,
		A5:  *a5,
		A6:  *a6,
		A7:  *a7,
		A8:  *a8,
		A9:  *a9,
		A10: *a10,
		A11: *a11,
	}
}

func (e Ext12) Sub(x, y *E12) *E12 {
	a0 := e.fp.Sub(&x.A0, &y.A0)
	a1 := e.fp.Sub(&x.A1, &y.A1)
	a2 := e.fp.Sub(&x.A2, &y.A2)
	a3 := e.fp.Sub(&x.A3, &y.A3)
	a4 := e.fp.Sub(&x.A4, &y.A4)
	a5 := e.fp.Sub(&x.A5, &y.A5)
	a6 := e.fp.Sub(&x.A6, &y.A6)
	a7 := e.fp.Sub(&x.A7, &y.A7)
	a8 := e.fp.Sub(&x.A8, &y.A8)
	a9 := e.fp.Sub(&x.A9, &y.A9)
	a10 := e.fp.Sub(&x.A10, &y.A10)
	a11 := e.fp.Sub(&x.A11, &y.A11)

	return &E12{
		A0:  *a0,
		A1:  *a1,
		A2:  *a2,
		A3:  *a3,
		A4:  *a4,
		A5:  *a5,
		A6:  *a6,
		A7:  *a7,
		A8:  *a8,
		A9:  *a9,
		A10: *a10,
		A11: *a11,
	}
}

func (e Ext12) Double(x *E12) *E12 {
	two := big.NewInt(2)
	a0 := e.fp.MulConst(&x.A0, two)
	a1 := e.fp.MulConst(&x.A1, two)
	a2 := e.fp.MulConst(&x.A2, two)
	a3 := e.fp.MulConst(&x.A3, two)
	a4 := e.fp.MulConst(&x.A4, two)
	a5 := e.fp.MulConst(&x.A5, two)
	a6 := e.fp.MulConst(&x.A6, two)
	a7 := e.fp.MulConst(&x.A7, two)
	a8 := e.fp.MulConst(&x.A8, two)
	a9 := e.fp.MulConst(&x.A9, two)
	a10 := e.fp.MulConst(&x.A10, two)
	a11 := e.fp.MulConst(&x.A11, two)

	return &E12{
		A0:  *a0,
		A1:  *a1,
		A2:  *a2,
		A3:  *a3,
		A4:  *a4,
		A5:  *a5,
		A6:  *a6,
		A7:  *a7,
		A8:  *a8,
		A9:  *a9,
		A10: *a10,
		A11: *a11,
	}
}

func (e Ext12) Conjugate(x *E12) *E12 {
	return &E12{
		A0:  x.A0,
		A1:  *e.fp.Neg(&x.A1),
		A2:  x.A2,
		A3:  *e.fp.Neg(&x.A3),
		A4:  x.A4,
		A5:  *e.fp.Neg(&x.A5),
		A6:  x.A6,
		A7:  *e.fp.Neg(&x.A7),
		A8:  x.A8,
		A9:  *e.fp.Neg(&x.A9),
		A10: x.A10,
		A11: *e.fp.Neg(&x.A11),
	}
}

func (e Ext12) Mul(x, y *E12) *E12 {
	return e.mulDirect(x, y)
}

func (e Ext12) mulDirect(a, b *E12) *E12 {

	// a = a11 w^11 + a10 w^10 + a9 w^9 + a8 w^8 + a7 w^7 + a6 w^6 + a5 w^5 + a4 w^4 + a3 w^3 + a2 w^2 + a1 w + a0
	// b = b11 w^11 + b10 w^10 + b9 w^9 + b8 w^8 + b7 w^7 + b6 w^6 + b5 w^5 + b4 w^4 + b3 w^3 + b2 w^2 + b1 w + b0
	//
	// Given that w^12 = 18 w^6 - 82, we can compute the product a * b as follows:
	//
	// a * b = d11 w^11 + d10 w^10 + d9 w^9 + d8 w^8 + d7 w^7 + d6 w^6 + d5 w^5 + d4 w^4 + d3 w^3 + d2 w^2 + d1 w + d0
	//
	// where:
	//
	// d0  =  c0  - 82 * c12 - 1476 * c18
	// d1  =  c1  - 82 * c13 - 1476 * c19
	// d2  =  c2  - 82 * c14 - 1476 * c20
	// d3  =  c3  - 82 * c15 - 1476 * c21
	// d4  =  c4  - 82 * c16 - 1476 * c22
	// d5  =  c5  - 82 * c17
	// d6  =  c6  + 18 * c12 + 242 * c18
	// d7  =  c7  + 18 * c13 + 242 * c19
	// d8  =  c8  + 18 * c14 + 242 * c20
	// d9  =  c9  + 18 * c15 + 242 * c21
	// d10 =  c10 + 18 * c16 + 242 * c22
	// d11 =  c11 + 18 * c17
	d := e.fp.MulPolyModTrinomial12(
		[12]*baseEl{&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5, &a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11},
		[12]*baseEl{&b.A0, &b.A1, &b.A2, &b.A3, &b.A4, &b.A5, &b.A6, &b.A7, &b.A8, &b.A9, &b.A10, &b.A11},
		18, -82,
	)
	return &E12{
		A0:  *d[0],
		A1:  *d[1],
		A2:  *d[2],
		A3:  *d[3],
		A4:  *d[4],
		A5:  *d[5],
		A6:  *d[6],
		A7:  *d[7],
		A8:  *d[8],
		A9:  *d[9],
		A10: *d[10],
		A11: *d[11],
	}
}

func (e Ext12) Square(x *E12) *E12 {
	return e.squareDirect(x)
}

func (e Ext12) squareDirect(a *E12) *E12 {
	af := [12]*baseEl{&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5, &a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11}
	d := e.fp.MulPolyModTrinomial12(af, af, 18, -82)
	return &E12{
		A0:  *d[0],
		A1:  *d[1],
		A2:  *d[2],
		A3:  *d[3],
		A4:  *d[4],
		A5:  *d[5],
		A6:  *d[6],
		A7:  *d[7],
		A8:  *d[8],
		A9:  *d[9],
		A10: *d[10],
		A11: *d[11],
	}
}

// Granger-Scott's cyclotomic square
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e Ext12) CyclotomicSquareGS(x *E12) *E12 {
	tower := e.ToTower(x)

	z := e.fp.EvalSystem([]emulated.PolySpec[emulated.BN254Fp]{
		{At: [][]*baseEl{{tower[8], tower[8]}, {tower[9], tower[9]}, {tower[8], tower[9]}, {tower[0], tower[0]}, {tower[1], tower[1]}, {tower[0]}}, Coefs: []int{27, -27, -6, 3, -3, -2}},
		{At: [][]*baseEl{{tower[8], tower[8]}, {tower[9], tower[9]}, {tower[8], tower[9]}, {tower[0], tower[1]}, {tower[1]}}, Coefs: []int{3, -3, 54, 6, -2}},
		{At: [][]*baseEl{{tower[4], tower[4]}, {tower[5], tower[5]}, {tower[4], tower[5]}, {tower[6], tower[6]}, {tower[7], tower[7]}, {tower[2]}}, Coefs: []int{27, -27, -6, 3, -3, -2}},
		{At: [][]*baseEl{{tower[4], tower[4]}, {tower[5], tower[5]}, {tower[4], tower[5]}, {tower[6], tower[7]}, {tower[3]}}, Coefs: []int{3, -3, 54, 6, -2}},
		{At: [][]*baseEl{{tower[10], tower[10]}, {tower[11], tower[11]}, {tower[10], tower[11]}, {tower[2], tower[2]}, {tower[3], tower[3]}, {tower[4]}}, Coefs: []int{27, -27, -6, 3, -3, -2}},
		{At: [][]*baseEl{{tower[10], tower[10]}, {tower[11], tower[11]}, {tower[10], tower[11]}, {tower[2], tower[3]}, {tower[5]}}, Coefs: []int{3, -3, 54, 6, -2}},
		{At: [][]*baseEl{{tower[2], tower[10]}, {tower[3], tower[11]}, {tower[2], tower[11]}, {tower[3], tower[10]}, {tower[6]}}, Coefs: []int{54, -54, -6, -6, 2}},
		{At: [][]*baseEl{{tower[2], tower[10]}, {tower[3], tower[11]}, {tower[2], tower[11]}, {tower[3], tower[10]}, {tower[7]}}, Coefs: []int{6, -6, 54, 54, 2}},
		{At: [][]*baseEl{{tower[0], tower[8]}, {tower[1], tower[9]}, {tower[8]}}, Coefs: []int{6, -6, 2}},
		{At: [][]*baseEl{{tower[0], tower[9]}, {tower[1], tower[8]}, {tower[9]}}, Coefs: []int{6, 6, 2}},
		{At: [][]*baseEl{{tower[4], tower[6]}, {tower[5], tower[7]}, {tower[10]}}, Coefs: []int{6, -6, 2}},
		{At: [][]*baseEl{{tower[4], tower[7]}, {tower[5], tower[6]}, {tower[11]}}, Coefs: []int{6, 6, 2}},
	})

	return e.FromTower([12]*baseEl{z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7], z[8], z[9], z[10], z[11]})
}

func (e Ext12) Inverse(x *E12) *E12 {
	res, err := e.fp.NewHint(inverseE12Hint, 12, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5, &x.A6, &x.A7, &x.A8, &x.A9, &x.A10, &x.A11)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E12{A0: *res[0], A1: *res[1], A2: *res[2], A3: *res[3], A4: *res[4], A5: *res[5], A6: *res[6], A7: *res[7], A8: *res[8], A9: *res[9], A10: *res[10], A11: *res[11]}
	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext12) DivUnchecked(x, y *E12) *E12 {
	res, err := e.fp.NewHint(divE12Hint, 12, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5, &x.A6, &x.A7, &x.A8, &x.A9, &x.A10, &x.A11, &y.A0, &y.A1, &y.A2, &y.A3, &y.A4, &y.A5, &y.A6, &y.A7, &y.A8, &y.A9, &y.A10, &y.A11)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E12{A0: *res[0], A1: *res[1], A2: *res[2], A3: *res[3], A4: *res[4], A5: *res[5], A6: *res[6], A7: *res[7], A8: *res[8], A9: *res[9], A10: *res[10], A11: *res[11]}

	// x = div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div

}

func (e Ext12) AssertIsEqual(a, b *E12) {
	e.fp.AssertIsEqual(&a.A0, &b.A0)
	e.fp.AssertIsEqual(&a.A1, &b.A1)
	e.fp.AssertIsEqual(&a.A2, &b.A2)
	e.fp.AssertIsEqual(&a.A3, &b.A3)
	e.fp.AssertIsEqual(&a.A4, &b.A4)
	e.fp.AssertIsEqual(&a.A5, &b.A5)
	e.fp.AssertIsEqual(&a.A6, &b.A6)
	e.fp.AssertIsEqual(&a.A7, &b.A7)
	e.fp.AssertIsEqual(&a.A8, &b.A8)
	e.fp.AssertIsEqual(&a.A9, &b.A9)
	e.fp.AssertIsEqual(&a.A10, &b.A10)
	e.fp.AssertIsEqual(&a.A11, &b.A11)
}

func (e Ext12) IsEqual(x, y *E12) frontend.Variable {
	diff0 := e.fp.Sub(&x.A0, &y.A0)
	diff1 := e.fp.Sub(&x.A1, &y.A1)
	diff2 := e.fp.Sub(&x.A2, &y.A2)
	diff3 := e.fp.Sub(&x.A3, &y.A3)
	diff4 := e.fp.Sub(&x.A4, &y.A4)
	diff5 := e.fp.Sub(&x.A5, &y.A5)
	diff6 := e.fp.Sub(&x.A6, &y.A6)
	diff7 := e.fp.Sub(&x.A7, &y.A7)
	diff8 := e.fp.Sub(&x.A8, &y.A8)
	diff9 := e.fp.Sub(&x.A9, &y.A9)
	diff10 := e.fp.Sub(&x.A10, &y.A10)
	diff11 := e.fp.Sub(&x.A11, &y.A11)
	isZero0 := e.fp.IsZero(diff0)
	isZero1 := e.fp.IsZero(diff1)
	isZero2 := e.fp.IsZero(diff2)
	isZero3 := e.fp.IsZero(diff3)
	isZero4 := e.fp.IsZero(diff4)
	isZero5 := e.fp.IsZero(diff5)
	isZero6 := e.fp.IsZero(diff6)
	isZero7 := e.fp.IsZero(diff7)
	isZero8 := e.fp.IsZero(diff8)
	isZero9 := e.fp.IsZero(diff9)
	isZero10 := e.fp.IsZero(diff10)
	isZero11 := e.fp.IsZero(diff11)

	return e.api.And(
		e.api.And(
			e.api.And(e.api.And(isZero0, isZero1), e.api.And(isZero2, isZero3)),
			e.api.And(e.api.And(isZero4, isZero5), e.api.And(isZero6, isZero7)),
		),
		e.api.And(e.api.And(isZero8, isZero9), e.api.And(isZero10, isZero11)),
	)
}

func (e Ext12) Copy(x *E12) *E12 {
	return &E12{
		A0:  x.A0,
		A1:  x.A1,
		A2:  x.A2,
		A3:  x.A3,
		A4:  x.A4,
		A5:  x.A5,
		A6:  x.A6,
		A7:  x.A7,
		A8:  x.A8,
		A9:  x.A9,
		A10: x.A10,
		A11: x.A11,
	}
}

func (e Ext12) Frobenius(a *E12) *E12 {
	tower := e.ToTower(a)

	tower[1] = e.fp.Neg(tower[1])
	tower[3] = e.fp.Neg(tower[3])
	tower[5] = e.fp.Neg(tower[5])
	tower[7] = e.fp.Neg(tower[7])
	tower[9] = e.fp.Neg(tower[9])
	tower[11] = e.fp.Neg(tower[11])

	t1 := e.Ext2.MulByNonResidue1Power2(&E2{A0: *tower[2], A1: *tower[3]})
	t2 := e.Ext2.MulByNonResidue1Power4(&E2{A0: *tower[4], A1: *tower[5]})
	t3 := e.Ext2.MulByNonResidue1Power1(&E2{A0: *tower[6], A1: *tower[7]})
	t4 := e.Ext2.MulByNonResidue1Power3(&E2{A0: *tower[8], A1: *tower[9]})
	t5 := e.Ext2.MulByNonResidue1Power5(&E2{A0: *tower[10], A1: *tower[11]})

	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(&t3.A0, e.fp.MulConst(&t3.A1, nine))
	A2 := e.fp.Sub(&t1.A0, e.fp.MulConst(&t1.A1, nine))
	A3 := e.fp.Sub(&t4.A0, e.fp.MulConst(&t4.A1, nine))
	A4 := e.fp.Sub(&t2.A0, e.fp.MulConst(&t2.A1, nine))
	A5 := e.fp.Sub(&t5.A0, e.fp.MulConst(&t5.A1, nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  t3.A1,
		A8:  t1.A1,
		A9:  t4.A1,
		A10: t2.A1,
		A11: t5.A1,
	}
}

func (e Ext12) FrobeniusSquare(a *E12) *E12 {
	tower := e.ToTower(a)

	t1 := e.Ext2.MulByNonResidue2Power2(&E2{A0: *tower[2], A1: *tower[3]})
	t2 := e.Ext2.MulByNonResidue2Power4(&E2{A0: *tower[4], A1: *tower[5]})
	t3 := e.Ext2.MulByNonResidue2Power1(&E2{A0: *tower[6], A1: *tower[7]})
	t4 := e.Ext2.MulByNonResidue2Power3(&E2{A0: *tower[8], A1: *tower[9]})
	t5 := e.Ext2.MulByNonResidue2Power5(&E2{A0: *tower[10], A1: *tower[11]})

	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(&t3.A0, e.fp.MulConst(&t3.A1, nine))
	A2 := e.fp.Sub(&t1.A0, e.fp.MulConst(&t1.A1, nine))
	A3 := e.fp.Sub(&t4.A0, e.fp.MulConst(&t4.A1, nine))
	A4 := e.fp.Sub(&t2.A0, e.fp.MulConst(&t2.A1, nine))
	A5 := e.fp.Sub(&t5.A0, e.fp.MulConst(&t5.A1, nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  t3.A1,
		A8:  t1.A1,
		A9:  t4.A1,
		A10: t2.A1,
		A11: t5.A1,
	}
}

func (e Ext12) FrobeniusCube(a *E12) *E12 {
	tower := e.ToTower(a)

	tower[1] = e.fp.Neg(tower[1])
	tower[3] = e.fp.Neg(tower[3])
	tower[5] = e.fp.Neg(tower[5])
	tower[7] = e.fp.Neg(tower[7])
	tower[9] = e.fp.Neg(tower[9])
	tower[11] = e.fp.Neg(tower[11])

	t1 := e.Ext2.MulByNonResidue3Power2(&E2{A0: *tower[2], A1: *tower[3]})
	t2 := e.Ext2.MulByNonResidue3Power4(&E2{A0: *tower[4], A1: *tower[5]})
	t3 := e.Ext2.MulByNonResidue3Power1(&E2{A0: *tower[6], A1: *tower[7]})
	t4 := e.Ext2.MulByNonResidue3Power3(&E2{A0: *tower[8], A1: *tower[9]})
	t5 := e.Ext2.MulByNonResidue3Power5(&E2{A0: *tower[10], A1: *tower[11]})

	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(&t3.A0, e.fp.MulConst(&t3.A1, nine))
	A2 := e.fp.Sub(&t1.A0, e.fp.MulConst(&t1.A1, nine))
	A3 := e.fp.Sub(&t4.A0, e.fp.MulConst(&t4.A1, nine))
	A4 := e.fp.Sub(&t2.A0, e.fp.MulConst(&t2.A1, nine))
	A5 := e.fp.Sub(&t5.A0, e.fp.MulConst(&t5.A1, nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  t3.A1,
		A8:  t1.A1,
		A9:  t4.A1,
		A10: t2.A1,
		A11: t5.A1,
	}
}

// tower to direct extension conversion
func FromE12(a *bn254.E12) E12 {
	// gnark-crypto uses a quadratic over cubic over quadratic 12th extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	// 		a000 a001 a010 a011 a020 a021 a100 a101 a110 a111 a120 a121
	//      a0   a1   a2   a3   a4   a5   a6   a7   a8   a9   a10  a11
	//
	//     A0  =  a000 - 9 * a001
	//     A1  =  a100 - 9 * a101
	//     A2  =  a010 - 9 * a011
	//     A3  =  a110 - 9 * a111
	//     A4  =  a020 - 9 * a021
	//     A5  =  a120 - 9 * a121
	//     A6  =  a001
	//     A7  =  a101
	//     A8  =  a011
	//     A9  =  a111
	//     A10 =  a021
	//     A11 =  a121

	var c0, c1, c2, c3, c4, c5, t fp_bn.Element
	t.SetUint64(9).Mul(&t, &a.C0.B0.A1)
	c0.Sub(&a.C0.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B0.A1)
	c1.Sub(&a.C1.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B1.A1)
	c2.Sub(&a.C0.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B1.A1)
	c3.Sub(&a.C1.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B2.A1)
	c4.Sub(&a.C0.B2.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B2.A1)
	c5.Sub(&a.C1.B2.A0, &t)

	return E12{
		A0:  emulated.ValueOf[emulated.BN254Fp](c0),
		A1:  emulated.ValueOf[emulated.BN254Fp](c1),
		A2:  emulated.ValueOf[emulated.BN254Fp](c2),
		A3:  emulated.ValueOf[emulated.BN254Fp](c3),
		A4:  emulated.ValueOf[emulated.BN254Fp](c4),
		A5:  emulated.ValueOf[emulated.BN254Fp](c5),
		A6:  emulated.ValueOf[emulated.BN254Fp](a.C0.B0.A1),
		A7:  emulated.ValueOf[emulated.BN254Fp](a.C1.B0.A1),
		A8:  emulated.ValueOf[emulated.BN254Fp](a.C0.B1.A1),
		A9:  emulated.ValueOf[emulated.BN254Fp](a.C1.B1.A1),
		A10: emulated.ValueOf[emulated.BN254Fp](a.C0.B2.A1),
		A11: emulated.ValueOf[emulated.BN254Fp](a.C1.B2.A1),
	}
}

func (e Ext12) ToTower(a *E12) [12]*baseEl {
	// gnark-crypto uses a quadratic over cubic over quadratic 12th extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	//
	//	   tower  =  a000 a001 a010 a011 a020 a021 a100 a101 a110 a111 a120 a121
	// 	   direct = a0   a1   a2   a3   a4   a5   a6   a7   a8   a9   a10  a11
	//
	//     a000 = A0  +  9 * A6
	//     a001 = A6
	//     a010 = A2  +  9 * A8
	//     a011 = A8
	//     a020 = A4  +  9 * A10
	//     a021 = A10
	//     a100 = A1  +  9 * A7
	//     a101 = A7
	//     a110 = A3  +  9 * A9
	//     a111 = A9
	//     a120 = A5  +  9 * A11
	//     a121 = A11
	nine := big.NewInt(9)
	a000 := e.fp.Add(&a.A0, e.fp.MulConst(&a.A6, nine))
	a001 := &a.A6
	a010 := e.fp.Add(&a.A2, e.fp.MulConst(&a.A8, nine))
	a011 := &a.A8
	a020 := e.fp.Add(&a.A4, e.fp.MulConst(&a.A10, nine))
	a021 := &a.A10
	a100 := e.fp.Add(&a.A1, e.fp.MulConst(&a.A7, nine))
	a101 := &a.A7
	a110 := e.fp.Add(&a.A3, e.fp.MulConst(&a.A9, nine))
	a111 := &a.A9
	a120 := e.fp.Add(&a.A5, e.fp.MulConst(&a.A11, nine))
	a121 := &a.A11

	tower := [12]*baseEl{a000, a001, a010, a011, a020, a021, a100, a101, a110, a111, a120, a121}
	return tower
}

func (e Ext12) FromTower(tower [12]*baseEl) *E12 {
	// gnark-crypto uses a quadratic over cubic over quadratic 12th extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	//
	//	   tower  =  a000 a001 a010 a011 a020 a021 a100 a101 a110 a111 a120 a121
	// 	   direct = a0   a1   a2   a3   a4   a5   a6   a7   a8   a9   a10  a11
	//
	//     A0  =  a000 - 9 * a001
	//     A1  =  a100 - 9 * a101
	//     A2  =  a010 - 9 * a011
	//     A3  =  a110 - 9 * a111
	//     A4  =  a020 - 9 * a021
	//     A5  =  a120 - 9 * a121
	//     A6  =  a001
	//     A7  =  a101
	//     A8  =  a011
	//     A9  =  a111
	//     A10 =  a021
	//     A11 =  a121
	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(tower[6], e.fp.MulConst(tower[7], nine))
	A2 := e.fp.Sub(tower[2], e.fp.MulConst(tower[3], nine))
	A3 := e.fp.Sub(tower[8], e.fp.MulConst(tower[9], nine))
	A4 := e.fp.Sub(tower[4], e.fp.MulConst(tower[5], nine))
	A5 := e.fp.Sub(tower[10], e.fp.MulConst(tower[11], nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  *tower[7],
		A8:  *tower[3],
		A9:  *tower[9],
		A10: *tower[5],
		A11: *tower[11],
	}
}
