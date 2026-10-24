// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/frontendtype"
)

// E6 element in a quadratic extension
type E6 struct {
	B0, B1, B2 E2
}

// SetZero returns a newly allocated element equal to 0
func (e *E6) SetZero() *E6 {
	e.B0.SetZero()
	e.B1.SetZero()
	e.B2.SetZero()
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E6) SetOne() *E6 {
	e.B0.SetOne()
	e.B1.SetZero()
	e.B2.SetZero()
	return e
}

func (e *E6) assign(e1 []frontend.Variable) {
	e.B0.A0 = e1[0]
	e.B0.A1 = e1[1]
	e.B1.A0 = e1[2]
	e.B1.A1 = e1[3]
	e.B2.A0 = e1[4]
	e.B2.A1 = e1[5]
}

// Double e6 elmt
func (e *E6) Double(api frontend.API, e1 E6) *E6 {
	e.B0.Double(api, e1.B0)
	e.B1.Double(api, e1.B1)
	e.B2.Double(api, e1.B2)
	return e
}

// Add creates a fp6elmt from fp elmts
func (e *E6) Add(api frontend.API, e1, e2 E6) *E6 {

	e.B0.Add(api, e1.B0, e2.B0)
	e.B1.Add(api, e1.B1, e2.B1)
	e.B2.Add(api, e1.B2, e2.B2)

	return e
}

// NewFp6Zero creates a new
func NewFp6Zero(api frontend.API) *E6 {
	return &E6{
		B0: E2{0, 0},
		B1: E2{0, 0},
		B2: E2{0, 0},
	}
}

// Sub creates a fp6elmt from fp elmts
func (e *E6) Sub(api frontend.API, e1, e2 E6) *E6 {

	e.B0.Sub(api, e1.B0, e2.B0)
	e.B1.Sub(api, e1.B1, e2.B1)
	e.B2.Sub(api, e1.B2, e2.B2)

	return e
}

// Neg negates an Fp6 elmt
func (e *E6) Neg(api frontend.API, e1 E6) *E6 {
	e.B0.Neg(api, e1.B0)
	e.B1.Neg(api, e1.B1)
	e.B2.Neg(api, e1.B2)
	return e
}

// Mul multiplies two E6 elmts
func (e *E6) Mul(api frontend.API, e1, e2 E6) *E6 {
	if ft, ok := api.Compiler().(frontendtype.FrontendTyper); ok {
		switch ft.FrontendType() {
		case frontendtype.R1CS:
			return e.mulToom3OverKaratsuba(api, e1, e2)
		case frontendtype.SCS:
			if _, ok := api.(frontend.Committer); ok {
				return e.mulSZ(api, e1, e2)
			}
			return e.mulKaratsubaOverKaratsuba(api, e1, e2)
		}
	}
	return e.mulKaratsubaOverKaratsuba(api, e1, e2)
}

// mulSZ computes e = e1 * e2 using the Schwartz-Zippel technique.
// P(X) = X^6 + 5. Soundness: 10/p ≈ 2^{-373}.
func (e *E6) mulSZ(api frontend.API, e1, e2 E6) *E6 {
	aCoeffs := e6Coeffs(&e1)
	bCoeffs := e6Coeffs(&e2)
	in := make([]frontend.Variable, 12)
	copy(in[:6], aCoeffs[:])
	copy(in[6:], bCoeffs[:])

	out, err := api.Compiler().NewHint(mulE6SZHint, 11, in...)
	if err != nil {
		panic(err)
	}

	assignE6(e, out[:6])

	var q [5]frontend.Variable
	copy(q[:], out[6:11])

	aMono := towerToMonomial6(aCoeffs)
	bMono := towerToMonomial6(bCoeffs)
	cMono := towerToMonomial6(e6Coeffs(e))

	addSZCheck(api, aMono[:], bMono[:], cMono[:], q[:])

	return e
}

func (e *E6) mulKaratsubaOverKaratsuba(api frontend.API, e1, e2 E6) *E6 {
	// Karatsuba over Karatsuba:
	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var t0, t1, t2, c0, c1, c2, tmp E2
	t0.Mul(api, e1.B0, e2.B0)
	t1.Mul(api, e1.B1, e2.B1)
	t2.Mul(api, e1.B2, e2.B2)

	c0.Add(api, e1.B1, e1.B2)
	tmp.Add(api, e2.B1, e2.B2)
	c0.Mul(api, c0, tmp).
		Sub(api, c0, t1).
		Sub(api, c0, t2).
		MulByNonResidue(api, c0).
		Add(api, c0, t0)

	c1.Add(api, e1.B0, e1.B1)
	tmp.Add(api, e2.B0, e2.B1)
	c1.Mul(api, c1, tmp).
		Sub(api, c1, t0).
		Sub(api, c1, t1)
	tmp.MulByNonResidue(api, t2)
	c1.Add(api, c1, tmp)

	tmp.Add(api, e1.B0, e1.B2)
	c2.Add(api, e2.B0, e2.B2).
		Mul(api, c2, tmp).
		Sub(api, c2, t0).
		Sub(api, c2, t2).
		Add(api, c2, t1)

	e.B0 = c0
	e.B1 = c1
	e.B2 = c2

	return e
}

func (e *E6) mulToom3OverKaratsuba(api frontend.API, e1, e2 E6) *E6 {
	// Toom-Cook-3x over Karatsuba:
	// We start by computing five interpolation points – these are evaluations of
	// the product x(u)y(u) with u ∈ {0, ±1, 2, ∞}:
	//
	// v0 = x(0)y(0) = x.A0 * y.A0
	// v1 = x(1)y(1) = (x.A0 + x.A1 + x.A2)(y.A0 + y.A1 + y.A2)
	// v2 = x(−1)y(−1) = (x.A0 − x.A1 + x.A2)(y.A0 − y.A1 + y.A2)
	// v3 = x(2)y(2) = (x.A0 + 2x.A1 + 4x.A2)(y.A0 + 2y.A1 + 4y.A2)
	// v4 = x(∞)y(∞) = x.A2 * y.A2
	var v0, v1, v2, v3, v4, t1, t2, t3 E2

	v0.Mul(api, e1.B0, e2.B0)

	t1.Add(api, e1.B0, e1.B2)
	t2.Add(api, e2.B0, e2.B2)
	t3.Add(api, t2, e2.B1)
	v1.Add(api, t1, e1.B1)
	v1.Mul(api, v1, t3)

	t3.Sub(api, t2, e2.B1)
	v2.Sub(api, t1, e1.B1)
	v2.Mul(api, v2, t3)

	t1.MulByFp(api, e1.B1, big.NewInt(2))
	t2.MulByFp(api, e1.B2, big.NewInt(4))
	v3.Add(api, t1, t2)
	v3.Add(api, v3, e1.B0)
	t1.MulByFp(api, e2.B1, big.NewInt(2))
	t2.MulByFp(api, e2.B2, big.NewInt(4))
	t3.Add(api, t1, t2)
	t3.Add(api, t3, e2.B0)
	v3.Mul(api, v3, t3)

	v4.Mul(api, e1.B2, e2.B2)

	// Then the interpolation is performed as:
	//
	// a0 = v0 + β((1/2)v0 − (1/2)v1 − (1/6)v2 + (1/6)v3 − 2v4)
	// a1 = −(1/2)v0 + v1 − (1/3)v2 − (1/6)v3 + 2v4 + βv4
	// a2 = −v0 + (1/2)v1 + (1/2)v2 − v4
	//
	// where β is the cubic non-residue.
	//
	// In-circuit, we compute 6*x*y as
	// c0 = 6v0 + β(3v0 − 3v1 − v2 + v3 − 12v4)
	// a1 = -(3v0 + 2v2 + v3) + 6(v1 + 2v4 + βv4)
	// a2 = 3(v1 + v2 - 2(v0 + v4))
	//
	// and then divide a0, a1 and a2 by 6 using a hint.
	var a0, a1, a2 E2
	a0.MulByFp(api, v0, big.NewInt(6))
	t1.Sub(api, v0, v1)
	t1.MulByFp(api, t1, big.NewInt(3))
	t1.Sub(api, t1, v2)
	t1.Add(api, t1, v3)
	t2.MulByFp(api, v4, big.NewInt(12))
	t1.Sub(api, t1, t2)
	t1.MulByNonResidue(api, t1)
	a0.Add(api, a0, t1)

	a1.MulByFp(api, v0, big.NewInt(3))
	t1.MulByFp(api, v2, big.NewInt(2))
	a1.Add(api, a1, t1)
	a1.Add(api, a1, v3)
	t1.MulByFp(api, v4, big.NewInt(2))
	t1.Add(api, t1, v1)
	t2.MulByNonResidue(api, v4)
	t1.Add(api, t1, t2)
	t1.MulByFp(api, t1, big.NewInt(6))
	a1.Sub(api, t1, a1)

	a2.Add(api, v1, v2)
	a2.MulByFp(api, a2, big.NewInt(3))
	t1.Add(api, v0, v4)
	t1.MulByFp(api, t1, big.NewInt(6))
	a2.Sub(api, a2, t1)

	e.B0.A0 = api.Div(a0.A0, 6)
	e.B0.A1 = api.Div(a0.A1, 6)
	e.B1.A0 = api.Div(a1.A0, 6)
	e.B1.A1 = api.Div(a1.A1, 6)
	e.B2.A0 = api.Div(a2.A0, 6)
	e.B2.A1 = api.Div(a2.A1, 6)

	return e
}

func (e *E6) Mul0By01(api frontend.API, a0, b0, b1 E2) *E6 {

	var t0, c1 E2

	t0.Mul(api, a0, b0)
	c1.Add(api, b0, b1)
	c1.Mul(api, c1, a0).Sub(api, c1, t0)

	e.B0 = t0
	e.B1 = c1
	e.B2 = E2{0, 0}

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) MulByFp2(api frontend.API, e1 E6, e2 E2) *E6 {
	res := E6{}

	res.B0.Mul(api, e1.B0, e2)
	res.B1.Mul(api, e1.B1, e2)
	res.B2.Mul(api, e1.B2, e2)

	e.B0 = res.B0
	e.B1 = res.B1
	e.B2 = res.B2

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F²)
func (e *E6) MulByNonResidue(api frontend.API, e1 E6) *E6 {
	res := E6{}
	res.B0.MulByNonResidue(api, e1.B2)
	e.B1 = e1.B0
	e.B2 = e1.B1
	e.B0 = res.B0
	return e
}

// Square sets z to the E6 product of x,x, returns e
func (e *E6) Square(api frontend.API, x E6) *E6 {
	if ft, ok := api.Compiler().(frontendtype.FrontendTyper); ok {
		if ft.FrontendType() == frontendtype.SCS {
			if _, ok := api.(frontend.Committer); ok {
				return e.squareSZ(api, x)
			}
		}
	}
	return e.squareKaratsuba(api, x)
}

func (e *E6) squareKaratsuba(api frontend.API, x E6) *E6 {
	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c4, c5, c1, c2, c3, c0 E2
	c4.Mul(api, x.B0, x.B1).Double(api, c4)
	c5.Square(api, x.B2)
	c1.MulByNonResidue(api, c5).Add(api, c1, c4)
	c2.Sub(api, c4, c5)
	c3.Square(api, x.B0)
	c4.Sub(api, x.B0, x.B1).Add(api, c4, x.B2)
	c5.Mul(api, x.B1, x.B2).Double(api, c5)
	c4.Square(api, c4)
	c0.MulByNonResidue(api, c5).Add(api, c0, c3)
	e.B2.Add(api, c2, c4).Add(api, e.B2, c5).Sub(api, e.B2, c3)
	e.B0 = c0
	e.B1 = c1

	return e
}

func (e *E6) squareSZ(api frontend.API, x E6) *E6 {
	aCoeffs := e6Coeffs(&x)
	in := make([]frontend.Variable, 6)
	copy(in, aCoeffs[:])

	out, err := api.Compiler().NewHint(squareE6SZHint, 11, in...)
	if err != nil {
		panic(err)
	}

	assignE6(e, out[:6])

	var q [5]frontend.Variable
	copy(q[:], out[6:11])

	aMono := towerToMonomial6(aCoeffs)
	cMono := towerToMonomial6(e6Coeffs(e))

	addSZSquareCheck(api, aMono[:], cMono[:], q[:])

	return e
}

// DivUnchecked e6 elmts
func (e *E6) DivUnchecked(api frontend.API, e1, e2 E6) *E6 {

	res, err := api.NewHint(divE6Hint, 6, e1.B0.A0, e1.B0.A1, e1.B1.A0, e1.B1.A1, e1.B2.A0, e1.B2.A1, e2.B0.A0, e2.B0.A1, e2.B1.A0, e2.B1.A1, e2.B2.A0, e2.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E6
	e3.assign(res[:6])
	one.SetOne()

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:6])

	return e
}

// Inverse e6 elmts
func (e *E6) Inverse(api frontend.API, e1 E6) *E6 {

	res, err := api.NewHint(inverseE6Hint, 6, e1.B0.A0, e1.B0.A1, e1.B1.A0, e1.B1.A1, e1.B2.A0, e1.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E6
	e3.assign(res[:6])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:6])

	return e
}

// Assign a value to self (witness assignment)
func (e *E6) Assign(a *bls12377.E6) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
	e.B2.Assign(&a.B2)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E6) AssertIsEqual(api frontend.API, other E6) {
	e.B0.AssertIsEqual(api, other.B0)
	e.B1.AssertIsEqual(api, other.B1)
	e.B2.AssertIsEqual(api, other.B2)
}

// IsEqual returns 1 if e is equal to other, 0 otherwise
func (e *E6) IsEqual(api frontend.API, other E6) frontend.Variable {
	b0Equal := e.B0.IsEqual(api, other.B0)
	b1Equal := e.B1.IsEqual(api, other.B1)
	b2Equal := e.B2.IsEqual(api, other.B2)
	// inputs are already boolean, so multiplication suffices.
	isEqual := api.Mul(b0Equal, b1Equal, b2Equal)
	api.Compiler().MarkBoolean(isEqual)
	return isEqual
}

// MulByE2 multiplies an element in E6 by an element in E2
func (e *E6) MulByE2(api frontend.API, e1 E6, e2 E2) *E6 {
	e.B0.Mul(api, e1.B0, e2)
	e.B1.Mul(api, e1.B1, e2)
	e.B2.Mul(api, e1.B2, e2)
	return e
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e *E6) MulBy01(api frontend.API, c0, c1 E2) *E6 {
	if ft, ok := api.Compiler().(frontendtype.FrontendTyper); ok {
		if ft.FrontendType() == frontendtype.SCS {
			if _, ok := api.(frontend.Committer); ok {
				return e.mulBy01SZ(api, c0, c1)
			}
		}
	}
	return e.mulBy01Karatsuba(api, c0, c1)
}

// mulBy01SZ computes e = e * sparse(c0, c1, 0) using SZ.
// Sparse monomial indices: 0, 1, 3, 4 are variable; 2, 5 are zero.
func (e *E6) mulBy01SZ(api frontend.API, c0, c1 E2) *E6 {
	aCoeffs := e6Coeffs(e)
	in := make([]frontend.Variable, 10)
	copy(in[:6], aCoeffs[:])
	in[6] = c0.A0
	in[7] = c0.A1
	in[8] = c1.A0
	in[9] = c1.A1

	out, err := api.Compiler().NewHint(mulBy01E6SZHint, 11, in...)
	if err != nil {
		panic(err)
	}

	assignE6(e, out[:6])

	var q [5]frontend.Variable
	copy(q[:], out[6:11])

	aMono := towerToMonomial6(aCoeffs)
	cMono := towerToMonomial6(e6Coeffs(e))

	// sparse b: tower = [c0.A0, c0.A1, c1.A0, c1.A1, 0, 0]
	// monomial = [c0.A0, c1.A0, 0, c0.A1, c1.A1, 0]
	var bMono [6]frontend.Variable
	bMono[0] = c0.A0
	bMono[1] = c1.A0
	bMono[2] = 0
	bMono[3] = c0.A1
	bMono[4] = c1.A1
	bMono[5] = 0

	addSZCheck(api, aMono[:], bMono[:], cMono[:], q[:])

	return e
}

func (e *E6) mulBy01Karatsuba(api frontend.API, c0, c1 E2) *E6 {
	var a, b, tmp, t0, t1, t2 E2

	a.Mul(api, e.B0, c0)
	b.Mul(api, e.B1, c1)

	tmp.Add(api, e.B1, e.B2)
	t0.Mul(api, c1, tmp)
	t0.Sub(api, t0, b)
	t0.MulByNonResidue(api, t0)
	t0.Add(api, t0, a)

	// for t2, schoolbook is faster than karatsuba
	// c2 = a0b2 + a1b1 + a2b0,
	// c2 = a2b0 + b ∵ b2 = 0, b = a1b1
	t2.Mul(api, e.B2, c0)
	t2.Add(api, t2, b)

	t1.Add(api, c0, c1)
	tmp.Add(api, e.B0, e.B1)
	t1.Mul(api, t1, tmp)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	e.B0 = t0
	e.B1 = t1
	e.B2 = t2

	return e
}

func Mul01By01(api frontend.API, c0, c1, d0, d1 E2) *E6 {
	var a, b, t1, tmp E2

	a.Mul(api, d0, c0)
	b.Mul(api, d1, c1)
	t1.Add(api, c0, c1)
	tmp.Add(api, d0, d1)
	t1.Mul(api, t1, tmp)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	return &E6{
		B0: a,
		B1: t1,
		B2: b,
	}
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E6) Select(api frontend.API, b frontend.Variable, r1, r2 E6) *E6 {

	e.B0.Select(api, b, r1.B0, r2.B0)
	e.B1.Select(api, b, r1.B1, r2.B1)
	e.B2.Select(api, b, r1.B2, r2.B2)

	return e
}
