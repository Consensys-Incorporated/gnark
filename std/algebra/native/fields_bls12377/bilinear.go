// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
)

// Minimum-rank bilinear evaluation-interpolation gadgets over Q for BLS12-377
// extension towers in R1CS circuits (where linear combinations are free and
// constraint cost equals the number of non-constant multiplications):
//
//   - E6  ≅ Fp[Y]/(Y^6 + 5)  with Y = v (v^3 = u, u^2 = -5):
//     degree-5 polynomials a(Y), b(Y) have product degree <= 10, uniquely
//     determined by 11 rational evaluations at {-5, -4, ..., 4, ∞}.
//     E6.Mul uses 11 R1CS constraints (vs 15 for Toom-3 over Karatsuba);
//     E6.MulBy01 (where b_5 = 0) omits the ∞ product and uses 10 R1CS constraints.
//
//   - E12 ≅ Fp[W]/(W^12 + 5) with W = w (w^2 = v, v^3 = u, u^2 = -5):
//     degree-11 polynomials a(W), b(W) have product degree <= 22, uniquely
//     determined by 23 rational evaluations at {-11, -10, ..., 10, ∞}.
//     E12.Mul uses 23 R1CS constraints (vs 45 for Karatsuba over Toom-3);
//     E12.MulBy01234 (where b_11 = 0) omits the ∞ product and uses 22 R1CS constraints.
//
// All constant divisions by Lagrange denominators are pre-inverted modulo
// api.Compiler().Field() at compile time; no in-circuit api.Div calls are used.

type rationalInterpTable struct {
	n          int
	numEval    int
	exactRats  [][]*big.Rat // [n][2n-1] exact folded Lagrange weights over Q
	denomCheck *big.Int     // factorial (2n-3)! whose prime factors cover all denominators
	cache      sync.Map     // map[string][][]*big.Int (keyed by field modulus string; nil entry == 0)
}

var (
	e6BilinearTable  = newRationalInterpTable(6)
	e12BilinearTable = newRationalInterpTable(12)
	bigOne           = big.NewInt(1)
	bigSix           = big.NewInt(6)
)

// newRationalInterpTable builds the exact n x (2n-1) rational reconstruction
// matrix R over Q mapping evaluations at {-(n-1), ..., n-2, ∞} to coefficients
// reduced modulo X^n + 5 = 0 (i.e. X^n = -5).
func newRationalInterpTable(n int) *rationalInterpTable {
	m := 2*n - 2 // finite node count and max product degree (10 for E6, 22 for E12)
	numEval := m + 1

	nodes := make([]int64, m)
	for l := 0; l < m; l++ {
		nodes[l] = int64(l - (n - 1))
	}

	// Master monic polynomial W(X) = prod_{j=0}^{m-1} (X - nodes[j]) of degree m.
	wPoly := make([]*big.Int, m+1)
	for i := range wPoly {
		wPoly[i] = new(big.Int)
	}
	wPoly[0].SetInt64(1)
	for deg := 0; deg < m; deg++ {
		negRoot := big.NewInt(-nodes[deg])
		for k := deg + 1; k >= 1; k-- {
			// wPoly[k] = wPoly[k-1] - nodes[deg]*wPoly[k]
			term := new(big.Int).Mul(wPoly[k], negRoot)
			wPoly[k].Add(wPoly[k-1], term)
		}
		wPoly[0].Mul(wPoly[0], negRoot)
	}

	// Unfolded basis polynomials L_l(X) of degree <= m for l = 0..m:
	//   - For l < m: L_l(X) = (W(X) / (X - nodes[l])) / prod_{j != l} (nodes[l] - nodes[j])
	//   - For l == m (∞): L_m(X) = W(X)
	basisCoeffs := make([][]*big.Rat, numEval)
	for l := 0; l < m; l++ {
		numPoly := make([]*big.Int, m)
		for i := range numPoly {
			numPoly[i] = new(big.Int)
		}
		// Synthetic division of W(X) by (X - nodes[l]).
		xL := big.NewInt(nodes[l])
		numPoly[m-1].Set(wPoly[m])
		for t := m - 2; t >= 0; t-- {
			numPoly[t].Mul(numPoly[t+1], xL)
			numPoly[t].Add(numPoly[t], wPoly[t+1])
		}
		rem := new(big.Int).Mul(numPoly[0], xL)
		rem.Add(rem, wPoly[0])
		if rem.Sign() != 0 {
			panic(fmt.Sprintf("fields_bls12377: non-zero synthetic division remainder for n=%d l=%d", n, l))
		}

		den := big.NewInt(1)
		for j := 0; j < m; j++ {
			if j == l {
				continue
			}
			den.Mul(den, big.NewInt(nodes[l]-nodes[j]))
		}

		basisCoeffs[l] = make([]*big.Rat, m+1)
		for t := 0; t < m; t++ {
			basisCoeffs[l][t] = new(big.Rat).SetFrac(numPoly[t], den)
		}
		basisCoeffs[l][m] = new(big.Rat)
	}

	basisCoeffs[m] = make([]*big.Rat, m+1)
	for t := 0; t <= m; t++ {
		basisCoeffs[m][t] = new(big.Rat).SetInt(wPoly[t])
	}

	// Fold modulo X^n + 5 = 0 (X^{k+n} -> -5 * X^k for k = 0..n-2; k = n-1 has k+n = 2n-1 > m).
	ratFive := big.NewRat(5, 1)
	folded := make([][]*big.Rat, n)
	for k := 0; k < n; k++ {
		folded[k] = make([]*big.Rat, numEval)
		for l := 0; l < numEval; l++ {
			val := new(big.Rat).Set(basisCoeffs[l][k])
			if k+n <= m {
				hi := new(big.Rat).Mul(ratFive, basisCoeffs[l][k+n])
				val.Sub(val, hi)
			}
			folded[k][l] = val
		}
	}

	// Denominators of L_l divide (m-1)! = (2n-3)!.
	denomCheck := big.NewInt(1)
	for f := int64(2); f <= int64(m-1); f++ {
		denomCheck.Mul(denomCheck, big.NewInt(f))
	}

	return &rationalInterpTable{
		n:          n,
		numEval:    numEval,
		exactRats:  folded,
		denomCheck: denomCheck,
	}
}

// weightsForField returns the n x (2n-1) modular reconstruction weights in F_field,
// or nil if field is not coprime to all Lagrange denominators (e.g. tiny characteristic).
func (t *rationalInterpTable) weightsForField(field *big.Int) ([][]*big.Int, bool) {
	if field == nil {
		return nil, false
	}
	key := field.String()
	if cached, ok := t.cache.Load(key); ok {
		w := cached.([][]*big.Int)
		return w, w != nil
	}

	if new(big.Int).ModInverse(t.denomCheck, field) == nil {
		var nilWeights [][]*big.Int
		t.cache.Store(key, nilWeights)
		return nil, false
	}

	weights := make([][]*big.Int, t.n)
	tmpNum := new(big.Int)
	tmpInv := new(big.Int)
	for k := 0; k < t.n; k++ {
		weights[k] = make([]*big.Int, t.numEval)
		for l := 0; l < t.numEval; l++ {
			r := t.exactRats[k][l]
			if r.Sign() == 0 {
				continue
			}
			tmpNum.Mod(r.Num(), field)
			if tmpNum.Sign() == 0 {
				continue
			}
			if tmpInv.ModInverse(r.Denom(), field) == nil {
				var nilWeights [][]*big.Int
				t.cache.Store(key, nilWeights)
				return nil, false
			}
			w := new(big.Int).Mul(tmpNum, tmpInv)
			w.Mod(w, field)
			if w.Sign() != 0 {
				weights[k][l] = w
			}
		}
	}

	t.cache.Store(key, weights)
	return weights, true
}

func assignMonomialE6(e *E6, d [6]frontend.Variable) {
	e.B0.A0 = d[0]
	e.B1.A0 = d[1]
	e.B2.A0 = d[2]
	e.B0.A1 = d[3]
	e.B1.A1 = d[4]
	e.B2.A1 = d[5]
}

func assignMonomialE12(e *E12, d [12]frontend.Variable) {
	e.C0.B0.A0 = d[0]
	e.C1.B0.A0 = d[1]
	e.C0.B1.A0 = d[2]
	e.C1.B1.A0 = d[3]
	e.C0.B2.A0 = d[4]
	e.C1.B2.A0 = d[5]
	e.C0.B0.A1 = d[6]
	e.C1.B0.A1 = d[7]
	e.C0.B1.A1 = d[8]
	e.C1.B1.A1 = d[9]
	e.C0.B2.A1 = d[10]
	e.C1.B2.A1 = d[11]
}

// evalPoly6 evaluates a degree-5 monomial polynomial a(Y) = sum_{i=0}^5 a[i] Y^i
// at the 10 integer points {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4} using even/odd sharing.
func evalPoly6(api frontend.API, a [6]frontend.Variable) [10]frontend.Variable {
	var out [10]frontend.Variable
	out[5] = a[0] // Y = 0

	for k := int64(1); k <= 4; k++ {
		k2 := k * k
		k4 := k2 * k2
		even := api.Add(a[0], api.Mul(a[2], k2), api.Mul(a[4], k4))
		odd := api.Add(a[1], api.Mul(a[3], k2), api.Mul(a[5], k4))
		if k != 1 {
			odd = api.Mul(odd, k)
		}
		out[5+k] = api.Add(even, odd)
		out[5-k] = api.Sub(even, odd)
	}

	// Y = -5
	even5 := api.Add(a[0], api.Mul(a[2], int64(25)), api.Mul(a[4], int64(625)))
	odd5 := api.Mul(api.Add(a[1], api.Mul(a[3], int64(25)), api.Mul(a[5], int64(625))), int64(5))
	out[0] = api.Sub(even5, odd5)
	return out
}

// evalSparse01Poly6 evaluates b(Y) = c0.A0 + c1.A0*Y + c0.A1*Y^3 + c1.A1*Y^4
// (where b_2 = b_5 = 0) at {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4}.
func evalSparse01Poly6(api frontend.API, c0, c1 E2) [10]frontend.Variable {
	var out [10]frontend.Variable
	out[5] = c0.A0 // Y = 0

	for k := int64(1); k <= 4; k++ {
		k2 := k * k
		k4 := k2 * k2
		even := api.Add(c0.A0, api.Mul(c1.A1, k4))
		odd := api.Add(c1.A0, api.Mul(c0.A1, k2))
		if k != 1 {
			odd = api.Mul(odd, k)
		}
		out[5+k] = api.Add(even, odd)
		out[5-k] = api.Sub(even, odd)
	}

	// Y = -5
	even5 := api.Add(c0.A0, api.Mul(c1.A1, int64(625)))
	odd5 := api.Mul(api.Add(c1.A0, api.Mul(c0.A1, int64(25))), int64(5))
	out[0] = api.Sub(even5, odd5)
	return out
}

// evalPoly12 evaluates a degree-11 monomial polynomial a(W) = sum_{i=0}^{11} a[i] W^i
// at the 22 integer points {-11, -10, ..., 0, ..., 10} using even/odd sharing.
func evalPoly12(api frontend.API, a [12]frontend.Variable) [22]frontend.Variable {
	var out [22]frontend.Variable
	out[11] = a[0] // W = 0

	for k := int64(1); k <= 10; k++ {
		p2 := k * k
		p4 := p2 * p2
		p6 := p4 * p2
		p8 := p4 * p4
		p10 := p8 * p2
		even := api.Add(
			a[0],
			api.Mul(a[2], p2),
			api.Mul(a[4], p4),
			api.Mul(a[6], p6),
			api.Mul(a[8], p8),
			api.Mul(a[10], p10),
		)
		odd := api.Add(
			a[1],
			api.Mul(a[3], p2),
			api.Mul(a[5], p4),
			api.Mul(a[7], p6),
			api.Mul(a[9], p8),
			api.Mul(a[11], p10),
		)
		if k != 1 {
			odd = api.Mul(odd, k)
		}
		out[11+k] = api.Add(even, odd)
		out[11-k] = api.Sub(even, odd)
	}

	// W = -11
	const (
		p2  int64 = 121
		p4  int64 = 14641
		p6  int64 = 1771561
		p8  int64 = 214358881
		p10 int64 = 25937424601
	)
	even11 := api.Add(
		a[0],
		api.Mul(a[2], p2),
		api.Mul(a[4], p4),
		api.Mul(a[6], p6),
		api.Mul(a[8], p8),
		api.Mul(a[10], p10),
	)
	odd11 := api.Mul(api.Add(
		a[1],
		api.Mul(a[3], p2),
		api.Mul(a[5], p4),
		api.Mul(a[7], p6),
		api.Mul(a[9], p8),
		api.Mul(a[11], p10),
	), int64(11))
	out[0] = api.Sub(even11, odd11)
	return out
}

// evalSparse01234Poly12 evaluates b(W) for sparse E12 element
// C0=(x[0],x[1],x[2]), C1=(x[3],x[4],0) (where b_5 = b_11 = 0) at {-11, ..., 10}.
func evalSparse01234Poly12(api frontend.API, x [5]E2) [22]frontend.Variable {
	// Monomial mapping:
	//   even: b0=x[0].A0, b2=x[1].A0, b4=x[2].A0, b6=x[0].A1, b8=x[1].A1, b10=x[2].A1
	//   odd:  b1=x[3].A0, b3=x[4].A0, b5=0,       b7=x[3].A1, b9=x[4].A1, b11=0
	var out [22]frontend.Variable
	out[11] = x[0].A0 // W = 0

	for k := int64(1); k <= 10; k++ {
		p2 := k * k
		p4 := p2 * p2
		p6 := p4 * p2
		p8 := p4 * p4
		p10 := p8 * p2
		even := api.Add(
			x[0].A0,
			api.Mul(x[1].A0, p2),
			api.Mul(x[2].A0, p4),
			api.Mul(x[0].A1, p6),
			api.Mul(x[1].A1, p8),
			api.Mul(x[2].A1, p10),
		)
		odd := api.Add(
			x[3].A0,
			api.Mul(x[4].A0, p2),
			api.Mul(x[3].A1, p6),
			api.Mul(x[4].A1, p8),
		)
		if k != 1 {
			odd = api.Mul(odd, k)
		}
		out[11+k] = api.Add(even, odd)
		out[11-k] = api.Sub(even, odd)
	}

	const (
		p2  int64 = 121
		p4  int64 = 14641
		p6  int64 = 1771561
		p8  int64 = 214358881
		p10 int64 = 25937424601
	)
	even11 := api.Add(
		x[0].A0,
		api.Mul(x[1].A0, p2),
		api.Mul(x[2].A0, p4),
		api.Mul(x[0].A1, p6),
		api.Mul(x[1].A1, p8),
		api.Mul(x[2].A1, p10),
	)
	odd11 := api.Mul(api.Add(
		x[3].A0,
		api.Mul(x[4].A0, p2),
		api.Mul(x[3].A1, p6),
		api.Mul(x[4].A1, p8),
	), int64(11))
	out[0] = api.Sub(even11, odd11)
	return out
}

func linearReconstruct(api frontend.API, weights [][]*big.Int, prods []frontend.Variable, out []frontend.Variable) {
	terms := make([]frontend.Variable, 0, len(prods))
	for k := range out {
		terms = terms[:0]
		row := weights[k]
		for l, m := range prods {
			w := row[l]
			if w == nil {
				continue
			}
			if w.Cmp(bigOne) == 0 {
				terms = append(terms, m)
			} else {
				terms = append(terms, api.Mul(m, w))
			}
		}
		switch len(terms) {
		case 0:
			out[k] = 0
		case 1:
			out[k] = terms[0]
		default:
			out[k] = api.Add(terms[0], terms[1], terms[2:]...)
		}
	}
}

// mulRank11 multiplies two E6 elements in exactly 11 R1CS constraints.
func (e *E6) mulRank11(api frontend.API, e1, e2 E6) *E6 {
	weights, ok := e6BilinearTable.weightsForField(api.Compiler().Field())
	if !ok {
		return e.mulKaratsubaOverKaratsuba(api, e1, e2)
	}

	aMono := towerToMonomial6(e6Coeffs(&e1))
	bMono := towerToMonomial6(e6Coeffs(&e2))

	u := evalPoly6(api, aMono)
	v := evalPoly6(api, bMono)

	var m [11]frontend.Variable
	for l := 0; l < 10; l++ {
		m[l] = api.Mul(u[l], v[l])
	}
	m[10] = api.Mul(aMono[5], bMono[5])

	var d [6]frontend.Variable
	linearReconstruct(api, weights, m[:], d[:])
	assignMonomialE6(e, d)
	return e
}

// mulBy01Rank10 multiplies e by sparse (c0, c1, 0) in E6 in exactly 10 R1CS constraints.
func (e *E6) mulBy01Rank10(api frontend.API, c0, c1 E2) *E6 {
	weights, ok := e6BilinearTable.weightsForField(api.Compiler().Field())
	if !ok {
		return e.mulBy01Karatsuba(api, c0, c1)
	}

	aMono := towerToMonomial6(e6Coeffs(e))
	u := evalPoly6(api, aMono)
	v := evalSparse01Poly6(api, c0, c1)

	// Since b_5 == 0, the evaluation at ∞ is a_5 * 0 = 0 (omitted from prods).
	var m [10]frontend.Variable
	for l := 0; l < 10; l++ {
		m[l] = api.Mul(u[l], v[l])
	}

	var d [6]frontend.Variable
	linearReconstruct(api, weights, m[:], d[:])
	assignMonomialE6(e, d)
	return e
}

// squareToom3 squares an E6 element in 10 R1CS constraints using 5 E2 squarings
// (Toom-Cook-3x over E2 at {0, 1, -1, 2, ∞}) and constant modular inverse of 6.
func (e *E6) squareToom3(api frontend.API, x E6) *E6 {
	field := api.Compiler().Field()
	if field == nil {
		return e.squareKaratsuba(api, x)
	}
	inv6 := new(big.Int).ModInverse(bigSix, field)
	if inv6 == nil {
		return e.squareKaratsuba(api, x)
	}

	var v0, v1, v2, v3, v4, t1, t2 E2
	v0.Square(api, x.B0)

	t1.Add(api, x.B0, x.B2)
	v1.Add(api, t1, x.B1)
	v1.Square(api, v1)

	v2.Sub(api, t1, x.B1)
	v2.Square(api, v2)

	t1.Double(api, x.B1)
	t2.MulByFp(api, x.B2, int64(4))
	v3.Add(api, t1, t2)
	v3.Add(api, v3, x.B0)
	v3.Square(api, v3)

	v4.Square(api, x.B2)

	var a0, a1, a2 E2
	a0.MulByFp(api, v0, int64(6))
	t1.Sub(api, v0, v1)
	t1.MulByFp(api, t1, int64(3))
	t1.Sub(api, t1, v2)
	t1.Add(api, t1, v3)
	t2.MulByFp(api, v4, int64(12))
	t1.Sub(api, t1, t2)
	t1.MulByNonResidue(api, t1)
	a0.Add(api, a0, t1)

	a1.MulByFp(api, v0, int64(3))
	t1.MulByFp(api, v2, int64(2))
	a1.Add(api, a1, t1)
	a1.Add(api, a1, v3)
	t1.MulByFp(api, v4, int64(2))
	t1.Add(api, t1, v1)
	t2.MulByNonResidue(api, v4)
	t1.Add(api, t1, t2)
	t1.MulByFp(api, t1, int64(6))
	a1.Sub(api, t1, a1)

	a2.Add(api, v1, v2)
	a2.MulByFp(api, a2, int64(3))
	t1.Add(api, v0, v4)
	t1.MulByFp(api, t1, int64(6))
	a2.Sub(api, a2, t1)

	e.B0.MulByFp(api, a0, inv6)
	e.B1.MulByFp(api, a1, inv6)
	e.B2.MulByFp(api, a2, inv6)
	return e
}

// mulRank23 multiplies two E12 elements in exactly 23 R1CS constraints.
func (e *E12) mulRank23(api frontend.API, e1, e2 E12) *E12 {
	weights, ok := e12BilinearTable.weightsForField(api.Compiler().Field())
	if !ok {
		return e.mulKaratsuba(api, e1, e2)
	}

	aMono := towerToMonomial12(e12Coeffs(&e1))
	bMono := towerToMonomial12(e12Coeffs(&e2))

	u := evalPoly12(api, aMono)
	v := evalPoly12(api, bMono)

	var m [23]frontend.Variable
	for l := 0; l < 22; l++ {
		m[l] = api.Mul(u[l], v[l])
	}
	m[22] = api.Mul(aMono[11], bMono[11])

	var d [12]frontend.Variable
	linearReconstruct(api, weights, m[:], d[:])
	assignMonomialE12(e, d)
	return e
}

// mulBy01234Rank22 multiplies e by sparse (x[0], x[1], x[2], x[3], x[4], 0)
// in E12 in exactly 22 R1CS constraints.
func (e *E12) mulBy01234Rank22(api frontend.API, x [5]E2) *E12 {
	weights, ok := e12BilinearTable.weightsForField(api.Compiler().Field())
	if !ok {
		return e.mulBy01234Karatsuba(api, x)
	}

	aMono := towerToMonomial12(e12Coeffs(e))
	u := evalPoly12(api, aMono)
	v := evalSparse01234Poly12(api, x)

	// Since b_11 == 0, the evaluation at ∞ is a_11 * 0 = 0 (omitted from prods).
	var m [22]frontend.Variable
	for l := 0; l < 22; l++ {
		m[l] = api.Mul(u[l], v[l])
	}

	var d [12]frontend.Variable
	linearReconstruct(api, weights, m[:], d[:])
	assignMonomialE12(e, d)
	return e
}
