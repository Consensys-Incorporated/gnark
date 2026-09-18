// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/rs/zerolog"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/compilelogger"
	"github.com/consensys/gnark/std/algebra/algopts"
)

// G1Affine point in affine coords
type G1Affine struct {
	X, Y frontend.Variable
}

// Neg outputs -p
func (p *G1Affine) Neg(api frontend.API, p1 G1Affine) *G1Affine {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(api frontend.API, p1 G1Affine) *G1Affine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	lambda := api.DivUnchecked(api.Sub(p1.Y, p.Y), api.Sub(p1.X, p.X))

	// xr = lambda**2-p.x-p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Add(p.X, p1.X))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p.X, xr)), p.Y)

	//p.x = xr
	p.X = xr
	return p
}

func (p *G1Affine) AddUnified(api frontend.API, q G1Affine) *G1Affine {
	// ---------------------------------------------------------------
	// BLS12-377 G1 has j-invariant 0. The Brier–Joye unified formula
	// λ = (x₁² + x₁x₂ + x₂²) / (y₁ + y₂) is NOT complete on j=0 curves:
	// Fp contains a primitive cube root of unity ω, and Q = -Φ(P) = (ω·P.x,
	// -P.y) satisfies y_P + y_Q = 0 with P ≠ -Q. The old formula returned
	// (0, 0) (infinity) on that pair — a soundness bug exploitable inside
	// scalarMulGLV's boundary corrections.
	//
	// We replace it with the chord/tangent split (one Div via the fold
	// trick: build num/den with Selects, divide once):
	//   • chord   λ = (q.Y − p.Y) / (q.X − p.X)   when p.X ≠ q.X
	//   • tangent λ = 3·p.X² / (2·p.Y)            when p.X = q.X (doubling)
	// Edge cases (p=O, q=O, p=−q) are handled by selectors at the end. The
	// inverse-case override is gated by `areFinite` so it doesn't fire when
	// one input is the SW infinity convention (0,0).
	//
	// Note: the only pair that hits the rational 2-torsion case (p=q with
	// p.Y=0, p.X≠0) is (-1,0), (-ω,0), (-ω²,0). These are NOT in the
	// prime-order subgroup G1, so the case can only be hit by an off-G1
	// caller — which is the caller's responsibility to gate.
	// ---------------------------------------------------------------

	// isPInf = 1 when p is (0,0) and 0 otherwise
	isPInf := api.And(api.IsZero(p.X), api.IsZero(p.Y))
	// isQInf = 1 when q is (0,0) and 0 otherwise
	isQInf := api.And(api.IsZero(q.X), api.IsZero(q.Y))

	xDiff := api.Sub(q.X, p.X)
	xEqual := api.IsZero(xDiff)

	// chord:    num = q.Y − p.Y, den = q.X − p.X
	// tangent:  num = 3·p.X²,     den = 2·p.Y
	numChord := api.Sub(q.Y, p.Y)
	denChord := xDiff
	xx := api.Mul(p.X, p.X)
	numTangent := api.Mul(xx, 3)  // const × var = free
	denTangent := api.Mul(p.Y, 2) // free

	num := api.Select(xEqual, numTangent, numChord)
	den := api.Select(xEqual, denTangent, denChord)
	denIsZero := api.IsZero(den)
	denSafe := api.Select(denIsZero, 1, den)
	λ := api.Div(num, denSafe)
	λ = api.Select(denIsZero, 0, λ)

	// xr = λ² - p.x - q.x
	xr := api.Sub(api.Mul(λ, λ), api.Add(p.X, q.X))
	// yr = λ·(p.x - xr) - p.y
	yr := api.Sub(api.Mul(λ, api.Sub(p.X, xr)), p.Y)

	result := G1Affine{X: xr, Y: yr}

	// if p=(0,0) return q
	result.Select(api, isPInf, q, result)
	// if q=(0,0) return p
	result.Select(api, isQInf, *p, result)

	// if p = −q (xEqual=1, yEqual=0, both finite), return (0, 0)
	yEqual := api.IsZero(api.Sub(p.Y, q.Y))
	areFinite := api.And(api.Sub(1, isPInf), api.Sub(1, isQInf))
	isInverse := api.And(api.And(xEqual, api.Sub(1, yEqual)), areFinite)
	result.Select(api, isInverse, G1Affine{X: 0, Y: 0}, result)

	p.X = result.X
	p.Y = result.Y
	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Affine) Select(api frontend.API, b frontend.Variable, p1, p2 G1Affine) *G1Affine {

	p.X = api.Select(b, p1.X, p2.X)
	p.Y = api.Select(b, p1.Y, p2.Y)

	return p

}

// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
// Returns:
//   - p1 if b0=0 and b1=0,
//   - p2 if b0=1 and b1=0,
//   - p3 if b0=0 and b1=1,
//   - p4 if b0=1 and b1=1.
func (p *G1Affine) Lookup2(api frontend.API, b1, b2 frontend.Variable, p1, p2, p3, p4 G1Affine) *G1Affine {

	p.X = api.Lookup2(b1, b2, p1.X, p2.X, p3.X, p4.X)
	p.Y = api.Lookup2(b1, b2, p1.Y, p2.Y, p3.Y, p4.Y)

	return p

}

// Double double a point in affine coords
func (p *G1Affine) Double(api frontend.API, p1 G1Affine) *G1Affine {

	var three, two big.Int
	three.SetInt64(3)
	two.SetInt64(2)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	lambda := api.DivUnchecked(api.Mul(p1.X, p1.X, three), api.Mul(p1.Y, two))

	// xr = lambda**2-2*p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Mul(p1.X, two))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p1.X, xr)), p1.Y)

	//p.x = xr
	p.X = xr

	return p
}

func (p *G1Affine) doubleN(api frontend.API, Q *G1Affine, n int) *G1Affine {
	pn := Q
	for s := 0; s < n; s++ {
		pn.Double(api, *pn)
	}
	return pn
}

func (p *G1Affine) scalarMulBySeed(api frontend.API, Q *G1Affine) *G1Affine {
	var z, t0, t1 G1Affine
	z.Double(api, *Q)
	z.AddAssign(api, *Q)
	z.DoubleAndAdd(api, &z, Q)
	t0.Double(api, z)
	t0.Double(api, t0)
	z.AddAssign(api, t0)
	t1.Double(api, z)
	t1.AddAssign(api, z)
	t0.AddAssign(api, t1)
	t0.doubleN(api, &t0, 9)
	z.DoubleAndAdd(api, &t0, &z)
	z.doubleN(api, &z, 45)
	p.DoubleAndAdd(api, &z, Q)

	return p
}

// ScalarMul sets P = [s] Q and returns P.
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
func (p *G1Affine) ScalarMul(api frontend.API, Q G1Affine, s interface{}, opts ...algopts.AlgebraOption) *G1Affine {
	// when Q is a compile-time constant point (for example the fixed
	// generator or a verification-key point), use the fixed-base comb method
	// with precomputed tables. The comb uses complete arithmetic and handles
	// the zero scalar; it requires the native field to accommodate the exact
	// recode identity (always the case over BW6-761).
	if xc, xok := api.Compiler().ConstantValue(Q.X); xok {
		if yc, yok := api.Compiler().ConstantValue(Q.Y); yok {
			if d, err := g1CombDataFor(xc, yc); err == nil && api.Compiler().FieldBitLen() > d.n+2 {
				res := g1CombScalarMul(api, d, s)
				p.X = res.X
				p.Y = res.Y
				return p
			}
		}
	}
	return p.scalarMulGLV(api, Q, s, opts...)
}

// scalarMulGLV sets P = [s]Q and returns P. It doesn't modify Q nor s.
// It implements an optimized version based on algorithm 1 of [Halo] (see Section 6.2 and appendix C).
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
//
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [Halo]: https://eprint.iacr.org/2019/1021.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (p *G1Affine) scalarMulGLV(api frontend.API, Q G1Affine, s frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	if cfg.IncompleteArithmetic {
		compilelogger.LogOnce(api.Compiler(), zerolog.InfoLevel,
			"sw_bls12377/g1/scalarMulGLV",
			"WithIncompleteArithmetic is deprecated for (*sw_bls12377.G1Affine).scalarMulGLV and complete arithmetic is always used")
	}
	// if Q=(0,0) we assign a dummy (1,1) to Q and continue
	selector := api.And(api.IsZero(Q.X), api.IsZero(Q.Y))
	Q.Select(api, selector, G1Affine{X: 1, Y: 1}, Q)

	// We use the endomorphism à la GLV to compute [s]Q as
	// 		[s1]Q + [s2]Φ(Q)
	//
	// The context we are working is based on the `outer` curve. However, the
	// points and the operations on the points are performed on the `inner`
	// curve of the outer curve. We require some parameters from the inner
	// curve.
	cc := getInnerCurveConfig(api.Compiler().Field())

	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := api.Compiler().NewHint(decomposeScalarG1Simple, 2, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	// s1 + λ * s2 == s
	api.AssertIsEqual(
		api.Add(s1, api.Mul(s2, cc.lambda)),
		s,
	)

	// For BLS12 λ bitsize is 127 equal to half of r bitsize
	nbits := cc.lambda.BitLen()
	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q) = -Φ²(Q)
	var Acc, B G1Affine
	cc.phi2Neg(api, &Acc, &Q)

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point B from:
	// 		B1 = +Q + Φ(Q)
	B1 := Acc
	// 		B2 = -Q - Φ(Q)
	B2 := G1Affine{}
	B2.Neg(api, B1)
	// 		B3 = +Q - Φ(Q)
	B3 := tableQ[1]
	B3.AddAssign(api, tablePhiQ[0])
	// 		B4 = -Q + Φ(Q)
	B4 := G1Affine{}
	B4.Neg(api, B3)
	//
	// Note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	// However when doing doubleAndAdd(Acc, B) as (Acc+B)+Acc it might happen
	// that Acc==B or -B. So we add the point H=(0,1) on BLS12-377 of order 2
	// to it to avoid incomplete additions in the loop by forcing Acc to be
	// different than the stored B.  Normally, the point H should be "killed
	// out" by the first doubling in the loop and the result will remain
	// unchanged. However, we are using affine coordinates that do not encode
	// the infinity point. Given the affine formulae, doubling (0,1) results in
	// (0,-1). Since the loop size N=nbits-1 is even we need to subtract
	// [2^N]H = (0,1) from the result at the end.
	//
	// Acc = Q + Φ(Q) + H
	Acc.AddAssign(api, G1Affine{X: 0, Y: 1})

	for i := nbits - 1; i > 0; i-- {
		B.X = api.Select(api.Xor(s1bits[i], s2bits[i]), B3.X, B2.X)
		B.Y = api.Lookup2(s1bits[i], s2bits[i], B2.Y, B3.Y, B4.Y, B1.Y)
		// Acc = [2]Acc + B
		Acc.DoubleAndAdd(api, &Acc, &B)
	}

	// i = 0
	// subtract the Q, R, Φ(Q), Φ(R) if the first bits are 0.
	// We use AddUnified so that when s=0 then Acc=(0,0) because
	// AddUnified(Q, -Q) = (0,0).
	tableQ[0].AddUnified(api, Acc)
	Acc.Select(api, s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddUnified(api, Acc)
	Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)

	// subtract [2^N]H = (0,1) since we added H at the beginning
	Acc.AddUnified(api, G1Affine{X: 0, Y: -1})
	Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)

	p.X = Acc.X
	p.Y = Acc.Y

	return p
}

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *bls12377.G1Affine) {
	p.X = (fr.Element)(p1.X)
	p.Y = (fr.Element)(p1.Y)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (p *G1Affine) AssertIsEqual(api frontend.API, other G1Affine) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
}

// DoubleAndAdd computes 2*p1+p in affine coords
func (p *G1Affine) DoubleAndAdd(api frontend.API, p1, p2 *G1Affine) *G1Affine {

	// compute lambda1 = (y2-y1)/(x2-x1)
	l1 := api.DivUnchecked(api.Sub(p1.Y, p2.Y), api.Sub(p1.X, p2.X))

	// compute x3 = lambda1**2-x1-x2
	x3 := api.Mul(l1, l1)
	x3 = api.Sub(x3, api.Add(p1.X, p2.X))

	// omit y3 computation
	// compute lambda2 = lambda1+2*y1/(x3-x1)
	l2 := api.DivUnchecked(api.Mul(p1.Y, big.NewInt(2)), api.Sub(x3, p1.X))
	l2 = api.Add(l2, l1)

	// compute x4 =lambda2**2-x1-x3
	x4 := api.Mul(l2, l2)
	x4 = api.Sub(x4, api.Add(p1.X, x3))

	// compute y4 = lambda2*(x4 - x1)-y1
	y4 := api.Sub(x4, p1.X)
	y4 = api.Mul(l2, y4)
	y4 = api.Sub(y4, p1.Y)

	p.X = x4
	p.Y = y4

	return p
}

// ScalarMulBase computes s * g1 and returns it, where g1 is the fixed generator. It doesn't modify s.
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
func (p *G1Affine) ScalarMulBase(api frontend.API, s frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	_, _, g1aff, _ := bls12377.Generators()
	generator := G1Affine{
		X: g1aff.X.BigInt(new(big.Int)),
		Y: g1aff.Y.BigInt(new(big.Int)),
	}
	return p.ScalarMul(api, generator, s, opts...)
}

// jointScalarMul computes [s]Q + [t]R and returns it. It doesn't modify the
// inputs.
//
// By default, uses complete arithmetic.
//
// In incomplete mode, the exceptional set includes at least zero scalars,
// infinity inputs, and Q = ±R. Additional sparse implementation-dependent
// failures may arise from precomputations and accumulator collisions in the
// underlying incomplete formulas.
func (p *G1Affine) jointScalarMul(api frontend.API, Q, R G1Affine, s, t frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	if !cfg.IncompleteArithmetic {
		var tmp G1Affine
		p.ScalarMul(api, Q, s, opts...)
		tmp.ScalarMul(api, R, t, opts...)
		p.AddUnified(api, tmp)
	} else {
		p.jointScalarMulUnsafe(api, Q, R, s, t)
	}
	return p
}

// jointScalarMulUnsafe computes [s]Q + [t]R using Shamir's trick.
//
// It is faster than the complete path but not complete. The exceptional set
// includes at least zero scalars, infinity inputs, and Q = ±R. Additional
// sparse implementation-dependent failures may arise from precomputations and
// DoubleAndAdd accumulator collisions.
func (p *G1Affine) jointScalarMulUnsafe(api frontend.API, Q, R G1Affine, s, t frontend.Variable) *G1Affine {
	cc := getInnerCurveConfig(api.Compiler().Field())

	sd, err := api.Compiler().NewHint(decomposeScalarG1Simple, 2, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	td, err := api.Compiler().NewHint(decomposeScalarG1Simple, 2, t)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	t1, t2 := td[0], td[1]

	api.AssertIsEqual(api.Add(s1, api.Mul(s2, cc.lambda)), s)
	api.AssertIsEqual(api.Add(t1, api.Mul(t2, cc.lambda)), t)

	nbits := cc.lambda.BitLen()

	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)
	t1bits := api.ToBinary(t1, nbits)
	t2bits := api.ToBinary(t2, nbits)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])
	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]G1Affine
	tableR[1] = R
	tableR[0].Neg(api, R)
	cc.phi1(api, &tablePhiR[1], &R)
	tablePhiR[0].Neg(api, tablePhiR[1])
	// precompute Q+R, -Q-R, Q-R, -Q+R, Φ(Q)+Φ(R), -Φ(Q)-Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R)
	var tableS, tablePhiS [4]G1Affine
	tableS[0] = tableQ[0]
	tableS[0].AddAssign(api, tableR[0])
	tableS[1].Neg(api, tableS[0])
	tableS[2] = Q
	tableS[2].AddAssign(api, tableR[0])
	tableS[3].Neg(api, tableS[2])
	cc.phi1(api, &tablePhiS[0], &tableS[0])
	cc.phi1(api, &tablePhiS[1], &tableS[1])
	cc.phi1(api, &tablePhiS[2], &tableS[2])
	cc.phi1(api, &tablePhiS[3], &tableS[3])

	// suppose first bit is 1 and set:
	// Acc = Q + R + Φ(Q) + Φ(R) = -Φ²(Q+R)
	var Acc G1Affine
	cc.phi2Neg(api, &Acc, &tableS[1])

	// Acc = [2]Acc ± Q ± R ± Φ(Q) ± Φ(R)
	var B G1Affine
	for i := nbits - 1; i > 0; i-- {
		B.X = api.Select(api.Xor(s1bits[i], t1bits[i]), tableS[2].X, tableS[0].X)
		B.Y = api.Lookup2(s1bits[i], t1bits[i], tableS[0].Y, tableS[2].Y, tableS[3].Y, tableS[1].Y)
		Acc.DoubleAndAdd(api, &Acc, &B)
		B.X = api.Select(api.Xor(s2bits[i], t2bits[i]), tablePhiS[2].X, tablePhiS[0].X)
		B.Y = api.Lookup2(s2bits[i], t2bits[i], tablePhiS[0].Y, tablePhiS[2].Y, tablePhiS[3].Y, tablePhiS[1].Y)
		Acc.AddAssign(api, B)
	}

	// i = 0
	// subtract the initial point from the accumulator when first bit was 0
	tableQ[0].AddAssign(api, Acc)
	Acc.Select(api, s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(api, Acc)
	Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	tableR[0].AddAssign(api, Acc)
	Acc.Select(api, t1bits[0], Acc, tableR[0])
	tablePhiR[0].AddAssign(api, Acc)
	Acc.Select(api, t2bits[0], Acc, tablePhiR[0])

	p.X = Acc.X
	p.Y = Acc.Y

	return p
}

// scalarBitsMul computes [s]Q and returns it where sBits is the bit decomposition of s. It doesn't modify Q nor sBits.
// The method is similar to varScalarMul.
func (p *G1Affine) scalarBitsMul(api frontend.API, Q G1Affine, s1bits, s2bits []frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var selector frontend.Variable
	if !cfg.IncompleteArithmetic {
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		selector = api.And(api.IsZero(Q.X), api.IsZero(Q.Y))
		Q.Select(api, selector, G1Affine{X: 1, Y: 1}, Q)
	}

	// We use the endomorphism à la GLV to compute [s]Q as
	// 		[s1]Q + [s2]Φ(Q)
	//
	// The context we are working is based on the `outer` curve. However, the
	// points and the operations on the points are performed on the `inner`
	// curve of the outer curve. We require some parameters from the inner
	// curve.
	cc := getInnerCurveConfig(api.Compiler().Field())

	// For BLS12 λ bitsize is 127 equal to half of r bitsize
	nbits := cc.lambda.BitLen()

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q) = -Φ²(Q)
	var Acc, B G1Affine
	cc.phi2Neg(api, &Acc, &Q)

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point B from:
	// 		B1 = +Q + Φ(Q)
	B1 := Acc
	// 		B2 = -Q - Φ(Q)
	B2 := G1Affine{}
	B2.Neg(api, B1)
	// 		B3 = +Q - Φ(Q)
	B3 := tableQ[1]
	B3.AddAssign(api, tablePhiQ[0])
	// 		B4 = -Q + Φ(Q)
	B4 := G1Affine{}
	B4.Neg(api, B3)
	//
	// Note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	// However when doing doubleAndAdd(Acc, B) as (Acc+B)+Acc it might happen
	// that Acc==B or -B. So we add the point H=(0,1) on BLS12-377 of order 2
	// to it to avoid incomplete additions in the loop by forcing Acc to be
	// different than the stored B.  Normally, the point H should be "killed
	// out" by the first doubling in the loop and the result will remain
	// unchanged. However, we are using affine coordinates that do not encode
	// the infinity point. Given the affine formulae, doubling (0,1) results in
	// (0,-1). Since the loop size N=nbits-1 is even we need to subtract
	// [2^N]H = (0,1) from the result at the end.
	//
	// Acc = Q + Φ(Q) + H
	Acc.AddAssign(api, G1Affine{X: 0, Y: 1})

	for i := nbits - 1; i > 0; i-- {
		B.X = api.Select(api.Xor(s1bits[i], s2bits[i]), B3.X, B2.X)
		B.Y = api.Lookup2(s1bits[i], s2bits[i], B2.Y, B3.Y, B4.Y, B1.Y)
		// Acc = [2]Acc + B
		Acc.DoubleAndAdd(api, &Acc, &B)
	}

	// i = 0
	// subtract the Q, R, Φ(Q), Φ(R) if the first bits are 0.
	// When not using incomplete arithmetic, we use AddUnified instead of Add. This means
	// when s=0 then Acc=(0,0) because AddUnified(Q, -Q) = (0,0).
	if !cfg.IncompleteArithmetic {
		tableQ[0].AddUnified(api, Acc)
		Acc.Select(api, s1bits[0], Acc, tableQ[0])
		tablePhiQ[0].AddUnified(api, Acc)
		Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
		Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)
	} else {
		tableQ[0].AddAssign(api, Acc)
		Acc.Select(api, s1bits[0], Acc, tableQ[0])
		tablePhiQ[0].AddAssign(api, Acc)
		Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	}

	if !cfg.IncompleteArithmetic {
		// subtract [2^N]G = (0,1) since we added H at the beginning
		Acc.AddUnified(api, G1Affine{X: 0, Y: -1})
		Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)
	} else {
		// subtract [2^N]G = (0,1) since we added H at the beginning
		Acc.AddAssign(api, G1Affine{X: 0, Y: -1})

	}

	p.X = Acc.X
	p.Y = Acc.Y

	return p
}
