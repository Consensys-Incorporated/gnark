package sw_bls12381

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[BaseField]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[ScalarField]

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bls12381.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

type G1 struct {
	api    frontend.API
	curveF *emulated.Field[BaseField]
	w      *emulated.Element[BaseField]
	halfp  *emulated.Element[BaseField]
}

func NewG1(api frontend.API) (*G1, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	w := ba.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	halfpE := ba.NewElement(new(big.Int).Div(fp_bls12381.Modulus(), big.NewInt(2))) // we know that the modulus is odd and division floors.
	return &G1{
		api:    api,
		curveF: ba,
		w:      w,
		halfp:  halfpE,
	}, nil
}

func (g1 G1) neg(p *G1Affine) *G1Affine {
	xr := &p.X
	yr := g1.curveF.Neg(&p.Y)
	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) phi(q *G1Affine) *G1Affine {
	x := g1.curveF.Mul(&q.X, g1.w)

	return &G1Affine{
		X: *x,
		Y: q.Y,
	}
}

func (g1 *G1) double(p *G1Affine) *G1Affine {
	// compute λ = (3p.x²)/2*p.y
	xx3a := g1.curveF.Mul(&p.X, &p.X)
	xx3a = g1.curveF.MulConst(xx3a, big.NewInt(3))
	y1 := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	λ := g1.curveF.Div(xx3a, y1)

	// xr = λ²-2p.x
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {&p.X}}, []int{1, -2})

	// yr = λ(p-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, g1.curveF.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) doubleN(p *G1Affine, n int) *G1Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g1.double(pn)
	}
	return pn
}

func (g1 G1) add(p, q *G1Affine) *G1Affine {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g1.curveF.Sub(&q.Y, &p.Y)
	qxpx := g1.curveF.Sub(&q.X, &p.X)
	λ := g1.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {g1.curveF.Add(&p.X, &q.X)}}, []int{1, -1})

	// p.y = λ(p.x-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, g1.curveF.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 G1) doubleAndAdd(p, q *G1Affine) *G1Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g1.curveF.Sub(&q.Y, &p.Y)
	xqxp := g1.curveF.Sub(&q.X, &p.X)
	λ1 := g1.curveF.Div(yqyp, xqxp)

	// compute x1 = λ1²-p.x-q.x
	x2 := g1.curveF.Eval([][]*baseEl{{λ1, λ1}, {g1.curveF.Add(&p.X, &q.X)}}, []int{1, -1})

	// omit y2 computation

	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	x2xp := g1.curveF.Sub(x2, &p.X)
	λ2 := g1.curveF.Div(ypyp, x2xp)
	λ2 = g1.curveF.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x3 := g1.curveF.Eval([][]*baseEl{{λ2, λ2}, {&p.X}, {x2}}, []int{1, -1, -1})

	// compute y3 = -λ2*(x3- p.x)-p.y
	y3 := g1.curveF.Eval([][]*baseEl{{λ2, g1.curveF.Sub(x3, &p.X)}, {&p.Y}}, []int{1, -1})

	return &G1Affine{
		X: *x3,
		Y: *y3,
	}
}

func (g1 G1) triple(p *G1Affine) *G1Affine {

	// compute λ1 = (3p.x²+a)/2p.y, here we assume a=0 (j invariant 0 curve)
	xx := g1.curveF.MulMod(&p.X, &p.X)
	xx = g1.curveF.MulConst(xx, big.NewInt(3))
	y2 := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	λ1 := g1.curveF.Div(xx, y2)

	// xr = λ1²-2p.x
	x2 := g1.curveF.Eval([][]*baseEl{{λ1, λ1}, {&p.X}}, []int{1, -2})

	// omit y2 computation, and
	// compute λ2 = 2p.y/(p.x-x2) − λ1.
	x1x2 := g1.curveF.Sub(&p.X, x2)
	λ2 := g1.curveF.Div(y2, x1x2)
	λ2 = g1.curveF.Sub(λ2, λ1)

	// xr = λ2²-p.x-x2
	xr := g1.curveF.Eval([][]*baseEl{{λ2, λ2}, {&p.X}, {x2}}, []int{1, -1, -1})

	// yr = λ2(p.x-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ2, g1.curveF.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) scalarMulBySeedSquare(q *G1Affine) *G1Affine {
	// It computes the scalar multiplication by the seed square. It is used to
	// verify if a point is in the subgroup of G1. However, it uses incomplete
	// formulas and as such doesn't work for point at infinity as we get a
	// division by zero. But as we represent the point at infinity as (0,0),
	// then in this case we can run the computations using a dummy point (1,1)
	// and then later replace it again with the point at infinity.
	isInfinity := g1.api.And(g1.curveF.IsZero(&q.X), g1.curveF.IsZero(&q.Y))
	q = &G1Affine{
		X: *g1.curveF.Select(isInfinity, g1.curveF.One(), &q.X),
		Y: *g1.curveF.Select(isInfinity, g1.curveF.One(), &q.Y),
	}
	z := g1.double(q)
	z = g1.add(q, z)
	z = g1.double(z)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 2)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 8)
	z = g1.doubleAndAdd(z, q)
	t0 := g1.double(z)
	t0 = g1.add(z, t0)
	t0 = g1.double(t0)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 2)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 8)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 31)
	z = g1.add(t0, z)
	z = g1.doubleN(z, 32)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 32)

	z = &G1Affine{
		X: *g1.curveF.Select(isInfinity, g1.curveF.Zero(), &z.X),
		Y: *g1.curveF.Select(isInfinity, g1.curveF.Zero(), &z.Y),
	}

	return z
}

func (g1 *G1) computeCurveEquation(P *G1Affine) (left, right *baseEl) {
	// Curve: Y² == X³ + aX + b, where a=0 and b=4
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if P=(0,0) we assign b=0 otherwise 4, and continue
	selector := g1.api.And(g1.curveF.IsZero(&P.X), g1.curveF.IsZero(&P.Y))
	four := g1.curveF.NewElement("4")
	b := g1.curveF.Select(selector, g1.curveF.Zero(), four)

	left = g1.curveF.Mul(&P.Y, &P.Y)
	right = g1.curveF.Eval([][]*emulated.Element[BaseField]{{&P.X, &P.X, &P.X}, {b}}, []int{1, 1})
	return left, right
}

func (g1 *G1) AssertIsOnCurve(P *G1Affine) {
	left, right := g1.computeCurveEquation(P)
	g1.curveF.AssertIsEqual(left, right)
}

func (g1 *G1) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	g1.AssertIsOnCurve(P)

	// 2- Check P is in the prime-order subgroup.
	//
	// We hint a preimage S and assert [x-1]S == P. Since the G1 cofactor
	// torsion has rank 2 its exponent is (x-1), so [x-1]E(Fp) = G1 exactly: a
	// point carrying cofactor torsion has no on-curve preimage. Completeness
	// holds because gcd(x-1, r) = 1 makes [x-1] a bijection on G1. See
	// [sw_emulated.CurveParams.CofactorClearing].
	//
	// This replaces the endomorphism test P = -[x²]ϕ(P) (Bowe, eprint
	// 2019/814), which needs a 128-bit ladder where this needs a 64-bit one.
	curve, err := sw_emulated.New[BaseField, ScalarField](g1.api, sw_emulated.GetBLS12381Params())
	if err != nil {
		panic(fmt.Sprintf("new emulated curve: %v", err))
	}
	curve.AssertIsInSubgroup(P)
}

// AssertIsEqual asserts that p and q are the same point.
func (g1 *G1) AssertIsEqual(p, q *G1Affine) {
	g1.curveF.AssertIsEqual(&p.X, &q.X)
	g1.curveF.AssertIsEqual(&p.Y, &q.Y)
}

func (g1 *G1) IsEqual(p, q *G1Affine) frontend.Variable {
	xDiff := g1.curveF.Sub(&p.X, &q.X)
	yDiff := g1.curveF.Sub(&p.Y, &q.Y)
	xIsZero := g1.curveF.IsZero(xDiff)
	yIsZero := g1.curveF.IsZero(yDiff)
	return g1.api.And(xIsZero, yIsZero)
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bls12381.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// ScalarField is the [emulated.FieldParams] implementation of the curve scalar field.
type ScalarField = emulated.BLS12381Fr

// BaseField is the [emulated.FieldParams] implementation of the curve base field.
type BaseField = emulated.BLS12381Fp
