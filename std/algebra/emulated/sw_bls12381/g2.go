package sw_bls12381

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2 struct {
	api frontend.API
	fp  *emulated.Field[BaseField]
	fr  *emulated.Field[ScalarField]
	*fields_bls12381.Ext2
	u1, w, w2  *emulated.Element[BaseField]
	eigenvalue *emulated.Element[ScalarField]
	v          *fields_bls12381.E2

	// SSWU map coefficients
	sswuCoeffA, sswuCoeffB *fields_bls12381.E2
	sswuZ                  *fields_bls12381.E2

	// Precomputed constants for the GLV+FakeGLV scalar mul ([EEMP25] §3.3).
	g2Gen      *g2AffP // G2 generator
	g2GenNbits *g2AffP // [2^(nbits-1)]G2 with nbits = (r.BitLen()+3)/4 + 2
}

type g2AffP struct {
	X, Y fields_bls12381.E2
}

// G2Affine represents G2 element with optional embedded line precomputations.
type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

func newG2AffP(v bls12381.G2Affine) g2AffP {
	return g2AffP{
		X: fields_bls12381.E2{
			A0: emulated.ValueOf[BaseField](v.X.A0),
			A1: emulated.ValueOf[BaseField](v.X.A1),
		},
		Y: fields_bls12381.E2{
			A0: emulated.ValueOf[BaseField](v.Y.A0),
			A1: emulated.ValueOf[BaseField](v.Y.A1),
		},
	}
}

func NewG2(api frontend.API) (*G2, error) {
	fp, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	fr, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	w := fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	w2 := fp.NewElement("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350")
	eigenvalue := fr.NewElement("228988810152649578064853576960394133503")
	u1 := fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	v := fields_bls12381.E2{
		A0: *fp.NewElement("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
		A1: *fp.NewElement("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"),
	}
	sswuCoeffA, sswuCoeffB := hash_to_curve.G2SSWUIsogenyCurveCoefficients()
	coeffA := &fields_bls12381.E2{
		A0: *fp.NewElement(sswuCoeffA.A0),
		A1: *fp.NewElement(sswuCoeffA.A1),
	}
	coeffB := &fields_bls12381.E2{
		A0: *fp.NewElement(sswuCoeffB.A0),
		A1: *fp.NewElement(sswuCoeffB.A1),
	}
	sswuZ := hash_to_curve.G2SSWUIsogenyZ()
	z := &fields_bls12381.E2{
		A0: *fp.NewElement(sswuZ.A0),
		A1: *fp.NewElement(sswuZ.A1),
	}

	// Precomputed G2 generator for GLV+FakeGLV.
	g2Gen := &g2AffP{
		X: fields_bls12381.E2{
			A0: *fp.NewElement("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160"),
			A1: *fp.NewElement("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758"),
		},
		Y: fields_bls12381.E2{
			A0: *fp.NewElement("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905"),
			A1: *fp.NewElement("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"),
		},
	}
	// [2^(nbits-1)]G2 where nbits = (255+3)/4 + 2 = 66, so this is [2^65]G2.
	g2GenNbits := &g2AffP{
		X: fields_bls12381.E2{
			A0: *fp.NewElement("1307001654908388153254394944417118155033503188409787277795273489312551176370209873126740711463572657296916966732684"),
			A1: *fp.NewElement("1066804690119577865989830850277879393407029322116864061755683314318400220056817483617033672656485029228353937929571"),
		},
		Y: fields_bls12381.E2{
			A0: *fp.NewElement("1233864651366532660795929818904272589705597977637697925481983092108793193162343169655985724823869788077854535468808"),
			A1: *fp.NewElement("2703972434797875065063829955607449483769333186572810763171217085444622779819503421195150761462859837038921185079043"),
		},
	}

	return &G2{
		api:        api,
		fp:         fp,
		fr:         fr,
		Ext2:       fields_bls12381.NewExt2(api),
		w:          w,
		w2:         w2,
		eigenvalue: eigenvalue,
		u1:         u1,
		v:          &v,
		// SSWU map
		sswuCoeffA: coeffA,
		sswuCoeffB: coeffB,
		sswuZ:      z,
		// GLV+FakeGLV precomputed values
		g2Gen:      g2Gen,
		g2GenNbits: g2GenNbits,
	}, nil
}

func NewG2Affine(v bls12381.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bls12381.G2Affine) G2Affine {
	if !v.IsInSubGroup() {
		// for the pairing check we check that G2 point is already in the
		// subgroup when we compute the lines in circuit. However, when the
		// point is given as a constant, then we already precompute the lines at
		// circuit compile time without explicitly checking the G2 membership.
		// So, we need to check that the point is in the subgroup before we
		// compute the lines.
		panic("given point is not in the G2 subgroup")
	}
	lines := precomputeLines(v)
	return G2Affine{
		P:     newG2AffP(v),
		Lines: &lines,
	}
}

// NewG2AffineFixedPlaceholder returns a placeholder for the circuit compilation
// when witness will be given with line precomputations using
// [NewG2AffineFixed].
func NewG2AffineFixedPlaceholder() G2Affine {
	var lines lineEvaluations
	for i := 0; i < len(bls12381.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}

func (g2 *G2) psi(q *G2Affine) *G2Affine {
	x := g2.Ext2.MulByElement(&q.P.X, g2.u1)
	y := g2.Ext2.Conjugate(&q.P.Y)
	y = g2.Ext2.Mul(y, g2.v)

	return &G2Affine{
		P: g2AffP{
			X: fields_bls12381.E2{A0: x.A1, A1: x.A0},
			Y: *y,
		},
	}
}

func (g2 *G2) psi2(q *G2Affine) *G2Affine {
	x := g2.Ext2.MulByElement(&q.P.X, g2.w)
	y := g2.Ext2.Neg(&q.P.Y)

	return &G2Affine{
		P: g2AffP{
			X: *x,
			Y: *y,
		},
	}
}

func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {

	z := g2.triple(q)
	z = g2.double(z)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 2)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 8)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 31)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 16)

	return g2.neg(z)
}

// AddUnified adds p and q and returns it. It doesn't modify p nor q.
//
// ✅ p can be equal to q, and either or both can be (0,0).
// ([0,0],[0,0]) is not on the twist but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It uses the unified formulas of Brier and Joye ([[BriJoy02]] (Corollary 1)).
//
// [BriJoy02]: https://link.springer.com/content/pdf/10.1007/3-540-45664-3_24.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (g2 *G2) AddUnified(p, q *G2Affine) *G2Affine {
	// ---------------------------------------------------------------
	// BLS12-381 G2 sits on a D-twist with j-invariant 0 over Fp². The
	// Brier–Joye unified formula is NOT complete on j=0: Fp ≡ 1 mod 3
	// gives a primitive cube root of unity ω in Fp ⊂ Fp², so the pair
	// Q = -Φ(P) = (ω·P.x, -P.y) satisfies y_P + y_Q = 0 with P ≠ -Q. The
	// old formula returned the EVM-infinity convention ([0,0], [0,0]) on
	// that pair — soundness bug exploitable in MultiScalarMul / scalar mul
	// boundary corrections.
	//
	// Replaced with the chord/tangent split + single-Div fold:
	//   • chord   λ = (q.Y − p.Y) / (q.X − p.X)   when p.X ≠ q.X
	//   • tangent λ = 3·p.X² / (2·p.Y)            when p.X = q.X
	// The inverse-case override is gated by `areFinite` so it doesn't fire
	// when one input is the SW infinity convention.
	// ---------------------------------------------------------------

	isPInf := g2.api.And(g2.Ext2.IsZero(&p.P.X), g2.Ext2.IsZero(&p.P.Y))
	isQInf := g2.api.And(g2.Ext2.IsZero(&q.P.X), g2.Ext2.IsZero(&q.P.Y))

	xDiff := g2.Sub(&q.P.X, &p.P.X)
	xEqual := g2.IsZero(xDiff)

	// chord:    num = q.Y − p.Y, den = q.X − p.X
	// tangent:  num = 3·p.X²,     den = 2·p.Y
	numChord := g2.Sub(&q.P.Y, &p.P.Y)
	denChord := xDiff
	xx := g2.Square(&p.P.X)
	numTangent := g2.MulByConstElement(xx, big.NewInt(3)) // free at constraint level
	denTangent := g2.MulByConstElement(&p.P.Y, big.NewInt(2))

	num := g2.Ext2.Select(xEqual, numTangent, numChord)
	den := g2.Ext2.Select(xEqual, denTangent, denChord)
	denIsZero := g2.IsZero(den)
	denSafe := g2.Ext2.Select(denIsZero, g2.One(), den)
	λ := g2.DivUnchecked(num, denSafe)
	λ = g2.Ext2.Select(denIsZero, g2.Zero(), λ)

	pxPlusQx := g2.Add(&p.P.X, &q.P.X)
	xr := g2.Mul(λ, λ)
	xr = g2.Sub(xr, pxPlusQx)

	pxMinusXr := g2.Sub(&p.P.X, xr)
	yr := g2.Mul(λ, pxMinusXr)
	yr = g2.Sub(yr, &p.P.Y)

	result := &G2Affine{
		P:     g2AffP{X: *xr, Y: *yr},
		Lines: nil,
	}

	result = g2.Select(isPInf, q, result)
	result = g2.Select(isQInf, p, result)

	// if p = −q (xEqual=1, yEqual=0, both finite), return infinity
	ySub := g2.Sub(&p.P.Y, &q.P.Y)
	yEqual := g2.IsZero(ySub)
	areFinite := g2.api.And(g2.api.Sub(1, isPInf), g2.api.Sub(1, isQInf))
	isInverse := g2.api.And(g2.api.And(xEqual, g2.api.Sub(1, yEqual)), areFinite)
	zero := g2.Ext2.Zero()
	infinity := G2Affine{
		P:     g2AffP{X: *zero, Y: *zero},
		Lines: nil,
	}
	result = g2.Select(isInverse, &infinity, result)

	return result
}

func (g2 G2) add(p, q *G2Affine) *G2Affine {

	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	qxpx := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ := g2.Ext2.DivUnchecked(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p.P.X.A0}, {&q.P.X.A0}}, []int{1, -1, -1, -1})
	xr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p.P.X.A1}, {&q.P.X.A1}}, []int{2, -1, -1})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// p.y = λ(p.x-r.x) - p.y
	yr := g2.Ext2.Sub(&p.P.X, xr)
	yr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {&λ.A1, &yr.A1}, {&p.P.Y.A0}}, []int{1, -1, -1})
	yr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {&p.P.Y.A1}}, []int{1, 1, -1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 G2) neg(p *G2Affine) *G2Affine {
	xr := &p.P.X
	yr := g2.Ext2.Neg(&p.P.Y)
	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

// muxE2Y8Signed selects from 8 E2 Y-values using selector (0-7) and conditionally
// negates based on signBit. This optimizes the common GLV pattern where Y[i] =
// -Y[15-i], reducing a 16-to-1 Mux to an 8-to-1 Mux plus conditional negation.
func (g2 *G2) muxE2Y8Signed(signBit frontend.Variable, selector frontend.Variable, yA0, yA1 [8]*emulated.Element[BaseField]) *fields_bls12381.E2 {
	baseA0 := g2.fp.Mux(selector, yA0[:]...)
	baseA1 := g2.fp.Mux(selector, yA1[:]...)
	negA0 := g2.fp.Neg(baseA0)
	negA1 := g2.fp.Neg(baseA1)
	return &fields_bls12381.E2{
		A0: *g2.fp.Select(signBit, negA0, baseA0),
		A1: *g2.fp.Select(signBit, negA1, baseA1),
	}
}

func (g2 G2) sub(p, q *G2Affine) *G2Affine {
	qNeg := g2.neg(q)
	return g2.add(p, qNeg)
}

func (g2 *G2) double(p *G2Affine) *G2Affine {
	return g2.doubleGeneric(p, false)
}

func (g2 *G2) doubleGeneric(p *G2Affine, unified bool) *G2Affine {
	// compute λ = (3p.x²)/2*p.y
	xx3a := g2.Square(&p.P.X)
	xx3a = g2.MulByConstElement(xx3a, big.NewInt(3))
	y2 := g2.Double(&p.P.Y)
	var isDoubleYZero frontend.Variable = 0
	if unified {
		isDoubleYZero = g2.Ext2.IsZero(y2)
		y2 = g2.Ext2.Select(isDoubleYZero, g2.Ext2.One(), y2)
	}
	λ := g2.DivUnchecked(xx3a, y2)
	if unified {
		λ = g2.Ext2.Select(isDoubleYZero, g2.Ext2.Zero(), λ)
	}

	// xr = λ²-2p.x
	xr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p.P.X.A0}}, []int{1, -1, -2})
	xr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p.P.X.A1}}, []int{2, -2})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// yr = λ(p-xr) - p.y
	yr := g2.Ext2.Sub(&p.P.X, xr)
	yr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {&λ.A1, &yr.A1}, {&p.P.Y.A0}}, []int{1, -1, -1})
	yr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {&p.P.Y.A1}}, []int{1, 1, -1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 *G2) doubleN(p *G2Affine, n int) *G2Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g2.double(pn)
	}
	return pn
}

func (g2 G2) triple(p *G2Affine) *G2Affine {

	// compute λ1 = (3p.x²)/2p.y
	xx := g2.Square(&p.P.X)
	xx = g2.MulByConstElement(xx, big.NewInt(3))
	y2 := g2.Double(&p.P.Y)
	λ1 := g2.DivUnchecked(xx, y2)

	// x2 = λ1²-2p.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p.P.X.A0}}, []int{1, -1, -2})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p.P.X.A1}}, []int{2, -2})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.Sub(&p.P.X, x2)
	λ2 := g2.DivUnchecked(y2, x1x2)
	λ2 = g2.Sub(λ2, λ1)

	// compute x3 =λ2²-p.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&p.P.X.A0}, {x20}}, []int{1, -1, -1, -1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&p.P.X.A1}, {x21}}, []int{2, -1, -1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.Ext2.Sub(&p.P.X, x3)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {&λ2.A1, &y3.A1}, {&p.P.Y.A0}}, []int{1, -1, -1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {&p.P.Y.A1}}, []int{1, 1, -1})
	y3 = &fields_bls12381.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

func (g2 G2) doubleAndAdd(p, q *G2Affine) *G2Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p.P.X.A0}, {&q.P.X.A0}}, []int{1, -1, -1, -1})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p.P.X.A1}, {&q.P.X.A1}}, []int{2, -1, -1})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit y2 computation
	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := g2.Ext2.Add(&p.P.Y, &p.P.Y)
	x2xp := g2.Ext2.Sub(x2, &p.P.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&p.P.X.A0}, {x20}}, []int{1, -1, -1, -1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&p.P.X.A1}, {x21}}, []int{2, -1, -1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// compute y3 = -λ2*(x3 - p.x)-p.y
	y3 := g2.Ext2.Sub(x3, &p.P.X)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {&λ2.A1, &y3.A1}, {&p.P.Y.A0}}, []int{1, -1, -1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {&p.P.Y.A1}}, []int{1, 1, -1})
	y3 = &fields_bls12381.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

// doubleAndAddSelect is the same as doubleAndAdd but computes either:
//
//	2p+q if b=1 or
//	2q+p if b=0
//
// It first computes the x-coordinate of p+q via the slope(p,q)
// and then based on a Select adds either p or q.
func (g2 G2) doubleAndAddSelect(b frontend.Variable, p, q *G2Affine) *G2Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p.P.X.A0}, {&q.P.X.A0}}, []int{1, -1, -1, -1})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p.P.X.A1}, {&q.P.X.A1}}, []int{2, -1, -1})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit y2 computation

	// conditional second addition
	t := g2.Select(b, p, q)

	// compute -λ2 = λ1+2*t.y/(x2-t.x)
	ypyp := g2.Ext2.Add(&t.P.Y, &t.P.Y)
	x2xp := g2.Ext2.Sub(x2, &t.P.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)

	// compute x3 = (-λ2)²-t.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&t.P.X.A0}, {x20}}, []int{1, -1, -1, -1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&t.P.X.A1}, {x21}}, []int{2, -1, -1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// compute y3 = -λ2*(x3 - t.x)-t.y
	y3 := g2.Ext2.Sub(x3, &t.P.X)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {&λ2.A1, &y3.A1}, {&t.P.Y.A0}}, []int{1, -1, -1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {&t.P.Y.A1}}, []int{1, 1, -1})
	y3 = &fields_bls12381.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

func (g2 *G2) computeTwistEquation(Q *G2Affine) (left, right *fields_bls12381.E2) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=4(1+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)
	bTwist := fields_bls12381.E2{
		A0: *g2.fp.NewElement("4"),
		A1: *g2.fp.NewElement("4"),
	}
	// if Q=(0,0) we assign b=0 otherwise 4(1+u), and continue
	selector := g2.api.And(g2.Ext2.IsZero(&Q.P.X), g2.Ext2.IsZero(&Q.P.Y))
	b := g2.Ext2.Select(selector, g2.Ext2.Zero(), &bTwist)

	left = g2.Ext2.Square(&Q.P.Y)
	right = &fields_bls12381.E2{
		A0: *g2.fp.Eval([][]*baseEl{{&Q.P.X.A0, &Q.P.X.A0, &Q.P.X.A0}, {&Q.P.X.A0, &Q.P.X.A1, &Q.P.X.A1}, {&b.A0}}, []int{1, -3, 1}),
		A1: *g2.fp.Eval([][]*baseEl{{&Q.P.X.A1, &Q.P.X.A0, &Q.P.X.A0}, {&Q.P.X.A1, &Q.P.X.A1, &Q.P.X.A1}, {&b.A1}}, []int{3, -1, 1}),
	}

	return left, right
}

func (g2 *G2) AssertIsOnTwist(Q *G2Affine) {
	left, right := g2.computeTwistEquation(Q)
	g2.Ext2.AssertIsEqual(left, right)
}

func (g2 *G2) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	g2.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	// [x₀]Q
	xQ := g2.scalarMulBySeed(Q)
	// ψ(Q)
	psiQ := g2.psi(Q)

	// [r]Q == 0 <==>  ψ(Q) == [x₀]Q
	g2.AssertIsEqual(xQ, psiQ)
}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (g2 *G2) Select(b frontend.Variable, p, q *G2Affine) *G2Affine {
	x := g2.Ext2.Select(b, &p.P.X, &q.P.X)
	y := g2.Ext2.Select(b, &p.P.Y, &q.P.Y)
	return &G2Affine{
		P:     g2AffP{X: *x, Y: *y},
		Lines: nil,
	}
}

// AssertIsEqual asserts that p and q are the same point.
// assertIsOnCurve asserts that P satisfies the BLS12-381 G2 (twist) curve
// equation Y² = X³ + b over 𝔽ₚ². The constant b is recovered from the
// (on-curve, in-subgroup) generator as b = Gy² − Gx³, avoiding a hardcoded literal.
func (g2 *G2) assertIsOnCurve(P *G2Affine) {
	x3 := g2.Ext2.Mul(&P.P.X, g2.Ext2.Square(&P.P.X))
	lhs := g2.Ext2.Sub(g2.Ext2.Square(&P.P.Y), x3)
	gx3 := g2.Ext2.Mul(&g2.g2Gen.X, g2.Ext2.Square(&g2.g2Gen.X))
	rhs := g2.Ext2.Sub(g2.Ext2.Square(&g2.g2Gen.Y), gx3)
	g2.Ext2.AssertIsEqual(lhs, rhs)
}

// mulByConstant returns [k]P for a fixed k > 0, via a width-4 signed-window (NAF)
// double-and-add using complete (unified) operations, so it is exception-free for
// any on-curve P. The signed window trims the additions to ~the w-NAF weight (vs
// the binary Hamming weight); the doubling count is unchanged. All operations stay
// unified (infinity-complete), which is soundness-critical since P is an
// adversarial preimage. k is a [big.Int] because the cofactor-clearing constant
// can exceed 64 bits.
func (g2 *G2) mulByConstant(P *G2Affine, k *big.Int) *G2Affine {
	digits := naf4Digits(k) // LSB-first; each digit is 0 or an odd d with |d| < 8
	// precompute the odd multiples 1P, 3P, 5P, 7P (negated on demand)
	p2 := g2.doubleGeneric(P, true)
	var odd [8]*G2Affine
	odd[1] = P
	odd[3] = g2.AddUnified(p2, P)
	odd[5] = g2.AddUnified(odd[3], p2)
	odd[7] = g2.AddUnified(odd[5], p2)
	pick := func(d int8) *G2Affine {
		if d > 0 {
			return odd[d]
		}
		return g2.neg(odd[-d])
	}
	top := len(digits) - 1
	for top >= 0 && digits[top] == 0 {
		top--
	}
	acc := pick(digits[top])
	for i := top - 1; i >= 0; i-- {
		acc = g2.doubleGeneric(acc, true) // unified (complete) doubling
		if digits[i] != 0 {
			acc = g2.AddUnified(acc, pick(digits[i]))
		}
	}
	return acc
}

// naf4Digits returns the width-4 non-adjacent form of k > 0, least-significant
// digit first: each digit is 0 or an odd integer with |d| < 8, nonzero digits are
// at least 4 positions apart, and Σ digits[i]·2^i == k.
func naf4Digits(k *big.Int) []int8 {
	k = new(big.Int).Set(k)
	mask := big.NewInt(15)
	tmp := new(big.Int)
	var digits []int8
	for k.Sign() > 0 {
		var d int8
		if k.Bit(0) == 1 {
			m := int8(tmp.And(k, mask).Int64())
			if m >= 8 {
				m -= 16
			}
			d = m
			k.Sub(k, big.NewInt(int64(d)))
		}
		digits = append(digits, d)
		k.Rsh(k, 1)
	}
	return digits
}

func (g2 *G2) AssertIsEqual(p, q *G2Affine) {
	g2.Ext2.AssertIsEqual(&p.P.X, &q.P.X)
	g2.Ext2.AssertIsEqual(&p.P.Y, &q.P.Y)
}

func (g2 *G2) IsEqual(p, q *G2Affine) frontend.Variable {
	xEqual := g2.Ext2.IsEqual(&p.P.X, &q.P.X)
	yEqual := g2.Ext2.IsEqual(&p.P.Y, &q.P.Y)
	return g2.api.And(xEqual, yEqual)
}

// scalarMulGeneric computes [s]p and returns it. It doesn't modify p nor s.
// This function doesn't check that the p is on the curve. See AssertIsOnCurve.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this test-only helper is
// faster but not complete. The exact exceptional set is currently unknown and
// should be treated as implementation-dependent.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It computes the right-to-left variable-base double-and-add algorithm ([Joye07], Alg.1).
//
// Since we use incomplete formulas for the addition law, we need to start with
// a non-zero accumulator point (R0). To do this, we skip the LSB (bit at
// position 0) and proceed assuming it was 1. At the end, we conditionally
// subtract the initial value (p) if LSB is 1. We also handle the bits at
// positions 1 and n-1 outside of the loop to optimize the number of
// constraints using [ELM03] (Section 3.1)
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
// [Joye07]: https://www.iacr.org/archive/ches2007/47270135/47270135.pdf
func (g2 *G2) scalarMulGeneric(p *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	var selector frontend.Variable
	if !cfg.IncompleteArithmetic {
		// if p=(0,0) we assign a dummy (0,1) to p and continue
		selector = g2.api.And(g2.Ext2.IsZero(&p.P.X), g2.Ext2.IsZero(&p.P.Y))
		one := g2.Ext2.One()
		p = g2.Select(selector, &G2Affine{P: g2AffP{X: *one, Y: *one}, Lines: nil}, p)
	}

	var st ScalarField
	sBits := g2.fr.ToBitsCanonical(s)
	n := st.Modulus().BitLen()
	if cfg.NbScalarBits > 2 && cfg.NbScalarBits < n {
		n = cfg.NbScalarBits
	}

	// i = 1
	Rb := g2.triple(p)
	R0 := g2.Select(sBits[1], Rb, p)
	R1 := g2.Select(sBits[1], p, Rb)

	for i := 2; i < n-1; i++ {
		Rb = g2.doubleAndAddSelect(sBits[i], R0, R1)
		R0 = g2.Select(sBits[i], Rb, R0)
		R1 = g2.Select(sBits[i], R1, Rb)
	}

	// i = n-1
	Rb = g2.doubleAndAddSelect(sBits[n-1], R0, R1)
	R0 = g2.Select(sBits[n-1], Rb, R0)

	// i = 0
	// we use AddUnified instead of Add. This is because:
	// 		- when s=0 then R0=P and AddUnified(P, -P) = (0,0). We return (0,0).
	// 		- when s=1 then R0=P AddUnified(Q, -Q) is well defined. We return R0=P.
	R0 = g2.Select(sBits[0], R0, g2.AddUnified(R0, g2.neg(p)))

	if !cfg.IncompleteArithmetic {
		// if p=(0,0), return (0,0)
		zero := g2.Ext2.Zero()
		R0 = g2.Select(selector, &G2Affine{P: g2AffP{X: *zero, Y: *zero}, Lines: nil}, R0)
	}

	return R0
}

// ScalarMul computes [s]Q using GLV+FakeGLV with proven r^(1/4) sub-scalar
// bounds (LLL Hermite). Routes through scalarMulGLVAndFakeGLV.
//
// Q is assumed to be in the prime-order G2 subgroup; this method does not check
// subgroup membership for arbitrary twist points.
//
// This method is complete by default.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. Besides Q=(0,0) and s in {0, ±1}, there is a sparse
// point-dependent exceptional set coming from incomplete precomputations and the
// initial bias step. This mode is intended for random non-adversarial inputs.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
//
// [EEMP25]: https://eprint.iacr.org/2025/933
func (g2 *G2) ScalarMul(Q *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	// when Q is a compile-time constant subgroup point (for example a fixed
	// verification-key or SRS point), use the fixed-base comb method with
	// precomputed tables (see fixedbase_g2.go). It uses complete arithmetic
	// and handles the zero scalar; [algopts.WithIncompleteArithmetic] is a
	// no-op on this path.
	if d, ok := g2.g2CombTryConst(Q); ok {
		return g2.scalarMulComb(d, s)
	}
	R := g2.scalarMulGLVAndFakeGLV(Q, s, opts...)
	g2.assertPointInSubgroup(R)
	return R
}

// assertPointInSubgroup binds an arbitrary hinted G2 point R into the prime-order
// subgroup via a preimage check: it hints S = [c⁻¹ mod r]·R (reusing
// scalarMulG2CofactorPreimageHint with the scalar input s = 1) and asserts S
// on-curve and [c]S == R, where c = g2CofactorClearingConstant clears every
// cofactor torsion of order < 2^nbits. A torsion-shifted R = R₀ + T (R₀ in the
// subgroup, ord(T) | c) has no on-curve preimage under [c], so it is rejected.
//
// Being point-based (independent of the scalar-mul inputs) it can be applied once
// to an aggregate MSM output instead of once per summand: each summand's
// accumulator forces its subgroup part exactly, so binding the sum forces the net
// torsion to O. See [G2.MultiScalarMul].
//
// The R = O case (encoded (0,0)) has no affine preimage, so a dummy in-subgroup
// point is substituted and the equality is made vacuous to preserve completeness.
func (g2 *G2) assertPointInSubgroup(R *G2Affine) {
	skip := g2.api.And(g2.Ext2.IsZero(&R.P.X), g2.Ext2.IsZero(&R.P.Y))
	dummy := &G2Affine{P: *g2.g2Gen} // in-subgroup, so [c][c⁻¹]dummy == dummy
	Rsafe := g2.Select(skip, dummy, R)
	_, preimg, _, err := emulated.NewVarGenericHint(g2.api, 0, 4, 0, nil,
		[]*emulated.Element[BaseField]{&Rsafe.P.X.A0, &Rsafe.P.X.A1, &Rsafe.P.Y.A0, &Rsafe.P.Y.A1},
		[]*emulated.Element[ScalarField]{g2.fr.One()},
		scalarMulG2CofactorPreimageHint)
	if err != nil {
		panic(fmt.Sprintf("scalarMulG2CofactorPreimageHint: %v", err))
	}
	S := &G2Affine{P: g2AffP{
		X: fields_bls12381.E2{A0: *preimg[0], A1: *preimg[1]},
		Y: fields_bls12381.E2{A0: *preimg[2], A1: *preimg[3]},
	}}
	g2.assertIsOnCurve(S)
	cS := g2.mulByConstant(S, g2CofactorClearingConstant)
	g2.AssertIsEqual(cS, g2.Select(skip, cS, R))
}

// scalarMulGLVAndFakeGLV computes [s]Q using GLV+FakeGLV with r^(1/4) bounds.
// It implements the "GLV + fake GLV" explained in [EEMP25] (Sec. 3.3).
//
// We hint the result R = [s]Q and verify the equation
//
//	[v1]R + [v2]Φ(R) + [u1]Q + [u2]Φ(Q) = O
//
// where (u1, u2, v1, v2) is the LLL-reduced 4-D Eisenstein decomposition of −s
// against the GLV eigenvalue λ, so each sub-scalar fits in roughly r^(1/4)
// bits — about a quarter of the iteration count of plain GLV.
//
// This method is complete by default.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. Besides Q=(0,0) and s in {0, ±1}, there is a sparse
// point-dependent exceptional set coming from incomplete precomputations and the
// initial bias step. This mode is intended for random non-adversarial inputs.
//
// [EEMP25]: https://eprint.iacr.org/2025/933
func (g2 *G2) scalarMulGLVAndFakeGLV(Q *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var st ScalarField
	// LLL Hermite bound: u_i, v_i < γ₄·r^(1/4), fits in (BitLen+3)/4 + 2 bits.
	nbits := (st.Modulus().BitLen()+3)/4 + 2

	// handle 0-scalar and (-1)-scalar cases
	var isScalarZero, isScalarZeroOrMinusOne, isScalarOne, isScalarMinusOne frontend.Variable
	_s := s
	if !cfg.IncompleteArithmetic {
		isScalarZero = g2.fr.IsZero(s)
		one := g2.fr.One()
		isScalarOne = g2.fr.IsZero(g2.fr.Sub(s, one))
		isScalarMinusOne = g2.fr.IsZero(g2.fr.Add(s, one))
		isScalarZeroOrMinusOne = g2.api.Or(isScalarZero, isScalarMinusOne)
		_s = g2.fr.Select(isScalarZeroOrMinusOne, one, s)
	}

	// Decompose s into (u1, u2, v1, v2) via LLL: s·(v1 + λ·v2) + u1 + λ·u2 ≡ 0
	// (mod r), with each sub-scalar bounded by ~r^(1/4).
	signs, sd, err := g2.fr.NewHintGeneric(rationalReconstructExtG2, 4, 4, nil, []*emulated.Element[ScalarField]{_s, g2.eigenvalue},
		emulated.WithHintOutputRangeCheckBits(map[int]int{4: nbits, 5: nbits, 6: nbits, 7: nbits}))
	if err != nil {
		panic(fmt.Sprintf("rationalReconstructExtG2 hint: %v", err))
	}
	u1, u2, v1, v2 := sd[0], sd[1], sd[2], sd[3]
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// Verify s·(v1 + λ·v2) + u1 + λ·u2 ≡ 0 (mod r).

	sv1 := g2.fr.Mul(_s, v1)
	sλv2 := g2.fr.Mul(_s, g2.fr.Mul(g2.eigenvalue, v2))
	λu2 := g2.fr.Mul(g2.eigenvalue, u2)
	zero := g2.fr.Zero()

	lhs1 := g2.fr.Select(isNegv1, zero, sv1)
	lhs2 := g2.fr.Select(isNegv2, zero, sλv2)
	lhs3 := g2.fr.Select(isNegu1, zero, u1)
	lhs4 := g2.fr.Select(isNegu2, zero, λu2)
	lhs := g2.fr.Add(g2.fr.Add(lhs1, lhs2), g2.fr.Add(lhs3, lhs4))

	rhs1 := g2.fr.Select(isNegv1, sv1, zero)
	rhs2 := g2.fr.Select(isNegv2, sλv2, zero)
	rhs3 := g2.fr.Select(isNegu1, u1, zero)
	rhs4 := g2.fr.Select(isNegu2, λu2, zero)
	rhs := g2.fr.Add(g2.fr.Add(rhs1, rhs2), g2.fr.Add(rhs3, rhs4))

	g2.fr.AssertIsEqual(lhs, rhs)

	// Soundness: forbid the trivial all-zeros decomposition. The MSM consumes
	// the signed coefficient (±v1) + λ·(±v2) of R, so the non-zero check must
	// be on that signed value — not on the unsigned hinted limbs — otherwise an
	// adversarial hint could zero the signed coefficient and leave R unconstrained.
	signedV1 := g2.fr.Select(isNegv1, g2.fr.Neg(v1), v1)
	signedV2 := g2.fr.Select(isNegv2, g2.fr.Neg(v2), v2)
	g2.fr.AssertIsDifferent(g2.fr.Add(signedV1, g2.fr.Mul(g2.eigenvalue, signedV2)), g2.fr.Zero())

	// Hint R = [s]Q.
	_, point, _, err := emulated.NewVarGenericHint(g2.api, 0, 4, 0, nil,
		[]*emulated.Element[BaseField]{&Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1},
		[]*emulated.Element[ScalarField]{s},
		scalarMulG2Hint)
	if err != nil {
		panic(fmt.Sprintf("scalarMulG2Hint: %v", err))
	}
	R := &G2Affine{
		P: g2AffP{
			X: fields_bls12381.E2{A0: *point[0], A1: *point[1]},
			Y: fields_bls12381.E2{A0: *point[2], A1: *point[3]},
		},
	}
	originalR := R // preserve the unmodified hint output for the return value

	// handle (0,0)-point and scalar edge cases
	var isInputPointAtInfinity frontend.Variable
	_Q := Q
	if !cfg.IncompleteArithmetic {
		dummyQ := &G2Affine{P: *g2.g2Gen}
		dummyR := &G2Affine{P: *g2.g2GenNbits}
		R = g2.Select(isScalarZeroOrMinusOne, dummyR, R)
		isInputPointAtInfinity = g2.api.And(g2.Ext2.IsZero(&Q.P.X), g2.Ext2.IsZero(&Q.P.Y))
		_Q = g2.Select(isInputPointAtInfinity, dummyQ, Q)
		R = g2.Select(isScalarOne, dummyR, R)
	}

	// NOTE: the returned point is NOT bound into the prime-order subgroup. On this
	// cofactor curve the accumulator below only pins it modulo the v-torsion, so a
	// torsion-shifted output satisfies the identity. Callers that expose the result
	// must bind it with [G2.assertPointInSubgroup]; the public entry points
	// ([G2.ScalarMul], [G2.MultiScalarMul]) do so — once per aggregate output, not
	// per summand.

	addFn := g2.add
	if !cfg.IncompleteArithmetic {
		addFn = g2.AddUnified
	}

	// Precompute -Q, -Φ(Q), Φ(Q).
	var tableQ, tablePhiQ [2]*G2Affine
	negQY := g2.Ext2.Neg(&_Q.P.Y)
	tableQ[1] = &G2Affine{
		P: g2AffP{
			X: _Q.P.X,
			Y: *g2.Ext2.Select(isNegu1, negQY, &_Q.P.Y),
		},
	}
	tableQ[0] = g2.neg(tableQ[1])
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&_Q.P.X, g2.w2),
			Y: *g2.Ext2.Select(isNegu2, negQY, &_Q.P.Y),
		},
	}
	tablePhiQ[0] = g2.neg(tablePhiQ[1])

	// Precompute -R, -Φ(R), Φ(R).
	var tableR, tablePhiR [2]*G2Affine
	negRY := g2.Ext2.Neg(&R.P.Y)
	tableR[1] = &G2Affine{
		P: g2AffP{
			X: R.P.X,
			Y: *g2.Ext2.Select(isNegv1, negRY, &R.P.Y),
		},
	}
	tableR[0] = g2.neg(tableR[1])
	tablePhiR[1] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&R.P.X, g2.w2),
			Y: *g2.Ext2.Select(isNegv2, negRY, &R.P.Y),
		},
	}
	tablePhiR[0] = g2.neg(tablePhiR[1])

	// Combine Q, R precomputations into ±Q±R, ±Φ(Q)±Φ(R) tables.
	var tableS [4]*G2Affine
	tableS[0] = addFn(tableQ[0], tableR[0])
	tableS[1] = g2.neg(tableS[0])
	tableS[2] = addFn(tableQ[1], tableR[0])
	tableS[3] = g2.neg(tableS[2])

	var tablePhiS [4]*G2Affine
	tablePhiS[0] = addFn(tablePhiQ[0], tablePhiR[0])
	tablePhiS[1] = g2.neg(tablePhiS[0])
	tablePhiS[2] = addFn(tablePhiQ[1], tablePhiR[0])
	tablePhiS[3] = g2.neg(tablePhiS[2])

	// Initial accumulator: Q + R + Φ(Q) + Φ(R) plus a fixed shift by the G2
	// generator to avoid incomplete additions in the loop. At the end Acc
	// will equal [2^(nbits-1)]G2 (the precomputed g2GenNbits).
	Acc := addFn(tableS[1], tablePhiS[1])
	B1 := Acc
	g2GenPoint := &G2Affine{P: *g2.g2Gen}
	Acc = addFn(Acc, g2GenPoint)

	u1bits := g2.fr.ToBits(u1)
	u2bits := g2.fr.ToBits(u2)
	v1bits := g2.fr.ToBits(v1)
	v2bits := g2.fr.ToBits(v2)

	// 16-entry Bi precomputation: ±Q ± R ± Φ(Q) ± Φ(R). Half the entries are
	// negatives of the other half (same X), so we use an 8-to-1 mux + signed Y.
	B2 := addFn(tableS[1], tablePhiS[2])
	B3 := addFn(tableS[1], tablePhiS[3])
	B4 := addFn(tableS[1], tablePhiS[0])
	B5 := addFn(tableS[2], tablePhiS[1])
	B6 := addFn(tableS[2], tablePhiS[2])
	B7 := addFn(tableS[2], tablePhiS[3])
	B8 := addFn(tableS[2], tablePhiS[0])
	B10 := g2.neg(B7)
	B12 := g2.neg(B5)
	B14 := g2.neg(B3)
	B16 := g2.neg(B1)

	var Bi *G2Affine
	for i := nbits - 1; i > 0; i-- {
		selectorY := g2.api.Add(
			u1bits[i],
			g2.api.Mul(u2bits[i], 2),
			g2.api.Mul(v1bits[i], 4),
			g2.api.Mul(v2bits[i], 8),
		)
		selectorX := g2.api.Add(
			g2.api.Mul(selectorY, g2.api.Sub(1, g2.api.Mul(v2bits[i], 2))),
			g2.api.Mul(v2bits[i], 15),
		)
		Bi = &G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{
					A0: *g2.fp.Mux(selectorX,
						&B16.P.X.A0, &B8.P.X.A0, &B14.P.X.A0, &B6.P.X.A0, &B12.P.X.A0, &B4.P.X.A0, &B10.P.X.A0, &B2.P.X.A0,
					),
					A1: *g2.fp.Mux(selectorX,
						&B16.P.X.A1, &B8.P.X.A1, &B14.P.X.A1, &B6.P.X.A1, &B12.P.X.A1, &B4.P.X.A1, &B10.P.X.A1, &B2.P.X.A1,
					),
				},
				Y: *g2.muxE2Y8Signed(v2bits[i], selectorX,
					[8]*emulated.Element[BaseField]{&B16.P.Y.A0, &B8.P.Y.A0, &B14.P.Y.A0, &B6.P.Y.A0, &B12.P.Y.A0, &B4.P.Y.A0, &B10.P.Y.A0, &B2.P.Y.A0},
					[8]*emulated.Element[BaseField]{&B16.P.Y.A1, &B8.P.Y.A1, &B14.P.Y.A1, &B6.P.Y.A1, &B12.P.Y.A1, &B4.P.Y.A1, &B10.P.Y.A1, &B2.P.Y.A1},
				),
			},
		}
		if !cfg.IncompleteArithmetic {
			Acc = g2.doubleGeneric(Acc, true)
			Acc = addFn(Acc, Bi)
		} else {
			Acc = g2.doubleAndAdd(Acc, Bi)
		}
	}

	// i = 0: subtract Q, Φ(Q), R, Φ(R) if the first bits are 0.
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = g2.Select(u1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = addFn(tablePhiQ[0], Acc)
	Acc = g2.Select(u2bits[0], Acc, tablePhiQ[0])
	tableR[0] = addFn(tableR[0], Acc)
	Acc = g2.Select(v1bits[0], Acc, tableR[0])
	tablePhiR[0] = addFn(tablePhiR[0], Acc)
	Acc = g2.Select(v2bits[0], Acc, tablePhiR[0])

	// At this point Acc must equal [2^(nbits-1)]G2 (the bias we added).
	expected := &G2Affine{P: *g2.g2GenNbits}

	if !cfg.IncompleteArithmetic {
		Acc = g2.Select(g2.api.Or(g2.api.Or(isScalarZeroOrMinusOne, isInputPointAtInfinity), isScalarOne), expected, Acc)
	}
	g2.AssertIsEqual(Acc, expected)

	if !cfg.IncompleteArithmetic {
		zeroE2 := g2.Ext2.Zero()
		zeroG2 := &G2Affine{P: g2AffP{X: *zeroE2, Y: *zeroE2}}
		result := g2.Select(isScalarOne, Q, originalR)
		result = g2.Select(isScalarZeroOrMinusOne, g2.neg(Q), result)
		result = g2.Select(isScalarZero, zeroG2, result)
		result = g2.Select(isInputPointAtInfinity, zeroG2, result)
		return result
	}
	return R
}

// MultiScalarMul computes the multi scalar multiplication of the points P and
// scalars s. It returns an error if the length of the slices mismatch. If the
// input slices are empty, then returns point at infinity.
//
// By default, uses complete arithmetic which correctly handles zero scalars and
// points at infinity.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. It inherits the exceptional sets of the underlying scalar-mul
// calls and additionally depends on internal accumulator collisions, so the
// incomplete exceptional set is not fully characterized at the API level.
func (g2 *G2) MultiScalarMul(p []*G2Affine, s []*Scalar, opts ...algopts.AlgebraOption) (*G2Affine, error) {

	if len(p) == 0 {
		return &G2Affine{
			P: g2AffP{
				X: *g2.Ext2.Zero(),
				Y: *g2.Ext2.Zero(),
			},
			Lines: nil,
		}, nil
	}
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	addFn := g2.add
	if !cfg.IncompleteArithmetic {
		addFn = g2.AddUnified
	}
	if !cfg.FoldMulti {
		// the scalars are unique
		if len(p) != len(s) {
			return nil, fmt.Errorf("mismatching points and scalars slice lengths")
		}
		n := len(p)
		// Deferred subgroup binding: fold constant prime-order points through the
		// comb (computed, already in-subgroup) and the variable points through the
		// UNBOUND fake-GLV, then bind the aggregate ONCE (n subgroup checks → 1).
		// Sound because each fake-GLV summand's accumulator forces its subgroup part
		// exactly, so binding the sum forces the net torsion to O; the comb summands
		// contribute no torsion.
		var res *G2Affine
		hasVar := false
		for i := 0; i < n; i++ {
			var q *G2Affine
			if d, ok := g2.g2CombTryConst(p[i]); ok {
				q = g2.scalarMulComb(d, s[i])
			} else {
				q = g2.scalarMulGLVAndFakeGLV(p[i], s[i], opts...)
				hasVar = true
			}
			if res == nil {
				res = q
			} else {
				res = addFn(res, q)
			}
		}
		if hasVar {
			g2.assertPointInSubgroup(res)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(s) == 0 {
			return nil, fmt.Errorf("need scalar for folding")
		}
		gamma := s[0]
		res := g2.ScalarMul(p[len(p)-1], gamma, opts...)
		for i := len(p) - 2; i > 0; i-- {
			res = addFn(p[i], res)
			res = g2.ScalarMul(res, gamma, opts...)
		}
		res = addFn(p[0], res)
		return res, nil
	}
}
