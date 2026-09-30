package sw_bw6761

import (
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// g2AffP is the raw G2 element without precomputations.
type g2AffP = sw_emulated.AffinePoint[BaseField]

// G2Affine represents G2 element with optional embedded line precomputations.
type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

func newG2AffP(v bw6761.G2Affine) g2AffP {
	return sw_emulated.AffinePoint[BaseField]{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

// NewG2Affine returns the witness of v without precomputations. In case of
// pairing the precomputation will be done in-circuit.
func NewG2Affine(v bw6761.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bw6761.G2Affine) G2Affine {
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
	for i := 0; i < len(bw6761.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}

type G2 struct {
	api    frontend.API
	curveF *emulated.Field[BaseField]
	fr     *emulated.Field[ScalarField]
	w      *emulated.Element[BaseField]
	// GLV eigenvalue for endomorphism
	eigenvalue *emulated.Element[ScalarField]

	// Precomputed G2 generator and its multiple for GLV+FakeGLV
	g2Gen      *g2AffP // G2 generator
	g2GenNbits *g2AffP // [2^(nbits-1)]G2 where nbits = (r.BitLen()+3)/4 + 2
}

func NewG2(api frontend.API) (*G2, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	fr, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	// w = thirdRootOneG2 = thirdRootOneG1^2 (used for GLV endomorphism)
	w := ba.NewElement("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648")
	// GLV eigenvalue: lambda such that phi(P) = [lambda]P
	eigenvalue := fr.NewElement("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945")

	// Precomputed G2 generator for GLV+FakeGLV
	g2Gen := &g2AffP{
		X: *ba.NewElement("6445332910596979336035888152774071626898886139774101364933948236926875073754470830732273879639675437155036544153105017729592600560631678554299562762294743927912429096636156401171909259073181112518725201388196280039960074422214428"),
		Y: *ba.NewElement("562923658089539719386922163444547387757586534741080263946953401595155211934630598999300396317104182598044793758153214972605680357108252243146746187917218885078195819486220416605630144001533548163105316661692978285266378674355041"),
	}
	// [2^(nbits-1)]G2 where nbits = (377+3)/4 + 2 = 97, so this is [2^96]G2
	// The loop does nbits-1 doublings, so the generator accumulates to [2^(nbits-1)]G2
	g2GenNbits := &g2AffP{
		X: *ba.NewElement("3095984673093732516312387265169694060996602327701627003095800025572039633257324043941471095859774515229409057356532230556857309141882262691503434703676863345821048055421798431014967860961114720963410640620563703233324706890355614"),
		Y: *ba.NewElement("6717446314608317454056612988521276523143603352262745009529835803932138303462642316467740443074785130100608444461459148229179290796669940701932233012187852232981798195344309857014515889020782044489099447799956729215609170567055537"),
	}

	return &G2{
		api:        api,
		curveF:     ba,
		fr:         fr,
		w:          w,
		eigenvalue: eigenvalue,
		// GLV+FakeGLV precomputed values
		g2Gen:      g2Gen,
		g2GenNbits: g2GenNbits,
	}, nil
}

func (g2 *G2) phi(q *G2Affine) *G2Affine {
	x := g2.curveF.Mul(&q.P.X, g2.w)

	return &G2Affine{
		P: g2AffP{
			X: *x,
			Y: q.P.Y,
		},
	}
}

// scalarMulBySeed computes the [x₀]q where x₀=9586122913090633729 is the seed of the curve.
func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {
	z := g2.triple(q)
	z = g2.doubleAndAdd(z, q)
	t0 := g2.double(z)
	t0 = g2.double(t0)
	z = g2.add(z, t0)
	t1 := g2.triple(z)
	t0 = g2.add(t0, t1)
	t0 = g2.doubleN(t0, 9)
	z = g2.doubleAndAdd(t0, z)
	z = g2.doubleN(z, 45)
	z = g2.doubleAndAdd(z, q)

	return z
}

// AddUnified adds p and q and returns it. It doesn't modify p nor q.
//
// ✅ p can be equal to q, and either or both can be (0,0).
// ([0,0],[0,0]) is not on the curve but we conventionally take it as the
// neutral/infinity point.
//
// It uses a chord/tangent split with a single-Div fold to avoid exceptional
// cases in complete-mode scalar multiplication.
func (g2 *G2) AddUnified(p, q *G2Affine) *G2Affine {
	isPInf := g2.api.And(g2.curveF.IsZero(&p.P.X), g2.curveF.IsZero(&p.P.Y))
	isQInf := g2.api.And(g2.curveF.IsZero(&q.P.X), g2.curveF.IsZero(&q.P.Y))

	xDiff := g2.curveF.Sub(&q.P.X, &p.P.X)
	xEqual := g2.curveF.IsZero(xDiff)

	numChord := g2.curveF.Sub(&q.P.Y, &p.P.Y)
	denChord := xDiff
	xx := g2.curveF.Mul(&p.P.X, &p.P.X)
	numTangent := g2.curveF.MulConst(xx, big.NewInt(3))
	denTangent := g2.curveF.MulConst(&p.P.Y, big.NewInt(2))

	num := g2.curveF.Select(xEqual, numTangent, numChord)
	den := g2.curveF.Select(xEqual, denTangent, denChord)
	denIsZero := g2.curveF.IsZero(den)
	denSafe := g2.curveF.Select(denIsZero, g2.curveF.One(), den)
	λ := g2.curveF.Div(num, denSafe)
	λ = g2.curveF.Select(denIsZero, g2.curveF.Zero(), λ)

	pxPlusQx := g2.curveF.Add(&p.P.X, &q.P.X)
	xr := g2.curveF.Mul(λ, λ)
	xr = g2.curveF.Sub(xr, pxPlusQx)

	pxMinusXr := g2.curveF.Sub(&p.P.X, xr)
	yr := g2.curveF.Mul(λ, pxMinusXr)
	yr = g2.curveF.Sub(yr, &p.P.Y)

	result := &G2Affine{
		P:     g2AffP{X: *xr, Y: *yr},
		Lines: nil,
	}

	result = g2.Select(isPInf, q, result)
	result = g2.Select(isQInf, p, result)

	ySub := g2.curveF.Sub(&p.P.Y, &q.P.Y)
	yEqual := g2.curveF.IsZero(ySub)
	areFinite := g2.api.And(g2.api.Sub(1, isPInf), g2.api.Sub(1, isQInf))
	isInverse := g2.api.And(g2.api.And(xEqual, g2.api.Sub(1, yEqual)), areFinite)
	zero := g2.curveF.Zero()
	infinity := G2Affine{
		P:     g2AffP{X: *zero, Y: *zero},
		Lines: nil,
	}
	result = g2.Select(isInverse, &infinity, result)

	return result
}

func (g2 G2) add(p, q *G2Affine) *G2Affine {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g2.curveF.Sub(&q.P.Y, &p.P.Y)
	qxpx := g2.curveF.Sub(&q.P.X, &p.P.X)
	λ := g2.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr := g2.curveF.Eval([][]*baseEl{{λ, λ}, {&p.P.X}, {&q.P.X}}, []int{1, -1, -1})

	// p.y = λ(p.x-r.x) - p.y
	yr := g2.curveF.Eval([][]*baseEl{{λ, &p.P.X}, {λ, xr}, {&p.P.Y}}, []int{1, -1, -1})

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 G2) neg(p *G2Affine) *G2Affine {
	xr := &p.P.X
	yr := g2.curveF.Neg(&p.P.Y)
	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

// muxY8Signed selects from 8 Y-values using selector (0-7) and conditionally
// negates based on signBit. This optimizes the common GLV pattern where Y[i] =
// -Y[15-i], reducing a 16-to-1 Mux to an 8-to-1 Mux plus conditional negation.
func (g2 *G2) muxY8Signed(signBit frontend.Variable, selector frontend.Variable, ys [8]*emulated.Element[BaseField]) *emulated.Element[BaseField] {
	y := g2.curveF.Mux(selector, ys[:]...)
	negY := g2.curveF.Neg(y)
	return g2.curveF.Select(signBit, negY, y)
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
	xx3a := g2.curveF.Mul(&p.P.X, &p.P.X)
	xx3a = g2.curveF.MulConst(xx3a, big.NewInt(3))
	y2 := g2.curveF.MulConst(&p.P.Y, big.NewInt(2))
	var isDoubleYZero frontend.Variable = 0
	if unified {
		isDoubleYZero = g2.curveF.IsZero(y2)
		y2 = g2.curveF.Select(isDoubleYZero, g2.curveF.One(), y2)
	}
	λ := g2.curveF.Div(xx3a, y2)
	if unified {
		λ = g2.curveF.Select(isDoubleYZero, g2.curveF.Zero(), λ)
	}

	// xr = λ²-2p.x
	xr := g2.curveF.Eval([][]*baseEl{{λ, λ}, {&p.P.X}}, []int{1, -2})

	// yr = λ(p.x-xr) - p.y
	yr := g2.curveF.Eval([][]*baseEl{{λ, &p.P.X}, {λ, xr}, {&p.P.Y}}, []int{1, -1, -1})

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

func (g2 G2) doubleAndAdd(p, q *G2Affine) *G2Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.curveF.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.curveF.Sub(&q.P.X, &p.P.X)
	λ1 := g2.curveF.Div(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x2 := g2.curveF.Eval([][]*baseEl{{λ1, λ1}, {&p.P.X}, {&q.P.X}}, []int{1, -1, -1})

	// omit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := g2.curveF.Add(&p.P.Y, &p.P.Y)
	x2xp := g2.curveF.Sub(x2, &p.P.X)
	λ2 := g2.curveF.Div(ypyp, x2xp)
	λ2 = g2.curveF.Add(λ1, λ2)
	λ2 = g2.curveF.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	x3 := g2.curveF.Eval([][]*baseEl{{λ2, λ2}, {&p.P.X}, {x2}}, []int{1, -1, -1})

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.curveF.Eval([][]*baseEl{{λ2, &p.P.X}, {λ2, x3}, {&p.P.Y}}, []int{1, -1, -1})

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

func (g2 G2) triple(p *G2Affine) *G2Affine {

	// compute λ = (3p.x²)/2*p.y
	xx := g2.curveF.Mul(&p.P.X, &p.P.X)
	xx = g2.curveF.MulConst(xx, big.NewInt(3))
	y2 := g2.curveF.MulConst(&p.P.Y, big.NewInt(2))
	λ1 := g2.curveF.Div(xx, y2)

	// xr = λ²-2p.x
	x2 := g2.curveF.Eval([][]*baseEl{{λ1, λ1}, {&p.P.X}}, []int{1, -2})

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.curveF.Sub(&p.P.X, x2)
	λ2 := g2.curveF.Div(y2, x1x2)
	λ2 = g2.curveF.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	xr := g2.curveF.Eval([][]*baseEl{{λ2, λ2}, {&p.P.X}, {x2}}, []int{1, -1, -1})

	// yr = λ(p.x-xr) - p.y
	yr := g2.curveF.Eval([][]*baseEl{{λ2, &p.P.X}, {λ2, xr}, {&p.P.Y}}, []int{1, -1, -1})

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (g2 *G2) AssertIsEqual(p, q *G2Affine) {
	g2.curveF.AssertIsEqual(&p.P.X, &q.P.X)
	g2.curveF.AssertIsEqual(&p.P.Y, &q.P.Y)
}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (g2 *G2) Select(b frontend.Variable, p, q *G2Affine) *G2Affine {
	x := g2.curveF.Select(b, &p.P.X, &q.P.X)
	y := g2.curveF.Select(b, &p.P.Y, &q.P.Y)
	return &G2Affine{
		P:     g2AffP{X: *x, Y: *y},
		Lines: nil,
	}
}

// assertIsOnCurve asserts that P satisfies the BW6-761 G2 curve equation
// Y² = X³ + b over 𝔽ₚ. The constant b is recovered from the (on-curve,
// in-subgroup) generator as b = Gy² − Gx³, avoiding a hardcoded literal.
func (g2 *G2) assertIsOnCurve(P *G2Affine) {
	x3 := g2.curveF.Mul(&P.P.X, g2.curveF.Mul(&P.P.X, &P.P.X))
	lhs := g2.curveF.Sub(g2.curveF.Mul(&P.P.Y, &P.P.Y), x3)
	gx3 := g2.curveF.Mul(&g2.g2Gen.X, g2.curveF.Mul(&g2.g2Gen.X, &g2.g2Gen.X))
	rhs := g2.curveF.Sub(g2.curveF.Mul(&g2.g2Gen.Y, &g2.g2Gen.Y), gx3)
	g2.curveF.AssertIsEqual(lhs, rhs)
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
	// BW6-761 G2 lives over Fp (a sextic twist), so its points are ordinary
	// sw_emulated affine points. We route ScalarMul through classic GLV rather
	// than GLV+fake-GLV: the classic-GLV output is *computed*, hence inherently in
	// the prime-order subgroup, so it needs no cofactor-clearing binding. This
	// closes the chosen-scalar cofactor hole (a rational φ-eigenvector reaches
	// torsion up to ~r^{1/2}, so a minimal clearing constant would be unsound, and
	// full-cofactor clearing is expensive) at lower cost — mirroring the
	// PreferClassicGLV routing of BLS12-381 G1 and BW6-761 G1 in sw_emulated.
	cr, err := sw_emulated.New[BaseField, ScalarField](g2.api, bw6761G2ClassicParams)
	if err != nil {
		panic(err)
	}
	res := cr.ScalarMul(&Q.P, s, opts...)
	return &G2Affine{P: *res}
}

// bw6761G2ClassicParams are the sw_emulated curve parameters for BW6-761's G2
// (y² = x³ + 4 over Fp), with PreferClassicGLV so ScalarMul uses classic GLV.
// Computed once (the generator table is a set of fixed G2 doublings).
var bw6761G2ClassicParams = func() sw_emulated.CurveParams {
	_, _, _, g2 := bw6761.Generators()
	lambda, _ := new(big.Int).SetString("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945", 10)
	// ω = thirdRootOneG2 = thirdRootOneG1² (the G2 endomorphism φ: (x,y) ↦ (ωx,y)).
	omega, _ := new(big.Int).SetString("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648", 10)
	return sw_emulated.CurveParams{
		A:                big.NewInt(0),
		B:                big.NewInt(4),
		Gx:               g2.X.BigInt(new(big.Int)),
		Gy:               g2.Y.BigInt(new(big.Int)),
		Gm:               computeBW6761G2Table(),
		Eigenvalue:       lambda,
		ThirdRootOne:     omega,
		PreferClassicGLV: true,
	}
}()

// computeBW6761G2Table returns the generator-multiples table for BW6-761 G2,
// mirroring sw_emulated's computeBW6761Table (G1) with G2 arithmetic.
func computeBW6761G2Table() [][2]*big.Int {
	_, Gjac, _, _ := bw6761.Generators()
	table := make([][2]*big.Int, 377)
	tmp := new(bw6761.G2Jac).Set(&Gjac)
	aff := new(bw6761.G2Affine)
	jac := new(bw6761.G2Jac)
	for i := 1; i < 377; i++ {
		tmp = tmp.Double(tmp)
		switch i {
		case 1, 2:
			jac.Set(tmp).AddAssign(&Gjac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		case 3:
			jac.Set(tmp).SubAssign(&Gjac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
			fallthrough
		default:
			aff.FromJacobian(tmp)
			table[i] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		}
	}
	return table
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
	// u1, u2, v1, v2 < c*r^{1/4} where c ≈ 1.25
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
	lhs := g2.fr.Add(
		g2.fr.Add(lhs1, lhs2),
		g2.fr.Add(lhs3, lhs4),
	)

	rhs1 := g2.fr.Select(isNegv1, sv1, zero)
	rhs2 := g2.fr.Select(isNegv2, sλv2, zero)
	rhs3 := g2.fr.Select(isNegu1, u1, zero)
	rhs4 := g2.fr.Select(isNegu2, λu2, zero)
	rhs := g2.fr.Add(
		g2.fr.Add(rhs1, rhs2),
		g2.fr.Add(rhs3, rhs4),
	)

	g2.fr.AssertIsEqual(lhs, rhs)

	// Soundness: forbid the trivial all-zeros decomposition. The MSM consumes
	// the signed coefficient (±v1) + λ·(±v2) of R, so the non-zero check must
	// be on that signed value — not on the unsigned hinted limbs — otherwise an
	// adversarial hint could zero the signed coefficient and leave R unconstrained.
	signedV1 := g2.fr.Select(isNegv1, g2.fr.Neg(v1), v1)
	signedV2 := g2.fr.Select(isNegv2, g2.fr.Neg(v2), v2)
	g2.fr.AssertIsDifferent(g2.fr.Add(signedV1, g2.fr.Mul(g2.eigenvalue, signedV2)), g2.fr.Zero())

	// Hint R = [s]Q.
	_, point, _, err := emulated.NewVarGenericHint(g2.api, 0, 2, 0, nil,
		[]*emulated.Element[BaseField]{&Q.P.X, &Q.P.Y},
		[]*emulated.Element[ScalarField]{s},
		scalarMulG2Hint)
	if err != nil {
		panic(fmt.Sprintf("scalarMulG2Hint: %v", err))
	}
	R := &G2Affine{
		P: g2AffP{
			X: *point[0],
			Y: *point[1],
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
		isInputPointAtInfinity = g2.api.And(g2.curveF.IsZero(&Q.P.X), g2.curveF.IsZero(&Q.P.Y))
		_Q = g2.Select(isInputPointAtInfinity, dummyQ, Q)
		R = g2.Select(isScalarOne, dummyR, R)
	}

	// Subgroup binding: force the hinted output R = [s]Q into the prime-order G2
	// subgroup via a preimage check [c]S == R with S constrained on-curve, where
	// c = g2CofactorClearingConstant = 3·13·261812779·10233228391030511371 clears
	// every cofactor prime < 2^nbits (h = 3·13·261812779·10233228391030511371·
	// (118-bit prime)·(170-bit prime); the two large prime parts have order ≫
	// 2^nbits, out of reach of the r^(1/4) sub-scalars). Without this, a
	// torsion-shifted R' = [s]Q + T with ord(T) | c satisfies the accumulator
	// identity and would be accepted as [s]Q.
	{
		_, preimg, _, errPre := emulated.NewVarGenericHint(g2.api, 0, 2, 0, nil,
			[]*emulated.Element[BaseField]{&Q.P.X, &Q.P.Y},
			[]*emulated.Element[ScalarField]{s},
			scalarMulG2CofactorPreimageHint)
		if errPre != nil {
			panic(fmt.Sprintf("scalarMulG2CofactorPreimageHint: %v", errPre))
		}
		S := &G2Affine{P: g2AffP{X: *preimg[0], Y: *preimg[1]}}
		if !cfg.IncompleteArithmetic {
			// R = O in the s=0 / Q=∞ cases: the identity has no affine preimage, so
			// substitute a dummy on-curve point and make the equality vacuous to
			// preserve completeness.
			skip := g2.api.Or(isScalarZero, isInputPointAtInfinity)
			S = g2.Select(skip, &G2Affine{P: *g2.g2Gen}, S)
			g2.assertIsOnCurve(S)
			cS := g2.mulByConstant(S, g2CofactorClearingConstant)
			g2.AssertIsEqual(cS, g2.Select(skip, cS, originalR))
		} else {
			g2.assertIsOnCurve(S)
			cS := g2.mulByConstant(S, g2CofactorClearingConstant)
			g2.AssertIsEqual(cS, originalR)
		}
	}

	addFn := g2.add
	if !cfg.IncompleteArithmetic {
		addFn = g2.AddUnified
	}

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]*G2Affine
	negQY := g2.curveF.Neg(&_Q.P.Y)
	tableQ[1] = &G2Affine{
		P: g2AffP{
			X: _Q.P.X,
			Y: *g2.curveF.Select(isNegu1, negQY, &_Q.P.Y),
		},
	}
	tableQ[0] = g2.neg(tableQ[1])
	// For BW6-761 G2, phi(Q) = (w * Q.X, Q.Y)
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: *g2.curveF.Mul(&_Q.P.X, g2.w),
			Y: *g2.curveF.Select(isNegu2, negQY, &_Q.P.Y),
		},
	}
	tablePhiQ[0] = g2.neg(tablePhiQ[1])

	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]*G2Affine
	negRY := g2.curveF.Neg(&R.P.Y)
	tableR[1] = &G2Affine{
		P: g2AffP{
			X: R.P.X,
			Y: *g2.curveF.Select(isNegv1, negRY, &R.P.Y),
		},
	}
	tableR[0] = g2.neg(tableR[1])
	tablePhiR[1] = &G2Affine{
		P: g2AffP{
			X: *g2.curveF.Mul(&R.P.X, g2.w),
			Y: *g2.curveF.Select(isNegv2, negRY, &R.P.Y),
		},
	}
	tablePhiR[0] = g2.neg(tablePhiR[1])

	// precompute -Q-R, Q+R, Q-R, -Q+R (combining the two points Q and R)
	var tableS [4]*G2Affine
	tableS[0] = addFn(tableQ[0], tableR[0]) // -Q - R
	tableS[1] = g2.neg(tableS[0])           // Q + R
	tableS[2] = addFn(tableQ[1], tableR[0]) // Q - R
	tableS[3] = g2.neg(tableS[2])           // -Q + R

	// precompute -Φ(Q)-Φ(R), Φ(Q)+Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R) (combining endomorphisms)
	var tablePhiS [4]*G2Affine
	tablePhiS[0] = addFn(tablePhiQ[0], tablePhiR[0]) // -Φ(Q) - Φ(R)
	tablePhiS[1] = g2.neg(tablePhiS[0])              // Φ(Q) + Φ(R)
	tablePhiS[2] = addFn(tablePhiQ[1], tablePhiR[0]) // Φ(Q) - Φ(R)
	tablePhiS[3] = g2.neg(tablePhiS[2])              // -Φ(Q) + Φ(R)

	// Acc = Q + Φ(Q) + R + Φ(R)
	Acc := addFn(tableS[1], tablePhiS[1])
	B1 := Acc

	// Add G2 generator to Acc to avoid incomplete additions in the loop.
	// At the end, since [u1]Q + [u2]Φ(Q) + [v1]R + [v2]Φ(R) = 0,
	// Acc will equal [2^nbits]G2 (precomputed).
	g2GenPoint := &G2Affine{P: *g2.g2Gen}
	Acc = addFn(Acc, g2GenPoint)

	u1bits := g2.fr.ToBits(u1)
	u2bits := g2.fr.ToBits(u2)
	v1bits := g2.fr.ToBits(v1)
	v2bits := g2.fr.ToBits(v2)

	// Precompute all 16 combinations: ±Q ± Φ(Q) ± R ± Φ(R)
	// Using tableS (Q±R) and tablePhiS (Φ(Q)±Φ(R)) to match G1 pattern
	// B1 = (Q+R) + (Φ(Q)+Φ(R)) = Q + R + Φ(Q) + Φ(R)
	B2 := addFn(tableS[1], tablePhiS[2]) // (Q+R) + (Φ(Q)-Φ(R)) = Q + R + Φ(Q) - Φ(R)
	B3 := addFn(tableS[1], tablePhiS[3]) // (Q+R) + (-Φ(Q)+Φ(R)) = Q + R - Φ(Q) + Φ(R)
	B4 := addFn(tableS[1], tablePhiS[0]) // (Q+R) + (-Φ(Q)-Φ(R)) = Q + R - Φ(Q) - Φ(R)
	B5 := addFn(tableS[2], tablePhiS[1]) // (Q-R) + (Φ(Q)+Φ(R)) = Q - R + Φ(Q) + Φ(R)
	B6 := addFn(tableS[2], tablePhiS[2]) // (Q-R) + (Φ(Q)-Φ(R)) = Q - R + Φ(Q) - Φ(R)
	B7 := addFn(tableS[2], tablePhiS[3]) // (Q-R) + (-Φ(Q)+Φ(R)) = Q - R - Φ(Q) + Φ(R)
	B8 := addFn(tableS[2], tablePhiS[0]) // (Q-R) + (-Φ(Q)-Φ(R)) = Q - R - Φ(Q) - Φ(R)
	B10 := g2.neg(B7)                    // -Q + R + Φ(Q) - Φ(R)
	B12 := g2.neg(B5)                    // -Q + R - Φ(Q) - Φ(R)
	B14 := g2.neg(B3)                    // -Q - R + Φ(Q) - Φ(R)
	B16 := g2.neg(B1)                    // -Q - R - Φ(Q) - Φ(R)

	var Bi *G2Affine
	for i := nbits - 1; i > 0; i-- {
		// selectorY takes values in [0,15]
		selectorY := g2.api.Add(
			u1bits[i],
			g2.api.Mul(u2bits[i], 2),
			g2.api.Mul(v1bits[i], 4),
			g2.api.Mul(v2bits[i], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := g2.api.Add(
			g2.api.Mul(selectorY, g2.api.Sub(1, g2.api.Mul(v2bits[i], 2))),
			g2.api.Mul(v2bits[i], 15),
		)

		// Only half of the Bi.X are distinct, and the other half of Bi.Y are
		// negations, so select from 8 entries and conditionally negate Y.
		Bi = &G2Affine{
			P: g2AffP{
				X: *g2.curveF.Mux(selectorX,
					&B16.P.X, &B8.P.X, &B14.P.X, &B6.P.X, &B12.P.X, &B4.P.X, &B10.P.X, &B2.P.X,
				),
				Y: *g2.muxY8Signed(v2bits[i], selectorX,
					[8]*emulated.Element[BaseField]{
						&B16.P.Y, &B8.P.Y, &B14.P.Y, &B6.P.Y, &B12.P.Y, &B4.P.Y, &B10.P.Y, &B2.P.Y,
					},
				),
			},
		}
		// Acc = [2]Acc + Bi
		if !cfg.IncompleteArithmetic {
			Acc = g2.doubleGeneric(Acc, true)
			Acc = addFn(Acc, Bi)
		} else {
			Acc = g2.doubleAndAdd(Acc, Bi)
		}
	}

	// i = 0: subtract Q, Φ(Q), R, Φ(R) if the first bits are 0
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = g2.Select(u1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = addFn(tablePhiQ[0], Acc)
	Acc = g2.Select(u2bits[0], Acc, tablePhiQ[0])
	tableR[0] = addFn(tableR[0], Acc)
	Acc = g2.Select(v1bits[0], Acc, tableR[0])
	tablePhiR[0] = addFn(tablePhiR[0], Acc)
	Acc = g2.Select(v2bits[0], Acc, tablePhiR[0])

	// Acc should now be [2^(nbits-1)]G2 since [u1]Q + [u2]Φ(Q) + [v1]R + [v2]Φ(R) = 0
	// and we added G2 to the initial accumulator.
	expected := &G2Affine{P: *g2.g2GenNbits}

	if !cfg.IncompleteArithmetic {
		Acc = g2.Select(g2.api.Or(g2.api.Or(isScalarZeroOrMinusOne, isInputPointAtInfinity), isScalarOne), expected, Acc)
	}
	g2.AssertIsEqual(Acc, expected)

	if !cfg.IncompleteArithmetic {
		zeroEl := g2.curveF.Zero()
		zeroG2 := &G2Affine{P: g2AffP{X: *zeroEl, Y: *zeroEl}}
		result := g2.Select(isScalarOne, Q, originalR)
		result = g2.Select(isScalarZeroOrMinusOne, g2.neg(Q), result)
		result = g2.Select(isScalarZero, zeroG2, result)
		result = g2.Select(isInputPointAtInfinity, zeroG2, result)
		return result
	}
	return R
}
