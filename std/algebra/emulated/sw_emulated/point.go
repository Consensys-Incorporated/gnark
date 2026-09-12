package sw_emulated

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// New returns a new [Curve] instance over the base field Base and scalar field
// Scalars defined by the curve parameters params. It returns an error if
// initialising the field emulation fails (for example, when the native field is
// too small) or when the curve parameters are incompatible with the fields.
func New[Base, Scalars emulated.FieldParams](api frontend.API, params CurveParams) (*Curve[Base, Scalars], error) {
	ba, err := emulated.NewField[Base](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	sa, err := emulated.NewField[Scalars](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	emuGm := make([]AffinePoint[Base], len(params.Gm))
	for i, v := range params.Gm {
		emuGm[i] = AffinePoint[Base]{*ba.NewElement(v[0]), *ba.NewElement(v[1])}
	}
	Gx := ba.NewElement(params.Gx)
	Gy := ba.NewElement(params.Gy)
	var eigenvalue *emulated.Element[Scalars]
	var thirdRootOne *emulated.Element[Base]
	if params.Eigenvalue != nil && params.ThirdRootOne != nil {
		eigenvalue = sa.NewElement(params.Eigenvalue)
		thirdRootOne = ba.NewElement(params.ThirdRootOne)
	}
	return &Curve[Base, Scalars]{
		params:    params,
		api:       api,
		baseApi:   ba,
		scalarApi: sa,
		g: AffinePoint[Base]{
			X: *Gx,
			Y: *Gy,
		},
		gm:           emuGm,
		a:            *ba.NewElement(params.A),
		b:            *ba.NewElement(params.B),
		addA:         params.A.Cmp(big.NewInt(0)) != 0,
		eigenvalue:   eigenvalue,
		thirdRootOne: thirdRootOne,
	}, nil
}

// Curve is an initialised curve which allows performing group operations.
type Curve[Base, Scalars emulated.FieldParams] struct {
	// params is the parameters of the curve
	params CurveParams
	// api is the native api, we construct it ourselves to be sure
	api frontend.API
	// baseApi is the api for point operations
	baseApi *emulated.Field[Base]
	// scalarApi is the api for scalar operations
	scalarApi *emulated.Field[Scalars]

	// g is the generator (base point) of the curve.
	g AffinePoint[Base]

	// gm are the pre-computed doubles the generator (base point) of the curve.
	gm []AffinePoint[Base]

	a            emulated.Element[Base]
	b            emulated.Element[Base]
	addA         bool
	eigenvalue   *emulated.Element[Scalars]
	thirdRootOne *emulated.Element[Base]

	// combCache caches the fixed-base comb tables per base point and window
	// width.
	combCache map[string]*combData
}

// Generator returns the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) Generator() *AffinePoint[B] {
	return &c.g
}

// GeneratorMultiples returns the pre-computed doubles of the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) GeneratorMultiples() []AffinePoint[B] {
	return c.gm
}

// AffinePoint represents a point on the elliptic curve. We do not check that
// the point is actually on the curve.
//
// Point (0,0) represents point at the infinity. This representation is
// compatible with the EVM representations of points at infinity.
type AffinePoint[Base emulated.FieldParams] struct {
	X, Y emulated.Element[Base]
}

// MarshalScalar marshals the scalar into bits. Compatible with scalar
// marshalling in gnark-crypto.
func (c *Curve[B, S]) MarshalScalar(s emulated.Element[S], opts ...algopts.AlgebraOption) []frontend.Variable {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	var fr S
	nbBits := 8 * ((fr.Modulus().BitLen() + 7) / 8)
	var sReduced *emulated.Element[S]
	if cfg.ToBitsCanonical {
		sReduced = c.scalarApi.ReduceStrict(&s)
	} else {
		sReduced = c.scalarApi.Reduce(&s)
	}
	res := c.scalarApi.ToBits(sReduced)[:nbBits]
	slices.Reverse(res)
	return res
}

// MarshalG1 marshals the affine point into bits. The output is compatible with
// the point marshalling in gnark-crypto.
func (c *Curve[B, S]) MarshalG1(p AffinePoint[B], opts ...algopts.AlgebraOption) []frontend.Variable {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	var fp B
	nbBits := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	var x, y *emulated.Element[B]
	if cfg.ToBitsCanonical {
		x = c.baseApi.ReduceStrict(&p.X)
		y = c.baseApi.ReduceStrict(&p.Y)
	} else {
		x = c.baseApi.Reduce(&p.X)
		y = c.baseApi.Reduce(&p.Y)
	}
	bx := c.baseApi.ToBits(x)[:nbBits]
	by := c.baseApi.ToBits(y)[:nbBits]
	slices.Reverse(bx)
	slices.Reverse(by)
	res := make([]frontend.Variable, 2*nbBits)
	copy(res, bx)
	copy(res[len(bx):], by)
	switch any(fp).(type) {
	case emparams.Secp256k1Fp:
		// in gnark-crypto we do not store the infinity bit for secp256k1 points
		return res
	}
	xZ := c.baseApi.IsZero(x)
	yZ := c.baseApi.IsZero(y)
	isZero := c.api.Mul(xZ, yZ)
	// isZero = 0 -> res[1]=0
	// isZero = 1, infty bit 0 -> res[1]=0
	// isZero = 1, infty bit 1 -> res[1]=1
	res[1] = c.api.Mul(isZero, c.marshalZeroG1())
	return res
}

// different curves have different marshalling for zero point
func (c *Curve[B, S]) marshalZeroG1() frontend.Variable {
	var fp B
	unusedBits := 64 - (fp.Modulus().BitLen() % 64)
	if unusedBits >= 3 {
		return 1
	}
	return 0
}

// Neg returns an inverse of p. It doesn't modify p.
func (c *Curve[B, S]) Neg(p *AffinePoint[B]) *AffinePoint[B] {
	return &AffinePoint[B]{
		X: p.X,
		Y: *c.baseApi.Neg(&p.Y),
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (c *Curve[B, S]) AssertIsEqual(p, q *AffinePoint[B]) {
	c.baseApi.AssertIsEqual(&p.X, &q.X)
	c.baseApi.AssertIsEqual(&p.Y, &q.Y)
}

// add adds p and q and returns it. It doesn't modify p nor q.
//
// ⚠️  p must be different than q and -q, and both nonzero.
//
// It uses incomplete formulas in affine coordinates.
func (c *Curve[B, S]) add(p, q *AffinePoint[B]) *AffinePoint[B] {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := c.baseApi.Sub(&q.Y, &p.Y)
	qxpx := c.baseApi.Sub(&q.X, &p.X)
	λ := c.assertedRatio(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr := c.baseApi.Eval([][]*emulated.Element[B]{{λ, λ}, {c.baseApi.Add(&p.X, &q.X)}}, []int{1, -1})

	// p.y = λ(p.x-r.x) - p.y
	yr := c.baseApi.Eval([][]*emulated.Element[B]{{λ, c.baseApi.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// AssertIsOnCurve asserts if p belongs to the curve. It doesn't modify p.
func (c *Curve[B, S]) AssertIsOnCurve(p *AffinePoint[B]) {
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if p=(0,0) we assign b=0 and continue
	isInfinity := c.api.And(c.baseApi.IsZero(&p.X), c.baseApi.IsZero(&p.Y))
	b := c.baseApi.Select(isInfinity, c.baseApi.Zero(), &c.b)

	var check *emulated.Element[B]
	if !c.addA {
		check = c.baseApi.Eval([][]*emulated.Element[B]{{&p.X, &p.X, &p.X}, {b}, {&p.Y, &p.Y}}, []int{1, 1, -1})
	} else {
		check = c.baseApi.Eval([][]*emulated.Element[B]{{&p.X, &p.X, &p.X}, {&c.a, &p.X}, {b}, {&p.Y, &p.Y}}, []int{1, 1, 1, -1})
	}
	c.baseApi.AssertIsEqual(check, c.baseApi.Zero())
}

// AddUnified adds p and q and returns it. It doesn't modify p nor q.
//
// ✅ p can be equal to q, and either or both can be (0,0).
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It uses the unified formulas of Brier and Joye ([[BriJoy02]] (Corollary 1)).
//
// [BriJoy02]: https://link.springer.com/content/pdf/10.1007/3-540-45664-3_24.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (c *Curve[B, S]) AddUnified(p, q *AffinePoint[B]) *AffinePoint[B] {

	// isPInfinity = 1 when p is (0,0) and 0 otherwise
	isPInfinity := c.api.And(c.baseApi.IsZero(&p.X), c.baseApi.IsZero(&p.Y))
	// isQInfinity = 1 when q is (0,0) and 0 otherwise
	isQInfinity := c.api.And(c.baseApi.IsZero(&q.X), c.baseApi.IsZero(&q.Y))

	zero := c.baseApi.Zero()
	infinity := &AffinePoint[B]{X: *zero, Y: *zero}

	var result *AffinePoint[B]
	if !c.addA {
		// ---------------------------------------------------------------
		// j-invariant 0 (a == 0).
		//
		// The Brier–Joye unified formula λ = (x₁²+x₁x₂+x₂²)/(y₁+y₂) is
		// NOT complete on these curves: Fp contains nontrivial cube roots
		// of unity ω, so two distinct non-inverse points can satisfy
		// y₁ + y₂ = 0 (e.g. q = −Φ(p) where Φ: (x,y) ↦ (ωx,y)).
		//
		// Instead we compute two slopes and select:
		//   • chord   λ = (q.Y − p.Y) / (q.X − p.X)   when p.X ≠ q.X
		//   • tangent λ = 3p.X² / (2p.Y)               when p.X = q.X (doubling)
		// and handle p = −q  (return O) and p/q = O via selectors.
		// ---------------------------------------------------------------

		xDiff := c.baseApi.Sub(&q.X, &p.X)
		xEqual := c.baseApi.IsZero(xDiff)

		// Build the slope with a *single* Div: select the chord/tangent
		// numerator and denominator before dividing, instead of computing two
		// slopes and selecting the result. Saves 1 Div + 1 IsZero on the j=0
		// path (the previous code computed both Div(q.Y-p.Y, xDiff) and
		// Div(3p.X², 2p.Y) before selecting).
		//   • chord   numerator = q.Y - p.Y,  denominator = q.X - p.X
		//   • tangent numerator = 3·p.X²,     denominator = 2·p.Y
		// The combined denominator is zero when p = q = (0,0) and also when
		// doubling a rational 2-torsion point (p = q, p.Y = 0, e.g. (1,0) on
		// BW6-761). In every such case an infinity-selector below overrides
		// `result` with O (or p), so we can safely divide by a dummy 1 and force
		// λ to 0 here.
		numChord := c.baseApi.Sub(&q.Y, &p.Y)
		denChord := xDiff
		denTangent := c.baseApi.MulConst(&p.Y, big.NewInt(2))

		den := c.baseApi.Select(xEqual, denTangent, denChord)
		denIsZero := c.baseApi.IsZero(den)
		denSafe := c.baseApi.Select(denIsZero, c.baseApi.One(), den)
		// witness the unified slope and certify it with a single deferred
		// zero-assertion, blending the chord and tangent numerators with the
		// xEqual indicator instead of materializing 3x² and selecting:
		//   λ·denSafe − xEqual·3x² − (1−xEqual)·(y2−y1) ≡ 0
		// λ remains pinned in all cases; when denIsZero the assertion is
		// satisfied by the hint value and λ is discarded by the select below.
		lams, err := c.baseApi.NewHint(unifiedSlopeHint, 1, &p.X, &p.Y, &q.X, &q.Y)
		if err != nil {
			panic(fmt.Sprintf("unified slope hint: %v", err))
		}
		λ := lams[0]
		zx := c.baseApi.FromBits(xEqual)
		nzx := c.baseApi.Sub(c.baseApi.One(), zx)
		c.baseApi.AssertEvalIsZero(
			[][]*emulated.Element[B]{{λ, denSafe}, {zx, &p.X, &p.X}, {nzx, numChord}},
			[]int{1, -3, -1},
		)
		λ = c.baseApi.Select(denIsZero, c.baseApi.Zero(), λ)

		// compute the result point from λ
		xr := c.baseApi.Eval([][]*emulated.Element[B]{{λ, λ}, {&p.X}, {&q.X}}, []int{1, -1, -1})
		yr := c.baseApi.Eval([][]*emulated.Element[B]{{λ, c.baseApi.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})
		result = &AffinePoint[B]{
			X: *xr,
			Y: *yr,
		}

		// if p=(0,0) return q
		result = c.Select(isPInfinity, q, result)
		// if q=(0,0) return p
		result = c.Select(isQInfinity, p, result)
		// Return O whenever two finite points share the same X and their sum is
		// the point at infinity. Two sub-cases:
		//   • p = −q  (same X, different Y): the chord is vertical.
		//   • doubling a rational 2-torsion point (same X, p = q, p.Y = 0): the
		//     tangent is vertical. BW6-761 uses y² = x³ − 1 and DOES have a
		//     finite order-2 point (1,0), so this case is reachable; the old
		//     "no j=0 curve has rational 2-torsion" assumption was wrong and let
		//     a prover certify (1,0)+(1,0) = (−2,0) instead of O.
		// Both sub-cases collapse to: same X and (different Y or p.Y = 0). Guard
		// with areFinite so O + Q (with Q.Y = 0) is not turned into O — the
		// infinity selectors above already handle the (0,0) inputs.
		yEqual := c.baseApi.IsZero(c.baseApi.Sub(&p.Y, &q.Y))
		areFinite := c.api.And(c.api.Sub(1, isPInfinity), c.api.Sub(1, isQInfinity))
		pyIsZero := c.baseApi.IsZero(&p.Y)
		isInverse := c.api.And(
			c.api.And(xEqual, areFinite),
			c.api.Or(c.api.Sub(1, yEqual), pyIsZero),
		)
		result = c.Select(isInverse, infinity, result)
	} else {
		// ---------------------------------------------------------------
		// j-invariant ≠ 0 (a ≠ 0).
		//
		// For the currently supported j≠0 curves (P-256, P-384 and STARK
		// curve), there is no rational 2-torsion, so no finite on-curve
		// point satisfies Y=0. Under that assumption p.Y + q.Y = 0 implies
		// p = -q, and the Brier-Joye unified formula is complete.
		//
		// If support is added for a j≠0 curve with rational 2-torsion, then
		// the isYSumZero override below must be guarded by finiteness, as in
		// the j=0 branch, to avoid turning O + Q into O when Q.Y = 0.
		// ---------------------------------------------------------------

		// λ = ((p.x+q.x)² - p.x*q.x + a)/(p.y + q.y), certified by a single
		// deferred zero-assertion without materializing the numerator:
		//   λ·denum − (p.x+q.x)² + p.x·q.x − a ≡ 0
		pxplusqx := c.baseApi.Add(&p.X, &q.X)
		denum := c.baseApi.Add(&p.Y, &q.Y)
		// if p.y + q.y = 0, assign dummy 1 to denum and continue
		isYSumZero := c.baseApi.IsZero(denum)
		denum = c.baseApi.Select(isYSumZero, c.baseApi.One(), denum)
		lams, err := c.baseApi.NewHint(bjSlopeHint, 1, &p.X, &p.Y, &q.X, &q.Y, &c.a)
		if err != nil {
			panic(fmt.Sprintf("bj slope hint: %v", err))
		}
		λ := lams[0]
		c.baseApi.AssertEvalIsZero(
			[][]*emulated.Element[B]{{λ, denum}, {pxplusqx, pxplusqx}, {&p.X, &q.X}, {&c.a}},
			[]int{1, -1, 1, -1},
		)

		// x = λ^2 - p.x - q.x
		xr := c.baseApi.MulMod(λ, λ)
		xr = c.baseApi.Sub(xr, pxplusqx)

		// y = λ(p.x - xr) - p.y
		yr := c.baseApi.Sub(&p.X, xr)
		yr = c.baseApi.MulMod(yr, λ)
		yr = c.baseApi.Sub(yr, &p.Y)
		result = &AffinePoint[B]{
			X: *xr,
			Y: *yr,
		}

		// if p=(0,0) return q
		result = c.Select(isPInfinity, q, result)
		// if q=(0,0) return p
		result = c.Select(isQInfinity, p, result)
		// if p.y + q.y = 0, return (0, 0)
		result = c.Select(isYSumZero, infinity, result)
	}

	return result
}

// Add performs unsafe addition of points p and q. For safe addition use
// [Curve.AddUnified].
func (c *Curve[B, S]) Add(p, q *AffinePoint[B]) *AffinePoint[B] {
	return c.add(p, q)
}

// mulByConstant returns [k]p for a fixed k > 0, via a width-4 signed-window (NAF)
// double-and-add using complete (unified) operations, so it is exception-free for
// any on-curve p. Used to clear the cofactor torsion in the fake-GLV subgroup
// binding. k is a [big.Int] because the cofactor-clearing constant can exceed 64
// bits (e.g. the full BLS12-381 G1 cofactor is 126 bits). The signed window trims
// the additions to ~the w-NAF weight (vs the binary Hamming weight); the doubling
// count is unchanged. All operations stay unified (infinity-complete), which is
// soundness-critical since p is an adversarial preimage.
func (c *Curve[B, S]) mulByConstant(p *AffinePoint[B], k *big.Int) *AffinePoint[B] {
	digits := naf4Digits(k) // LSB-first; each digit is 0 or an odd d with |d| < 8
	// precompute the odd multiples 1p, 3p, 5p, 7p (negated on demand)
	p2 := c.doubleGeneric(p, true)
	var odd [8]*AffinePoint[B]
	odd[1] = p
	odd[3] = c.AddUnified(p2, p)
	odd[5] = c.AddUnified(odd[3], p2)
	odd[7] = c.AddUnified(odd[5], p2)
	pick := func(d int8) *AffinePoint[B] {
		if d > 0 {
			return odd[d]
		}
		return c.Neg(odd[-d])
	}
	// scan from the most-significant nonzero digit down
	top := len(digits) - 1
	for top >= 0 && digits[top] == 0 {
		top--
	}
	acc := pick(digits[top])
	for i := top - 1; i >= 0; i-- {
		acc = c.doubleGeneric(acc, true) // unified (complete) doubling
		if digits[i] != 0 {
			acc = c.AddUnified(acc, pick(digits[i]))
		}
	}
	return acc
}

// naf4Digits returns the width-4 non-adjacent form of k > 0, least-significant
// digit first: each digit is 0 or an odd integer with |d| < 8, nonzero digits are
// at least 4 positions apart, and Σ digits[i]·2^i == k. Used to drive a
// signed-window scalar multiplication by a fixed constant.
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

// assertPointInSubgroup binds an arbitrary hinted point R into the prime-order
// subgroup, when the curve has a nontrivial cofactor. It hints a preimage
// S = [c⁻¹ mod r]·R and asserts S on-curve and [c]S == R, where
// c = params.CofactorClearing clears every cofactor torsion of order < 2^nbits.
// A torsion-shifted R = R₀ + T (R₀ in the subgroup, ord(T) | c) has no on-curve
// preimage under [c], so it is rejected. No-op for prime-order curves (c == nil).
//
// Unlike a per-(P,s) binding, this is a point-based check that does not reference
// the scalar-mul inputs, so it can be applied once to an aggregate output (an MSM
// or joint-scalar-mul sum) instead of once per summand: each summand's accumulator
// already forces its subgroup part exactly (Qᵢ = [sᵢ]Pᵢ + Tᵢ with Tᵢ pure torsion,
// given Pᵢ in the subgroup), so binding the sum forces ΣTᵢ = O and the aggregate
// equals Σ[sᵢ]Pᵢ. See [Curve.MultiScalarMul] and [Curve.jointScalarMulGLV].
//
// The R = O case (encoded (0,0)) has no affine preimage, so a dummy in-subgroup
// point is substituted and the equality is made vacuous to preserve completeness.
func (c *Curve[B, S]) assertPointInSubgroup(R *AffinePoint[B]) {
	cc := c.params.CofactorClearing
	if cc == nil {
		return
	}
	var sc S
	cInv := new(big.Int).ModInverse(cc, sc.Modulus())
	if cInv == nil {
		panic("sw_emulated: CofactorClearing not invertible mod r")
	}
	skipZero := c.api.And(c.baseApi.IsZero(&R.X), c.baseApi.IsZero(&R.Y))
	dummy := &c.GeneratorMultiples()[3] // in-subgroup, so [c][c⁻¹]dummy == dummy
	Rsafe := c.Select(skipZero, dummy, R)
	_, pre, _, err := emulated.NewVarGenericHint(c.api, 0, 2, 0, nil,
		[]*emulated.Element[B]{&Rsafe.X, &Rsafe.Y}, []*emulated.Element[S]{c.scalarApi.NewElement(cInv)}, scalarMulPreimageHint)
	if err != nil {
		panic(fmt.Sprintf("cofactor preimage hint: %v", err))
	}
	Sp := &AffinePoint[B]{X: *pre[0], Y: *pre[1]}
	c.AssertIsOnCurve(Sp)
	cS := c.mulByConstant(Sp, cc)
	c.AssertIsEqual(cS, c.Select(skipZero, cS, R))
}

// double doubles p and return it. It doesn't modify p.
//
// ⚠️  p.Y must be nonzero.
//
// It uses affine coordinates.
func (c *Curve[B, S]) double(p *AffinePoint[B]) *AffinePoint[B] {
	return c.doubleGeneric(p, false)
}

func (c *Curve[B, S]) doubleGeneric(p *AffinePoint[B], unified bool) *AffinePoint[B] {
	// compute λ = (3p.x²+a)/2*p.y via a hinted witness and a single deferred
	// zero-assertion, without materializing x². In unified mode y ≡ 0 forces
	// λ = 0 and keeps the assertion satisfiable (see tangentSlope).
	λ := c.tangentSlope(p, unified)

	// xr = λ²-2p.x
	xr := c.baseApi.Eval([][]*emulated.Element[B]{{λ, λ}, {&p.X}}, []int{1, -2})

	// yr = λ(p-xr) - p.y
	yr := c.baseApi.Eval([][]*emulated.Element[B]{{λ, c.baseApi.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})

	return &AffinePoint[B]{
		X: *xr,
		Y: *yr,
	}
}

// triple triples p and return it. It follows [ELM03] (Section 3.1).
// Saves the computation of the y coordinate of 2p as it is used only in the computation of λ2,
// which can be computed as
//
//	λ2 = -λ1-2*p.y/(x2-p.x)
//
// instead. It doesn't modify p.
//
// ⚠️  p.Y must be nonzero.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
func (c *Curve[B, S]) triple(p *AffinePoint[B]) *AffinePoint[B] {
	return c.tripleGeneric(p, false)
}

func (c *Curve[B, S]) tripleGeneric(p *AffinePoint[B], unified bool) *AffinePoint[B] {

	// compute λ1 = (3p.x²+a)/2p.y, here we assume a=0 (j invariant 0 curve)
	xx := c.baseApi.MulMod(&p.X, &p.X)
	xx = c.baseApi.MulConst(xx, big.NewInt(3))
	if c.addA {
		xx = c.baseApi.Add(xx, &c.a)
	}
	y2 := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	var isDoubleYZero frontend.Variable = 0
	if unified {
		// if 2p.y = 0, assign dummy 1 to y2 and continue
		isDoubleYZero = c.baseApi.IsZero(y2)
		y2 = c.baseApi.Select(isDoubleYZero, c.baseApi.One(), y2)
	}
	λ1 := c.assertedRatio(xx, y2)
	if unified {
		λ1 = c.baseApi.Select(isDoubleYZero, c.baseApi.Zero(), λ1)
	}

	// xr = λ1²-2p.x
	x2 := c.baseApi.Eval([][]*emulated.Element[B]{{λ1, λ1}, {&p.X}}, []int{1, -2})

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := c.baseApi.Sub(&p.X, x2)
	var isSecondSlopeDenominatorZero frontend.Variable = 0
	if unified {
		isSecondSlopeDenominatorZero = c.baseApi.IsZero(x1x2)
		x1x2 = c.baseApi.Select(isSecondSlopeDenominatorZero, c.baseApi.One(), x1x2)
	}
	λ2 := c.assertedRatio(y2, x1x2)
	if unified {
		λ2 = c.baseApi.Select(isSecondSlopeDenominatorZero, c.baseApi.Zero(), λ2)
	}
	λ2 = c.baseApi.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	xr := c.baseApi.Eval([][]*emulated.Element[B]{{λ2, λ2}, {&p.X}, {x2}}, []int{1, -1, -1})

	// yr = λ(p.x-xr) - p.y
	yr := c.baseApi.Eval([][]*emulated.Element[B]{{λ2, c.baseApi.Sub(&p.X, xr)}, {&p.Y}}, []int{1, -1})

	return &AffinePoint[B]{
		X: *xr,
		Y: *yr,
	}
}

// doubleAndAdd computes 2p+q as (p+q)+p. It follows [ELM03] (Section 3.1)
// Saves the computation of the y coordinate of p+q as it is used only in the computation of λ2,
// which can be computed as
//
//	λ2 = -λ1-2*p.y/(x2-p.x)
//
// instead. It doesn't modify p nor q.
//
// ⚠️  p must be different than q and -q, and both nonzero.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
func (c *Curve[B, S]) doubleAndAdd(p, q *AffinePoint[B]) *AffinePoint[B] {
	return c.doubleAndAddGeneric(p, q, false)
}

func (c *Curve[B, S]) doubleAndAddGeneric(p, q *AffinePoint[B], unified bool) *AffinePoint[B] {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := c.baseApi.Sub(&q.Y, &p.Y)
	xpn := c.baseApi.Neg(&p.X)
	xqxp := c.baseApi.Add(&q.X, xpn)
	var isChordDenominatorZero frontend.Variable = 0
	if unified {
		isChordDenominatorZero = c.baseApi.IsZero(xqxp)
		xqxp = c.baseApi.Select(isChordDenominatorZero, c.baseApi.One(), xqxp)
	}
	λ1 := c.assertedRatio(yqyp, xqxp)
	if unified {
		λ1 = c.baseApi.Select(isChordDenominatorZero, c.baseApi.Zero(), λ1)
	}

	// compute x2 = λ1²-p.x-q.x
	x2 := c.baseApi.Eval([][]*emulated.Element[B]{{λ1, λ1}, {c.baseApi.Add(&p.X, &q.X)}}, []int{1, -1})

	// omit y2 computation

	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	x2xp := c.baseApi.Add(x2, xpn)
	var isSecondSlopeDenominatorZero frontend.Variable = 0
	if unified {
		isSecondSlopeDenominatorZero = c.baseApi.IsZero(x2xp)
		x2xp = c.baseApi.Select(isSecondSlopeDenominatorZero, c.baseApi.One(), x2xp)
	}
	λ2 := c.assertedRatio(ypyp, x2xp)
	if unified {
		λ2 = c.baseApi.Select(isSecondSlopeDenominatorZero, c.baseApi.Zero(), λ2)
	}
	λ2 = c.baseApi.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x3 := c.baseApi.Eval([][]*emulated.Element[B]{{λ2, λ2}, {&p.X}, {x2}}, []int{1, -1, -1})

	// compute y3 = -λ2*(x3 - p.x)-p.y
	y3 := c.baseApi.Eval([][]*emulated.Element[B]{{λ2, c.baseApi.Add(x3, xpn)}, {&p.Y}}, []int{1, -1})

	return &AffinePoint[B]{
		X: *x3,
		Y: *y3,
	}

}

// doubleAndAddSelect is the same as doubleAndAdd but computes either:
//
//	2p+q if b=1 or
//	2q+p if b=0
//
// It first computes the x-coordinate of p+q via the slope(p,q)
// and then based on a Select adds either p or q.
func (c *Curve[B, S]) doubleAndAddSelect(b frontend.Variable, p, q *AffinePoint[B]) *AffinePoint[B] {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := c.baseApi.Sub(&q.Y, &p.Y)
	xqxp := c.baseApi.Sub(&q.X, &p.X)
	λ1 := c.assertedRatio(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x2 := c.baseApi.Eval([][]*emulated.Element[B]{{λ1, λ1}, {&p.X}, {&q.X}}, []int{1, -1, -1})

	// omit y2 computation

	// conditional second addition
	t := c.Select(b, p, q)

	// compute -λ2 = λ1+2*t.y/(x2-t.x)
	ypyp := c.baseApi.MulConst(&t.Y, big.NewInt(2))
	x2xp := c.baseApi.Sub(x2, &t.X)
	λ2 := c.assertedRatio(ypyp, x2xp)
	λ2 = c.baseApi.Add(λ1, λ2)

	// compute x3 = (-λ2)²-t.x-x2
	x3 := c.baseApi.Eval([][]*emulated.Element[B]{{λ2, λ2}, {&t.X}, {x2}}, []int{1, -1, -1})

	// compute y3 = -λ2*(x3 - t.x)-t.y
	y3 := c.baseApi.Eval([][]*emulated.Element[B]{{λ2, x3}, {λ2, &t.X}, {&t.Y}}, []int{1, -1, -1})

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(x3),
		Y: *c.baseApi.Reduce(y3),
	}

}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (c *Curve[B, S]) Select(b frontend.Variable, p, q *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Select(b, &p.X, &q.X)
	y := c.baseApi.Select(b, &p.Y, &q.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// Lookup2 performs a 2-bit lookup between i0, i1, i2, i3 based on bits b0
// and b1. Returns:
//   - i0 if b0=0 and b1=0,
//   - i1 if b0=1 and b1=0,
//   - i2 if b0=0 and b1=1,
//   - i3 if b0=1 and b1=1.
func (c *Curve[B, S]) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Lookup2(b0, b1, &i0.X, &i1.X, &i2.X, &i3.X)
	y := c.baseApi.Lookup2(b0, b1, &i0.Y, &i1.Y, &i2.Y, &i3.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// Mux performs a lookup from the inputs and returns inputs[sel]. It is most
// efficient for power of two lengths of the inputs, but works for any number of
// inputs.
func (c *Curve[B, S]) Mux(sel frontend.Variable, inputs ...*AffinePoint[B]) *AffinePoint[B] {
	xs := make([]*emulated.Element[B], len(inputs))
	ys := make([]*emulated.Element[B], len(inputs))
	for i := range inputs {
		xs[i] = &inputs[i].X
		ys[i] = &inputs[i].Y
	}
	return &AffinePoint[B]{
		X: *c.baseApi.Mux(sel, xs...),
		Y: *c.baseApi.Mux(sel, ys...),
	}
}

// muxY8Signed selects from 8 Y values using selector (0-7) and conditionally
// negates based on signBit. This optimizes the common GLV pattern where Y[i] =
// -Y[15-i], reducing a 16-to-1 Mux to an 8-to-1 Mux plus conditional negation.
func (c *Curve[B, S]) muxY8Signed(signBit frontend.Variable, selector frontend.Variable, yValues ...*emulated.Element[B]) *emulated.Element[B] {
	if len(yValues) != 8 {
		panic("muxY8Signed requires exactly 8 Y values")
	}
	baseY := c.baseApi.Mux(selector, yValues...)
	return c.baseApi.Select(signBit, c.baseApi.Neg(baseY), baseY)
}

// ScalarMul computes [s]p and returns it. It doesn't modify p nor s.
// This function doesn't check that the p is on the curve. See AssertIsOnCurve.
//
// By default, uses complete arithmetic.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, the exact exceptional set
// depends on the scalar-multiplication algorithm selected for the current
// curve:
//   - curves without an efficient endomorphism inherit the documented
//     exceptional set of [Curve.scalarMulFakeGLV]
//     and currently include P-256, P-384 and STARK curve
//   - curves with an efficient endomorphism inherit the documented exceptional
//     set of [Curve.scalarMulGLVAndFakeGLV] and currently include BN254,
//     BLS12-381, BW6-761 and secp256k1.
//
// ScalarMul calls scalarMulFakeGLV or scalarMulGLVAndFakeGLV depending on whether an efficient endomorphism is available.
//
// N.B. For scalarMulGLVAndFakeGLV, the result is undefined when the input point is
// not on the prime order subgroup. For scalarMulFakeGLV the result is well
// defined for any point on the curve
//
// When p is a compile-time constant point of prime order r (for example a
// point from a fixed verification key or SRS), the method automatically uses
// the fixed-base comb method with precomputed tables (see
// [Curve.scalarMulComb]), which uses complete arithmetic and is significantly
// cheaper. In this case the [algopts.WithIncompleteArithmetic] option is a
// no-op.
func (c *Curve[B, S]) ScalarMul(p *AffinePoint[B], s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	if px, ok := c.baseApi.ConstantValue(&p.X); ok {
		if py, ok := c.baseApi.ConstantValue(&p.Y); ok {
			// constant point: try the fixed-base comb. combDataFor verifies
			// at compile time that (px, py) is a finite curve point of prime
			// order r; otherwise we fall back to the variable-base methods
			// below which have no such requirement.
			if d, err := c.combDataFor(px, py, c.combWindow()); err == nil {
				return c.scalarMulComb(d, s)
			}
		}
	}
	hasEndo := c.eigenvalue != nil && c.thirdRootOne != nil
	switch {
	case hasEndo && c.params.PreferClassicGLV:
		// cofactor curves where the fake-GLV subgroup clearing outweighs its
		// r^(1/4) savings (e.g. BLS12-381 G1); classic GLV is faster and sound.
		return c.scalarMulGLV(p, s, opts...)
	case hasEndo:
		// scalarMulGLVAndFakeGLV returns an unbound (possibly torsion-shifted)
		// output; bind it into the prime-order subgroup (no-op if prime-order).
		q := c.scalarMulGLVAndFakeGLV(p, s, opts...)
		c.assertPointInSubgroup(q)
		return q
	default:
		return c.scalarMulFakeGLV(p, s, opts...)
	}
}

// scalarMulGLV computes [s]Q using an efficient endomorphism and returns it. It doesn't modify Q nor s.
// It implements an optimized version based on algorithm 1 of [Halo] (see Section 6.2 and appendix C).
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. The exact exceptional set is not documented and should be
// treated as implementation-dependent.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [Halo]: https://eprint.iacr.org/2019/1021.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (c *Curve[B, S]) scalarMulGLV(Q *AffinePoint[B], s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var st S
	nbits := st.Modulus().BitLen()>>1 + 2
	addFn := c.Add
	var isPointAtInfinity frontend.Variable
	if !cfg.IncompleteArithmetic {
		addFn = c.AddUnified
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		isPointAtInfinity = c.api.And(c.baseApi.IsZero(&Q.X), c.baseApi.IsZero(&Q.Y))
		one := c.baseApi.One()
		Q = c.Select(isPointAtInfinity, &AffinePoint[B]{X: *one, Y: *one}, Q)
	}

	// We use the endomorphism à la GLV to compute [s]Q as
	// 		[s1]Q + [s2]Φ(Q)
	// the sub-scalars s1, s2 can be negative (bigints) in the hint. If so,
	// they will be reduced in-circuit modulo the SNARK scalar field and not
	// the emulated field. So we return in the hint |s1|, |s2| and boolean
	// flags sdBits to negate the points Q, Φ(Q) instead of the corresponding
	// sub-scalars.

	// decompose s into s1 and s2
	sdBits, sd, err := c.scalarApi.NewHintGeneric(decomposeScalarG1, 2, 2, nil, []*emulated.Element[S]{s, c.eigenvalue},
		emulated.WithHintOutputRangeCheckBits(map[int]int{2: nbits, 3: nbits}),
	)
	if err != nil {
		panic(fmt.Sprintf("compute GLV decomposition: %v", err))
	}
	s1, s2 := sd[0], sd[1]
	isS1Negative, isS2Negative := sdBits[0], sdBits[1]
	s3 := c.scalarApi.Select(isS1Negative, c.scalarApi.Neg(s1), s1)
	s4 := c.scalarApi.Select(isS2Negative, c.scalarApi.Neg(s2), s2)
	// s == s3 + [λ]s4
	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(s3, c.scalarApi.Mul(s4, c.eigenvalue)),
		s,
	)

	s1bits := c.scalarApi.ToBits(s1)
	s2bits := c.scalarApi.ToBits(s2)

	// precompute -Q, Q, 3Q, -Φ(Q), Φ(Q), 3Φ(Q)
	var tableQ, tablePhiQ [3]*AffinePoint[B]
	negQY := c.baseApi.Neg(&Q.Y)
	tableQ[1] = &AffinePoint[B]{
		X: Q.X,
		Y: *c.baseApi.Select(isS1Negative, negQY, &Q.Y),
	}
	tableQ[0] = c.Neg(tableQ[1])
	tablePhiQ[1] = &AffinePoint[B]{
		X: *c.baseApi.Mul(&Q.X, c.thirdRootOne),
		Y: *c.baseApi.Select(isS2Negative, negQY, &Q.Y),
	}
	tablePhiQ[0] = c.Neg(tablePhiQ[1])
	tableQ[2] = c.triple(tableQ[1])
	// tablePhiQ[2] must be [3]·tablePhiQ[1] = ε_s2·[3]Φ(Q). Deriving it from
	// tableQ[2] = ε_s1·[3]Q (twist X, re-apply only ε_s2) entangles the s1 sign:
	// tableQ[2].Y = ε_s1·[3]Q.Y, so the result would be ε_s1·ε_s2·[3]Q.Y — a
	// negated point whenever s1 < 0 (a malicious hint can select such a lattice
	// rep). Build it directly from the correctly-signed tablePhiQ[1] instead.
	tablePhiQ[2] = c.triple(tablePhiQ[1])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q)
	Acc := c.Add(tableQ[1], tablePhiQ[1])

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point P from:
	// 		B1 = Q+Φ(Q)
	// 		B2 = -Q-Φ(Q)
	// 		B3 = Q-Φ(Q)
	// 		B4 = -Q+Φ(Q)
	//
	// If we extend this by merging two iterations, we need to look up P and P'
	// both from {B1, B2, B3, B4} and compute:
	// 		[2]([2]Acc+P)+P' = [4]Acc + T
	// where T = [2]P+P'. So at each (merged) iteration, we can compute [4]Acc
	// and look up T from the precomputed list of points:
	//
	// T = [3](Q + Φ(Q))
	// P = B1 and P' = B1
	t1 := c.Add(tableQ[2], tablePhiQ[2])
	// T = Q + Φ(Q)
	// P = B1 and P' = B2
	T2 := Acc
	// T = [3]Q + Φ(Q)
	// P = B1 and P' = B3
	T3 := c.Add(tableQ[2], tablePhiQ[1])
	// T = Q + [3]Φ(Q)
	// P = B1 and P' = B4
	t4 := c.Add(tableQ[1], tablePhiQ[2])
	// T  = -Q - Φ(Q)
	// P = B2 and P' = B1
	T5 := c.Neg(T2)
	// T  = -[3](Q + Φ(Q))
	// P = B2 and P' = B2
	T6 := c.Neg(t1)
	// T = -Q - [3]Φ(Q)
	// P = B2 and P' = B3
	T7 := c.Neg(t4)
	// T = [3]Q - Φ(Q)
	// P = B3 and P' = B1
	t9 := c.Add(tableQ[2], tablePhiQ[0])
	// T = Q - [3]Φ(Q)
	// P = B3 and P' = B2
	t := c.Neg(tablePhiQ[2])
	T10 := c.Add(tableQ[1], t)
	// T = [3](Q - Φ(Q))
	// P = B3 and P' = B3
	T11 := c.Add(tableQ[2], t)
	// T = -Φ(Q) + Q
	// P = B3 and P' = B4
	T12 := c.Add(tablePhiQ[0], tableQ[1])
	// T = Φ(Q) - [3]Q
	// P = B4 and P' = B2
	T14 := c.Neg(t9)
	// T = Φ(Q) - Q
	// P = B4 and P' = B3
	T15 := c.Neg(T12)
	// note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	// when nbits is even, we need to handle the first iteration separately
	if nbits%2 == 0 {
		// Acc = [2]Acc ± Q ± Φ(Q)
		T := &AffinePoint[B]{
			X: *c.baseApi.Select(c.api.Xor(s1bits[nbits-1], s2bits[nbits-1]), &T12.X, &T5.X),
			Y: *c.baseApi.Lookup2(s1bits[nbits-1], s2bits[nbits-1], &T5.Y, &T12.Y, &T15.Y, &T2.Y),
		}
		// We don't use doubleAndAdd here as it would involve edge cases
		// when bits are 00 (T==-Acc) or 11 (T==Acc).
		Acc = c.double(Acc)
		Acc = c.add(Acc, T)
	} else {
		// when nbits is odd we start the main loop at normally nbits - 1
		nbits++
	}
	for i := nbits - 2; i > 0; i -= 2 {
		// selectorY takes values in [0,15]
		selectorY := c.api.Add(
			s1bits[i],
			c.api.Mul(s2bits[i], 2),
			c.api.Mul(s1bits[i-1], 4),
			c.api.Mul(s2bits[i-1], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := c.api.Add(
			c.api.Mul(selectorY, c.api.Sub(1, c.api.Mul(s2bits[i-1], 2))),
			c.api.Mul(s2bits[i-1], 15),
		)
		// Half of the Bi.X are distinct (8-to-1) and Y[i] = -Y[15-i],
		// so we use 8-to-1 Mux for both X and Y, with conditional negation for Y.
		T := &AffinePoint[B]{
			X: *c.baseApi.Mux(selectorX,
				&T6.X, &T10.X, &T14.X, &T2.X, &T7.X, &T11.X, &T15.X, &T3.X,
			),
			Y: *c.muxY8Signed(s2bits[i-1], selectorX,
				&T6.Y, &T10.Y, &T14.Y, &T2.Y, &T7.Y, &T11.Y, &T15.Y, &T3.Y,
			),
		}
		// Acc = [4]Acc + T
		Acc = c.double(Acc)
		Acc = c.doubleAndAdd(Acc, T)
	}

	// i = 0
	// subtract the Q, Φ(Q) if the first bits are 0.
	// When not using incomplete arithmetic, we use AddUnified instead of Add.
	// This means when s=0 then Acc=(0,0) because AddUnified(Q, -Q) = (0,0).
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = c.Select(s1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = addFn(tablePhiQ[0], Acc)
	Acc = c.Select(s2bits[0], Acc, tablePhiQ[0])

	if !cfg.IncompleteArithmetic {
		zero := c.baseApi.Zero()
		Acc = c.Select(isPointAtInfinity, &AffinePoint[B]{X: *zero, Y: *zero}, Acc)
	}

	return Acc
}

// scalarMulJoye computes [s]p and returns it. It doesn't modify p nor s.
// This function doesn't check that the p is on the curve. See AssertIsOnCurve.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. The exact exceptional set is currently unknown and should be
// treated as implementation-dependent.
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
// Contrary to the GLV method, this method doesn't require the endomorphism and
// thus is also suitable for points not in the prime order subgroup.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
// [Joye07]: https://www.iacr.org/archive/ches2007/47270135/47270135.pdf
func (c *Curve[B, S]) scalarMulJoye(p *AffinePoint[B], s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	var isPointAtInfinity frontend.Variable
	if !cfg.IncompleteArithmetic {
		// if p=(0,0) we assign a dummy (0,1) to p and continue
		isPointAtInfinity = c.api.And(c.baseApi.IsZero(&p.X), c.baseApi.IsZero(&p.Y))
		one := c.baseApi.One()
		p = c.Select(isPointAtInfinity, &AffinePoint[B]{X: *one, Y: *one}, p)
	}

	var st S
	sr := c.scalarApi.Reduce(s)
	sBits := c.scalarApi.ToBits(sr)
	n := st.Modulus().BitLen()
	if cfg.NbScalarBits > 2 && cfg.NbScalarBits < n {
		n = cfg.NbScalarBits
	}

	// i = 1
	Rb := c.triple(p)
	R0 := c.Select(sBits[1], Rb, p)
	R1 := c.Select(sBits[1], p, Rb)

	for i := 2; i < n-1; i++ {
		Rb = c.doubleAndAddSelect(sBits[i], R0, R1)
		R0 = c.Select(sBits[i], Rb, R0)
		R1 = c.Select(sBits[i], R1, Rb)
	}

	// i = n-1
	Rb = c.doubleAndAddSelect(sBits[n-1], R0, R1)
	R0 = c.Select(sBits[n-1], Rb, R0)

	// i = 0
	// we use AddUnified instead of Add. This is because:
	// 		- when s=0 then R0=P and AddUnified(P, -P) = (0,0). We return (0,0).
	// 		- when s=1 then R0=P AddUnified(Q, -Q) is well defined. We return R0=P.
	R0 = c.Select(sBits[0], R0, c.AddUnified(R0, c.Neg(p)))

	if !cfg.IncompleteArithmetic {
		// if p=(0,0), return (0,0)
		zero := c.baseApi.Zero()
		R0 = c.Select(isPointAtInfinity, &AffinePoint[B]{X: *zero, Y: *zero}, R0)
	}

	return R0
}

// jointScalarMul computes [s1]p1 + [s2]p2 and returns it. It doesn't modify the inputs.
// This function doesn't check that the p1 and p2 are on the curve. See AssertIsOnCurve.
//
// jointScalarMul calls jointScalarMulGeneric or jointScalarMulGLV depending on whether an efficient endomorphism is available.
func (c *Curve[B, S]) jointScalarMul(p1, p2 *AffinePoint[B], s1, s2 *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	if c.params.Eigenvalue != nil && c.params.ThirdRootOne != nil {
		return c.jointScalarMulGLV(p1, p2, s1, s2, opts...)

	} else {
		return c.jointScalarMulFakeGLV(p1, p2, s1, s2, opts...)

	}
}

// jointScalarMulFakeGLV computes [s1]p1 + [s2]p2. It doesn't modify p1, p2 nor s1, s2.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. It inherits the documented exceptional set of
// [Curve.scalarMulFakeGLV] independently for (p1, s1) and (p2, s2). The final
// merge uses [Curve.AddUnified] and does not introduce additional
// incomplete-arithmetic restrictions.
func (c *Curve[B, S]) jointScalarMulFakeGLV(p1, p2 *AffinePoint[B], s1, s2 *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	sm1 := c.scalarMulFakeGLV(p1, s1, opts...)
	sm2 := c.scalarMulFakeGLV(p2, s2, opts...)
	return c.AddUnified(sm1, sm2)
}

// jointScalarMulGenericUnsafe computes [s1]p1 + [s2]p2 using Shamir's trick and returns it. It doesn't modify p1, p2 nor s1, s2.
// ⚠️  The scalars must be nonzero and the points different from (0,0).
func (c *Curve[B, S]) jointScalarMulGenericUnsafe(p1, p2 *AffinePoint[B], s1, s2 *emulated.Element[S]) *AffinePoint[B] {
	var Acc, B1, p1Neg, p2Neg *AffinePoint[B]
	p1Neg = c.Neg(p1)
	p2Neg = c.Neg(p2)

	// Acc = P1 + P2
	Acc = c.Add(p1, p2)

	s1bits := c.scalarApi.ToBits(s1)
	s2bits := c.scalarApi.ToBits(s2)

	var st S
	nbits := st.Modulus().BitLen()

	for i := nbits - 1; i > 0; i-- {
		B1 = &AffinePoint[B]{
			X: p1Neg.X,
			Y: *c.baseApi.Select(s1bits[i], &p1.Y, &p1Neg.Y),
		}
		Acc = c.doubleAndAdd(Acc, B1)
		B1 = &AffinePoint[B]{
			X: p2Neg.X,
			Y: *c.baseApi.Select(s2bits[i], &p2.Y, &p2Neg.Y),
		}
		Acc = c.Add(Acc, B1)

	}

	// i = 0
	p1Neg = c.Add(p1Neg, Acc)
	Acc = c.Select(s1bits[0], Acc, p1Neg)
	p2Neg = c.Add(p2Neg, Acc)
	Acc = c.Select(s2bits[0], Acc, p2Neg)

	return Acc
}

// jointScalarMulGLV computes [s1]p1 + [s2]p2 using an endomorphism. It doesn't modify p1, p2 nor s1, s2.
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. The exceptional set includes at least zero scalars, points at
// infinity and p1 = ±p2, and may additionally include sparse
// implementation-dependent failures from precomputations and accumulator
// collisions in [Curve.jointScalarMulGLVUnsafe].
func (c *Curve[B, S]) jointScalarMulGLV(p1, p2 *AffinePoint[B], s1, s2 *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	if !cfg.IncompleteArithmetic {
		// On PreferClassicGLV curves (e.g. BLS12-381 G1) route each summand
		// through classic GLV, matching [Curve.ScalarMul]/[Curve.ScalarMulBase]:
		// its computed output is inherently in-subgroup and cheaper than
		// GLV+fake-GLV once the (here full-cofactor) clearing is included.
		if c.params.PreferClassicGLV {
			// classic GLV: computed, inherently in-subgroup, no binding needed.
			res1 := c.scalarMulGLV(p1, s1, opts...)
			res2 := c.scalarMulGLV(p2, s2, opts...)
			return c.AddUnified(res1, res2)
		}
		// Deferred binding: each summand is unbound (torsion-shiftable), but its
		// subgroup part is exact, so bind the SUM once instead of each summand.
		res1 := c.scalarMulGLVAndFakeGLV(p1, s1, opts...)
		res2 := c.scalarMulGLVAndFakeGLV(p2, s2, opts...)
		res := c.AddUnified(res1, res2)
		c.assertPointInSubgroup(res)
		return res
	} else {
		return c.jointScalarMulGLVUnsafe(p1, p2, s1, s2)
	}
}

// jointScalarMulGLVUnsafe computes [s]Q + [t]R using Shamir's trick with an efficient endomorphism and returns it. It doesn't modify Q, R nor s, t.
// ⚠️  The exceptional set includes at least zero scalars, points equal to
// (0,0), and Q = ±R. Additional sparse implementation-dependent failures may
// arise from incomplete precomputations and accumulator collisions.
func (c *Curve[B, S]) jointScalarMulGLVUnsafe(Q, R *AffinePoint[B], s, t *emulated.Element[S]) *AffinePoint[B] {
	// We use the endomorphism à la GLV to compute [s]Q + [t]R as
	// 		[s1]Q + [s2]Φ(Q) + [t1]R + [t2]Φ(R)
	// the sub-scalars s1, s2, t1, t2 can be negative (bigints) in the hint. If
	// so, they will be reduced in-circuit modulo the SNARK scalar field and
	// not the emulated field. So we return in the hint |s1|, |s2|, |t1|, |t2|
	// and boolean flags sdBits and tdBits to negate the points Q, Φ(Q), R and
	// Φ(R) instead of the corresponding sub-scalars.

	var st S
	nbits := st.Modulus().BitLen()>>1 + 2
	// decompose s into s1 and s2
	sdBits, sd, err := c.scalarApi.NewHintGeneric(decomposeScalarG1, 2, 2, nil, []*emulated.Element[S]{s, c.eigenvalue},
		emulated.WithHintOutputRangeCheckBits(map[int]int{2: nbits, 3: nbits}),
	)
	if err != nil {
		panic(fmt.Sprintf("compute GLV decomposition s: %v", err))
	}
	s1, s2 := sd[0], sd[1]
	isS1Negative, isS2Negative := sdBits[0], sdBits[1]
	s3 := c.scalarApi.Select(isS1Negative, c.scalarApi.Neg(s1), s1)
	s4 := c.scalarApi.Select(isS2Negative, c.scalarApi.Neg(s2), s2)
	// s == s3 + [λ]s4
	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(s3, c.scalarApi.Mul(s4, c.eigenvalue)),
		s,
	)

	// decompose t into t1 and t2
	tdBits, td, err := c.scalarApi.NewHintGeneric(decomposeScalarG1, 2, 2, nil, []*emulated.Element[S]{t, c.eigenvalue},
		emulated.WithHintOutputRangeCheckBits(map[int]int{2: nbits, 3: nbits}),
	)
	if err != nil {
		panic(fmt.Sprintf("compute GLV decomposition t: %v", err))
	}
	t1, t2 := td[0], td[1]
	isT1Negative, isT2Negative := tdBits[0], tdBits[1]
	t3 := c.scalarApi.Select(isT1Negative, c.scalarApi.Neg(t1), t1)
	t4 := c.scalarApi.Select(isT2Negative, c.scalarApi.Neg(t2), t2)
	// t == t3 + [λ]t4
	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(t3, c.scalarApi.Mul(t4, c.eigenvalue)),
		t,
	)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]*AffinePoint[B]
	negQY := c.baseApi.Neg(&Q.Y)
	tableQ[1] = &AffinePoint[B]{
		X: Q.X,
		Y: *c.baseApi.Select(isS1Negative, negQY, &Q.Y),
	}
	tableQ[0] = c.Neg(tableQ[1])
	tablePhiQ[1] = &AffinePoint[B]{
		X: *c.baseApi.Mul(&Q.X, c.thirdRootOne),
		Y: *c.baseApi.Select(isS2Negative, negQY, &Q.Y),
	}
	tablePhiQ[0] = c.Neg(tablePhiQ[1])

	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]*AffinePoint[B]
	negRY := c.baseApi.Neg(&R.Y)
	tableR[1] = &AffinePoint[B]{
		X: R.X,
		Y: *c.baseApi.Select(isT1Negative, negRY, &R.Y),
	}
	tableR[0] = c.Neg(tableR[1])
	tablePhiR[1] = &AffinePoint[B]{
		X: *c.baseApi.Mul(&R.X, c.thirdRootOne),
		Y: *c.baseApi.Select(isT2Negative, negRY, &R.Y),
	}
	tablePhiR[0] = c.Neg(tablePhiR[1])

	// precompute Q+R, -Q-R, Q-R, -Q+R, Φ(Q)+Φ(R), -Φ(Q)-Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R)
	var tableS, tablePhiS [4]*AffinePoint[B]
	tableS[0] = tableQ[0]
	tableS[0] = c.Add(tableS[0], tableR[0])
	tableS[1] = c.Neg(tableS[0])
	tableS[2] = tableQ[1]
	tableS[2] = c.Add(tableS[2], tableR[0])
	tableS[3] = c.Neg(tableS[2])
	// Build the Φ-side combinations directly from the correctly-signed
	// tablePhiQ/tablePhiR (mirroring tableS from tableQ/tableR). The previous
	// twist-trick derived tablePhiS.X/.Y from tableS — which carries the s1/t1
	// signs — while re-applying only the s2/t2 signs, so the Φ(Q)/Φ(R) digits
	// picked up ε_s1/ε_t1 and were negated whenever s1 < 0 or t1 < 0 (a malicious
	// hint can select such a lattice rep).
	tablePhiS[0] = c.Add(tablePhiQ[0], tablePhiR[0])
	tablePhiS[1] = c.Neg(tablePhiS[0])
	tablePhiS[2] = c.Add(tablePhiQ[1], tablePhiR[0])
	tablePhiS[3] = c.Neg(tablePhiS[2])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + R + Φ(Q) + Φ(R)
	Acc := c.Add(tableS[1], tablePhiS[1])
	b1 := Acc
	// then we conditionally add to Acc either G (the base point) or
	// conditionally Φ²(G) (if Acc==-G) to avoid incomplete additions in the
	// loop, because when doing doubleAndAdd(Acc, Bi) as (Acc+Bi)+Acc it might
	// happen that Acc==Bi or Acc==-Bi. But now we force Acc to be different
	// than the stored Bi.  However we need at the end to subtract [2^nbits]G
	// or conditionally [2^nbits]Φ²(G) from the result.
	//
	// g0 = G
	g0 := c.Generator()
	// g1 = Φ²(G)
	g1 := &AffinePoint[B]{
		X: *c.baseApi.Mul(
			c.baseApi.Mul(&g0.X, c.thirdRootOne), c.thirdRootOne),
		Y: g0.Y,
	}
	isAccNegGenerator := c.baseApi.IsZero(
		c.baseApi.Add(&Acc.Y, &g0.Y),
	)
	g := c.Select(isAccNegGenerator, g1, g0)
	// Acc = Q + R + Φ(Q) + Φ(R) + G or
	// Q + R + Φ(Q) + Φ(R) + Φ²(G) ( = -G+Φ²(G) = -2G-Φ(G) )
	Acc = c.Add(Acc, g)

	s1bits := c.scalarApi.ToBits(s1)
	s2bits := c.scalarApi.ToBits(s2)
	t1bits := c.scalarApi.ToBits(t1)
	t2bits := c.scalarApi.ToBits(t2)

	// At each iteration we look up the point Bi from:
	// 		B1  = +Q + R + Φ(Q) + Φ(R)
	// 		B2  = +Q + R + Φ(Q) - Φ(R)
	B2 := c.Add(tableS[1], tablePhiS[2])
	// 		b3  = +Q + R - Φ(Q) + Φ(R)
	b3 := c.Add(tableS[1], tablePhiS[3])
	// 		B4  = +Q + R - Φ(Q) - Φ(R)
	B4 := c.Add(tableS[1], tablePhiS[0])
	// 		b5  = +Q - R + Φ(Q) + Φ(R)
	b5 := c.Add(tableS[2], tablePhiS[1])
	// 		B6  = +Q - R + Φ(Q) - Φ(R)
	B6 := c.Add(tableS[2], tablePhiS[2])
	// 		b7  = +Q - R - Φ(Q) + Φ(R)
	b7 := c.Add(tableS[2], tablePhiS[3])
	// 		B8  = +Q - R - Φ(Q) - Φ(R)
	B8 := c.Add(tableS[2], tablePhiS[0])
	// 		B10 = -Q + R + Φ(Q) - Φ(R)
	B10 := c.Neg(b7)
	// 		B12 = -Q + R - Φ(Q) - Φ(R)
	B12 := c.Neg(b5)
	// 		B14 = -Q - R + Φ(Q) - Φ(R)
	B14 := c.Neg(b3)
	// 		B16 = -Q - R - Φ(Q) - Φ(R)
	B16 := c.Neg(b1)
	// note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	var Bi *AffinePoint[B]
	// run the loop with the accumulator y-coordinate in implicit form on
	// j = 0 curves (see implicitDoubleAndAdd).
	var iAcc *implicitAcc[B]
	if !c.addA {
		iAcc = c.implicitFromAffine(Acc)
	}
	for i := nbits - 1; i > 0; i-- {
		// selectorY takes values in [0,15]
		selectorY := c.api.Add(
			s1bits[i],
			c.api.Mul(s2bits[i], 2),
			c.api.Mul(t1bits[i], 4),
			c.api.Mul(t2bits[i], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := c.api.Add(
			c.api.Mul(selectorY, c.api.Sub(1, c.api.Mul(t2bits[i], 2))),
			c.api.Mul(t2bits[i], 15),
		)
		// Half of the Bi.X are distinct (8-to-1) and Y[i] = -Y[15-i],
		// so we use 8-to-1 Mux for both X and Y, with conditional negation for Y.
		Bi = &AffinePoint[B]{
			X: *c.baseApi.Mux(selectorX,
				&B16.X, &B8.X, &B14.X, &B6.X, &B12.X, &B4.X, &B10.X, &B2.X,
			),
			Y: *c.muxY8Signed(t2bits[i], selectorX,
				&B16.Y, &B8.Y, &B14.Y, &B6.Y, &B12.Y, &B4.Y, &B10.Y, &B2.Y,
			),
		}
		// Acc = [2]Acc + Bi
		if iAcc != nil {
			c.implicitDoubleAndAdd(iAcc, Bi)
		} else {
			Acc = c.doubleAndAdd(Acc, Bi)
		}
	}
	if iAcc != nil {
		Acc = c.implicitToAffine(iAcc)
	}

	// i = 0
	// subtract the Q, R, Φ(Q), Φ(R) if the first bits are 0
	tableQ[0] = c.Add(tableQ[0], Acc)
	Acc = c.Select(s1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = c.Add(tablePhiQ[0], Acc)
	Acc = c.Select(s2bits[0], Acc, tablePhiQ[0])
	tableR[0] = c.Add(tableR[0], Acc)
	Acc = c.Select(t1bits[0], Acc, tableR[0])
	tablePhiR[0] = c.Add(tablePhiR[0], Acc)
	Acc = c.Select(t2bits[0], Acc, tablePhiR[0])

	// subtract [2^nbits]G or conditionally [2^nbits]Φ²(G)
	gm := c.GeneratorMultiples()[nbits-1]
	g = c.Select(
		isAccNegGenerator,
		// [2^nbits]Φ²(G)
		&AffinePoint[B]{
			X: *c.baseApi.Mul(
				c.baseApi.Mul(&gm.X, c.thirdRootOne), c.thirdRootOne),
			Y: gm.Y,
		},
		// [2^nbits]G
		&gm,
	)
	Acc = c.Add(Acc, c.Neg(g))

	return Acc

}

// ScalarMulBase computes [s]g and returns it where g is the fixed curve generator. It doesn't modify p nor s.
//
// It uses the fixed-base comb method with compile-time constant window tables
// (see [Curve.scalarMulBaseComb]), which uses complete arithmetic and
// correctly handles the zero scalar. The [algopts.WithIncompleteArithmetic]
// option is a no-op for this method as the comb method is both complete and
// cheaper than the incomplete variable-base fallbacks.
//
// For custom curve parameters where the comb tables cannot be constructed, it
// falls back to the variable-base scalar multiplication with the generator:
//   - curves without an efficient endomorphism inherit the documented
//     exceptional set of [Curve.scalarMulFakeGLV]
//   - curves with an efficient endomorphism inherit the documented exceptional
//     set of [Curve.scalarMulGLVAndFakeGLV].
func (c *Curve[B, S]) ScalarMulBase(s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	// The fixed-base comb is complete and cheapest; it requires the generator to
	// be a prime-order point, which combData verifies at compile time.
	if _, err := c.combData(c.combWindow()); err == nil {
		return c.scalarMulBaseComb(s, c.combWindow())
	}
	hasEndo := c.eigenvalue != nil && c.thirdRootOne != nil
	switch {
	case hasEndo && c.params.PreferClassicGLV:
		// cofactor curves where the fake-GLV subgroup clearing outweighs its
		// r^(1/4) savings (e.g. BLS12-381 G1); classic GLV is faster and sound.
		// Kept consistent with the [Curve.ScalarMul] dispatch.
		return c.scalarMulGLV(c.Generator(), s, opts...)
	case hasEndo:
		q := c.scalarMulGLVAndFakeGLV(c.Generator(), s, opts...)
		c.assertPointInSubgroup(q)
		return q
	default:
		return c.scalarMulFakeGLV(c.Generator(), s, opts...)
	}
}

// JointScalarMulBase computes [s1]g + [s2]p and returns it, where g is the
// fixed generator. It doesn't modify p, s1 and s2.
//
// By default, uses complete arithmetic which correctly handles s1=0, s2=0 and
// p=(0,0).
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. The checks below remove common degenerate inputs, but they do
// not fully characterize the exceptional set:
//   - p must NOT be (0,0)
//   - p must NOT be ±g
//   - s1 and s2 must NOT be 0
//
// Incomplete mode additionally inherits sparse implementation-dependent
// failures from the underlying joint-scalar algorithm.
//
// JointScalarMulBase is used to verify an ECDSA signature (r,s) for example on
// the secp256k1 curve. In this case, p is a public key, s2=r/s and s1=hash/s.
//   - hash cannot be 0, because of pre-image resistance.
//   - r cannot be 0, because r is the x coordinate of a random point on
//     secp256k1 (y²=x³+7 mod p) and 7 is not a square mod p. For any other
//     curve, (_,0) is a point of order 2 which is not the prime subgroup.
//   - (0,0) is not a valid public key.
//
// The [EVM] specifies these checks, which are performed on the zkEVM
// arithmetization side before calling the circuit that uses this method.
func (c *Curve[B, S]) JointScalarMulBase(p *AffinePoint[B], s2, s1 *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	if _, cerr := c.combData(c.combWindow()); cerr == nil && !cfg.IncompleteArithmetic {
		// In complete mode, compute the fixed-base part with the comb method
		// (complete, handles s1 = 0) and the variable-base part separately,
		// and merge with the complete addition. This is cheaper than two
		// variable-base scalar multiplications.
		//
		// We do NOT take this path in incomplete mode: composing the comb
		// with the incomplete variable-base [Curve.ScalarMul] would be
		// cheaper still, but the incomplete scalar multiplication has a
		// non-negligible exceptional set when p has a small known relation
		// to the generator (e.g. p = [2]g fails for a noticeable fraction of
		// scalars), whereas the joint Shamir-based algorithm below handles
		// those points.
		sm1 := c.scalarMulBaseComb(s1, c.combWindow())
		sm2 := c.ScalarMul(p, s2, opts...)
		return c.AddUnified(sm1, sm2)
	}
	return c.jointScalarMul(c.Generator(), p, s1, s2, opts...)
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
// calls and additionally depends on internal accumulator and prefix-sum
// collisions, so the incomplete exceptional set is not fully characterized at
// the API level.
func (c *Curve[B, S]) MultiScalarMul(p []*AffinePoint[B], s []*emulated.Element[S], opts ...algopts.AlgebraOption) (*AffinePoint[B], error) {

	if len(p) == 0 {
		return &AffinePoint[B]{
			X: *c.baseApi.Zero(),
			Y: *c.baseApi.Zero(),
		}, nil
	}
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	addFn := c.Add
	if !cfg.IncompleteArithmetic {
		addFn = c.AddUnified
	}
	if !cfg.FoldMulti {
		// the scalars are unique
		if len(p) != len(s) {
			return nil, fmt.Errorf("mismatching points and scalars slice lengths")
		}
		// route compile-time constant points of prime order through the
		// fixed-base comb (complete arithmetic, much cheaper) and fold only
		// the remaining variable points through the joint scalar
		// multiplications.
		var res *AffinePoint[B]
		varP := make([]*AffinePoint[B], 0, len(p))
		varS := make([]*emulated.Element[S], 0, len(s))
		for i := range p {
			var d *combData
			if px, ok := c.baseApi.ConstantValue(&p[i].X); ok {
				if py, ok := c.baseApi.ConstantValue(&p[i].Y); ok {
					if dd, derr := c.combDataFor(px, py, c.combWindow()); derr == nil {
						d = dd
					}
				}
			}
			if d == nil {
				varP = append(varP, p[i])
				varS = append(varS, s[i])
				continue
			}
			q := c.scalarMulComb(d, s[i])
			if res == nil {
				res = q
			} else {
				res = addFn(res, q)
			}
		}
		n := len(varP)
		if n > 0 {
			var vres *AffinePoint[B]
			hasEndo := c.eigenvalue != nil && c.thirdRootOne != nil
			if hasEndo && !c.params.PreferClassicGLV && !cfg.IncompleteArithmetic {
				// Deferred subgroup binding: accumulate the UNBOUND per-point
				// fake-GLV outputs and bind the variable-point aggregate ONCE (n
				// subgroup checks → 1). Sound because each summand's accumulator
				// forces its subgroup part exactly (Qᵢ = [sᵢ]Pᵢ + Tᵢ with Tᵢ pure
				// torsion, given Pᵢ in the subgroup), so binding the sum forces
				// ΣTᵢ = O. The constant prime-order points already folded into res
				// go through the comb and are already in the subgroup.
				vres = c.scalarMulGLVAndFakeGLV(varP[0], varS[0], opts...)
				for i := 1; i < n; i++ {
					vres = addFn(vres, c.scalarMulGLVAndFakeGLV(varP[i], varS[i], opts...))
				}
				c.assertPointInSubgroup(vres)
			} else {
				// classic-GLV / no-endo / incomplete: the per-call scalar muls bind
				// their own output (or are computed in-subgroup / prime-order).
				if n%2 == 1 {
					vres = c.ScalarMul(varP[n-1], varS[n-1], opts...)
				} else {
					vres = c.jointScalarMul(varP[n-2], varP[n-1], varS[n-2], varS[n-1], opts...)
				}
				for i := 1; i < n-1; i += 2 {
					q := c.jointScalarMul(varP[i-1], varP[i], varS[i-1], varS[i], opts...)
					vres = addFn(vres, q)
				}
			}
			if res == nil {
				res = vres
			} else {
				res = addFn(res, vres)
			}
		}
		return res, nil
	} else {
		// scalars are powers
		if len(s) == 0 {
			return nil, fmt.Errorf("need scalar for folding")
		}
		gamma := s[0]
		res := c.ScalarMul(p[len(p)-1], gamma, opts...)
		for i := len(p) - 2; i > 0; i-- {
			res = addFn(p[i], res)
			res = c.ScalarMul(res, gamma, opts...)
		}
		res = addFn(p[0], res)
		return res, nil
	}
}

// scalarMulFakeGLV computes [s]Q and returns it. It doesn't modify Q nor s.
// It implements the "fake GLV" explained in [EEMP25] (Sec. 3.1).
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. Besides Q=(0,0) and s=0, the documented exceptional set also
// includes the small structured scalar set
// {±1, ±3, ±3⁻¹ mod r}. Outside of this set, the method is intended for
// random non-adversarial inputs.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// TODO @yelhousni: generalize for any supported curve as it currently supports only:
// P256, P384 and STARK curve.
//
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
// [EEMP25]: https://eprint.iacr.org/2025/933
func (c *Curve[B, S]) scalarMulFakeGLV(Q *AffinePoint[B], s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var st S
	nbits := (st.Modulus().BitLen() + 1) / 2

	var isScalarZero frontend.Variable
	_s := s
	if !cfg.IncompleteArithmetic {
		isScalarZero = c.scalarApi.IsZero(s)
		_s = c.scalarApi.Select(isScalarZero, c.scalarApi.One(), s)
	}

	// First we find the sub-salars s1, s2 s.t. s1 + s2*s = 0 mod r and |s1|,|s2| < γ₂·√r ≈ 1.15·√r.
	// we also output the sign in case s2 is negative. In that case we compute _s2 = -s2 mod r.
	sign, sd, err := c.scalarApi.NewHintGeneric(rationalReconstruct, 1, 2, nil, []*emulated.Element[S]{_s},
		// we know that the hint will return s1, s2 < sqrt(r) so we can set the hint output range check bits to nbits = ceil(log2(sqrt(r))) = ceil(log2(r)/2)
		emulated.WithHintOutputRangeCheckBits(map[int]int{1: nbits, 2: nbits}))
	if err != nil {
		panic(fmt.Sprintf("rationalReconstruct hint: %v", err))
	}
	s1, s2 := sd[0], sd[1]
	_s2 := c.scalarApi.Select(sign[0], c.scalarApi.Neg(s2), s2)
	// We check that s1 + s*_s2 == 0 mod r
	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(s1, c.scalarApi.Mul(_s, _s2)),
		c.scalarApi.Zero(),
	)
	// A malicious hint can provide s1=s2=0 mod r
	// So we check that _s2 is non-zero otherwise [0]([s]Q = ∀R) is always true
	c.api.AssertIsEqual(c.scalarApi.IsZero(_s2), 0)

	// Then we compute the hinted scalar mul R = [s]Q
	// Q coordinates are in Fp and the scalar s in Fr
	// we decompose Q.X, Q.Y, s into limbs and recompose them in the hint.
	_, R, _, err := emulated.NewVarGenericHint(c.api, 0, 2, 0, nil, []*emulated.Element[B]{&Q.X, &Q.Y}, []*emulated.Element[S]{s}, scalarMulHint)
	if err != nil {
		panic(fmt.Sprintf("scalar mul hint: %v", err))
	}
	r0, r1 := R[0], R[1]

	var isInputPointAtInfinity frontend.Variable
	one := c.baseApi.One()
	dummy := &AffinePoint[B]{X: *one, Y: *one}
	addFn := c.Add
	if !cfg.IncompleteArithmetic {
		addFn = c.AddUnified
		// if Q=(0,0) we assign a dummy (1,1) to Q and R and continue
		isInputPointAtInfinity = c.api.And(c.baseApi.IsZero(&Q.X), c.baseApi.IsZero(&Q.Y))
		Q = c.Select(isInputPointAtInfinity, dummy, Q)
		r0 = c.baseApi.Select(isInputPointAtInfinity, c.baseApi.Zero(), r0)
		r1 = c.baseApi.Select(isInputPointAtInfinity, &dummy.Y, r1)
	}

	s1bits := c.scalarApi.ToBits(s1)
	s2bits := c.scalarApi.ToBits(s2)

	// Precomputations:
	// 		tableQ[0] = -Q
	//   	tableQ[1] = Q
	// 		tableQ[2] = [3]Q
	// 		tableR[0] = -R or R if s2 is negative
	//   	tableR[1] = R or -R if s2 is negative
	// 		tableR[2] = [3]R or [-3]R if s2 is negative
	var tableQ, tableR [3]*AffinePoint[B]
	tableQ[1] = Q
	tableQ[0] = c.Neg(Q)
	tableQ[2] = c.triple(tableQ[1])
	tableR[1] = &AffinePoint[B]{
		X: *r0,
		Y: *c.baseApi.Select(sign[0], c.baseApi.Neg(r1), r1),
	}
	tableR[0] = c.Neg(tableR[1])
	if !cfg.IncompleteArithmetic {
		tableR[2] = c.AddUnified(tableR[1], tableR[1])
		tableR[2] = c.AddUnified(tableR[2], tableR[1])
	} else {
		tableR[2] = c.triple(tableR[1])
	}

	// We should start the accumulator by the infinity point, but since affine
	// formulae are incomplete we suppose that the first bits of the
	// sub-scalars s1 and s2 are 1, and set:
	// 		Acc = Q + R
	Acc := addFn(tableQ[1], tableR[1])

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± R.
	// We can compute [2]Acc and look up the (precomputed) point P from:
	// 		B1 = Q+R
	// 		B2 = -Q-R
	// 		B3 = Q-R
	// 		B4 = -Q+R
	//
	// If we extend this by merging two iterations, we need to look up P and P'
	// both from {B1, B2, B3, B4} and compute:
	// 		[2]([2]Acc+P)+P' = [4]Acc + T
	// where T = [2]P+P'. So at each (merged) iteration, we can compute [4]Acc
	// and look up T from the precomputed list of points:
	//
	// T = [3](Q + R)
	// P = B1 and P' = B1
	t1 := addFn(tableQ[2], tableR[2])
	// T = Q + R
	// P = B1 and P' = B2
	T2 := Acc
	// T = [3]Q + R
	// P = B1 and P' = B3
	T3 := addFn(tableQ[2], tableR[1])
	// T = Q + [3]R
	// P = B1 and P' = B4
	t4 := addFn(tableQ[1], tableR[2])
	// T  = -Q - R
	// P = B2 and P' = B1
	T5 := c.Neg(T2)
	// T  = -[3](Q + R)
	// P = B2 and P' = B2
	T6 := c.Neg(t1)
	// T = -Q - [3]R
	// P = B2 and P' = B3
	T7 := c.Neg(t4)
	// T = -[3]Q - R
	// T = [3]Q - R
	// P = B3 and P' = B1
	t9 := addFn(tableQ[2], tableR[0])
	// T = Q - [3]R
	// P = B3 and P' = B2
	t := c.Neg(tableR[2])
	T10 := addFn(tableQ[1], t)
	// T = [3](Q - R)
	// P = B3 and P' = B3
	T11 := addFn(tableQ[2], t)
	// T = -R + Q
	// P = B3 and P' = B4
	T12 := addFn(tableR[0], tableQ[1])
	// T = R - [3]Q
	// P = B4 and P' = B2
	T14 := c.Neg(t9)
	// T = R - Q
	// P = B4 and P' = B3
	T15 := c.Neg(T12)
	// note that half of these points are negatives of the other half,
	// hence have the same X coordinates.

	// When nbits is even, we need to handle the first iteration separately
	if nbits%2 == 0 {
		// Acc = [2]Acc ± Q ± R
		T := &AffinePoint[B]{
			X: *c.baseApi.Select(c.api.Xor(s1bits[nbits-1], s2bits[nbits-1]), &T12.X, &T5.X),
			Y: *c.baseApi.Lookup2(s1bits[nbits-1], s2bits[nbits-1], &T5.Y, &T12.Y, &T15.Y, &T2.Y),
		}
		// We don't use doubleAndAdd here as it would involve edge cases
		// when bits are 00 (T==-Acc) or 11 (T==Acc).
		Acc = c.doubleGeneric(Acc, !cfg.IncompleteArithmetic)
		Acc = addFn(Acc, T)
	} else {
		// when nbits is odd we start the main loop at normally nbits - 1
		nbits++
	}
	for i := nbits - 2; i > 2; i -= 2 {
		// selectorY takes values in [0,15]
		selectorY := c.api.Add(
			s1bits[i],
			c.api.Mul(s2bits[i], 2),
			c.api.Mul(s1bits[i-1], 4),
			c.api.Mul(s2bits[i-1], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := c.api.Add(
			c.api.Mul(selectorY, c.api.Sub(1, c.api.Mul(s2bits[i-1], 2))),
			c.api.Mul(s2bits[i-1], 15),
		)
		// Half of the Bi.X are distinct (8-to-1) and Y[i] = -Y[15-i],
		// so we use 8-to-1 Mux for both X and Y, with conditional negation for Y.
		T := &AffinePoint[B]{
			X: *c.baseApi.Mux(selectorX,
				&T6.X, &T10.X, &T14.X, &T2.X, &T7.X, &T11.X, &T15.X, &T3.X,
			),
			Y: *c.muxY8Signed(s2bits[i-1], selectorX,
				&T6.Y, &T10.Y, &T14.Y, &T2.Y, &T7.Y, &T11.Y, &T15.Y, &T3.Y,
			),
		}
		// Acc = [4]Acc + T
		Acc = c.doubleGeneric(Acc, !cfg.IncompleteArithmetic)
		Acc = c.doubleAndAddGeneric(Acc, T, !cfg.IncompleteArithmetic)
	}

	// i = 2
	// we isolate the last iteration to avoid falling into incomplete additions
	//
	// selectorY takes values in [0,15]
	selectorY := c.api.Add(
		s1bits[2],
		c.api.Mul(s2bits[2], 2),
		c.api.Mul(s1bits[1], 4),
		c.api.Mul(s2bits[1], 8),
	)
	// selectorX takes values in [0,7] s.t.:
	// 		- when selectorY < 8: selectorX = selectorY
	// 		- when selectorY >= 8: selectorX = 15 - selectorY
	selectorX := c.api.Add(
		c.api.Mul(selectorY, c.api.Sub(1, c.api.Mul(s2bits[1], 2))),
		c.api.Mul(s2bits[1], 15),
	)
	// Half of the Bi.X are distinct (8-to-1) and Y[i] = -Y[15-i],
	// so we use 8-to-1 Mux for both X and Y, with conditional negation for Y.
	T := &AffinePoint[B]{
		X: *c.baseApi.Mux(selectorX,
			&T6.X, &T10.X, &T14.X, &T2.X, &T7.X, &T11.X, &T15.X, &T3.X,
		),
		Y: *c.muxY8Signed(s2bits[1], selectorX,
			&T6.Y, &T10.Y, &T14.Y, &T2.Y, &T7.Y, &T11.Y, &T15.Y, &T3.Y,
		),
	}
	// to avoid incomplete additions we add [3]R to the precomputed T before computing [4]Acc+T
	// 		Acc = [4]Acc + T + [3]R
	T = addFn(T, tableR[2])
	Acc = c.doubleGeneric(Acc, !cfg.IncompleteArithmetic)
	Acc = c.doubleAndAddGeneric(Acc, T, !cfg.IncompleteArithmetic)

	// i = 0
	// subtract Q and R if the first bits are 0.
	// When not using incomplete arithmetic, we use AddUnified instead of Add.
	// This means when s=0 then Acc=(0,0) because AddUnified(Q, -Q) = (0,0).
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = c.Select(s1bits[0], Acc, tableQ[0])
	tableR[0] = addFn(tableR[0], Acc)
	Acc = c.Select(s2bits[0], Acc, tableR[0])

	if !cfg.IncompleteArithmetic {
		Acc = c.Select(c.api.Or(isScalarZero, isInputPointAtInfinity), tableR[2], Acc)
	}
	// we added [3]R at the last iteration so the result should be
	// 		Acc = [s1]Q + [s2]R + [3]R
	// 		    = [s1]Q + [s2*s]Q + [3]R
	// 		    = [s1+s2*s]Q + [3]R
	// 		    = [0]Q + [3]R
	// 		    = [3]R
	c.AssertIsEqual(Acc, tableR[2])

	res := &AffinePoint[B]{
		X: *R[0],
		Y: *R[1],
	}
	if !cfg.IncompleteArithmetic {
		zero := c.baseApi.Zero()
		// On the complete-arithmetic edge branches (s=0 or Q=(0,0)) the
		// accumulator check is rerouted through a dummy path, so we must also
		// return the canonical infinity point instead of the unverified hint output.
		res = c.Select(c.api.Or(isScalarZero, isInputPointAtInfinity), &AffinePoint[B]{X: *zero, Y: *zero}, res)
	}
	return res
}

// scalarMulGLVAndFakeGLV computes [s]P and returns it. It doesn't modify P nor s.
// It implements the "GLV + fake GLV" explained in [EEMP25] (Sec. 3.3).
//
// ⚠️  When [algopts.WithIncompleteArithmetic] is set, this method is faster but
// not complete. Besides P=(0,0) and s in {0, ±1}, there is a sparse
// point-dependent exceptional set coming from incomplete precomputations and the
// initial bias step. This mode is intended for random non-adversarial inputs.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// The result is undefined for input points that are not in the prime subgroup.
//
// TODO @yelhousni: generalize for any supported curve as it currently supports only:
// BN254, BLS12-381, BW6-761 and Secp256k1.
//
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
// [EEMP25]: https://eprint.iacr.org/2025/933
func (c *Curve[B, S]) scalarMulGLVAndFakeGLV(P *AffinePoint[B], s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var st S
	// LLL Hermite bound (gnark-crypto/algebra/lattice): u1, u2, v1, v2 are
	// bounded by γ₄·r^(1/4) ≈ 1.25·r^(1/4), which fits in (BitLen+3)/4 + 2 bits.
	// This is tighter than the previous heuristic BitLen/4 + 9 (saves ~7 iters).
	nbits := (st.Modulus().BitLen()+3)/4 + 2

	// handle 0-scalar and (-1)-scalar cases
	var isScalarZero, isScalarZeroOrMinusOne, isScalarOne, isScalarMinusOne frontend.Variable
	_s := s
	if !cfg.IncompleteArithmetic {
		isScalarZero = c.scalarApi.IsZero(s)
		one := c.scalarApi.One()
		isScalarOne = c.scalarApi.IsZero(c.scalarApi.Sub(s, one))
		isScalarMinusOne = c.scalarApi.IsZero(c.scalarApi.Add(s, one))
		isScalarZeroOrMinusOne = c.api.Or(isScalarZero, isScalarMinusOne)
		_s = c.scalarApi.Select(isScalarZeroOrMinusOne, one, s)
	}

	// Instead of computing [s]P=Q, we check that Q-[s]P == 0.
	// Checking Q - [s]P = 0 is equivalent to [v]Q + [-s*v]P = 0 for some nonzero v.
	//
	// The GLV curves supported in gnark have j-invariant 0, which means the eigenvalue
	// of the GLV endomorphism is a primitive cube root of unity.  If we write
	// v, s and r as Eisenstein integers we can express the check as:
	//
	// 			[v1 + λ*v2]Q + [u1 + λ*u2]P = 0
	// 			[v1]Q + [v2]phi(Q) + [u1]P + [u2]phi(P) = 0
	//
	// where (v1 + λ*v2)*(s1 + λ*s2) = u1 + λu2 mod (r1 + λ*r2)
	// and u1, u2, v1, v2 < r^{1/4} (up to a constant factor).
	//
	// This can be done as follows:
	// 		1. decompose s into s1 + λ*s2 mod r s.t. s1, s2 < sqrt(r) (hinted classical GLV decomposition).
	// 		2. decompose r into r1 + λ*r2  s.t. r1, r2 < sqrt(r) (hardcoded half-GCD of λ mod r).
	// 		3. find u1, u2, v1, v2 < c*r^{1/4} s.t. (v1 + λ*v2)*(s1 + λ*s2) = (u1 + λ*u2) mod (r1 + λ*r2).
	// 		   This can be done through a hinted half-GCD in the number field
	// 		   K=Q[w]/f(w).  This corresponds to K being the Eisenstein ring of
	// 		   integers i.e. w is a primitive cube root of unity, f(w)=w^2+w+1=0.
	//
	// The hint returns u1, u2, v1, v2.
	// In-circuit we check that (v1 + λ*v2)*s = (u1 + λ*u2) mod r
	//
	//
	// Eisenstein integers real and imaginary parts can be negative. So we
	// return the absolute value in the hint and negate the corresponding
	// points here when needed.
	signs, sd, err := c.scalarApi.NewHintGeneric(rationalReconstructExt, 4, 4, nil, []*emulated.Element[S]{_s, c.eigenvalue},
		// we later need to check that u1, u2, v1, v2 < c*r^(1/4) so we provide a hint output range check with nbits = (BitLen+3)/4 + 2
		emulated.WithHintOutputRangeCheckBits(map[int]int{4: nbits, 5: nbits, 6: nbits, 7: nbits}),
	)
	if err != nil {
		panic(fmt.Sprintf("rationalReconstructExt hint: %v", err))
	}
	u1, u2, v1, v2 := sd[0], sd[1], sd[2], sd[3]
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// We need to check that:
	// 		s*(v1 + λ*v2) + u1 + λ*u2 = 0
	sv1 := c.scalarApi.Mul(_s, v1)
	sλv2 := c.scalarApi.Mul(_s, c.scalarApi.Mul(c.eigenvalue, v2))
	λu2 := c.scalarApi.Mul(c.eigenvalue, u2)
	zero := c.scalarApi.Zero()

	lhs1 := c.scalarApi.Select(isNegv1, zero, sv1)
	lhs2 := c.scalarApi.Select(isNegv2, zero, sλv2)
	lhs3 := c.scalarApi.Select(isNegu1, zero, u1)
	lhs4 := c.scalarApi.Select(isNegu2, zero, λu2)
	lhs := c.scalarApi.Add(
		c.scalarApi.Add(lhs1, lhs2),
		c.scalarApi.Add(lhs3, lhs4),
	)

	rhs1 := c.scalarApi.Select(isNegv1, sv1, zero)
	rhs2 := c.scalarApi.Select(isNegv2, sλv2, zero)
	rhs3 := c.scalarApi.Select(isNegu1, u1, zero)
	rhs4 := c.scalarApi.Select(isNegu2, λu2, zero)
	rhs := c.scalarApi.Add(
		c.scalarApi.Add(rhs1, rhs2),
		c.scalarApi.Add(rhs3, rhs4),
	)

	c.scalarApi.AssertIsEqual(lhs, rhs)

	// Soundness: forbid the trivial all-zeros Eisenstein decomposition
	// (v1 = v2 = 0). Without this, a malicious hint can return the all-zeros
	// solution, making the relation s·(v1 + λ·v2) + u1 + λ·u2 = 0 satisfied
	// vacuously and the in-circuit accumulator constraint becomes independent
	// of the hinted scalar-mul output Q — letting any Q pass. Forbidding v ≠ 0
	// forces s·(v1 + λ·v2) ≠ 0, which constrains (u1, u2) to the genuine
	// lattice point and Q to [s]P.
	c.api.AssertIsEqual(c.api.Mul(c.scalarApi.IsZero(v1), c.scalarApi.IsZero(v2)), 0)

	// Next we compute the hinted scalar mul Q = [s]P
	// P coordinates are in Fp and the scalar s in Fr
	// we decompose Q.X, Q.Y, s into limbs and recompose them in the hint.
	_, point, _, err := emulated.NewVarGenericHint(c.api, 0, 2, 0, nil, []*emulated.Element[B]{&P.X, &P.Y}, []*emulated.Element[S]{s}, scalarMulHint)
	if err != nil {
		panic(fmt.Sprintf("scalar mul hint: %v", err))
	}
	Q := &AffinePoint[B]{X: *point[0], Y: *point[1]}

	// handle (0,0)-point
	var isInputPointAtInfinity frontend.Variable
	_P := P
	if !cfg.IncompleteArithmetic {
		// if Q=(0,0) we assign a dummy point to Q and continue
		Q = c.Select(isScalarZeroOrMinusOne, &c.GeneratorMultiples()[3], Q)
		// if P=(0,0) we assign a dummy point to P and continue
		isInputPointAtInfinity = c.api.And(c.baseApi.IsZero(&P.X), c.baseApi.IsZero(&P.Y))
		_P = c.Select(isInputPointAtInfinity, &c.GeneratorMultiples()[4], P)
		// if s=1 we assign a dummy point to Q and continue
		Q = c.Select(isScalarOne, &c.GeneratorMultiples()[3], Q)
	}

	// NOTE: the returned point is NOT bound into the prime-order subgroup. The
	// accumulator below only pins it modulo the v-torsion, so on cofactor curves a
	// torsion-shifted output satisfies the identity. Callers that expose the result
	// must bind it with [Curve.assertPointInSubgroup]; the public entry points
	// ([Curve.ScalarMul], [Curve.ScalarMulBase], [Curve.jointScalarMulGLV],
	// [Curve.MultiScalarMul]) do so — once per aggregate output, not per summand.

	addFn := c.Add
	if !cfg.IncompleteArithmetic {
		addFn = c.AddUnified
	}

	// precompute -P, -Φ(P), Φ(P)
	var tableP, tablePhiP [2]*AffinePoint[B]
	negPY := c.baseApi.Neg(&_P.Y)
	tableP[1] = &AffinePoint[B]{
		X: _P.X,
		Y: *c.baseApi.Select(isNegu1, negPY, &_P.Y),
	}
	tableP[0] = c.Neg(tableP[1])
	tablePhiP[1] = &AffinePoint[B]{
		X: *c.baseApi.Mul(&_P.X, c.thirdRootOne),
		Y: *c.baseApi.Select(isNegu2, negPY, &_P.Y),
	}
	tablePhiP[0] = c.Neg(tablePhiP[1])

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]*AffinePoint[B]
	negQY := c.baseApi.Neg(&Q.Y)
	tableQ[1] = &AffinePoint[B]{
		X: Q.X,
		Y: *c.baseApi.Select(isNegv1, negQY, &Q.Y),
	}
	tableQ[0] = c.Neg(tableQ[1])
	tablePhiQ[1] = &AffinePoint[B]{
		X: *c.baseApi.Mul(&Q.X, c.thirdRootOne),
		Y: *c.baseApi.Select(isNegv2, negQY, &Q.Y),
	}
	tablePhiQ[0] = c.Neg(tablePhiQ[1])

	// precompute -P-Q, P+Q, P-Q, -P+Q, -Φ(P)-Φ(Q), Φ(P)+Φ(Q), Φ(P)-Φ(Q), -Φ(P)+Φ(Q)
	var tableS, tablePhiS [4]*AffinePoint[B]
	tableS[0] = addFn(tableP[0], tableQ[0])
	tableS[1] = c.Neg(tableS[0])
	tableS[2] = addFn(tableP[1], tableQ[0])
	tableS[3] = c.Neg(tableS[2])
	tablePhiS[0] = addFn(tablePhiP[0], tablePhiQ[0])
	tablePhiS[1] = c.Neg(tablePhiS[0])
	tablePhiS[2] = addFn(tablePhiP[1], tablePhiQ[0])
	tablePhiS[3] = c.Neg(tablePhiS[2])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = P + Q + Φ(P) + Φ(Q)
	Acc := addFn(tableS[1], tablePhiS[1])
	b1 := Acc
	// then we add G (the base point) to Acc to avoid incomplete additions in
	// the loop, because when doing doubleAndAdd(Acc, Bi) as (Acc+Bi)+Acc it
	// might happen that Acc==Bi or Acc==-Bi. But now we force Acc to be
	// different than the stored Bi. However, at the end, Acc will not be the
	// point at infinity but [2^nbits]G.
	//
	// N.B.: Acc cannot be equal to G, otherwise this means G = -Φ²([s+1]P)
	g := c.Generator()
	Acc = addFn(Acc, g)

	u1bits := c.scalarApi.ToBits(u1)
	u2bits := c.scalarApi.ToBits(u2)
	v1bits := c.scalarApi.ToBits(v1)
	v2bits := c.scalarApi.ToBits(v2)

	// At each iteration we look up the point Bi from:
	// 		B1  = +P + Q + Φ(P) + Φ(Q)
	// 		B2  = +P + Q + Φ(P) - Φ(Q)
	B2 := addFn(tableS[1], tablePhiS[2])
	// 		b3  = +P + Q - Φ(P) + Φ(Q)
	b3 := addFn(tableS[1], tablePhiS[3])
	// 		B4  = +P + Q - Φ(P) - Φ(Q)
	B4 := addFn(tableS[1], tablePhiS[0])
	// 		b5  = +P - Q + Φ(P) + Φ(Q)
	b5 := addFn(tableS[2], tablePhiS[1])
	// 		B6  = +P - Q + Φ(P) - Φ(Q)
	B6 := addFn(tableS[2], tablePhiS[2])
	// 		b7  = +P - Q - Φ(P) + Φ(Q)
	b7 := addFn(tableS[2], tablePhiS[3])
	// 		B8  = +P - Q - Φ(P) - Φ(Q)
	B8 := addFn(tableS[2], tablePhiS[0])
	// 		B10 = -P + Q + Φ(P) - Φ(Q)
	B10 := c.Neg(b7)
	// 		B12 = -P + Q - Φ(P) - Φ(Q)
	B12 := c.Neg(b5)
	// 		B14 = -P - Q + Φ(P) - Φ(Q)
	B14 := c.Neg(b3)
	// 		B16 = -P - Q - Φ(P) - Φ(Q)
	B16 := c.Neg(b1)
	// note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	var Bi *AffinePoint[B]
	// in incomplete mode on j = 0 curves, run the loop with the accumulator
	// y-coordinate in implicit form (see implicitDoubleAndAdd): one deferred
	// check saved per iteration, y materialized once after the loop.
	var iAcc *implicitAcc[B]
	if cfg.IncompleteArithmetic && !c.addA {
		iAcc = c.implicitFromAffine(Acc)
	}
	for i := nbits - 1; i > 0; i-- {
		// selectorY takes values in [0,15]
		selectorY := c.api.Add(
			u1bits[i],
			c.api.Mul(u2bits[i], 2),
			c.api.Mul(v1bits[i], 4),
			c.api.Mul(v2bits[i], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := c.api.Add(
			c.api.Mul(selectorY, c.api.Sub(1, c.api.Mul(v2bits[i], 2))),
			c.api.Mul(v2bits[i], 15),
		)
		// Half of the Bi.X are distinct (8-to-1) and Y[i] = -Y[15-i],
		// so we use 8-to-1 Mux for both X and Y, with conditional negation for Y.
		Bi = &AffinePoint[B]{
			X: *c.baseApi.Mux(selectorX,
				&B16.X, &B8.X, &B14.X, &B6.X, &B12.X, &B4.X, &B10.X, &B2.X,
			),
			Y: *c.muxY8Signed(v2bits[i], selectorX,
				&B16.Y, &B8.Y, &B14.Y, &B6.Y, &B12.Y, &B4.Y, &B10.Y, &B2.Y,
			),
		}
		// Acc = [2]Acc + Bi
		if !cfg.IncompleteArithmetic {
			Acc = c.doubleGeneric(Acc, true)
			Acc = addFn(Acc, Bi)
		} else if iAcc != nil {
			c.implicitDoubleAndAdd(iAcc, Bi)
		} else {
			Acc = c.doubleAndAdd(Acc, Bi)
		}
	}
	if iAcc != nil {
		Acc = c.implicitToAffine(iAcc)
	}

	// i = 0
	// subtract the P, Q, Φ(P), Φ(Q) if the first bits are 0
	tableP[0] = addFn(tableP[0], Acc)
	Acc = c.Select(u1bits[0], Acc, tableP[0])
	tablePhiP[0] = addFn(tablePhiP[0], Acc)
	Acc = c.Select(u2bits[0], Acc, tablePhiP[0])
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = c.Select(v1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = addFn(tablePhiQ[0], Acc)
	Acc = c.Select(v2bits[0], Acc, tablePhiQ[0])

	// Acc should be now equal to [2^nbits]G
	gm := c.GeneratorMultiples()[nbits-1]
	if !cfg.IncompleteArithmetic {
		Acc = c.Select(c.api.Or(c.api.Or(isScalarZeroOrMinusOne, isInputPointAtInfinity), isScalarOne), &gm, Acc)
	}
	c.AssertIsEqual(Acc, &gm)

	res := &AffinePoint[B]{
		X: *point[0],
		Y: *point[1],
	}
	if !cfg.IncompleteArithmetic {
		zero := c.baseApi.Zero()
		// The complete-arithmetic edge branches (s=0, s=-1, s=1, or P=(0,0))
		// reroute the accumulator check through dummy points, so we must also
		// return the canonical in-circuit result instead of the unverified hint output.
		res = c.Select(isScalarOne, _P, res)
		res = c.Select(isScalarZeroOrMinusOne, c.Neg(_P), res)
		res = c.Select(isScalarZero, &AffinePoint[B]{X: *zero, Y: *zero}, res)
		res = c.Select(isInputPointAtInfinity, &AffinePoint[B]{X: *zero, Y: *zero}, res)
	}
	return res
}
