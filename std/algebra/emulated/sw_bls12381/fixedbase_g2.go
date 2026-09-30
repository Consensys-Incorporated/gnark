package sw_bls12381

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
)

// Fixed-base signed-digit comb for compile-time constant G2 points, following
// the same construction and soundness argument as the G1 comb in
// sw_emulated/fixedbase.go: odd recode k' = s + 1 − b0 pinned by a single
// mod-r assertion, constant window tables [d(j)·2^{w·t}]P selected by one-hot
// flags shared across all coordinate limbs, provably collision-free
// incomplete chord additions over E2, parity fold in the top window, and a
// complete AddUnified tail.
const g2CombWindow = 8

// g2CombPlonkWindow is the window width on PLONKish backends, where the
// one-hot selection's constant linear combinations expand into addition
// gates (see the G1 comb in sw_emulated). Width 5 is the current SCS optimum
// measured on BN254 and BLS12-381 G2.
const g2CombPlonkWindow = 5

// g2CombWindowFor returns the comb window width for the current backend.
func (g2 *G2) g2CombWindowFor() int {
	if _, ok := g2.api.Compiler().(frontend.PlonkAPI); ok {
		return g2CombPlonkWindow
	}
	return g2CombWindow
}

type g2CombData struct {
	w         int
	nw        int
	n         int
	tw        int
	nbUnified int
	// windows[t][j] = [d(j)·2^{w·t} mod r]P as (X.A0, X.A1, Y.A0, Y.A1).
	// For the lower windows d(j) = 2j − 2^w + 1; for the top window w is
	// replaced by tw.
	windows [][][4]*big.Int
	// doubles[t][j] = 2*windows[t][j], used by the screened complete tail
	// when a trailing addition degenerates into a doubling.
	doubles        [][][4]*big.Int
	topEven        [][4]*big.Int
	topEvenDoubles [][4]*big.Int
}

var g2CombCache sync.Map

func g2CombDataFor(x0, x1, y0, y1 *big.Int, w int) (*g2CombData, error) {
	key := fmt.Sprintf("%d|%s|%s|%s|%s", w, x0.Text(16), x1.Text(16), y0.Text(16), y1.Text(16))
	if v, ok := g2CombCache.Load(key); ok {
		return v.(*g2CombData), nil
	}
	var P bls12381.G2Affine
	P.X.A0.SetBigInt(x0)
	P.X.A1.SetBigInt(x1)
	P.Y.A0.SetBigInt(y0)
	P.Y.A1.SetBigInt(y1)
	if P.IsInfinity() {
		return nil, errors.New("base point is the point at infinity")
	}
	if !P.IsOnCurve() {
		return nil, errors.New("base point is not on the twist")
	}
	if !P.IsInSubGroup() {
		return nil, errors.New("base point is not in the prime-order subgroup")
	}
	r := fr_bls.Modulus()
	rBits := r.BitLen()
	nw := (rBits + w - 1) / w
	n := rBits
	var frParams ScalarField
	if n > int(frParams.NbLimbs()*frParams.BitsPerLimb()) {
		return nil, errors.New("recoded scalar exceeds scalar field emulation capacity")
	}
	tw := n - w*(nw-1)
	nbUnified := 0
	for t := nw - 1; t >= 1; t-- {
		endBit := w * (t + 1)
		if t == nw-1 {
			endBit = n
		}
		if new(big.Int).Lsh(big.NewInt(1), uint(endBit)).Cmp(r) <= 0 {
			break
		}
		nbUnified++
	}
	nbUnified = max(nbUnified, 1)

	toBig := func(a *bls12381.G2Affine) ([4]*big.Int, error) {
		if a.IsInfinity() {
			return [4]*big.Int{}, errors.New("unexpected point at infinity in comb table")
		}
		return [4]*big.Int{
			a.X.A0.BigInt(new(big.Int)),
			a.X.A1.BigInt(new(big.Int)),
			a.Y.A0.BigInt(new(big.Int)),
			a.Y.A1.BigInt(new(big.Int)),
		}, nil
	}
	toDoubleBig := func(a *bls12381.G2Affine) ([4]*big.Int, error) {
		var j bls12381.G2Jac
		j.FromAffine(a)
		j.DoubleAssign()
		var d bls12381.G2Affine
		d.FromJacobian(&j)
		return toBig(&d)
	}

	windows := make([][][4]*big.Int, nw)
	doubles := make([][][4]*big.Int, nw)
	var Bt bls12381.G2Jac
	Bt.FromAffine(&P)
	for t := 0; t < nw; t++ {
		if t > 0 {
			for k := 0; k < w; k++ {
				Bt.DoubleAssign()
			}
		}
		tw := w
		if t == nw-1 {
			tw = n - w*(nw-1)
		}
		var D bls12381.G2Jac
		D.Set(&Bt).DoubleAssign()
		half := 1 << (tw - 1)
		odd := make([]bls12381.G2Affine, half)
		acc := new(bls12381.G2Jac).Set(&Bt)
		odd[0].FromJacobian(acc)
		for m := 1; m < half; m++ {
			acc.AddAssign(&D)
			odd[m].FromJacobian(acc)
		}
		tab := make([][4]*big.Int, 1<<tw)
		dbl := make([][4]*big.Int, 1<<tw)
		for j := range tab {
			d := 2*j - (1 << tw) + 1
			var e bls12381.G2Affine
			if d > 0 {
				e = odd[(d-1)/2]
			} else {
				e.Neg(&odd[(-d-1)/2])
			}
			c, err := toBig(&e)
			if err != nil {
				return nil, err
			}
			tab[j] = c
			dc, err := toDoubleBig(&e)
			if err != nil {
				return nil, fmt.Errorf("double comb table point: %w", err)
			}
			dbl[j] = dc
		}
		windows[t] = tab
		doubles[t] = dbl
	}
	var negP bls12381.G2Jac
	var negPAff bls12381.G2Affine
	negPAff.Neg(&P)
	negP.FromAffine(&negPAff)
	topEven := make([][4]*big.Int, 1<<tw)
	topEvenDoubles := make([][4]*big.Int, 1<<tw)
	for j := range topEven {
		var e bls12381.G2Affine
		e.X.A0.SetBigInt(windows[nw-1][j][0])
		e.X.A1.SetBigInt(windows[nw-1][j][1])
		e.Y.A0.SetBigInt(windows[nw-1][j][2])
		e.Y.A1.SetBigInt(windows[nw-1][j][3])
		var acc bls12381.G2Jac
		acc.FromAffine(&e)
		acc.AddAssign(&negP)
		var res bls12381.G2Affine
		res.FromJacobian(&acc)
		c, err := toBig(&res)
		if err != nil {
			return nil, fmt.Errorf("parity-fold table: %w", err)
		}
		topEven[j] = c
		dc, err := toDoubleBig(&res)
		if err != nil {
			return nil, fmt.Errorf("double parity-fold table point: %w", err)
		}
		topEvenDoubles[j] = dc
	}
	d := &g2CombData{
		w:              w,
		nw:             nw,
		n:              n,
		tw:             tw,
		nbUnified:      nbUnified,
		windows:        windows,
		doubles:        doubles,
		topEven:        topEven,
		topEvenDoubles: topEvenDoubles,
	}
	g2CombCache.Store(key, d)
	return d, nil
}

// g2CombOneHot returns the 2^len(bs) one-hot indicator vector of the
// little-endian boolean bits bs (2^len(bs) − 2 constraints).
func g2CombOneHot(api frontend.API, bs []frontend.Variable) []frontend.Variable {
	flags := []frontend.Variable{1}
	for _, b := range bs {
		next := make([]frontend.Variable, 2*len(flags))
		if len(flags) == 1 {
			next[0] = api.Sub(1, b)
			next[1] = b
		} else {
			for j := range flags {
				hi := api.Mul(flags[j], b)
				next[j] = api.Sub(flags[j], hi)
				next[j+len(flags)] = hi
			}
		}
		flags = next
	}
	return flags
}

// g2CombSelect selects the table entry indexed by the bits, splitting the
// index into row and column one-hots so that the column flags combine with
// the constant limbs into free affine forms; every selected limb is a convex
// combination of constant limbs and needs no range check.
func (g2 *G2) g2CombSelect(table [][4]*big.Int, bs []frontend.Variable) g2AffP {
	var fp BaseField
	nbLimbs := int(fp.NbLimbs())
	nbBits := fp.BitsPerLimb()
	w := len(bs)
	if len(table) != 1<<w {
		panic("table size mismatch")
	}
	nbOut := 4 * nbLimbs
	oneHotCost := func(k int) int {
		if k <= 1 {
			return 0
		}
		return 1<<k - 2
	}
	rb := 0
	bestCost := oneHotCost(w)
	for cand := 1; cand <= w; cand++ {
		cost := oneHotCost(cand) + oneHotCost(w-cand) + (1<<cand)*nbOut
		if cost < bestCost {
			bestCost = cost
			rb = cand
		}
	}
	rows := g2CombOneHot(g2.api, bs[:rb])
	cols := g2CombOneHot(g2.api, bs[rb:])

	tabLimbs := make([][4][]*big.Int, len(table))
	for j := range table {
		for coord := 0; coord < 4; coord++ {
			res := make([]*big.Int, nbLimbs)
			for i := range res {
				res[i] = new(big.Int)
			}
			if err := limbs.Decompose(table[j][coord], nbBits, res); err != nil {
				panic(err)
			}
			tabLimbs[j][coord] = res
		}
	}

	selLimb := func(coord, limb int) frontend.Variable {
		inner := make([]frontend.Variable, len(rows))
		for i := range rows {
			terms := make([]frontend.Variable, len(cols))
			for j := range cols {
				terms[j] = g2.api.Mul(cols[j], tabLimbs[i+(j<<rb)][coord][limb])
			}
			if len(terms) == 1 {
				inner[i] = terms[0]
			} else {
				inner[i] = g2.api.Add(terms[0], terms[1], terms[2:]...)
			}
		}
		if len(rows) == 1 {
			return inner[0]
		}
		out := make([]frontend.Variable, len(rows))
		for i := range rows {
			out[i] = g2.api.Mul(rows[i], inner[i])
		}
		return g2.api.Add(out[0], out[1], out[2:]...)
	}

	comp := func(coord int) *emulated.Element[BaseField] {
		ls := make([]frontend.Variable, nbLimbs)
		for l := 0; l < nbLimbs; l++ {
			ls[l] = selLimb(coord, l)
		}
		return g2.fp.UnsafeFromLimbs(ls)
	}
	return g2AffP{
		X: fields_bls12381.E2{A0: *comp(0), A1: *comp(1)},
		Y: fields_bls12381.E2{A0: *comp(2), A1: *comp(3)},
	}
}

// g2CombChainStep performs one incomplete chord addition of the comb chain
// with the accumulator y-coordinate kept implicit (y = λprev·(xTprev − x) −
// yTprev over E2, as in the G1 comb): the slope λ ∈ Fp² is witnessed by a
// hint and certified by two deferred zero-assertions (one per E2 component,
// with the u² = −1 cross terms), and only the two x-components are
// materialized. This costs 4 deferred checks per addition instead of ~9 for
// the DivUnchecked/Square/Mul formulation.
func (g2 *G2) g2CombChainStep(lamPrev, xAcc, xTPrev, yTPrev *fields_bls12381.E2, q *g2AffP) (lam, xNew *fields_bls12381.E2) {
	lams, err := g2.fp.NewHint(g2CombChainLambdaHint, 2,
		&lamPrev.A0, &lamPrev.A1, &xAcc.A0, &xAcc.A1,
		&xTPrev.A0, &xTPrev.A1, &yTPrev.A0, &yTPrev.A1,
		&q.X.A0, &q.X.A1, &q.Y.A0, &q.Y.A1)
	if err != nil {
		panic(fmt.Sprintf("comb chain hint: %v", err))
	}
	lam = &fields_bls12381.E2{A0: *lams[0], A1: *lams[1]}
	dxC := g2.Ext2.Sub(&q.X, xAcc)
	dxP := g2.Ext2.Sub(xTPrev, xAcc)
	// slope identity λ·(xT − x) + λprev·(xTprev − x) − yT − yTprev = 0 (E2),
	// component 0 (u² = −1):
	g2.fp.AssertEvalIsZero(
		[][]*emulated.Element[BaseField]{
			{&lam.A0, &dxC.A0}, {&lam.A1, &dxC.A1},
			{&lamPrev.A0, &dxP.A0}, {&lamPrev.A1, &dxP.A1},
			{&q.Y.A0}, {&yTPrev.A0},
		},
		[]int{1, -1, 1, -1, -1, -1},
	)
	// component 1:
	g2.fp.AssertEvalIsZero(
		[][]*emulated.Element[BaseField]{
			{&lam.A0, &dxC.A1}, {&lam.A1, &dxC.A0},
			{&lamPrev.A0, &dxP.A1}, {&lamPrev.A1, &dxP.A0},
			{&q.Y.A1}, {&yTPrev.A1},
		},
		[]int{1, 1, 1, 1, -1, -1},
	)
	// x' = λ² − x − xT componentwise: (λ0² − λ1², 2λ0λ1) − ...
	x0 := g2.fp.Eval(
		[][]*emulated.Element[BaseField]{{&lam.A0, &lam.A0}, {&lam.A1, &lam.A1}, {&xAcc.A0}, {&q.X.A0}},
		[]int{1, -1, -1, -1},
	)
	x1 := g2.fp.Eval(
		[][]*emulated.Element[BaseField]{{&lam.A0, &lam.A1}, {&xAcc.A1}, {&q.X.A1}},
		[]int{2, -1, -1},
	)
	return lam, &fields_bls12381.E2{A0: *x0, A1: *x1}
}

// g2CombTailAdd is a complete addition specialized for the comb tail. The
// table point q is finite and qDouble = 2q is selected from the matching
// constant double table. Exceptional cases are screened before the incomplete
// chord assertion and are routed to a fixed safe pair whose result is discarded.
func (g2 *G2) g2CombTailAdd(p *G2Affine, q, qDouble *g2AffP) *G2Affine {
	qAff := &G2Affine{P: *q}
	qDoubleAff := &G2Affine{P: *qDouble}

	isPInf := g2.api.And(g2.Ext2.IsZero(&p.P.X), g2.Ext2.IsZero(&p.P.Y))
	xEqual := g2.Ext2.IsZero(g2.Ext2.Sub(&q.X, &p.P.X))
	yEqual := g2.Ext2.IsZero(g2.Ext2.Sub(&q.Y, &p.P.Y))
	pFinite := g2.api.Sub(1, isPInf)
	isSame := g2.api.And(g2.api.And(xEqual, yEqual), pFinite)
	isInverse := g2.api.And(g2.api.And(xEqual, g2.api.Sub(1, yEqual)), pFinite)
	exceptional := g2.api.Or(isPInf, xEqual)

	safeP := &G2Affine{P: *g2.g2Gen}
	safeQ := &G2Affine{P: *g2.g2GenNbits}
	routedP := g2.Select(exceptional, safeP, p)
	routedQ := g2.Select(exceptional, safeQ, qAff)
	result := g2.add(routedP, routedQ)

	zero := g2.Ext2.Zero()
	infinity := &G2Affine{P: g2AffP{X: *zero, Y: *zero}}
	result = g2.Select(isSame, qDoubleAff, result)
	result = g2.Select(isInverse, infinity, result)
	result = g2.Select(isPInf, qAff, result)
	return result
}

// scalarMulComb computes [s]P for the constant base point of the tables d.
// It returns (0,0) when s ≡ 0 (mod r).
func (g2 *G2) scalarMulComb(d *g2CombData, s *Scalar) *G2Affine {
	w, n, nw, tw := d.w, d.n, d.nw, d.tw
	nbInc := nw - 1 - d.nbUnified
	rets, err := g2.fr.NewHintWithNativeOutput(g2CombRecodeHint, 1+n, s)
	if err != nil {
		panic(fmt.Sprintf("comb recode hint: %v", err))
	}
	b0 := rets[0]
	cbits := rets[1:]
	// FromBits constrains all bits (and b0) to be boolean; the single mod-r
	// assertion 2c + b0 ≡ s + 2^n pins k' = s + 1 − b0 modulo r, so the hint
	// only affects completeness.
	cEl := g2.fr.FromBits(cbits...)
	b0El := g2.fr.FromBits(b0)
	lhs := g2.fr.Add(g2.fr.MulConst(cEl, big.NewInt(2)), b0El)
	rhs := g2.fr.Add(s, g2.fr.NewElement(new(big.Int).Lsh(big.NewInt(1), uint(n))))
	g2.fr.AssertIsEqual(lhs, rhs)

	pts := make([]g2AffP, nw)
	dbls := make([]g2AffP, nw)
	for t := 0; t < nw-1; t++ {
		pts[t] = g2.g2CombSelect(d.windows[t], cbits[t*w:(t+1)*w])
		if t > nbInc {
			dbls[t] = g2.g2CombSelect(d.doubles[t], cbits[t*w:(t+1)*w])
		}
	}
	stacked := make([][4]*big.Int, 0, 2<<tw)
	stacked = append(stacked, d.topEven...)
	stacked = append(stacked, d.windows[nw-1]...)
	stackedDoubles := make([][4]*big.Int, 0, 2<<tw)
	stackedDoubles = append(stackedDoubles, d.topEvenDoubles...)
	stackedDoubles = append(stackedDoubles, d.doubles[nw-1]...)
	topBits := make([]frontend.Variable, 0, tw+1)
	topBits = append(topBits, cbits[(nw-1)*w:]...)
	topBits = append(topBits, b0)
	pts[nw-1] = g2.g2CombSelect(stacked, topBits)
	if nw-1 > nbInc {
		dbls[nw-1] = g2.g2CombSelect(stackedDoubles, topBits)
	}

	var res *G2Affine
	if nbInc >= 1 {
		// implicit-y chain: at the first step the accumulator is T_0 whose
		// y is directly available; encode it as λprev·(xTprev − x) − yTprev
		// with xTprev = x = xT0 and yTprev = −yT0, so the λprev term
		// vanishes identically for any λprev (we pass xT0 as a dummy).
		xAcc := &pts[0].X
		lamPrev := &pts[0].X
		xTPrev := &pts[0].X
		yTPrev := g2.Ext2.Neg(&pts[0].Y)
		for t := 1; t <= nbInc; t++ {
			lamPrev, xAcc = g2.g2CombChainStep(lamPrev, xAcc, xTPrev, yTPrev, &pts[t])
			xTPrev, yTPrev = &pts[t].X, &pts[t].Y
		}
		// materialize y = λprev·(xTprev − x) − yTprev once
		dy := g2.Ext2.Sub(xTPrev, xAcc)
		y0 := g2.fp.Eval(
			[][]*emulated.Element[BaseField]{{&lamPrev.A0, &dy.A0}, {&lamPrev.A1, &dy.A1}, {&yTPrev.A0}},
			[]int{1, -1, -1},
		)
		y1 := g2.fp.Eval(
			[][]*emulated.Element[BaseField]{{&lamPrev.A0, &dy.A1}, {&lamPrev.A1, &dy.A0}, {&yTPrev.A1}},
			[]int{1, 1, -1},
		)
		res = &G2Affine{P: g2AffP{X: *xAcc, Y: fields_bls12381.E2{A0: *y0, A1: *y1}}}
	} else {
		res = &G2Affine{P: pts[0]}
	}
	for t := nbInc + 1; t <= nw-1; t++ {
		res = g2.g2CombTailAdd(res, &pts[t], &dbls[t])
	}
	return res
}

// g2CombTryConst returns the comb tables when Q is a compile-time constant
// finite G2 subgroup point and the comb is supported in the current
// compilation context; otherwise ok is false.
func (g2 *G2) g2CombTryConst(Q *G2Affine) (*g2CombData, bool) {
	if smallfields.IsSmallField(g2.api.Compiler().Field()) {
		return nil, false
	}
	x0, ok := g2.fp.ConstantValue(&Q.P.X.A0)
	if !ok {
		return nil, false
	}
	x1, ok := g2.fp.ConstantValue(&Q.P.X.A1)
	if !ok {
		return nil, false
	}
	y0, ok := g2.fp.ConstantValue(&Q.P.Y.A0)
	if !ok {
		return nil, false
	}
	y1, ok := g2.fp.ConstantValue(&Q.P.Y.A1)
	if !ok {
		return nil, false
	}
	d, err := g2CombDataFor(x0, x1, y0, y1, g2.g2CombWindowFor())
	if err != nil {
		return nil, false
	}
	return d, true
}

// g2CombRecodeHint computes the comb recoding of the scalar (see the G1
// version in sw_emulated).
func g2CombRecodeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeOutput(inputs, outputs, func(r *big.Int, in, out []*big.Int) error {
		if len(in) != 1 {
			return errors.New("expecting one input")
		}
		if len(out) < 2 {
			return errors.New("expecting at least two outputs")
		}
		n := len(out) - 1
		s := new(big.Int).Mod(in[0], r)
		b0 := s.Bit(0)
		kp := new(big.Int).Set(s)
		if b0 == 0 {
			kp.Add(kp, big.NewInt(1))
		}
		cv := new(big.Int).Lsh(big.NewInt(1), uint(n))
		cv.Sub(cv, big.NewInt(1)).Add(cv, kp).Rsh(cv, 1)
		out[0].SetUint64(uint64(b0))
		for i := 0; i < n; i++ {
			out[1+i].SetUint64(uint64(cv.Bit(i)))
		}
		return nil
	})
}

// g2CombChainLambdaHint computes the chord slope of the next comb chain
// addition over Fp² (u² = −1). Inputs (component pairs): λprev, x, xTprev,
// yTprev, xT, yT. The accumulator y is recomputed in its implicit form
// y = λprev·(xTprev − x) − yTprev and the output is λ = (yT − y)/(xT − x).
func g2CombChainLambdaHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 12 || len(out) != 2 {
			return errors.New("expecting twelve inputs and two outputs")
		}
		mod := func(v *big.Int) *big.Int { return new(big.Int).Mod(v, p) }
		lamP := [2]*big.Int{mod(in[0]), mod(in[1])}
		x := [2]*big.Int{mod(in[2]), mod(in[3])}
		xTp := [2]*big.Int{mod(in[4]), mod(in[5])}
		yTp := [2]*big.Int{mod(in[6]), mod(in[7])}
		xT := [2]*big.Int{mod(in[8]), mod(in[9])}
		yT := [2]*big.Int{mod(in[10]), mod(in[11])}
		e2Sub := func(a, b [2]*big.Int) [2]*big.Int {
			return [2]*big.Int{
				new(big.Int).Mod(new(big.Int).Sub(a[0], b[0]), p),
				new(big.Int).Mod(new(big.Int).Sub(a[1], b[1]), p),
			}
		}
		e2Mul := func(a, b [2]*big.Int) [2]*big.Int {
			c0 := new(big.Int).Mul(a[0], b[0])
			c0.Sub(c0, new(big.Int).Mul(a[1], b[1])).Mod(c0, p)
			c1 := new(big.Int).Mul(a[0], b[1])
			c1.Add(c1, new(big.Int).Mul(a[1], b[0])).Mod(c1, p)
			return [2]*big.Int{c0, c1}
		}
		// y = λprev·(xTprev − x) − yTprev
		y := e2Mul(lamP, e2Sub(xTp, x))
		y = e2Sub(y, yTp)
		den := e2Sub(xT, x)
		// den⁻¹ = (den0 − den1·u)/(den0² + den1²)
		nrm := new(big.Int).Mul(den[0], den[0])
		nrm.Add(nrm, new(big.Int).Mul(den[1], den[1])).Mod(nrm, p)
		if nrm.Sign() == 0 {
			return errors.New("comb chain: x-coordinate collision")
		}
		nrm.ModInverse(nrm, p)
		inv := [2]*big.Int{
			new(big.Int).Mod(new(big.Int).Mul(den[0], nrm), p),
			new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Neg(den[1]), nrm), p),
		}
		lam := e2Mul(e2Sub(yT, y), inv)
		out[0].Set(lam[0])
		out[1].Set(lam[1])
		return nil
	})
}
