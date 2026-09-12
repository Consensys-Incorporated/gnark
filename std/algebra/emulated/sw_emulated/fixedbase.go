package sw_emulated

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
)

// This file implements a fixed-base scalar multiplication using a signed-digit
// comb method with compile-time constant window tables.
//
// The scalar s is recoded into an odd integer k' = s + 1 − b0 (b0 the parity
// of s) represented in signed binary digits d_i ∈ {−1, +1}:
//
//	k' = Σ_{i<n} d_i·2^i,   d_i = 2c_i − 1,   c = (k' + 2^n − 1)/2.
//
// The digits are grouped into nw windows: the lower windows have w bits and
// the top window may be narrower. Every window value
// d(j) = Σ_i (2j_i − 1)·2^i is a non-zero odd integer, so the window points
// [d(j)·2^{w·t}]G are precomputed constants which are never the point at
// infinity, and the running partial sums [m_t]G are always odd non-zero
// multiples of G. This makes the incomplete (chord) addition formulas
// provably complete for all windows t where the covered scalar range is below
// r: an x-coordinate collision would need m ≡ ±v·2^{w·t} (mod r) with
// |m ∓ v·2^{w·t}| < r and m ∓ v·2^{w·t} odd, which is impossible. Only the
// last addition(s) use the complete [Curve.AddUnified] formulas.
//
// The −(1−b0) parity correction is folded into the top window: when the
// scalar is even, the top window selects from the shifted constant table
// [d(j)·2^{w·(nw−1)} − 1]G instead, so that the comb always outputs [s]G with
// a single final (complete) addition and no separate correction step.
//
// The chain of incomplete additions carries the accumulator's y-coordinate
// implicitly: after adding the window point T = (xT, yT) with slope λ, the new
// y-coordinate is y = λ·(xT − x) − yT, which is a degree-1 expression in
// already-materialized values. Instead of materializing y at every step, the
// next step's slope λ' is witnessed by a hint and pinned by the single
// multivariate zero-assertion
//
//	λ'·(xT' − x) + λ·(xT − x) − yT' − yT = 0
//
// which costs one deferred evaluation check instead of a division (two
// checks) plus a y materialization (one check). The y-coordinate is
// materialized once, before the final complete addition.

// combDefaultWindow is the default window width of the fixed-base comb. With
// 64-bit limb emulation it is supported by all built-in curves (the recoded
// scalar fits the scalar-field limb capacity) and is close to the
// constraint-count optimum in R1CS.
const combDefaultWindow = 8

// combPlonkWindow is the window width used on PLONKish backends. The one-hot
// selection's wide constant linear combinations are free in R1CS but expand
// into one addition gate per term in PLONK, making the selector cost scale
// with 2^w·nbLimbs per window; a smaller window rebalances selector versus
// chain-addition cost. With a partial top window, w=5 is the current SCS
// optimum measured on secp256k1.
const combPlonkWindow = 5

// combWindow returns the comb window width for the current backend.
func (c *Curve[B, S]) combWindow() int {
	if _, ok := c.api.Compiler().(frontend.PlonkAPI); ok {
		return combPlonkWindow
	}
	return combDefaultWindow
}

// combData holds the compile-time data of the comb: the constant window
// tables and the derived parameters.
type combData struct {
	w  int // window width in bits
	nw int // number of windows
	n  int // number of recoded signed digits, n = bitlen(r)
	tw int // width of the top window, in bits
	// nbUnified is the number of trailing window additions which must use the
	// complete addition formulas.
	nbUnified int
	// windows[t][j] is the affine point [d(j)·2^{w·t} mod r]G. For the lower
	// windows d(j) = 2j − 2^w + 1; for the top window w is replaced by tw.
	windows [][][2]*big.Int
	// topEven[j] is [d(j)·2^{w·(nw−1)} − 1 mod r]G: the parity-folded top
	// window table selected when the scalar is even.
	topEven [][2]*big.Int
}

// combAffine is a non-infinity affine point used during compile-time table
// computation.
type combAffine struct {
	x, y *big.Int
}

func combNeg(p *combAffine, prime *big.Int) *combAffine {
	return &combAffine{x: p.x, y: new(big.Int).Sub(prime, p.y)}
}

// combAdd adds two distinct-x points. Returns an error on an x-coordinate
// collision (doubling or cancellation), which the caller treats as an
// unsupported curve/window combination.
func combAdd(p, q *combAffine, prime *big.Int) (*combAffine, error) {
	dx := new(big.Int).Sub(q.x, p.x)
	dx.Mod(dx, prime)
	if dx.Sign() == 0 {
		return nil, errors.New("x-coordinate collision in comb table computation")
	}
	dx.ModInverse(dx, prime)
	lam := new(big.Int).Sub(q.y, p.y)
	lam.Mul(lam, dx).Mod(lam, prime)
	xr := new(big.Int).Mul(lam, lam)
	xr.Sub(xr, p.x).Sub(xr, q.x).Mod(xr, prime)
	yr := new(big.Int).Sub(p.x, xr)
	yr.Mul(yr, lam).Sub(yr, p.y).Mod(yr, prime)
	return &combAffine{x: xr, y: yr}, nil
}

// combDouble doubles a point on y² = x³ + ax + b. Returns an error when the
// point is 2-torsion (never the case on the supported prime-order curves).
func combDouble(p *combAffine, a, prime *big.Int) (*combAffine, error) {
	if p.y.Sign() == 0 {
		return nil, errors.New("doubling a 2-torsion point in comb table computation")
	}
	den := new(big.Int).Lsh(p.y, 1)
	den.Mod(den, prime)
	den.ModInverse(den, prime)
	lam := new(big.Int).Mul(p.x, p.x)
	lam.Mul(lam, big.NewInt(3))
	if a != nil && a.Sign() != 0 {
		lam.Add(lam, a)
	}
	lam.Mul(lam, den).Mod(lam, prime)
	xr := new(big.Int).Mul(lam, lam)
	xr.Sub(xr, p.x).Sub(xr, p.x).Mod(xr, prime)
	yr := new(big.Int).Sub(p.x, xr)
	yr.Mul(yr, lam).Sub(yr, p.y).Mod(yr, prime)
	return &combAffine{x: xr, y: yr}, nil
}

// combCheckPoint checks that the base point (gx, gy) is a finite point on the
// curve y² = x³ + ax + b of prime order r: it verifies the curve equation and
// that [r−1](gx, gy) = −(gx, gy). Both are required for the comb soundness
// argument: the window tables must contain no point at infinity and the
// partial-sum collision analysis works modulo the order of the base point.
func combCheckPoint(gx, gy, a, b, prime, r *big.Int) error {
	if gx.Sign() == 0 && gy.Sign() == 0 {
		return errors.New("base point is the point at infinity")
	}
	lhs := new(big.Int).Mul(gy, gy)
	lhs.Mod(lhs, prime)
	rhs := new(big.Int).Mul(gx, gx)
	rhs.Mul(rhs, gx)
	if a != nil && a.Sign() != 0 {
		rhs.Add(rhs, new(big.Int).Mul(a, gx))
	}
	if b != nil {
		rhs.Add(rhs, b)
	}
	rhs.Mod(rhs, prime)
	if lhs.Cmp(rhs) != 0 {
		return errors.New("base point is not on the curve")
	}
	// check [r−1]P = −P by double-and-add. The intermediate partial sums are
	// [m]P with 0 < m < r−1, so if ord(P) = r the chain never encounters the
	// point at infinity nor an x-collision; conversely any such failure means
	// ord(P) ≠ r and we reject.
	P := &combAffine{x: gx, y: gy}
	e := new(big.Int).Sub(r, big.NewInt(1))
	acc := P
	var err error
	for i := e.BitLen() - 2; i >= 0; i-- {
		if acc, err = combDouble(acc, a, prime); err != nil {
			return fmt.Errorf("base point order check: %w", err)
		}
		if e.Bit(i) == 1 {
			if acc, err = combAdd(acc, P, prime); err != nil {
				return fmt.Errorf("base point order check: %w", err)
			}
		}
	}
	negP := combNeg(P, prime)
	if acc.x.Cmp(negP.x) != 0 || acc.y.Cmp(negP.y) != 0 {
		return errors.New("base point does not have prime order r")
	}
	return nil
}

// computeCombData computes the comb tables for the curve y² = x³ + ax + b
// over the prime field of modulus prime, with base point (gx, gy) of prime
// order r, window width w and a recoded-scalar capacity of scalarCap bits
// (the recomposition capacity of the scalar field emulation).
func computeCombData(gx, gy, a, b, prime, r *big.Int, w int, scalarCap int) (*combData, error) {
	if w < 2 || w > 14 {
		return nil, fmt.Errorf("unsupported window width %d", w)
	}
	if err := combCheckPoint(gx, gy, a, b, prime, r); err != nil {
		return nil, err
	}
	rBits := r.BitLen()
	nw := (rBits + w - 1) / w
	if nw < 2 {
		return nil, fmt.Errorf("window width %d too large for %d-bit scalar field", w, rBits)
	}
	n := rBits
	if n > scalarCap {
		return nil, fmt.Errorf("recoded scalar needs %d bits, scalar field emulation has capacity %d", n, scalarCap)
	}
	tw := n - w*(nw-1)
	// Adding window t (t ≥ 1) with incomplete formulas is safe iff the absolute
	// value of every running sum is below r. For a partial top window this
	// bound is 2^n on the top window and 2^{w·(t+1)} otherwise. The final
	// addition is always complete as it may cancel to the point at infinity or
	// double.
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

	G := &combAffine{x: new(big.Int).Set(gx), y: new(big.Int).Set(gy)}
	windows := make([][][2]*big.Int, nw)
	Bt := G
	var err error
	for t := 0; t < nw; t++ {
		if t > 0 {
			for k := 0; k < w; k++ {
				if Bt, err = combDouble(Bt, a, prime); err != nil {
					return nil, err
				}
			}
		}
		tw := w
		if t == nw-1 {
			tw = n - w*(nw-1)
		}
		// odd multiples odd[m] = [(2m+1)·2^{w·t}]G
		D, err := combDouble(Bt, a, prime)
		if err != nil {
			return nil, err
		}
		half := 1 << (tw - 1)
		odd := make([]*combAffine, half)
		odd[0] = Bt
		for m := 1; m < half; m++ {
			if odd[m], err = combAdd(odd[m-1], D, prime); err != nil {
				return nil, err
			}
		}
		tab := make([][2]*big.Int, 1<<tw)
		for j := range tab {
			d := 2*j - (1 << tw) + 1
			var pt *combAffine
			if d > 0 {
				pt = odd[(d-1)/2]
			} else {
				pt = combNeg(odd[(-d-1)/2], prime)
			}
			tab[j] = [2]*big.Int{pt.x, pt.y}
		}
		windows[t] = tab
	}
	// parity-folded top window: topEven[j] = windows[nw−1][j] + (−G)
	negG := combNeg(G, prime)
	topEven := make([][2]*big.Int, 1<<tw)
	for j := range topEven {
		q := &combAffine{x: windows[nw-1][j][0], y: windows[nw-1][j][1]}
		s, err := combAdd(q, negG, prime)
		if err != nil {
			return nil, fmt.Errorf("parity-fold table: %w", err)
		}
		topEven[j] = [2]*big.Int{s.x, s.y}
	}
	return &combData{
		w:         w,
		nw:        nw,
		n:         n,
		tw:        tw,
		nbUnified: nbUnified,
		windows:   windows,
		topEven:   topEven,
	}, nil
}

// combData returns the (cached) comb tables for the generator and the given
// window width.
func (c *Curve[B, S]) combData(w int) (*combData, error) {
	return c.combDataFor(c.params.Gx, c.params.Gy, w)
}

// combDataFor returns the (cached) comb tables for the given constant base
// point and window width. It returns an error when the tables cannot be
// constructed: unsupported window width, recoded scalar exceeding the scalar
// field emulation capacity, or a base point which is not a finite curve point
// of prime order r.
func (c *Curve[B, S]) combDataFor(gx, gy *big.Int, w int) (*combData, error) {
	if smallfields.IsSmallField(c.api.Compiler().Field()) {
		// in small-field mode the emulated field instance uses a different
		// limb layout than the static field parameters which the comb
		// selector and recode assume; fall back to the generic methods.
		return nil, errors.New("fixed-base comb unsupported over small fields")
	}
	key := fmt.Sprintf("%d|%s|%s", w, gx.Text(16), gy.Text(16))
	if d, ok := c.combCache[key]; ok {
		return d, nil
	}
	var fp B
	var fr S
	d, err := computeCombData(gx, gy, c.params.A, c.params.B, fp.Modulus(), fr.Modulus(), w, int(fr.NbLimbs()*fr.BitsPerLimb()))
	if err != nil {
		return nil, err
	}
	if c.combCache == nil {
		c.combCache = make(map[string]*combData)
	}
	c.combCache[key] = d
	return d, nil
}

// oneHot returns the 2^len(bs) one-hot indicator vector of the little-endian
// bit vector bs: exactly the entry at index Σ bs_i·2^i is 1 and all others are
// 0. The construction guarantees the one-hot property whenever the inputs are
// boolean. It costs 2^len(bs) − 2 multiplications.
func oneHot(api frontend.API, bs []frontend.Variable) []frontend.Variable {
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

// combSelect selects the table entry indexed by the little-endian bit vector
// bs and returns it as a pair of base field elements. The table entries are
// compile-time constants, so every selected limb is a convex combination of
// constant limbs weighted by a one-hot vector and needs no range check.
//
// The index bits are split into rb low "row" bits and len(bs)−rb high
// "column" bits. The column one-hot combines with the constant limbs into
// free affine forms, and each output limb is the rows-weighted sum of those
// forms, costing 2^rb multiplications per limb. rb is chosen to minimize the
// total multiplication count; rb = 0 degenerates to a materialized full
// one-hot with free affine selection.
func (c *Curve[B, S]) combSelect(table [][2]*big.Int, bs []frontend.Variable) (x, y *emulated.Element[B]) {
	var fp B
	nbLimbs := int(fp.NbLimbs())
	nbBits := fp.BitsPerLimb()
	w := len(bs)
	if len(table) != 1<<w {
		panic("table size mismatch")
	}
	nbOut := 2 * nbLimbs
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
	rows := oneHot(c.api, bs[:rb])
	cols := oneHot(c.api, bs[rb:])

	// tabLimbs[j][coord] holds the constant limbs of table entry j
	tabLimbs := make([][2][]*big.Int, len(table))
	for j := range table {
		for coord := 0; coord < 2; coord++ {
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
				cst := tabLimbs[i+(j<<rb)][coord][limb]
				terms[j] = c.api.Mul(cols[j], cst)
			}
			if len(terms) == 1 {
				inner[i] = terms[0]
			} else {
				inner[i] = c.api.Add(terms[0], terms[1], terms[2:]...)
			}
		}
		if len(rows) == 1 {
			// rb = 0: the column one-hot covers the whole index and the
			// selection is a free affine combination.
			return inner[0]
		}
		out := make([]frontend.Variable, len(rows))
		for i := range rows {
			out[i] = c.api.Mul(rows[i], inner[i])
		}
		return c.api.Add(out[0], out[1], out[2:]...)
	}

	xLimbs := make([]frontend.Variable, nbLimbs)
	yLimbs := make([]frontend.Variable, nbLimbs)
	for l := 0; l < nbLimbs; l++ {
		xLimbs[l] = selLimb(0, l)
		yLimbs[l] = selLimb(1, l)
	}
	return c.baseApi.UnsafeFromLimbs(xLimbs), c.baseApi.UnsafeFromLimbs(yLimbs)
}

// scalarMulBaseComb computes [s]G for the fixed generator G using the
// signed-digit comb method with window width w. It returns (0,0) when
// s ≡ 0 (mod r). See the package comment at the top of this file for the
// algorithm and its soundness argument.
func (c *Curve[B, S]) scalarMulBaseComb(s *emulated.Element[S], w int) *AffinePoint[B] {
	d, err := c.combData(w)
	if err != nil {
		panic(fmt.Sprintf("comb data: %v", err))
	}
	return c.scalarMulComb(d, s)
}

// scalarMulComb computes [s]P where P is the compile-time constant base point
// of the comb tables d. It returns (0,0) when s ≡ 0 (mod r).
func (c *Curve[B, S]) scalarMulComb(d *combData, s *emulated.Element[S]) *AffinePoint[B] {
	w := d.w
	n, nw, tw := d.n, d.nw, d.tw

	// scalar recode: b0 = parity of s, c = (k' + 2^n − 1)/2 with
	// k' = s + 1 − b0.
	rets, err := c.scalarApi.NewHintWithNativeOutput(combRecodeHint, 1+n, s)
	if err != nil {
		panic(fmt.Sprintf("recode hint: %v", err))
	}
	b0 := rets[0]
	cbits := rets[1:]
	// FromBits constrains all bits (and b0) to be boolean.
	cEl := c.scalarApi.FromBits(cbits...)
	b0El := c.scalarApi.FromBits(b0)
	// The single scalar-field assertion 2c + b0 ≡ s + 2^n (mod r) pins
	// k' := 2c − (2^n − 1) ≡ s + 1 − b0 (mod r). The comb below computes
	// [k' − (1−b0)]G ≡ [s]G, so the hint values only affect completeness,
	// not soundness.
	lhs := c.scalarApi.Add(c.scalarApi.MulConst(cEl, big.NewInt(2)), b0El)
	rhs := c.scalarApi.Add(s, c.scalarApi.NewElement(new(big.Int).Lsh(big.NewInt(1), uint(n))))
	c.scalarApi.AssertIsEqual(lhs, rhs)

	// select the window points
	xT := make([]*emulated.Element[B], nw)
	yT := make([]*emulated.Element[B], nw)
	for t := 0; t < nw-1; t++ {
		xT[t], yT[t] = c.combSelect(d.windows[t], cbits[t*w:(t+1)*w])
	}
	// top window with the parity fold: b0 acts as an extra index bit
	// selecting between the even-scalar table (with the −G correction folded
	// in) and the regular table.
	stacked := make([][2]*big.Int, 0, 2<<tw)
	stacked = append(stacked, d.topEven...)
	stacked = append(stacked, d.windows[nw-1]...)
	topBits := make([]frontend.Variable, 0, tw+1)
	topBits = append(topBits, cbits[(nw-1)*w:]...)
	topBits = append(topBits, b0)
	xT[nw-1], yT[nw-1] = c.combSelect(stacked, topBits)

	// chain of incomplete additions with implicit y
	nbInc := nw - 1 - d.nbUnified
	xAcc := xT[0]
	var lamPrev, xTPrev, yTPrev *emulated.Element[B]
	for t := 1; t <= nbInc; t++ {
		lamPrevIn, xTPrevIn, yTPrevIn := lamPrev, xTPrev, yTPrev
		if t == 1 {
			// The accumulator starts at T_0, whose y-coordinate is directly
			// available: encode it in the implicit form
			// λprev·(xTprev − x) − yTprev with xTprev = x = xT0 and
			// yTprev = −yT0, so that the λprev term vanishes identically
			// (both in the hint and in the assertion) for ANY λprev value.
			// We pass xT0 as a dummy λprev to avoid a zero-limb constant.
			lamPrevIn, xTPrevIn, yTPrevIn = xT[0], xT[0], c.baseApi.Neg(yT[0])
		}
		lams, err := c.baseApi.NewHint(combChainLambdaHint, 1, lamPrevIn, xAcc, xTPrevIn, yTPrevIn, xT[t], yT[t])
		if err != nil {
			panic(fmt.Sprintf("chain hint: %v", err))
		}
		lam := lams[0]
		dxCur := c.baseApi.Sub(xT[t], xAcc)
		// slope assertion λ·(xT − x) − yT + y = 0 with the accumulator y in
		// implicit form y = λprev·(xTprev − x) − yTprev. It pins λ uniquely
		// as xT − x ≠ 0 for all valid assignments (see the completeness
		// argument in the package comment).
		dxPrev := c.baseApi.Sub(xTPrevIn, xAcc)
		c.baseApi.AssertEvalIsZero(
			[][]*emulated.Element[B]{{lam, dxCur}, {lamPrevIn, dxPrev}, {yT[t]}, {yTPrevIn}},
			[]int{1, 1, -1, -1},
		)
		// x' = λ² − x − xT
		xAcc = c.baseApi.Eval([][]*emulated.Element[B]{{lam, lam}, {xAcc}, {xT[t]}}, []int{1, -1, -1})
		lamPrev, xTPrev, yTPrev = lam, xT[t], yT[t]
	}

	// materialize the accumulator y and finish with complete additions
	var acc *AffinePoint[B]
	if nbInc >= 1 {
		yAcc := c.baseApi.Eval([][]*emulated.Element[B]{{lamPrev, c.baseApi.Sub(xTPrev, xAcc)}, {yTPrev}}, []int{1, -1})
		acc = &AffinePoint[B]{X: *xAcc, Y: *yAcc}
	} else {
		acc = &AffinePoint[B]{X: *xT[0], Y: *yT[0]}
	}
	for t := nbInc + 1; t <= nw-1; t++ {
		acc = c.AddUnified(acc, &AffinePoint[B]{X: *xT[t], Y: *yT[t]})
	}
	return acc
}

// combRecodeHint computes the comb recoding of the scalar: given the scalar s
// (nonnative), it returns as native outputs the parity bit b0 = s mod 2
// followed by the n bits of c = (k' + 2^n − 1)/2 where k' = s + 1 − b0 and n
// is the number of signed digits (inferred from the output count).
func combRecodeHint(_ *big.Int, inputs, outputs []*big.Int) error {
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
		// c = (k' + 2^n − 1)/2
		cv := new(big.Int).Lsh(big.NewInt(1), uint(n))
		cv.Sub(cv, big.NewInt(1)).Add(cv, kp).Rsh(cv, 1)
		out[0].SetUint64(uint64(b0))
		for i := 0; i < n; i++ {
			out[1+i].SetUint64(uint64(cv.Bit(i)))
		}
		return nil
	})
}

// combChainLambdaHint computes the chord slope of the next comb chain
// addition. Inputs (nonnative, base field): λprev, x (the accumulator
// x-coordinate), xTprev, yTprev (the previously added table point), xT, yT
// (the table point being added). The accumulator y-coordinate is recomputed
// in its implicit form y = λprev·(xTprev − x) − yTprev and the output is
// λ = (yT − y) / (xT − x).
func combChainLambdaHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 6 {
			return errors.New("expecting six inputs")
		}
		if len(out) != 1 {
			return errors.New("expecting one output")
		}
		lamPrev, x, xTPrev, yTPrev, xT, yT := in[0], in[1], in[2], in[3], in[4], in[5]
		y := new(big.Int).Sub(xTPrev, x)
		y.Mul(y, lamPrev).Sub(y, yTPrev).Mod(y, p)
		den := new(big.Int).Sub(xT, x)
		den.Mod(den, p)
		if den.Sign() == 0 {
			return errors.New("comb chain: x-coordinate collision")
		}
		den.ModInverse(den, p)
		out[0].Sub(yT, y).Mul(out[0], den).Mod(out[0], p)
		return nil
	})
}
