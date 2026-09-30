package sw_bls12377

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
)

// This file implements a fixed-base scalar multiplication for compile-time
// constant G1 points using a signed-digit comb method, following the same
// construction as the emulated sw_emulated comb (see the package comment
// there for the algorithm and soundness argument):
//
//   - the scalar is recoded into the odd k' = s + 1 − b0 represented by n
//     signed binary digits, witnessed as the bits of c = (k' + 2^n − 1)/2 and
//     pinned by the exact native identity 2c + b0 = s + 2^n. The top bit of c
//     is constrained to 1, proving 2c + b0 ≥ 2^n and excluding native-field
//     wrap-around;
//   - windows of w digits select from compile-time constant tables
//     [d(j)·2^{w·t}]P. With constant tables the selection is a free affine
//     combination of the one-hot flags, so only the flag products cost
//     constraints;
//   - the parity correction −(1−b0) is folded into the top window table;
//   - all partial sums are odd non-zero multiples of P, so the chain uses the
//     incomplete AddAssign (3 constraints) except for the final complete
//     AddUnified addition(s).
//
// In the native setting a small window width is optimal: the incomplete
// addition costs only 3 constraints, so wide windows are dominated by the
// one-hot flag products. With w = 2 the flags cost 2 constraints per window.
const g1CombWindow = 2

type g1CombData struct {
	w         int
	nw        int
	n         int
	nbUnified int
	// windows[t][j] = [d(j)·2^{w·t} mod r]P with d(j) = 2j − 2^w + 1,
	// coordinates as big.Int
	windows [][][2]*big.Int
	// topEven[j] = [d(j)·2^{w·(nw−1)} − 1 mod r]P
	topEven [][2]*big.Int
}

// g1CombCache caches tables per constant base point. Keyed by the hex
// coordinates; access is concurrent-safe as circuits may compile in parallel.
var g1CombCache sync.Map

// g1CombDataFor returns the comb tables for the constant point (gx, gy). It
// errors when the point is not a finite G1 (prime-order subgroup) point, in
// which case callers fall back to the generic scalar multiplication.
func g1CombDataFor(gx, gy *big.Int) (*g1CombData, error) {
	key := gx.Text(16) + "|" + gy.Text(16)
	if v, ok := g1CombCache.Load(key); ok {
		return v.(*g1CombData), nil
	}
	var P bls12377.G1Affine
	P.X.SetBigInt(gx)
	P.Y.SetBigInt(gy)
	if P.IsInfinity() {
		return nil, errors.New("base point is the point at infinity")
	}
	if !P.IsOnCurve() {
		return nil, errors.New("base point is not on the curve")
	}
	if !P.IsInSubGroup() {
		return nil, errors.New("base point is not in the prime-order subgroup")
	}
	w := g1CombWindow
	r := fr_bls.Modulus()
	rBits := r.BitLen()
	nw := (rBits + w - 1) / w
	n := w * nw
	// adding window t (t ≥ 1) with incomplete formulas is safe iff
	// 2^{w·(t+1)} ≤ r; the final addition is always complete.
	nbUnified := 0
	for t := nw - 1; t >= 1; t-- {
		if new(big.Int).Lsh(big.NewInt(1), uint(w*(t+1))).Cmp(r) <= 0 {
			break
		}
		nbUnified++
	}
	nbUnified = max(nbUnified, 1)

	toBig := func(a *bls12377.G1Affine) [2]*big.Int {
		if a.IsInfinity() {
			// cannot happen for r > 2^w (window digits are odd non-zero and
			// small), but guard anyway
			return [2]*big.Int{nil, nil}
		}
		return [2]*big.Int{a.X.BigInt(new(big.Int)), a.Y.BigInt(new(big.Int))}
	}

	half := 1 << (w - 1)
	windows := make([][][2]*big.Int, nw)
	var Bt bls12377.G1Jac
	Bt.FromAffine(&P)
	for t := 0; t < nw; t++ {
		if t > 0 {
			for k := 0; k < w; k++ {
				Bt.DoubleAssign()
			}
		}
		var D bls12377.G1Jac
		D.Set(&Bt).DoubleAssign()
		odd := make([]bls12377.G1Affine, half)
		acc := new(bls12377.G1Jac).Set(&Bt)
		odd[0].FromJacobian(acc)
		for m := 1; m < half; m++ {
			acc.AddAssign(&D)
			odd[m].FromJacobian(acc)
		}
		tab := make([][2]*big.Int, 1<<w)
		for j := range tab {
			d := 2*j - (1 << w) + 1
			var e bls12377.G1Affine
			if d > 0 {
				e = odd[(d-1)/2]
			} else {
				e.Neg(&odd[(-d-1)/2])
			}
			c := toBig(&e)
			if c[0] == nil {
				return nil, errors.New("unexpected point at infinity in comb table")
			}
			tab[j] = c
		}
		windows[t] = tab
	}
	// parity-folded top window: topEven[j] = windows[nw−1][j] + (−P)
	var negP bls12377.G1Jac
	var negPAff bls12377.G1Affine
	negPAff.Neg(&P)
	negP.FromAffine(&negPAff)
	topEven := make([][2]*big.Int, 1<<w)
	for j := range topEven {
		var e bls12377.G1Affine
		e.X.SetBigInt(windows[nw-1][j][0])
		e.Y.SetBigInt(windows[nw-1][j][1])
		var acc bls12377.G1Jac
		acc.FromAffine(&e)
		acc.AddAssign(&negP)
		var res bls12377.G1Affine
		res.FromJacobian(&acc)
		c := toBig(&res)
		if c[0] == nil {
			return nil, errors.New("point at infinity in parity-fold table")
		}
		topEven[j] = c
	}
	d := &g1CombData{
		w:         w,
		nw:        nw,
		n:         n,
		nbUnified: nbUnified,
		windows:   windows,
		topEven:   topEven,
	}
	g1CombCache.Store(key, d)
	return d, nil
}

// g1CombOneHot returns the 2^len(bs) one-hot indicator vector of the
// little-endian boolean bits bs, costing 2^len(bs) − 2 constraints.
func g1CombOneHot(api frontend.API, bs []frontend.Variable) []frontend.Variable {
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

// g1CombSelect returns the affine combination of the constant table weighted
// by the one-hot flags: with constant coordinates this is constraint-free.
func g1CombSelect(api frontend.API, table [][2]*big.Int, flags []frontend.Variable) (x, y frontend.Variable) {
	x = frontend.Variable(0)
	y = frontend.Variable(0)
	for j := range flags {
		x = api.Add(x, api.Mul(flags[j], table[j][0]))
		y = api.Add(y, api.Mul(flags[j], table[j][1]))
	}
	return x, y
}

// g1CombScalarMul computes [s]P for the constant base point of the tables d.
// It returns (0,0) when s ≡ 0 (mod r). The recoding constraints force s < 2^n;
// callers that need canonical scalar encodings must separately enforce s < r.
func g1CombScalarMul(api frontend.API, d *g1CombData, s frontend.Variable) *G1Affine {
	w, n, nw := d.w, d.n, d.nw
	rets, err := api.Compiler().NewHint(g1CombRecodeHint, 1+n, s)
	if err != nil {
		panic(fmt.Sprintf("comb recode hint: %v", err))
	}
	b0 := rets[0]
	cbits := rets[1:]
	api.AssertIsBoolean(b0)
	// The top bit of c proves 2c+b0 ≥ 2^n. Since 2c+b0 < 2^{n+1}
	// and 2^{n+1} is far below the native modulus, the equality below cannot
	// be satisfied by a wrapped s+2^n value. It therefore holds over the
	// integers and pins k' = 2c − (2^n − 1) = s + 1 − b0.
	cSum := frontend.Variable(0)
	coef := big.NewInt(2)
	for i := range cbits {
		api.AssertIsBoolean(cbits[i])
		cSum = api.Add(cSum, api.Mul(cbits[i], new(big.Int).Set(coef)))
		coef.Lsh(coef, 1)
	}
	api.AssertIsEqual(cbits[n-1], 1)
	twoN := new(big.Int).Lsh(big.NewInt(1), uint(n))
	api.AssertIsEqual(api.Add(cSum, b0), api.Add(s, twoN))

	// window selections (free affine combinations of the one-hot flags)
	xT := make([]frontend.Variable, nw)
	yT := make([]frontend.Variable, nw)
	for t := 0; t < nw-1; t++ {
		flags := g1CombOneHot(api, cbits[t*w:(t+1)*w])
		xT[t], yT[t] = g1CombSelect(api, d.windows[t], flags)
	}
	// top window with the parity fold: b0 selects between the even-scalar
	// table (with the −P correction folded in) and the regular table.
	stacked := make([][2]*big.Int, 0, 2<<w)
	stacked = append(stacked, d.topEven...)
	stacked = append(stacked, d.windows[nw-1]...)
	topBits := make([]frontend.Variable, 0, w+1)
	topBits = append(topBits, cbits[(nw-1)*w:]...)
	topBits = append(topBits, b0)
	topFlags := g1CombOneHot(api, topBits)
	xT[nw-1], yT[nw-1] = g1CombSelect(api, stacked, topFlags)

	// chain: incomplete additions (provably collision-free), complete tail
	nbInc := nw - 1 - d.nbUnified
	acc := G1Affine{X: xT[0], Y: yT[0]}
	for t := 1; t <= nbInc; t++ {
		acc.AddAssign(api, G1Affine{X: xT[t], Y: yT[t]})
	}
	for t := nbInc + 1; t <= nw-1; t++ {
		acc.AddUnified(api, G1Affine{X: xT[t], Y: yT[t]})
	}
	return &acc
}

// g1CombRecodeHint computes the comb recoding: given the scalar s (reduced),
// it returns b0 = s mod 2 followed by the n bits of c = (k' + 2^n − 1)/2
// where k' = s + 1 − b0 and n is inferred from the output count.
func g1CombRecodeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one input")
	}
	if len(outputs) < 2 {
		return errors.New("expecting at least two outputs")
	}
	n := len(outputs) - 1
	s := inputs[0]
	b0 := s.Bit(0)
	kp := new(big.Int).Set(s)
	if b0 == 0 {
		kp.Add(kp, big.NewInt(1))
	}
	cv := new(big.Int).Lsh(big.NewInt(1), uint(n))
	cv.Sub(cv, big.NewInt(1)).Add(cv, kp).Rsh(cv, 1)
	outputs[0].SetUint64(uint64(b0))
	for i := 0; i < n; i++ {
		outputs[1+i].SetUint64(uint64(cv.Bit(i)))
	}
	return nil
}
