package sw_bls12377

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

// G2 variant of the fixed-base signed-digit comb (see fixedbase.go for the
// construction and soundness argument; it is identical, with coordinates in
// E2 represented by their two components). With constant tables the selection
// remains a free affine combination per component; the E2 incomplete addition
// costs more than the G1 one, so a slightly wider window is optimal.
const g2CombWindow = 3

type g2CombData struct {
	w         int
	nw        int
	n         int
	nbUnified int
	// windows[t][j] = [d(j)·2^{w·t} mod r]P as (X.A0, X.A1, Y.A0, Y.A1)
	windows [][][4]*big.Int
	// topEven[j] = [d(j)·2^{w·(nw−1)} − 1 mod r]P
	topEven [][4]*big.Int
}

var g2CombCache sync.Map

// g2CombDataFor returns the comb tables for the constant G2 point with E2
// coordinates (x0 + x1·u, y0 + y1·u). It errors when the point is not a
// finite point of the prime-order G2 subgroup.
func g2CombDataFor(x0, x1, y0, y1 *big.Int) (*g2CombData, error) {
	key := x0.Text(16) + "|" + x1.Text(16) + "|" + y0.Text(16) + "|" + y1.Text(16)
	if v, ok := g2CombCache.Load(key); ok {
		return v.(*g2CombData), nil
	}
	var P bls12377.G2Affine
	P.X.A0.SetBigInt(x0)
	P.X.A1.SetBigInt(x1)
	P.Y.A0.SetBigInt(y0)
	P.Y.A1.SetBigInt(y1)
	if P.IsInfinity() {
		return nil, errors.New("base point is the point at infinity")
	}
	if !P.IsOnCurve() {
		return nil, errors.New("base point is not on the curve")
	}
	if !P.IsInSubGroup() {
		return nil, errors.New("base point is not in the prime-order subgroup")
	}
	w := g2CombWindow
	r := fr_bls.Modulus()
	rBits := r.BitLen()
	nw := (rBits + w - 1) / w
	n := w * nw
	nbUnified := 0
	for t := nw - 1; t >= 1; t-- {
		if new(big.Int).Lsh(big.NewInt(1), uint(w*(t+1))).Cmp(r) <= 0 {
			break
		}
		nbUnified++
	}
	nbUnified = max(nbUnified, 1)

	toBig := func(a *bls12377.G2Affine) ([4]*big.Int, error) {
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

	half := 1 << (w - 1)
	windows := make([][][4]*big.Int, nw)
	var Bt bls12377.G2Jac
	Bt.FromAffine(&P)
	for t := 0; t < nw; t++ {
		if t > 0 {
			for k := 0; k < w; k++ {
				Bt.DoubleAssign()
			}
		}
		var D bls12377.G2Jac
		D.Set(&Bt).DoubleAssign()
		odd := make([]bls12377.G2Affine, half)
		acc := new(bls12377.G2Jac).Set(&Bt)
		odd[0].FromJacobian(acc)
		for m := 1; m < half; m++ {
			acc.AddAssign(&D)
			odd[m].FromJacobian(acc)
		}
		tab := make([][4]*big.Int, 1<<w)
		for j := range tab {
			d := 2*j - (1 << w) + 1
			var e bls12377.G2Affine
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
		}
		windows[t] = tab
	}
	var negP bls12377.G2Jac
	var negPAff bls12377.G2Affine
	negPAff.Neg(&P)
	negP.FromAffine(&negPAff)
	topEven := make([][4]*big.Int, 1<<w)
	for j := range topEven {
		var e bls12377.G2Affine
		e.X.A0.SetBigInt(windows[nw-1][j][0])
		e.X.A1.SetBigInt(windows[nw-1][j][1])
		e.Y.A0.SetBigInt(windows[nw-1][j][2])
		e.Y.A1.SetBigInt(windows[nw-1][j][3])
		var acc bls12377.G2Jac
		acc.FromAffine(&e)
		acc.AddAssign(&negP)
		var res bls12377.G2Affine
		res.FromJacobian(&acc)
		c, err := toBig(&res)
		if err != nil {
			return nil, fmt.Errorf("parity-fold table: %w", err)
		}
		topEven[j] = c
	}
	d := &g2CombData{
		w:         w,
		nw:        nw,
		n:         n,
		nbUnified: nbUnified,
		windows:   windows,
		topEven:   topEven,
	}
	g2CombCache.Store(key, d)
	return d, nil
}

// g2CombSelect returns the affine combination of the constant table weighted
// by the one-hot flags: constraint-free for constant coordinates.
func g2CombSelect(api frontend.API, table [][4]*big.Int, flags []frontend.Variable) g2AffP {
	comps := make([]frontend.Variable, 4)
	for c := 0; c < 4; c++ {
		acc := frontend.Variable(0)
		for j := range flags {
			acc = api.Add(acc, api.Mul(flags[j], table[j][c]))
		}
		comps[c] = acc
	}
	return g2AffP{
		X: fields_bls12377.E2{A0: comps[0], A1: comps[1]},
		Y: fields_bls12377.E2{A0: comps[2], A1: comps[3]},
	}
}

// g2CombScalarMul computes [s]P for the constant base point of the tables d.
// It returns (0,0) when s ≡ 0 (mod r). The recoding constraints force s < 2^n;
// callers that need canonical scalar encodings must separately enforce s < r.
func g2CombScalarMul(api frontend.API, d *g2CombData, s frontend.Variable) *g2AffP {
	w, n, nw := d.w, d.n, d.nw
	rets, err := api.Compiler().NewHint(g1CombRecodeHint, 1+n, s)
	if err != nil {
		panic(fmt.Sprintf("comb recode hint: %v", err))
	}
	b0 := rets[0]
	cbits := rets[1:]
	api.AssertIsBoolean(b0)
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

	pts := make([]g2AffP, nw)
	for t := 0; t < nw-1; t++ {
		flags := g1CombOneHot(api, cbits[t*w:(t+1)*w])
		pts[t] = g2CombSelect(api, d.windows[t], flags)
	}
	stacked := make([][4]*big.Int, 0, 2<<w)
	stacked = append(stacked, d.topEven...)
	stacked = append(stacked, d.windows[nw-1]...)
	topBits := make([]frontend.Variable, 0, w+1)
	topBits = append(topBits, cbits[(nw-1)*w:]...)
	topBits = append(topBits, b0)
	topFlags := g1CombOneHot(api, topBits)
	pts[nw-1] = g2CombSelect(api, stacked, topFlags)

	nbInc := nw - 1 - d.nbUnified
	acc := pts[0]
	for t := 1; t <= nbInc; t++ {
		acc.AddAssign(api, pts[t])
	}
	for t := nbInc + 1; t <= nw-1; t++ {
		acc.AddUnified(api, pts[t])
	}
	return &acc
}
