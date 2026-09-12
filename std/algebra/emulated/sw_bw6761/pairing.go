package sw_bw6761

import (
	"errors"
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bw6761.Ext6
	curveF       *emulated.Field[BaseField]
	curve        *sw_emulated.Curve[BaseField, ScalarField]
	g1           *G1
	g2           *G2
	thirdRootOne *emulated.Element[BaseField]
}

type GTEl = fields_bw6761.E6
type baseEl = emulated.Element[BaseField]

func NewGTEl(v bw6761.GT) GTEl {
	return GTEl{
		A0: emulated.ValueOf[BaseField](v.B0.A0),
		A1: emulated.ValueOf[BaseField](v.B1.A0),
		A2: emulated.ValueOf[BaseField](v.B0.A1),
		A3: emulated.ValueOf[BaseField](v.B1.A1),
		A4: emulated.ValueOf[BaseField](v.B0.A2),
		A5: emulated.ValueOf[BaseField](v.B1.A2),
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBW6761Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	g1, err := NewG1(api)
	if err != nil {
		return nil, fmt.Errorf("new G1 struct: %w", err)
	}
	g2, err := NewG2(api)
	if err != nil {
		return nil, fmt.Errorf("new G2 struct: %w", err)
	}
	// thirdRootOne² + thirdRootOne + 1 = 0 in BW6761Fp
	thirdRootOne := ba.NewElement("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	return &Pairing{
		api:          api,
		Ext6:         fields_bw6761.NewExt6(api),
		curveF:       ba,
		curve:        curve,
		g1:           g1,
		g2:           g2,
		thirdRootOne: thirdRootOne,
	}, nil
}

// FinalExponentiation computes the exponentiation zᵈ where
//
// d = (p⁶-1)/r = (p⁶-1)/Φ₆(p) ⋅ Φ₆(p)/r = (p³-1)(p+1)(p²-p+1)/r
//
// we use instead d = s⋅(p³-1)(p+1)(p²-p+1)/r
// where s is the cofactor (x₀+1)
func (pr *Pairing) FinalExponentiation(z *GTEl) *GTEl {

	z = pr.Reduce(z)
	result := pr.Copy(z)

	// 1. Easy part
	// (p³-1)(p+1)
	// buf = conj(result)·result⁻¹. Using Inverse (which constrains
	// result·result⁻¹ == 1) rather than DivUnchecked rejects a witness GT equal
	// to 0: a plain DivUnchecked(conj(0), 0) only enforces q·0 == 0 and leaves
	// the quotient free, letting a prover prove FinalExponentiation(0) == 1.
	buf := pr.Conjugate(result)
	buf = pr.Mul(buf, pr.Inverse(result))
	result = pr.Frobenius(buf)
	result = pr.Mul(result, buf)

	// 2. Hard part (up to permutation)
	// (x₀+1)(p²-p+1)/r
	// Algorithm 4.4 from https://yelhousni.github.io/phd.pdf
	a := pr.ExpX0Minus1Square(result)
	a = pr.Mul(a, pr.Frobenius(result))
	b := pr.ExpX0Plus1(a)
	b = pr.Mul(b, pr.Conjugate(result))
	t := pr.CyclotomicSquareKarabina12345(a)
	t = pr.DecompressKarabina12345(t)
	a = pr.Mul(a, t)
	c := pr.ExptMinus1Div3(b)
	d := pr.ExpX0Minus1(c)
	e := pr.ExpX0Minus1Square(d)
	e = pr.Mul(e, d)
	d = pr.Conjugate(d)
	f := pr.Mul(d, b)
	g := pr.ExpX0Plus1(e)
	g = pr.Mul(g, f)
	h := pr.Mul(g, c)
	i := pr.Mul(g, d)
	i = pr.ExpX0Plus1(i)
	i = pr.Mul(i, pr.Conjugate(f))
	j := pr.ExpC1(h)
	j = pr.Mul(j, e)
	k := pr.CyclotomicSquareKarabina12345(j)
	k = pr.DecompressKarabina12345(k)
	k = pr.Mul(k, j)
	k = pr.Mul(k, b)
	t = pr.ExpC2(i)
	k = pr.Mul(k, t)
	result = pr.Mul(a, k)

	return result
}

// AssertFinalExponentiationIsOne checks that a Miller function output x lies in the
// same equivalence class as the reduced pairing. This replaces the final
// exponentiation step in-circuit.
// The method is adapted from Section 4 of [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) AssertFinalExponentiationIsOne(x *GTEl) {
	res, err := pr.curveF.NewHint(finalExpHint, 6, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitness := GTEl{
		A0: *res[0],
		A1: *res[1],
		A2: *res[2],
		A3: *res[3],
		A4: *res[4],
		A5: *res[5],
	}

	// Check that x == residueWitness^Λ
	// where Λ = x₀+1+p(x₀³-x₀²-x₀) and residueWitness from the hint.

	// exponentiation by U2 = x₀+1
	t1 := pr.Ext6.ExpByU2(&residueWitness)
	// exponentiation by x₀³-x₀²-x₀ = (x₀³-x₀²+1) - (x₀+1) = U1 - U2,
	// where ExpByU1 raises to U1 = x₀³-x₀²+1.
	t0 := pr.Ext6.ExpByU1(&residueWitness)
	t0 = pr.Ext6.DivUnchecked(t0, t1)
	t0 = pr.Ext6.Frobenius(t0)
	t0 = pr.Ext6.Mul(t0, t1)

	pr.AssertIsEqual(t0, x)
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function does not check that Pᵢ and Qᵢ are in the correct subgroup. See
// AssertIsOnG1 and AssertIsOnG2. NB! This mismatches the interfaces of sw_bls12381 and
// sw_bn254 packages where G2 membership check is performed automatically!
func (pr *Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	f, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, err
	}
	return pr.FinalExponentiation(f), nil
}

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr *Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	// check input size match
	nP := len(P)
	nQ := len(Q)
	if nP == 0 || nP != nQ {
		return errors.New("invalid inputs sizes")
	}
	// hint the non-residue witness
	inputs := make([]*baseEl, 0, 2*nP+2*nQ)
	for _, p := range P {
		inputs = append(inputs, &p.X, &p.Y)
	}
	for _, q := range Q {
		inputs = append(inputs, &q.P.X, &q.P.Y)
	}
	hint, err := pr.curveF.NewHint(pairingCheckHint, 6, inputs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitnessInv := &GTEl{
		A0: *hint[0],
		A1: *hint[1],
		A2: *hint[2],
		A3: *hint[3],
		A4: *hint[4],
		A5: *hint[5],
	}

	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := pr.computeLines(&Q[i].P)
			Q[i].Lines = &Qlines
		}
		lines[i] = *Q[i].Lines
	}

	res, err := pr.millerLoopLines(P, lines, residueWitnessInv, false)
	if err != nil {
		return fmt.Errorf("miller loop: %w", err)
	}

	// Check that: MillerLoop(P,Q) == residueWitness^Λ
	// where Λ = x₀+1+p(x₀³-x₀²-x₀) and residueWitness from the hint.
	//
	// Note that at this point:
	// 		result = MillerLoop(P,Q) * residueWitnessInv^{x₀+1+p(x₀³-x₀²-x₀)}
	// since we initialized the Miller loop accumulator with residueWitnessInv^{p}.
	// So we only need to check that:
	// 		result == 1.
	pr.AssertIsEqual(res, pr.Ext6.One())

	return nil
}

func (pr *Pairing) IsEqual(x, y *GTEl) frontend.Variable {
	return pr.Ext6.IsEqual(x, y)
}

func (pr *Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext6.AssertIsEqual(x, y)
}

func (pr *Pairing) MuxG2(sel frontend.Variable, inputs ...*G2Affine) *G2Affine {
	if len(inputs) == 0 {
		return nil
	}
	if len(inputs) == 1 {
		pr.api.AssertIsEqual(sel, 0)
		return inputs[0]
	}
	for i := 1; i < len(inputs); i++ {
		if (inputs[0].Lines == nil) != (inputs[i].Lines == nil) {
			panic("muxing points with and without precomputed lines")
		}
	}
	var ret G2Affine
	Xs := make([]*emulated.Element[BaseField], len(inputs))
	Ys := make([]*emulated.Element[BaseField], len(inputs))
	for i := range inputs {
		Xs[i] = &inputs[i].P.X
		Ys[i] = &inputs[i].P.Y
	}
	ret.P.X = *pr.curveF.Mux(sel, Xs...)
	ret.P.Y = *pr.curveF.Mux(sel, Ys...)

	if inputs[0].Lines == nil {
		return &ret
	}

	// switch precomputed lines
	ret.Lines = new(lineEvaluations)
	for j := range inputs[0].Lines[0] {
		lineR0s := make([]*emulated.Element[BaseField], len(inputs))
		lineR1s := make([]*emulated.Element[BaseField], len(inputs))
		for k := 0; k < 2; k++ {
			for i := range inputs {
				lineR0s[i] = &inputs[i].Lines[k][j].R0
				lineR1s[i] = &inputs[i].Lines[k][j].R1
			}
			le := &lineEvaluation{
				R0: *pr.curveF.Mux(sel, lineR0s...),
				R1: *pr.curveF.Mux(sel, lineR1s...),
			}
			ret.Lines[k][j] = le
		}
	}

	return &ret
}

func (pr *Pairing) MuxGt(sel frontend.Variable, inputs ...*GTEl) *GTEl {
	if len(inputs) == 0 {
		return nil
	}
	if len(inputs) == 1 {
		pr.api.AssertIsEqual(sel, 0)
		return inputs[0]
	}
	var ret GTEl
	A0s := make([]*emulated.Element[BaseField], len(inputs))
	A1s := make([]*emulated.Element[BaseField], len(inputs))
	A2s := make([]*emulated.Element[BaseField], len(inputs))
	A3s := make([]*emulated.Element[BaseField], len(inputs))
	A4s := make([]*emulated.Element[BaseField], len(inputs))
	A5s := make([]*emulated.Element[BaseField], len(inputs))
	for i := range inputs {
		A0s[i] = &inputs[i].A0
		A1s[i] = &inputs[i].A1
		A2s[i] = &inputs[i].A2
		A3s[i] = &inputs[i].A3
		A4s[i] = &inputs[i].A4
		A5s[i] = &inputs[i].A5
	}
	ret.A0 = *pr.curveF.Mux(sel, A0s...)
	ret.A1 = *pr.curveF.Mux(sel, A1s...)
	ret.A2 = *pr.curveF.Mux(sel, A2s...)
	ret.A3 = *pr.curveF.Mux(sel, A3s...)
	ret.A4 = *pr.curveF.Mux(sel, A4s...)
	ret.A5 = *pr.curveF.Mux(sel, A5s...)
	return &ret
}

func (pr *Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
}

func (pr *Pairing) AssertIsOnTwist(Q *G2Affine) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=4
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 4, and continue
	selector := pr.api.And(pr.curveF.IsZero(&Q.P.X), pr.curveF.IsZero(&Q.P.Y))
	bTwist := pr.curveF.NewElement(4)
	b := pr.curveF.Select(selector, pr.curveF.Zero(), bTwist)

	left := pr.curveF.Mul(&Q.P.Y, &Q.P.Y)
	right := pr.curveF.Eval([][]*emulated.Element[BaseField]{
		{&Q.P.X, &Q.P.X, &Q.P.X},
		{b},
	}, []int{1, 1})
	pr.curveF.AssertIsEqual(left, right)
}

func (pr *Pairing) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)

	// 2- Check P has the right subgroup order
	// we check that [x₀+1]P == [-x₀³+x₀²-1]ϕ(P)
	xP := pr.g1.scalarMulBySeed(P)
	x2P := pr.g1.scalarMulBySeed(xP)
	x3P := pr.g1.scalarMulBySeed(x2P)

	left := pr.g1.add(xP, P)
	right := pr.g1.sub(x2P, x3P)
	right = pr.g1.sub(right, P)
	right = pr.g1.phi(right)

	// [r]P == 0 <==> [x₀+1]P == [-x₀³+x₀²-1]ϕ(P)
	pr.curve.AssertIsEqual(left, right)
}

func (pr *Pairing) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	pr.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	// we check that [x₀+1]Q == [-x₀³+x₀²-1]ϕ(Q)
	xQ := pr.g2.scalarMulBySeed(Q)
	x2Q := pr.g2.scalarMulBySeed(xQ)
	x3Q := pr.g2.scalarMulBySeed(x2Q)

	left := pr.g2.add(xQ, Q)
	right := pr.g2.sub(x2Q, x3Q)
	right = pr.g2.sub(right, Q)
	right = pr.g2.phi(right)

	// [r]Q == 0 <==> [x₀+1]Q == [-x₀³+x₀²-1]ϕ(Q)
	pr.g2.AssertIsEqual(left, right)
}

// seed x₀=9586122913090633729
//
// x₀+1 in binary (64 bits) padded with 0s
var loopCounter1 = [190]int8{
	0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0,
	0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

// x₀³-x₀²-x₀ in 2-NAF
var loopCounter2 = [190]int8{
	-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, -1,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1,
	0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, 1, 0, 0, 1, 0, -1, 0, 1, 0,
	1, 0, 0, 0, 1, 0, -1, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, 1,
}

// MillerLoop computes the optimal Tate multi-Miller loop (or twisted ate or Eta
// revisited)
//
// ∏ᵢ { fᵢ_{x₀+1+λ(x₀³-x₀²-x₀),Qᵢ}(Pᵢ) }
//
// This function does not check that Pᵢ and Qᵢ are in the correct subgroup. See
// AssertIsOnG1 and AssertIsOnG2. NB! This mismatches the interfaces of sw_bls12381 and
// sw_bn254 packages where G2 membership check is performed automatically!
//
// Alg.2 in https://eprint.iacr.org/2021/1359.pdf Eq. (6') in
// https://hackmd.io/@gnark/BW6-761-changes
func (pr *Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}
	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := pr.computeLines(&Q[i].P)
			Q[i].Lines = &Qlines
		}
		lines[i] = *Q[i].Lines
	}
	return pr.millerLoopLines(P, lines, nil, true)

}

// millerLoopLines computes the multi-Miller loop from points in G1 and precomputed lines in G2
func (pr *Pairing) millerLoopLines(P []*G1Affine, lines []lineEvaluations, init *GTEl, first bool) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(lines) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations
	yInv := make([]*baseEl, n)
	xNegOverY := make([]*baseEl, n)

	for k := 0; k < n; k++ {
		// P are supposed to be on G1 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xNegOverY[k] = pr.curveF.Mul(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	// Compute f_{x₀+1+λ(x₀³-x₀²-x₀),Q}(P)
	var prodLines [5]*baseEl
	result := pr.Ext6.One()

	var initInv, frobInit, frobInitInv GTEl
	if init != nil {
		initInv = *pr.Ext6.Inverse(init)
		frobInit = *pr.Ext6.Frobenius(init)
		frobInitInv = *pr.Ext6.Frobenius(&initInv)
		result = &frobInit
	}

	j := len(loopCounter2) - 2
	if first {
		// i = j
		// k = 0
		result = &GTEl{
			A0: *pr.curveF.Mul(&lines[0][0][j].R1, yInv[0]),
			A1: result.A1,
			A2: *pr.curveF.Mul(&lines[0][0][j].R0, xNegOverY[0]),
			A3: *pr.curveF.One(),
			A4: result.A4,
			A5: result.A5,
		}

		if n >= 2 {
			// k = 1, separately to avoid MulBy023 (res × ℓ)
			// (res is also a line at this point, so we use Mul023By023 ℓ × ℓ)
			prodLines = pr.Mul023By023(
				pr.curveF.Mul(&lines[1][0][j].R1, yInv[1]),
				pr.curveF.Mul(&lines[1][0][j].R0, xNegOverY[1]),
				&result.A0,
				&result.A2,
			)
			result = &GTEl{
				A0: *prodLines[0],
				A1: result.A1,
				A2: *prodLines[1],
				A3: *prodLines[2],
				A4: *prodLines[3],
				A5: *prodLines[4],
			}
		}

		// k >= 2: batch lines 2-by-2
		for k := 3; k < n; k += 2 {
			prodLines = pr.Mul023By023(
				pr.curveF.Mul(&lines[k][0][j].R1, yInv[k]),
				pr.curveF.Mul(&lines[k][0][j].R0, xNegOverY[k]),
				pr.curveF.Mul(&lines[k-1][0][j].R1, yInv[k-1]),
				pr.curveF.Mul(&lines[k-1][0][j].R0, xNegOverY[k-1]),
			)
			result = pr.MulBy02345(result, prodLines)
		}
		// Handle remaining line if (n-2) is odd
		if n >= 3 && (n-2)%2 != 0 {
			result = pr.MulBy023(result,
				pr.curveF.Mul(&lines[n-1][0][j].R1, yInv[n-1]),
				pr.curveF.Mul(&lines[n-1][0][j].R0, xNegOverY[n-1]),
			)
		}
		j--
	}

	for i := j; i > 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		j := loopCounter1[i] + 3*loopCounter2[i]
		switch j {
		// cases -4, -2, 2, 4 do not occur, given the static LoopCounters
		case -3:
			if init != nil {
				// mul by frobInitInv to capture -1's in x₀³-x₀²-x₀
				result = pr.Ext6.Mul(result, &frobInitInv)
			}
			// mul by tangent and line
			for k := 0; k < n; k++ {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k][1][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][1][i].R0, xNegOverY[k]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
		case -1:
			if init != nil {
				// mul by initInv to capture -1's in x₀+1
				result = pr.Ext6.Mul(result, &initInv)
			}
			// mul by tangent and line
			for k := 0; k < n; k++ {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k][1][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][1][i].R0, xNegOverY[k]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
		case 0:
			// mul tangents 2-by-2 and then by accumulator
			for k := 1; k < n; k += 2 {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k-1][0][i].R1, yInv[k-1]),
					pr.curveF.Mul(&lines[k-1][0][i].R0, xNegOverY[k-1]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
			// if number of tangents is odd, mul last line by res
			// works for n=1 as well
			if n%2 != 0 {
				// ℓ × res
				result = pr.MulBy023(result,
					pr.curveF.Mul(&lines[n-1][0][i].R1, yInv[n-1]),
					pr.curveF.Mul(&lines[n-1][0][i].R0, xNegOverY[n-1]),
				)
			}
		case 1:
			if init != nil {
				// mul by init to capture 1's in x₀+1
				result = pr.Ext6.Mul(result, init)
			}
			// mul by line and tangent
			for k := 0; k < n; k++ {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k][1][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][1][i].R0, xNegOverY[k]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
		case 3:
			if init != nil {
				// mul by frobInit to capture 1's in x₀³-x₀²-x₀
				result = pr.Ext6.Mul(result, &frobInit)
			}
			for k := 0; k < n; k++ {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k][1][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][1][i].R0, xNegOverY[k]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
		default:
			panic("unknown case for loopCounter")
		}
	}

	// i = 0 (j = -3)
	result = pr.Square(result)
	if init != nil {
		// mul by frobInitInv to capture -1's in x₀³-x₀²-x₀
		result = pr.Ext6.Mul(result, &frobInitInv)
	}
	// x₀+1+λ(x₀³-x₀²-x₀) = 0 mod r so accQ = ∞ at the last iteration,
	// we only mul by tangent.
	// mul tangents 2-by-2 and then by accumulator
	for k := 1; k < n; k += 2 {
		prodLines = pr.Mul023By023(
			pr.curveF.Mul(&lines[k][0][0].R1, yInv[k]),
			pr.curveF.Mul(&lines[k][0][0].R0, xNegOverY[k]),
			pr.curveF.Mul(&lines[k-1][0][0].R1, yInv[k-1]),
			pr.curveF.Mul(&lines[k-1][0][0].R0, xNegOverY[k-1]),
		)
		result = pr.MulBy02345(result, prodLines)
	}
	// if number of tangents is odd, mul last line by res
	// works for n=1 as well
	if n%2 != 0 {
		// ℓ × res
		result = pr.MulBy023(result,
			pr.curveF.Mul(&lines[n-1][0][0].R1, yInv[n-1]),
			pr.curveF.Mul(&lines[n-1][0][0].R0, xNegOverY[n-1]),
		)
	}

	return result, nil

}

// doubleAndAddStep doubles p1 and adds or subs p2 to the result in affine coordinates, based on the isSub boolean.
// Then evaluates the lines going through p1 and p2 or -p2 (line1) and p1 and p1+p2 or p1-p2 (line2).
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleAndAddStep(p1, p2 *g2AffP, isSub bool) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP

	// compute λ1 = (y1-y2)/(x1-x2) or λ1 = (y1+y2)/(x1-x2) if isSub is true
	var n *emulated.Element[BaseField]
	if isSub {
		n = pr.curveF.Add(&p1.Y, &p2.Y)
	} else {
		n = pr.curveF.Sub(&p1.Y, &p2.Y)
	}
	d := pr.curveF.Sub(&p1.X, &p2.X)
	l1 := pr.divWithZeroGuard(n, d)

	// compute x3 =λ1²-x1-x2
	x3 := pr.curveF.Eval([][]*baseEl{{l1, l1}, {&p1.X}, {&p2.X}}, []int{1, -1, -1})

	// omit y3 computation

	// compute line1
	line1.R0 = *l1
	line1.R1 = *pr.curveF.Eval([][]*baseEl{{l1, &p1.X}, {&p1.Y}}, []int{1, -1})

	// compute -λ2 = λ1+2y1/(x3-x1)
	ypyp := pr.curveF.MulConst(&p1.Y, big.NewInt(2))
	x2xp := pr.curveF.Sub(x3, &p1.X)
	l2 := pr.divWithZeroGuard(ypyp, x2xp)
	l2 = pr.curveF.Add(l1, l2)

	// compute x4 = (-λ2)²-x1-x3
	x4 := pr.curveF.Eval([][]*baseEl{{l2, l2}, {&p1.X}, {x3}}, []int{1, -1, -1})

	// compute y4 = -λ2(-x1 + x4)-y1
	y4 := pr.curveF.Eval([][]*baseEl{{l2, pr.curveF.Sub(x4, &p1.X)}, {&p1.Y}}, []int{1, -1})

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *pr.curveF.Neg(l2)
	line2.R1 = *pr.curveF.Eval([][]*baseEl{{l2, &p1.X}, {&p1.Y}}, []int{-1, -1})

	return &p, &line1, &line2
}

// doubleStep doubles p1 in affine coordinates, and evaluates the tangent line to p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation) {

	var p g2AffP
	var line lineEvaluation

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	n = pr.curveF.MulConst(n, big.NewInt(3))
	d := pr.curveF.MulConst(&p1.Y, big.NewInt(2))
	λ := pr.divWithZeroGuard(n, d)

	// xr = λ²-2x
	xr := pr.curveF.Eval([][]*baseEl{{λ, λ}, {&p1.X}}, []int{1, -2})

	// yr = λ(x-xr)-y
	yr := pr.curveF.Eval([][]*baseEl{{λ, pr.curveF.Sub(&p1.X, xr)}, {&p1.Y}}, []int{1, -1})

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1 = *pr.curveF.Eval([][]*baseEl{{λ, &p1.X}, {&p1.Y}}, []int{1, -1})

	return &p, &line

}

// tangentCompute computes the tangent line to p1, but does not compute [2]p1.
func (pr *Pairing) tangentCompute(p1 *g2AffP) *lineEvaluation {

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	n = pr.curveF.MulConst(n, big.NewInt(3))
	d := pr.curveF.MulConst(&p1.Y, big.NewInt(2))
	λ := pr.divWithZeroGuard(n, d)

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Eval([][]*baseEl{{λ, &p1.X}, {&p1.Y}}, []int{1, -1})

	return &line

}

// divWithZeroGuard computes n/d as a line slope, but when d == 0 it returns 0
// with the quotient *constrained* to 0 rather than left as a free (prover-chosen)
// hint value. A plain Div(n, 0) only enforces λ·0 == n, i.e. 0 == 0, which leaves
// λ unconstrained; that is the soundness gap when Q = (0,0) (the point at
// infinity) is fed to the Miller loop and every affine line evaluation becomes
// 0/0. Non-degenerate steps (d ≠ 0) are unchanged, and the degenerate value
// matches the honest 0/0 = 0 convention, so completeness (incl. legitimate
// G2-infinity inputs) is preserved.
func (pr *Pairing) divWithZeroGuard(n, d *baseEl) *baseEl {
	dIsZero := pr.curveF.IsZero(d)
	dSafe := pr.curveF.Select(dIsZero, pr.curveF.One(), d)
	λ := pr.curveF.Div(n, dSafe)
	return pr.curveF.Select(dIsZero, pr.curveF.Zero(), λ)
}
