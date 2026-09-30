package sw_bls12381

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bls12381.Ext12
	*fields_bls12381.Ext2
	curveF *emulated.Field[BaseField]
	curve  *sw_emulated.Curve[BaseField, ScalarField]
	g2     *G2
	g1     *G1
}

type baseEl = emulated.Element[BaseField]
type GTEl = fields_bls12381.E12

func NewGTEl(a bls12381.GT) GTEl {

	var c0, c1, c2, c3, c4, c5 fp.Element
	c0.Sub(&a.C0.B0.A0, &a.C0.B0.A1)
	c1.Sub(&a.C1.B0.A0, &a.C1.B0.A1)
	c2.Sub(&a.C0.B1.A0, &a.C0.B1.A1)
	c3.Sub(&a.C1.B1.A0, &a.C1.B1.A1)
	c4.Sub(&a.C0.B2.A0, &a.C0.B2.A1)
	c5.Sub(&a.C1.B2.A0, &a.C1.B2.A1)

	return GTEl{
		A0:  emulated.ValueOf[BaseField](c0),
		A1:  emulated.ValueOf[BaseField](c1),
		A2:  emulated.ValueOf[BaseField](c2),
		A3:  emulated.ValueOf[BaseField](c3),
		A4:  emulated.ValueOf[BaseField](c4),
		A5:  emulated.ValueOf[BaseField](c5),
		A6:  emulated.ValueOf[BaseField](a.C0.B0.A1),
		A7:  emulated.ValueOf[BaseField](a.C1.B0.A1),
		A8:  emulated.ValueOf[BaseField](a.C0.B1.A1),
		A9:  emulated.ValueOf[BaseField](a.C1.B1.A1),
		A10: emulated.ValueOf[BaseField](a.C0.B2.A1),
		A11: emulated.ValueOf[BaseField](a.C1.B2.A1),
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBLS12381Params())
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
	return &Pairing{
		api:    api,
		Ext12:  fields_bls12381.NewExt12(api),
		Ext2:   fields_bls12381.NewExt2(api),
		curveF: ba,
		curve:  curve,
		g1:     g1,
		g2:     g2,
	}, nil
}

// Pair calculates the reduced pairing for a set of points
//
//	∏ᵢ e(Pᵢ, Qᵢ).
//
// This function checks that the Qᵢ are in the correct subgroup, but does not
// check Pᵢ. See AssertIsOnG1.
func (pr *Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.FinalExponentiation(res)
	return res, nil
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
	inputs := make([]*baseEl, 0, 2*nP+4*nQ)
	for _, p := range P {
		inputs = append(inputs, &p.X, &p.Y)
	}
	for _, q := range Q {
		inputs = append(inputs, &q.P.X.A0, &q.P.X.A1, &q.P.Y.A0, &q.P.Y.A1)
	}
	hint, err := pr.curveF.NewHint(pairingCheckHint, 18, inputs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitnessInv := pr.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]})
	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - a001
	//     A1  =  0
	//     A2  =  a010 - a011
	//     A3  =  0
	//     A4  =  a020 - a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	scalingFactor := GTEl{
		A0:  *pr.curveF.Sub(hint[12], hint[13]),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(hint[14], hint[15]),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(hint[16], hint[17]),
		A5:  *pr.curveF.Zero(),
		A6:  *hint[13],
		A7:  *pr.curveF.Zero(),
		A8:  *hint[15],
		A9:  *pr.curveF.Zero(),
		A10: *hint[17],
		A11: *pr.curveF.Zero(),
	}

	lines := make([]lineEvaluations, nQ)
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
	res = pr.Ext12.Conjugate(res)

	// Check that: MillerLoop(P,Q) * scalingFactor * residueWitnessInv^(p-x₀) == 1
	// where u=-0xd201000000010000 is the BLS12-381 seed, and residueWitness,
	// scalingFactor from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{-x₀} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	// So we only need to check that:
	// 		res * scalingFactor * residueWitnessInv^p == 1
	res = pr.Ext12.Mul(res, &scalingFactor)
	t0 := pr.Frobenius(residueWitnessInv)
	res = pr.Ext12.Mul(res, t0)

	pr.AssertIsEqual(res, pr.Ext12.One())
	return nil
}

func (pr *Pairing) IsEqual(x, y *GTEl) frontend.Variable {
	return pr.Ext12.IsEqual(x, y)
}

func (pr *Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
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
	XA0 := make([]*emulated.Element[BaseField], len(inputs))
	XA1 := make([]*emulated.Element[BaseField], len(inputs))
	YA0 := make([]*emulated.Element[BaseField], len(inputs))
	YA1 := make([]*emulated.Element[BaseField], len(inputs))
	for i := range inputs {
		XA0[i] = &inputs[i].P.X.A0
		XA1[i] = &inputs[i].P.X.A1
		YA0[i] = &inputs[i].P.Y.A0
		YA1[i] = &inputs[i].P.Y.A1
	}
	ret.P.X.A0 = *pr.curveF.Mux(sel, XA0...)
	ret.P.X.A1 = *pr.curveF.Mux(sel, XA1...)
	ret.P.Y.A0 = *pr.curveF.Mux(sel, YA0...)
	ret.P.Y.A1 = *pr.curveF.Mux(sel, YA1...)

	if inputs[0].Lines == nil {
		return &ret
	}

	// switch precomputed lines
	ret.Lines = new(lineEvaluations)
	for j := range inputs[0].Lines[0] {
		lineR0A0 := make([]*emulated.Element[BaseField], len(inputs))
		lineR0A1 := make([]*emulated.Element[BaseField], len(inputs))
		lineR1A0 := make([]*emulated.Element[BaseField], len(inputs))
		lineR1A1 := make([]*emulated.Element[BaseField], len(inputs))
		for k := 0; k < 2; k++ {
			for i := range inputs {
				lineR0A0[i] = &inputs[i].Lines[k][j].R0.A0
				lineR0A1[i] = &inputs[i].Lines[k][j].R0.A1
				lineR1A0[i] = &inputs[i].Lines[k][j].R1.A0
				lineR1A1[i] = &inputs[i].Lines[k][j].R1.A1
			}
			le := &lineEvaluation{
				R0: fields_bls12381.E2{
					A0: *pr.curveF.Mux(sel, lineR0A0...),
					A1: *pr.curveF.Mux(sel, lineR0A1...),
				},
				R1: fields_bls12381.E2{
					A0: *pr.curveF.Mux(sel, lineR1A0...),
					A1: *pr.curveF.Mux(sel, lineR1A1...),
				},
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
	A6s := make([]*emulated.Element[BaseField], len(inputs))
	A7s := make([]*emulated.Element[BaseField], len(inputs))
	A8s := make([]*emulated.Element[BaseField], len(inputs))
	A9s := make([]*emulated.Element[BaseField], len(inputs))
	A10s := make([]*emulated.Element[BaseField], len(inputs))
	A11s := make([]*emulated.Element[BaseField], len(inputs))
	for i := range inputs {
		A0s[i] = &inputs[i].A0
		A1s[i] = &inputs[i].A1
		A2s[i] = &inputs[i].A2
		A3s[i] = &inputs[i].A3
		A4s[i] = &inputs[i].A4
		A5s[i] = &inputs[i].A5
		A6s[i] = &inputs[i].A6
		A7s[i] = &inputs[i].A7
		A8s[i] = &inputs[i].A8
		A9s[i] = &inputs[i].A9
		A10s[i] = &inputs[i].A10
		A11s[i] = &inputs[i].A11
	}
	ret.A0 = *pr.curveF.Mux(sel, A0s...)
	ret.A1 = *pr.curveF.Mux(sel, A1s...)
	ret.A2 = *pr.curveF.Mux(sel, A2s...)
	ret.A3 = *pr.curveF.Mux(sel, A3s...)
	ret.A4 = *pr.curveF.Mux(sel, A4s...)
	ret.A5 = *pr.curveF.Mux(sel, A5s...)
	ret.A6 = *pr.curveF.Mux(sel, A6s...)
	ret.A7 = *pr.curveF.Mux(sel, A7s...)
	ret.A8 = *pr.curveF.Mux(sel, A8s...)
	ret.A9 = *pr.curveF.Mux(sel, A9s...)
	ret.A10 = *pr.curveF.Mux(sel, A10s...)
	ret.A11 = *pr.curveF.Mux(sel, A11s...)
	return &ret
}

// IsOnCurve returns a boolean indicating if the G1 point is in the curve.
func (pr *Pairing) IsOnCurve(P *G1Affine) frontend.Variable {
	left, right := pr.g1.computeCurveEquation(P)
	diff := pr.curveF.Sub(left, right)
	return pr.curveF.IsZero(diff)
}

func (pr *Pairing) AssertIsOnG1(P *G1Affine) {
	pr.g1.AssertIsOnG1(P)
}

// IsOnG1 returns a boolean indicating if the G1 point is on the curve and in
// the prime subgroup.
func (pr *Pairing) IsOnG1(P *G1Affine) frontend.Variable {
	// To check that a point P is on G1, we need to check it is of prime order r.
	// This means that we need to check:
	//   [r]P == 0
	// Instead of computing a big scalar multiplication, we check the equivalent condition:
	//   P + [x^2]ϕ(P) == 0
	// where ϕ is the endomorphism of G1, and x is the seed of the curve.
	// The last equation is equivalent of checking that:
	//   P = -[x^2]ϕ(P)

	// 1 - is P on curve
	isOnCurve := pr.IsOnCurve(P)
	// 2- Check P has the right subgroup order
	// [x²]ϕ(P)
	phiP := pr.g1.phi(P)
	_P := pr.g1.scalarMulBySeedSquare(phiP)
	_P = pr.curve.Neg(_P)
	// [r]P == 0 <==>  P = -[x²]ϕ(P)
	isInSubgroup := pr.g1.IsEqual(_P, P)
	return pr.api.And(isOnCurve, isInSubgroup)
}

func (pr *Pairing) AssertIsOnTwist(Q *G2Affine) {
	pr.g2.AssertIsOnTwist(Q)
}

// IsOnTwist returns a boolean indicating if the G2 point is in the twist.
func (pr *Pairing) IsOnTwist(Q *G2Affine) frontend.Variable {
	left, right := pr.g2.computeTwistEquation(Q)
	diff := pr.Ext2.Sub(left, right)
	return pr.Ext2.IsZero(diff)
}

func (pr *Pairing) AssertIsOnG2(Q *G2Affine) {
	pr.g2.AssertIsOnG2(Q)
}

// IsOnG2 returns a boolean indicating if the G2 point is on the curve and in
// the prime subgroup.
func (pr *Pairing) IsOnG2(Q *G2Affine) frontend.Variable {
	// 1 - is Q on curve
	isOnCurve := pr.IsOnTwist(Q)
	// 2 - is Q in the subgroup
	xQ := pr.g2.scalarMulBySeed(Q)
	psiQ := pr.g2.psi(Q)
	isInSubgroup := pr.g2.IsEqual(xQ, psiQ)
	return pr.api.And(isOnCurve, isInSubgroup)
}

// loopCounter = seed in binary
//
//	seed=-15132376222941642752
var loopCounter = [64]int8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 0, 0, 1, 0, 1, 1,
}

// MillerLoop computes the multi-Miller loop
//
//	∏ᵢ { fᵢ_{u,Q}(P) }
//
// This function checks that the Qᵢ are in the correct subgroup, but does not
// check Pᵢ. See AssertIsOnG1.
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
		// If we have point at infinity, we set yInv[k] to 0 manually to avoid
		// undefined inversion of 0.
		isYZero := pr.curveF.IsZero(&P[k].Y)
		y := pr.curveF.Select(isYZero, pr.curveF.One(), &P[k].Y)
		yInv[k] = pr.curveF.Select(isYZero, pr.curveF.Zero(), pr.curveF.Inverse(y))
		xNegOverY[k] = pr.curveF.MulMod(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	res := pr.Ext12.One()

	if init != nil {
		res = init
	}

	j := len(loopCounter) - 2
	if first {
		// i = j, separately to avoid an E12 Square
		// (Square(res) = 1² = 1)
		// Batch lines within each pair using sparse×sparse optimization
		for k := 0; k < n; k++ {
			res = pr.Mul02368By02368ThenMul(res,
				pr.MulByElement(&lines[k][0][j].R1, yInv[k]),
				pr.MulByElement(&lines[k][0][j].R0, xNegOverY[k]),
				pr.MulByElement(&lines[k][1][j].R1, yInv[k]),
				pr.MulByElement(&lines[k][1][j].R0, xNegOverY[k]),
			)
		}
		j--
	}

	for i := j; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res = pr.Ext12.Square(res)

		if loopCounter[i] == 0 {
			// For 0-bit: batch lines 2-by-2 across pairs using sparse×sparse optimization
			k := 0
			for ; k+1 < n; k += 2 {
				// Batch lines[k] and lines[k+1] together
				res = pr.Mul02368By02368ThenMul(res,
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.MulByElement(&lines[k+1][0][i].R1, yInv[k+1]),
					pr.MulByElement(&lines[k+1][0][i].R0, xNegOverY[k+1]),
				)
			}
			// Handle odd remaining line
			if k < n {
				res = pr.MulBy02368(res,
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
				)
			}
		} else {
			if init != nil {
				// multiply by init when bit=1
				res = pr.Ext12.Mul(res, init)
			}
			// For 1-bit: batch the two lines within each pair, then batch pairs 2-by-2
			k := 0
			for ; k+1 < n; k += 2 {
				// First pair: lines[k][0] × lines[k][1]
				res = pr.Mul02368By02368ThenMul(res,
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.MulByElement(&lines[k][1][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
				)
				// Second pair: lines[k+1][0] × lines[k+1][1]
				res = pr.Mul02368By02368ThenMul(res,
					pr.MulByElement(&lines[k+1][0][i].R1, yInv[k+1]),
					pr.MulByElement(&lines[k+1][0][i].R0, xNegOverY[k+1]),
					pr.MulByElement(&lines[k+1][1][i].R1, yInv[k+1]),
					pr.MulByElement(&lines[k+1][1][i].R0, xNegOverY[k+1]),
				)
			}
			// Handle odd remaining pair
			if k < n {
				res = pr.Mul02368By02368ThenMul(res,
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.MulByElement(&lines[k][1][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
				)
			}
		}
	}

	// negative x₀
	res = pr.Ext12.Conjugate(res)

	return res, nil
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 3 (Hayashida et al.)
func (pr *Pairing) FinalExponentiation(e *GTEl) *GTEl {
	z := pr.Copy(e)

	// Easy part
	// (p⁶-1)(p²+1)
	// t0 = conj(z)·z⁻¹. Using Inverse (which constrains z·z⁻¹ == 1) rather than
	// DivUnchecked rejects a witness GT equal to 0: a plain DivUnchecked(conj(0),
	// 0) only enforces q·0 == 0 and leaves the quotient free, letting a prover
	// prove FinalExponentiation(0) == 1.
	t0 := pr.Ext12.Conjugate(z)
	t0 = pr.Ext12.Mul(t0, pr.Ext12.Inverse(z))
	z = pr.Ext12.FrobeniusSquare(t0)
	z = pr.Ext12.Mul(z, t0)

	// Hard part (up to permutation)
	// Daiki Hayashida, Kenichiro Hayasaka and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	z = pr.finalExpHardPart(z)

	return z
}

// finalExpHardPart computes the hard part of the final exponentiation:
// (p⁴-p²+1)/r with cofactor 3
// Daiki Hayashida, Kenichiro Hayasaka and Tadanori Teruya
// https://eprint.iacr.org/2020/875.pdf
func (pr *Pairing) finalExpHardPart(z *GTEl) *GTEl {
	t0 := pr.Ext12.CyclotomicSquareGS(z)
	t1 := pr.Ext12.ExptHalfGS(t0)
	t2 := pr.Ext12.Conjugate(z)
	t1 = pr.Ext12.Mul(t1, t2)
	t2 = pr.Ext12.ExptGS(t1)
	t1 = pr.Ext12.Conjugate(t1)
	t1 = pr.Ext12.Mul(t1, t2)
	t2 = pr.Ext12.ExptGS(t1)
	t1 = pr.Ext12.Frobenius(t1)
	t1 = pr.Ext12.Mul(t1, t2)
	z = pr.Ext12.Mul(z, t0)
	t0 = pr.Ext12.ExptGS(t1)
	t2 = pr.Ext12.ExptGS(t0)
	t0 = pr.Ext12.FrobeniusSquare(t1)
	t1 = pr.Ext12.Conjugate(t1)
	t1 = pr.Ext12.Mul(t1, t2)
	t1 = pr.Ext12.Mul(t1, t0)
	z = pr.Ext12.Mul(z, t1)

	return z
}

// AssertFinalExponentiationIsOne checks that a Miller function output x lies in the
// same equivalence class as the reduced pairing. This replaces the final
// exponentiation step in-circuit.
// The method is inspired from [On Proving Pairings] paper by A. Novakovic and
// L. Eagen, and is based on a personal communication with A. Novakovic.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) AssertFinalExponentiationIsOne(x *GTEl) {
	tower := pr.ToTower(x)

	res, err := pr.curveF.NewHint(finalExpHint, 18, tower[0], tower[1], tower[2], tower[3], tower[4], tower[5], tower[6], tower[7], tower[8], tower[9], tower[10], tower[11])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitness := pr.FromTower([12]*baseEl{res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7], res[8], res[9], res[10], res[11]})

	// Constrain residueWitness to be invertible (non-zero). The check below,
	// x·scalingFactor == residueWitness^(q-u), is homogeneous in the hint
	// outputs residueWitness and scalingFactor, so the all-zero witness would
	// satisfy it (0 == 0) for any x. Inverse asserts
	// residueWitness·residueWitness⁻¹ == 1, ruling that out.
	pr.Ext12.Inverse(residueWitness)

	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - a001
	//     A1  =  0
	//     A2  =  a010 - a011
	//     A3  =  0
	//     A4  =  a020 - a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	scalingFactor := GTEl{
		A0:  *pr.curveF.Sub(res[12], res[13]),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(res[14], res[15]),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(res[16], res[17]),
		A5:  *pr.curveF.Zero(),
		A6:  *res[13],
		A7:  *pr.curveF.Zero(),
		A8:  *res[15],
		A9:  *pr.curveF.Zero(),
		A10: *res[17],
		A11: *pr.curveF.Zero(),
	}

	// Check that  x * scalingFactor == residueWitness^(q-u)
	// where u=-0xd201000000010000 is the BLS12-381 seed,
	// and residueWitness, scalingFactor from the hint.
	t0 := pr.Frobenius(residueWitness)
	// exponentiation by -u
	t1 := pr.ExptNeg(residueWitness)
	t0 = pr.Ext12.Mul(t0, t1)

	t1 = pr.Ext12.Mul(x, &scalingFactor)

	pr.AssertIsEqual(t0, t1)
}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates.
// Then evaluates the lines going through p1 and p2 or -p2 (line1) and p1 and p1+p2 (line2).
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleAndAddStep(p1, p2 *g2AffP) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP

	// compute λ1 = (y2-y1)/(x2-x1)
	n := pr.Ext2.Sub(&p1.Y, &p2.Y)
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	λ1 := pr.divE2WithZeroGuard(n, d)

	// compute x3 =λ1²-x1-x2
	x30 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	x31 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// omit y3 computation

	// compute line1
	line1.R0 = *λ1
	line1.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A0}, {&λ1.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line1.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A1}, {&λ1.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	d = pr.Ext2.Sub(x3, &p1.X)
	λ2 := pr.divE2WithZeroGuard(n, d)
	λ2 = pr.Ext2.Add(λ2, λ1)
	λ2 = pr.Ext2.Neg(λ2)

	// compute x4 = λ2²-x1-x3
	x40 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&p1.X.A0}, {x30}}, []int{1, -1, -1, -1})
	x41 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&p1.X.A1}, {x31}}, []int{2, -1, -1})
	x4 := &fields_bls12381.E2{A0: *x40, A1: *x41}

	// compute y4 = λ2(x1 - x4)-y1
	y4 := pr.Ext2.Sub(&p1.X, x4)
	y40 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &y4.A0}, {&λ2.A1, &y4.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	y41 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &y4.A1}, {&λ2.A1, &y4.A0}, {&p1.Y.A1}}, []int{1, 1, -1})
	y4 = &fields_bls12381.E2{A0: *y40, A1: *y41}

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *λ2
	line2.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A0}, {&λ2.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line2.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A1}, {&λ2.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &p, &line1, &line2
}

// doubleStep doubles p1 in affine coordinates, and evaluates the tangent line to p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation) {

	var p g2AffP
	var line lineEvaluation

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	n = pr.Ext2.MulByConstElement(n, big.NewInt(3))
	d := pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	λ := pr.divE2WithZeroGuard(n, d)

	// xr = λ²-2x
	xr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}}, []int{1, -1, -2})
	xr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}}, []int{2, -2})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x-xr)-y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {&λ.A1, &yr.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {&p1.Y.A1}}, []int{1, 1, -1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A0}, {&λ.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A1}, {&λ.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &p, &line

}

// divE2WithZeroGuard computes n/d as a line slope, but when d == 0 it returns 0
// with the quotient *constrained* to 0 rather than left as a free (prover-chosen)
// hint value. A plain DivUnchecked(n, 0) only enforces λ·0 == n, i.e. 0 == 0,
// which leaves λ unconstrained; that is the soundness gap when Q = (0,0)
// (the point at infinity) is fed to the Miller loop and every affine line
// evaluation becomes 0/0. Non-degenerate steps (d ≠ 0) are unchanged, and the
// degenerate value matches the honest 0/0 = 0 convention, so completeness (incl.
// legitimate G2-infinity inputs) is preserved.
func (pr *Pairing) divE2WithZeroGuard(n, d *fields_bls12381.E2) *fields_bls12381.E2 {
	dIsZero := pr.Ext2.IsZero(d)
	dSafe := pr.Ext2.Select(dIsZero, pr.Ext2.One(), d)
	λ := pr.Ext2.DivUnchecked(n, dSafe)
	return pr.Ext2.Select(dIsZero, pr.Ext2.Zero(), λ)
}

// tripleStep triples p1 in affine coordinates, and evaluates the line in Miller loop
func (pr *Pairing) tripleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var res g2AffP

	// λ1 = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	λ1 := pr.divE2WithZeroGuard(n, d)

	// compute line1
	line1.R0 = *λ1
	line1.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A0}, {&λ1.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line1.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A1}, {&λ1.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	// x2 = λ1²-2x
	x20 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p1.X.A0}}, []int{1, -1, -2})
	x21 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p1.X.A1}}, []int{2, -2})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit yr computation, and
	// compute λ2 = 2y/(x2 − x) − λ1.
	x1x2 := pr.Ext2.Sub(&p1.X, x2)
	λ2 := pr.divE2WithZeroGuard(d, x1x2)
	λ2 = pr.Ext2.Sub(λ2, λ1)

	// compute line2
	line2.R0 = *λ2
	line2.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A0}, {&λ2.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line2.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A1}, {&λ2.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	// xr = λ²-x1-x2
	xr0 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&p1.X.A0}, {x20}}, []int{1, -1, -1, -1})
	xr1 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&p1.X.A1}, {x21}}, []int{2, -1, -1})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr) - y1
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr0 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &yr.A0}, {&λ2.A1, &yr.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &yr.A1}, {&λ2.A1, &yr.A0}, {&p1.Y.A1}}, []int{1, 1, -1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	res.X = *xr
	res.Y = *yr

	return &res, &line1, &line2
}

// MillerLoopAndMul computes the Miller loop between P and Q
// and multiplies it in 𝔽p¹² by previous.
//
// This method is needed for evmprecompiles/ecpair.
func (pr *Pairing) MillerLoopAndMul(P *G1Affine, Q *G2Affine, previous *GTEl) (*GTEl, error) {
	res, err := pr.MillerLoop([]*G1Affine{P}, []*G2Affine{Q})
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.Ext12.Conjugate(res)
	res = pr.Ext12.Mul(res, previous)
	return res, err
}

// AssertMillerLoopAndFinalExpIsOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and checks that the result lies in the
// same equivalence class as the reduced pairing purported to be 1. This check
// replaces the final exponentiation step in-circuit and follows Section 4 of
// [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) AssertMillerLoopAndFinalExpIsOne(P *G1Affine, Q *G2Affine, previous *GTEl) {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)
	pr.AssertIsEqual(t2, pr.Ext12.One())
}

// millerLoopAndFinalExpResult computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and returns the result.
func (pr *Pairing) millerLoopAndFinalExpResult(P *G1Affine, Q *G2Affine, previous *GTEl) *GTEl {
	tower := pr.ToTower(previous)

	// hint the non-residue witness
	hint, err := pr.curveF.NewHint(millerLoopAndCheckFinalExpHint, 18, &P.X, &P.Y, &Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1, tower[0], tower[1], tower[2], tower[3], tower[4], tower[5], tower[6], tower[7], tower[8], tower[9], tower[10], tower[11])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	residueWitnessInv := pr.Ext12.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]})
	// constrain scalingFactor to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - a001
	//     A1  =  0
	//     A2  =  a010 - a011
	//     A3  =  0
	//     A4  =  a020 - a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	scalingFactor := GTEl{
		A0:  *pr.curveF.Sub(hint[12], hint[13]),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(hint[14], hint[15]),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(hint[16], hint[17]),
		A5:  *pr.curveF.Zero(),
		A6:  *hint[13],
		A7:  *pr.curveF.Zero(),
		A8:  *hint[15],
		A9:  *pr.curveF.Zero(),
		A10: *hint[17],
		A11: *pr.curveF.Zero(),
	}

	if Q.Lines == nil {
		Qlines := pr.computeLines(&Q.P)
		Q.Lines = &Qlines
	}
	lines := *Q.Lines

	res, err := pr.millerLoopLines(
		[]*G1Affine{P},
		[]lineEvaluations{lines},
		residueWitnessInv,
		false,
	)
	if err != nil {
		return nil
	}
	res = pr.Ext12.Conjugate(res)

	// multiply by previous multi-Miller function
	res = pr.Ext12.Mul(res, previous)

	// Check that: MillerLoop(P,Q) * scalingFactor * residueWitnessInv^(p-x₀) == 1
	// where u=-0xd201000000010000 is the BLS12-381 seed, and residueWitnessInv,
	// scalingFactor from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{-x₀} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	// So we only need to check that:
	// 		res * scalingFactor * residueWitnessInv^p == 1
	res = pr.Ext12.Mul(res, &scalingFactor)
	t0 := pr.Frobenius(residueWitnessInv)
	res = pr.Ext12.Mul(res, t0)

	return res

}

// IsMillerLoopAndFinalExpOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and returns a boolean indicating if
// the result lies in the same equivalence class as the reduced pairing
// purported to be 1.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) IsMillerLoopAndFinalExpOne(P *G1Affine, Q *G2Affine, previous *GTEl) frontend.Variable {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)

	res := pr.IsEqual(t2, pr.Ext12.One())
	return res
}
