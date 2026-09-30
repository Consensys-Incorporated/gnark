package sw_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fp_bn "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type baseEl = emulated.Element[BaseField]
type GTEl = fields_bn254.E12

type Pairing struct {
	api frontend.API
	*fields_bn254.Ext12
	*fields_bn254.Ext2
	curveF *emulated.Field[BaseField]
	curve  *sw_emulated.Curve[BaseField, ScalarField]
	g2     *G2
	bTwist *fields_bn254.E2
}

func NewGTEl(a bn254.GT) GTEl {
	var c0, c1, c2, c3, c4, c5, t fp_bn.Element
	t.SetUint64(9).Mul(&t, &a.C0.B0.A1)
	c0.Sub(&a.C0.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B0.A1)
	c1.Sub(&a.C1.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B1.A1)
	c2.Sub(&a.C0.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B1.A1)
	c3.Sub(&a.C1.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B2.A1)
	c4.Sub(&a.C0.B2.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B2.A1)
	c5.Sub(&a.C1.B2.A0, &t)

	return GTEl{
		A0:  emulated.ValueOf[emulated.BN254Fp](c0),
		A1:  emulated.ValueOf[emulated.BN254Fp](c1),
		A2:  emulated.ValueOf[emulated.BN254Fp](c2),
		A3:  emulated.ValueOf[emulated.BN254Fp](c3),
		A4:  emulated.ValueOf[emulated.BN254Fp](c4),
		A5:  emulated.ValueOf[emulated.BN254Fp](c5),
		A6:  emulated.ValueOf[emulated.BN254Fp](a.C0.B0.A1),
		A7:  emulated.ValueOf[emulated.BN254Fp](a.C1.B0.A1),
		A8:  emulated.ValueOf[emulated.BN254Fp](a.C0.B1.A1),
		A9:  emulated.ValueOf[emulated.BN254Fp](a.C1.B1.A1),
		A10: emulated.ValueOf[emulated.BN254Fp](a.C0.B2.A1),
		A11: emulated.ValueOf[emulated.BN254Fp](a.C1.B2.A1),
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	bTwist := fields_bn254.E2{
		A0: *ba.NewElement("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
		A1: *ba.NewElement("266929791119991161246907387137283842545076965332900288569378510910307636690"),
	}
	g2, err := NewG2(api)
	if err != nil {
		return nil, fmt.Errorf("new g2: %w", err)
	}
	return &Pairing{
		api:    api,
		Ext12:  fields_bn254.NewExt12(api),
		Ext2:   fields_bn254.NewExt2(api),
		curveF: ba,
		curve:  curve,
		g2:     g2,
		bTwist: &bTwist,
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

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 2x₀(6x₀²+3x₀+1)
func (pr *Pairing) FinalExponentiation(e *GTEl) *GTEl {
	// Easy part
	// (p⁶-1)(p²+1)
	t0 := pr.Ext12.Conjugate(e)
	e = pr.Ext12.Inverse(e)
	t0 = pr.Ext12.Mul(t0, e)
	e = pr.Ext12.FrobeniusSquare(t0)
	e = pr.Ext12.Mul(e, t0)

	// Hard part (up to permutation)
	// 2x₀(6x₀²+3x₀+1)(p⁴-p²+1)/r
	// Duquesne and Ghammam
	// https://eprint.iacr.org/2015/192.pdf
	// Fuentes et al. (alg. 6)
	t0 = pr.Ext12.Expt(e)
	t0 = pr.Ext12.Conjugate(t0)
	t0 = pr.Ext12.CyclotomicSquareGS(t0)
	t1 := pr.Ext12.CyclotomicSquareGS(t0)
	t1 = pr.Ext12.Mul(t0, t1)
	t2 := pr.Ext12.Expt(t1)
	t2 = pr.Ext12.Conjugate(t2)
	t3 := pr.Ext12.Conjugate(t1)
	t1 = pr.Ext12.Mul(t2, t3)
	t3 = pr.Ext12.CyclotomicSquareGS(t2)
	t4 := pr.Ext12.Expt(t3)
	t4 = pr.Ext12.Mul(t1, t4)
	t3 = pr.Ext12.Mul(t0, t4)
	t0 = pr.Ext12.Mul(t2, t4)
	t0 = pr.Ext12.Mul(e, t0)
	t2 = pr.Ext12.Frobenius(t3)
	t0 = pr.Ext12.Mul(t2, t0)
	t2 = pr.Ext12.FrobeniusSquare(t4)
	t0 = pr.Ext12.Mul(t2, t0)
	t2 = pr.Ext12.Conjugate(e)
	t2 = pr.Ext12.Mul(t2, t3)
	t2 = pr.Ext12.FrobeniusCube(t2)
	t0 = pr.Ext12.Mul(t2, t0)

	return t0
}

// AssertFinalExponentiationIsOne checks that a Miller function output x lies in the
// same equivalence class as the reduced pairing. This replaces the final
// exponentiation step in-circuit.
// The method follows Section 4 of [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) AssertFinalExponentiationIsOne(a *GTEl) {
	tower := pr.Ext12.ToTower(a)

	res, err := pr.curveF.NewHint(finalExpHint, 18, tower[0], tower[1], tower[2], tower[3], tower[4], tower[5], tower[6], tower[7], tower[8], tower[9], tower[10], tower[11])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	nine := big.NewInt(9)
	residueWitness := pr.Ext12.FromTower([12]*baseEl{res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7], res[8], res[9], res[10], res[11]})

	// Constrain residueWitness to be invertible (non-zero). The check below,
	// x·cubicNonResiduePower == residueWitness^λ, is homogeneous in the hint
	// outputs residueWitness and cubicNonResiduePower, so the all-zero witness
	// would satisfy it (0 == 0) for any x. Inverse asserts
	// residueWitness·residueWitness⁻¹ == 1, ruling that out.
	pr.Ext12.Inverse(residueWitness)

	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - 9 * a001
	//     A1  =  0
	//     A2  =  a010 - 9 * a011
	//     A3  =  0
	//     A4  =  a020 - 9 * a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	cubicNonResiduePower := GTEl{
		A0:  *pr.curveF.Sub(res[12], pr.curveF.MulConst(res[13], nine)),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(res[14], pr.curveF.MulConst(res[15], nine)),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(res[16], pr.curveF.MulConst(res[17], nine)),
		A5:  *pr.curveF.Zero(),
		A6:  *res[13],
		A7:  *pr.curveF.Zero(),
		A8:  *res[15],
		A9:  *pr.curveF.Zero(),
		A10: *res[17],
		A11: *pr.curveF.Zero(),
	}

	// Check that  x * cubicNonResiduePower == residueWitness^λ
	// where λ = 6u + 2 + q^3 - q^2 + q, with u the BN254 seed
	// and residueWitness, cubicNonResiduePower from the hint.
	t2 := pr.Ext12.Mul(&cubicNonResiduePower, a)

	t1 := pr.Ext12.FrobeniusCube(residueWitness)
	t0 := pr.Ext12.FrobeniusSquare(residueWitness)
	t1 = pr.Ext12.DivUnchecked(t1, t0)
	t0 = pr.Ext12.Frobenius(residueWitness)
	t1 = pr.Ext12.Mul(t1, t0)

	// exponentiation by U=6u+2
	t0 = pr.Ext12.ExpByU(residueWitness)

	t0 = pr.Ext12.Mul(t0, t1)

	pr.AssertIsEqual(t0, t2)
}

// PairingCheck calculates the reduced pairing for a set of points and asserts
// if the result is one:
//
//	∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function checks that the Qᵢ are in the correct subgroup, but does not
// check Pᵢ. See AssertIsOnG1.
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
	residueWitnessInv := pr.Ext12.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]})

	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - 9 * a001
	//     A1  =  0
	//     A2  =  a010 - 9 * a011
	//     A3  =  0
	//     A4  =  a020 - 9 * a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	nine := big.NewInt(9)
	cubicNonResiduePower := GTEl{
		A0:  *pr.curveF.Sub(hint[12], pr.curveF.MulConst(hint[13], nine)),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(hint[14], pr.curveF.MulConst(hint[15], nine)),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(hint[16], pr.curveF.MulConst(hint[17], nine)),
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

	// Check that  res * cubicNonResiduePower * residueWitnessInv^λ' == 1
	// where λ' = q^3 - q^2 + q, with u the BN254 seed
	// and residueWitnessInv, cubicNonResiduePower from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{6x₀+2} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	t2 := pr.Ext12.Mul(&cubicNonResiduePower, res)

	t1 := pr.FrobeniusCube(residueWitnessInv)
	t0 := pr.FrobeniusSquare(residueWitnessInv)
	t1 = pr.Ext12.DivUnchecked(t1, t0)
	t0 = pr.Frobenius(residueWitnessInv)
	t1 = pr.Ext12.Mul(t1, t0)

	t2 = pr.Ext12.Mul(t2, t1)

	pr.AssertIsEqual(t2, pr.Ext12.One())

	return nil
}

func (pr *Pairing) IsEqual(x, y *GTEl) frontend.Variable {
	return pr.Ext12.IsEqual(x, y)
}

func (pr *Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
}

func (pr *Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
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
				R0: fields_bn254.E2{
					A0: *pr.curveF.Mux(sel, lineR0A0...),
					A1: *pr.curveF.Mux(sel, lineR0A1...),
				},
				R1: fields_bn254.E2{
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

func (pr *Pairing) computeTwistEquation(Q *G2Affine) (left, right *fields_bn254.E2) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=3/(9+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 3/(9+u), and continue
	selector := pr.api.And(pr.Ext2.IsZero(&Q.P.X), pr.Ext2.IsZero(&Q.P.Y))
	b := pr.Ext2.Select(selector, pr.Ext2.Zero(), pr.bTwist)

	left = pr.Ext2.Square(&Q.P.Y)
	right = pr.Ext2.Cube(&Q.P.X)
	right = pr.Ext2.Add(right, b)
	return left, right
}

func (pr *Pairing) AssertIsOnTwist(Q *G2Affine) {
	left, right := pr.computeTwistEquation(Q)
	pr.Ext2.AssertIsEqual(left, right)
}

// IsOnTwist returns a boolean indicating if the G2 point is in the twist.
func (pr *Pairing) IsOnTwist(Q *G2Affine) frontend.Variable {
	left, right := pr.computeTwistEquation(Q)
	diff := pr.Ext2.Sub(left, right)
	return pr.Ext2.IsZero(diff)
}

func (pr *Pairing) AssertIsOnG1(P *G1Affine) {
	// BN254 has a prime order, so we only
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)
}

// computeG2ShortVector computes ψ³([2x₀]Q) - ψ²([x₀]Q) - ψ([x₀]Q) - [x₀]Q
func (pr *Pairing) computeG2ShortVector(Q *G2Affine) (_Q *G2Affine) {
	// [x₀]Q
	xQ := pr.g2.scalarMulBySeed(Q)
	// ψ([x₀]Q)
	psixQ := pr.g2.psi(xQ)
	// ψ²([x₀]Q) = -ϕ([x₀]Q)
	psi2xQ := pr.g2.phi(xQ)
	// ψ³([2x₀]Q)
	psi3xxQ := pr.g2.double(psi2xQ)
	psi3xxQ = pr.g2.psi(psi3xxQ)

	// _Q = ψ³([2x₀]Q) - ψ²([x₀]Q) - ψ([x₀]Q) - [x₀]Q
	_Q = pr.g2.sub(psi3xxQ, psi2xQ)
	_Q = pr.g2.sub(_Q, psixQ)
	_Q = pr.g2.sub(_Q, xQ)
	return _Q
}

func (pr *Pairing) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	pr.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	// 		[r]Q == 0 <==>  ψ³([2x₀]Q) - ψ²([x₀]Q) - ψ([x₀]Q) - [x₀]Q == Q
	// This is a valid short vector since x₀ ≠ 5422 mod 2196.
	// See Sec. 3.1.2 (Example 1) in https://eprint.iacr.org/2022/348.
	_Q := pr.computeG2ShortVector(Q)
	pr.g2.AssertIsEqual(Q, _Q)
}

// IsOnG2 returns a boolean indicating if the G2 point is on the curve and in
// the subgroup.
func (pr *Pairing) IsOnG2(Q *G2Affine) frontend.Variable {
	// 1 - is Q on curve
	isOnCurve := pr.IsOnTwist(Q)
	// 2 - is Q in the subgroup
	_Q := pr.computeG2ShortVector(Q)
	isInSubgroup := pr.g2.IsEqual(Q, _Q)
	return pr.api.And(isOnCurve, isInSubgroup)
}

// loopCounter = 6x₀+2 = 29793968203157093288
//
// in 2-NAF
var loopCounter = [66]int8{
	0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
	0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
	-1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
	-1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
}

// MillerLoop computes the multi-Miller loop
//
//	∏ᵢ { fᵢ_{6x₀+2,Q}(P) · ℓᵢ_{[6x₀+2]Q,π(Q)}(P) · ℓᵢ_{[6x₀+2]Q+π(Q),-π²(Q)}(P) }
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
		xNegOverY[k] = pr.curveF.Mul(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	// Compute f_{6x₀+2,Q}(P)
	var prodLines [10]*baseEl
	res := pr.Ext12.One()

	var initInv GTEl
	if init != nil {
		res = init
		initInv = *pr.Ext12.Inverse(init)
	}

	j := len(loopCounter) - 2
	if first {
		// i = j
		// k = 0
		c3 := pr.Ext2.MulByElement(&lines[0][0][j].R0, xNegOverY[0])
		c4 := pr.Ext2.MulByElement(&lines[0][0][j].R1, yInv[0])
		nine := big.NewInt(9)
		res = &GTEl{
			A0:  *pr.curveF.One(),
			A1:  *pr.curveF.Sub(&c3.A0, pr.curveF.MulConst(&c3.A1, nine)),
			A2:  *pr.curveF.Zero(),
			A3:  *pr.curveF.Sub(&c4.A0, pr.curveF.MulConst(&c4.A1, nine)),
			A4:  *pr.curveF.Zero(),
			A5:  *pr.curveF.Zero(),
			A6:  *pr.curveF.Zero(),
			A7:  c3.A1,
			A8:  *pr.curveF.Zero(),
			A9:  c4.A1,
			A10: *pr.curveF.Zero(),
			A11: *pr.curveF.Zero(),
		}

		if n >= 2 {
			// k = 1, separately to avoid MulBy01379 (res × ℓ)
			// (res is also a line at this point, so we use Mul01379By01379 ℓ × ℓ)
			// line evaluation at P[1]
			prodLines = pr.Mul01379By01379(
				pr.Ext2.MulByElement(&lines[1][0][j].R0, xNegOverY[1]), //nolint: gosec // incorrectly flagged by gosec as out of bounds read (G602)
				pr.Ext2.MulByElement(&lines[1][0][j].R1, yInv[1]),      //nolint: gosec // incorrectly flagged by gosec as out of bounds read (G602)
				c3,
				c4,
			)
			res = &GTEl{
				A0:  *prodLines[0],
				A1:  *prodLines[1],
				A2:  *prodLines[2],
				A3:  *prodLines[3],
				A4:  *prodLines[4],
				A5:  *pr.curveF.Zero(),
				A6:  *prodLines[5],
				A7:  *prodLines[6],
				A8:  *prodLines[7],
				A9:  *prodLines[8],
				A10: *prodLines[9],
				A11: *pr.curveF.Zero(),
			}
		}

		if n >= 3 {
			// k >= 2: batch lines 2-by-2
			for k := 3; k < n; k += 2 {
				prodLines = pr.Mul01379By01379(
					pr.Ext2.MulByElement(&lines[k][0][j].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][0][j].R1, yInv[k]),
					pr.Ext2.MulByElement(&lines[k-1][0][j].R0, xNegOverY[k-1]),
					pr.Ext2.MulByElement(&lines[k-1][0][j].R1, yInv[k-1]),
				)
				res = pr.Ext12.MulBy012346789(res, prodLines)
			}
			// Handle remaining line if (n-2) is odd
			if (n-2)%2 != 0 {
				res = pr.MulBy01379(
					res,
					pr.Ext2.MulByElement(&lines[n-1][0][j].R0, xNegOverY[n-1]),
					pr.Ext2.MulByElement(&lines[n-1][0][j].R1, yInv[n-1]),
				)
			}
		}
		j--
	}

	for i := j; i >= 0; i-- {
		res = pr.Ext12.Square(res)

		switch loopCounter[i] {
		case 0:
			// Batch lines 2-by-2 across pairs using sparse×sparse multiplication
			for k := 1; k < n; k += 2 {
				prodLines = pr.Mul01379By01379(
					pr.Ext2.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.Ext2.MulByElement(&lines[k-1][0][i].R0, xNegOverY[k-1]),
					pr.Ext2.MulByElement(&lines[k-1][0][i].R1, yInv[k-1]),
				)
				res = pr.Ext12.MulBy012346789(res, prodLines)
			}
			// Handle odd remaining line
			if n%2 != 0 {
				res = pr.MulBy01379(
					res,
					pr.Ext2.MulByElement(&lines[n-1][0][i].R0, xNegOverY[n-1]),
					pr.Ext2.MulByElement(&lines[n-1][0][i].R1, yInv[n-1]),
				)
			}
		case 1:
			if init != nil {
				// multiply by init when bit=1
				res = pr.Ext12.Mul(res, init)
			}
			// ℓ × ℓ
			for k := 0; k < n; k++ {
				prodLines := pr.Mul01379By01379(
					pr.Ext2.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.Ext2.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][1][i].R1, yInv[k]),
				)
				// (ℓ × ℓ) × res
				res = pr.Ext12.MulBy012346789(res, prodLines)
			}
		case -1:
			if init != nil {
				// multiply by 1/init when bit=-1
				res = pr.Ext12.Mul(res, &initInv)
			}
			for k := 0; k < n; k++ {
				// ℓ × ℓ
				prodLines := pr.Mul01379By01379(
					pr.Ext2.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.Ext2.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][1][i].R1, yInv[k]),
				)
				// (ℓ × ℓ) × res
				res = pr.Ext12.MulBy012346789(res, prodLines)
			}
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}
	}

	// Compute  ℓ_{[6x₀+2]Q,π(Q)}(P) · ℓ_{[6x₀+2]Q+π(Q),-π²(Q)}(P)
	// lines evaluations at P
	// and ℓ × ℓ
	for k := 0; k < n; k++ {
		prodLines = pr.Mul01379By01379(
			pr.Ext2.MulByElement(&lines[k][0][65].R0, xNegOverY[k]),
			pr.Ext2.MulByElement(&lines[k][0][65].R1, yInv[k]),
			pr.Ext2.MulByElement(&lines[k][1][65].R0, xNegOverY[k]),
			pr.Ext2.MulByElement(&lines[k][1][65].R1, yInv[k]),
		)
		res = pr.Ext12.MulBy012346789(res, prodLines)
	}

	return res, nil
}

// doubleAndAddStep doubles p1 and adds or subs p2 to the result in affine coordinates, based on the isSub boolean.
// Then evaluates the lines going through p1 and p2 or -p2 (line1) and p1 and p1+p2 or p1-p2 (line2).
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleAndAddStep(p1, p2 *g2AffP, isSub bool) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP

	// compute λ1 = (y1-y2)/(x1-x2) or λ1 = (y1+y2)/(x1-x2) if isSub is true
	var n *fields_bn254.E2
	if isSub {
		n = pr.Ext2.Add(&p1.Y, &p2.Y)
	} else {
		n = pr.Ext2.Sub(&p1.Y, &p2.Y)
	}
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	λ1 := pr.divE2WithZeroGuard(n, d)

	// compute x3 =λ1²-x1-x2
	x30 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	x31 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	x3 := &fields_bn254.E2{A0: *x30, A1: *x31}

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
	x4 := &fields_bn254.E2{A0: *x40, A1: *x41}

	// compute y4 = λ2(x1 - x4)-y1
	y4 := pr.Ext2.Sub(&p1.X, x4)
	y40 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &y4.A0}, {&λ2.A1, &y4.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	y41 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &y4.A1}, {&λ2.A1, &y4.A0}, {&p1.Y.A1}}, []int{1, 1, -1})
	y4 = &fields_bn254.E2{A0: *y40, A1: *y41}

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
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x-xr)-y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {&λ.A1, &yr.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {&p1.Y.A1}}, []int{1, 1, -1})
	yr = &fields_bn254.E2{A0: *yr0, A1: *yr1}

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A0}, {&λ.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A1}, {&λ.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &p, &line

}

// addStep adds p1 and p2 in affine coordinates, and evaluates the line through p1 and p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) addStep(p1, p2 *g2AffP) (*g2AffP, *lineEvaluation) {

	// compute λ = (y2-y1)/(x2-x1)
	p2ypy := pr.Ext2.Sub(&p2.Y, &p1.Y)
	p2xpx := pr.Ext2.Sub(&p2.X, &p1.X)
	λ := pr.divE2WithZeroGuard(p2ypy, p2xpx)

	// xr = λ²-x1-x2
	xr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	xr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr) - y1
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {&λ.A1, &yr.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {&p1.Y.A1}}, []int{1, 1, -1})
	yr = &fields_bn254.E2{A0: *yr0, A1: *yr1}

	var res g2AffP
	res.X = *xr
	res.Y = *yr

	var line lineEvaluation
	line.R0 = *λ
	line.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A0}, {&λ.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A1}, {&λ.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &res, &line

}

// lineCompute computes the line through p1 and p2, but does not compute p1+p2.
func (pr *Pairing) lineCompute(p1, p2 *g2AffP) *lineEvaluation {

	// compute λ = (y2+y1)/(x2-x1)
	qypy := pr.Ext2.Add(&p1.Y, &p2.Y)
	qxpx := pr.Ext2.Sub(&p1.X, &p2.X)
	λ := pr.divE2WithZeroGuard(qypy, qxpx)

	var line lineEvaluation
	line.R0 = *λ
	line.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A0}, {&λ.A1, &p1.X.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	line.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A1}, {&λ.A1, &p1.X.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &line

}

// divE2WithZeroGuard computes n/d as a line slope, but when d == 0 it returns 0
// with the quotient *constrained* to 0 rather than left as a free (prover-chosen)
// hint value. A plain DivUnchecked(n, 0) only enforces λ·0 == n, i.e. 0 == 0,
// which leaves λ unconstrained; that is the soundness gap when Q = (0,0)
// (the point at infinity) is fed to the Miller loop and every affine line
// evaluation becomes 0/0. Non-degenerate steps (d ≠ 0) are unchanged, and the
// degenerate value matches the honest 0/0 = 0 convention, so completeness (incl.
// legitimate G2-infinity inputs) is preserved.
func (pr *Pairing) divE2WithZeroGuard(n, d *fields_bn254.E2) *fields_bn254.E2 {
	dIsZero := pr.Ext2.IsZero(d)
	dSafe := pr.Ext2.Select(dIsZero, pr.Ext2.One(), d)
	λ := pr.Ext2.DivUnchecked(n, dSafe)
	return pr.Ext2.Select(dIsZero, pr.Ext2.Zero(), λ)
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
	res = pr.Ext12.Mul(res, previous)
	return res, err
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
	residueWitness := pr.Ext12.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]})

	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - 9 * a001
	//     A1  =  0
	//     A2  =  a010 - 9 * a011
	//     A3  =  0
	//     A4  =  a020 - 9 * a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	nine := big.NewInt(9)
	cubicNonResiduePower := GTEl{
		A0:  *pr.curveF.Sub(hint[12], pr.curveF.MulConst(hint[13], nine)),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(hint[14], pr.curveF.MulConst(hint[15], nine)),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(hint[16], pr.curveF.MulConst(hint[17], nine)),
		A5:  *pr.curveF.Zero(),
		A6:  *hint[13],
		A7:  *pr.curveF.Zero(),
		A8:  *hint[15],
		A9:  *pr.curveF.Zero(),
		A10: *hint[17],
		A11: *pr.curveF.Zero(),
	}

	// residueWitnessInv = 1 / residueWitness
	residueWitnessInv := pr.Ext12.Inverse(residueWitness)

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

	// multiply by previous multi-Miller function
	res = pr.Ext12.Mul(res, previous)

	// Check that  res * cubicNonResiduePower * residueWitnessInv^λ' == 1
	// where λ' = q^3 - q^2 + q, with u the BN254 seed
	// and residueWitnessInv, cubicNonResiduePower from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{6x₀+2} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	t2 := pr.Ext12.Mul(&cubicNonResiduePower, res)

	t1 := pr.FrobeniusCube(residueWitnessInv)
	t0 := pr.FrobeniusSquare(residueWitness)
	t1 = pr.Ext12.Mul(t1, t0)
	t0 = pr.Frobenius(residueWitnessInv)
	t1 = pr.Ext12.Mul(t1, t0)

	t2 = pr.Ext12.Mul(t2, t1)

	return t2
}

// IsMillerLoopAndFinalExpOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and returns a boolean indicating if
// the result lies in the same equivalence class as the reduced pairing
// purported to be 1. This check replaces the final exponentiation step
// in-circuit and follows Section 4 of [On Proving Pairings] paper by A.
// Novakovic and L. Eagen.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) IsMillerLoopAndFinalExpOne(P *G1Affine, Q *G2Affine, previous *GTEl) frontend.Variable {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)

	res := pr.IsEqual(t2, pr.Ext12.One())
	return res
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
