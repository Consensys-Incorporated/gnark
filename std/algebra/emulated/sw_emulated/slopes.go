package sw_emulated

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

// This file implements the slope computations used by the point addition and
// doubling formulas with hinted witnesses certified by single deferred
// zero-assertions, instead of the [emulated.Field.Div] pattern which costs
// two deferred checks (a multiplication check and an equality check).
//
// The constraint content is unchanged: Div asserts λ·den = num (mod p), and
// so does the zero-assertion here. In particular the exceptional behavior is
// identical: when den ≡ 0 and num ≢ 0 the assertion is unsatisfiable, and
// when den ≡ num ≡ 0 the slope is unconstrained (callers exclude or handle
// both cases exactly as they did with Div).

// assertedRatio returns λ = num/den certified by the single deferred
// assertion λ·den − num ≡ 0 (mod p).
func (c *Curve[B, S]) assertedRatio(num, den *emulated.Element[B]) *emulated.Element[B] {
	lams, err := c.baseApi.NewHint(ratioHint, 1, num, den)
	if err != nil {
		panic(fmt.Sprintf("ratio hint: %v", err))
	}
	lam := lams[0]
	c.baseApi.AssertEvalIsZero(
		[][]*emulated.Element[B]{{lam, den}, {num}},
		[]int{1, -1},
	)
	return lam
}

// tangentSlope returns the tangent slope λ = (3x² + a)/(2y) at p, certified
// by a single deferred zero-assertion without materializing x².
//
// When unified is set, y ≡ 0 forces λ = 0 while keeping the assertion
// satisfiable (matching the dummy-denominator Select pattern of the unified
// formulas): the certified relation becomes λ·(2y + z) − (1−z)·(3x² + a) ≡ 0
// with z the y ≡ 0 indicator bit. Otherwise y ≡ 0 makes the circuit
// unsatisfiable, as with the previous Div-based tangent.
func (c *Curve[B, S]) tangentSlope(p *AffinePoint[B], unified bool) *emulated.Element[B] {
	var lams []*emulated.Element[B]
	var err error
	if c.addA {
		lams, err = c.baseApi.NewHint(tangentHintA, 1, &p.X, &p.Y, &c.a)
	} else {
		lams, err = c.baseApi.NewHint(tangentHint, 1, &p.X, &p.Y)
	}
	if err != nil {
		panic(fmt.Sprintf("tangent hint: %v", err))
	}
	lam := lams[0]
	if !unified {
		// λ·2y − 3x² − a ≡ 0
		terms := [][]*emulated.Element[B]{{lam, &p.Y}, {&p.X, &p.X}}
		coefs := []int{2, -3}
		if c.addA {
			terms = append(terms, []*emulated.Element[B]{&c.a})
			coefs = append(coefs, -1)
		}
		c.baseApi.AssertEvalIsZero(terms, coefs)
		return lam
	}
	// unified: z = 1 iff y ≡ 0. The multiplier 2y + z never vanishes: it is
	// 2y ≠ 0 when y ≢ 0 and 1 when y ≡ 0, so λ is always pinned; in the
	// latter case the right-hand side is zeroed by 1−z and λ = 0.
	isYZero := c.baseApi.IsZero(&p.Y)
	zEl := c.baseApi.FromBits(isYZero)
	nzEl := c.baseApi.Sub(c.baseApi.One(), zEl)
	terms := [][]*emulated.Element[B]{{lam, &p.Y}, {lam, zEl}, {nzEl, &p.X, &p.X}}
	coefs := []int{2, 1, -3}
	if c.addA {
		terms = append(terms, []*emulated.Element[B]{nzEl, &c.a})
		coefs = append(coefs, -1)
	}
	c.baseApi.AssertEvalIsZero(terms, coefs)
	return lam
}

// ratioHint computes num/den modulo the emulated modulus, or 0 when
// den ≡ 0 (the zero-assertion then decides satisfiability).
func ratioHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		den := new(big.Int).Mod(in[1], p)
		if den.Sign() == 0 {
			out[0].SetInt64(0)
			return nil
		}
		den.ModInverse(den, p)
		out[0].Mod(in[0], p)
		out[0].Mul(out[0], den).Mod(out[0], p)
		return nil
	})
}

// tangentHint computes 3x²/(2y) modulo the emulated modulus (curves with
// a = 0), or 0 when y ≡ 0.
func tangentHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		return tangentSlopeVal(p, in[0], in[1], nil, out[0])
	})
}

// tangentHintA computes (3x² + a)/(2y) modulo the emulated modulus, or 0
// when y ≡ 0.
func tangentHintA(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 3 || len(out) != 1 {
			return errors.New("expecting three inputs and one output")
		}
		return tangentSlopeVal(p, in[0], in[1], in[2], out[0])
	})
}

func tangentSlopeVal(p, x, y, a, out *big.Int) error {
	den := new(big.Int).Lsh(y, 1)
	den.Mod(den, p)
	if den.Sign() == 0 {
		out.SetInt64(0)
		return nil
	}
	den.ModInverse(den, p)
	num := new(big.Int).Mul(x, x)
	num.Mod(num, p)
	num.Mul(num, big.NewInt(3))
	if a != nil {
		num.Add(num, a)
	}
	num.Mod(num, p)
	out.Mul(num, den).Mod(out, p)
	return nil
}

// unifiedSlopeHint computes the slope of the j-invariant-0 unified addition:
// the tangent 3x1²/(2y1) when x1 ≡ x2, the chord (y2−y1)/(x2−x1) otherwise.
// When x1 ≡ x2 but the tangent denominator 2y1 vanishes (doubling a rational
// 2-torsion point such as (1,0) on BW6-761), it returns the numerator 3x1²:
// the caller substitutes a dummy denominator denSafe = 1 in that case, so the
// deferred assertion λ·denSafe − 3x1² ≡ 0 demands λ = 3x1² for the honest
// prover. Returning 0 there (as a plain tangent hint would) makes the honest
// witness fail while a forged hint could pass, so we mirror denSafe = 1 here.
// The λ this yields is discarded by the caller's select and the result is
// overridden with O. Inputs: x1, y1, x2, y2.
func unifiedSlopeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 4 || len(out) != 1 {
			return errors.New("expecting four inputs and one output")
		}
		x1 := new(big.Int).Mod(in[0], p)
		y1 := new(big.Int).Mod(in[1], p)
		x2 := new(big.Int).Mod(in[2], p)
		y2 := new(big.Int).Mod(in[3], p)
		dx := new(big.Int).Sub(x2, x1)
		dx.Mod(dx, p)
		if dx.Sign() == 0 {
			den := new(big.Int).Lsh(y1, 1)
			den.Mod(den, p)
			if den.Sign() == 0 {
				// degenerate tangent (2y1 ≡ 0): denSafe = 1 downstream, so
				// return the bare numerator 3x1².
				out[0].Mul(x1, x1)
				out[0].Mul(out[0], big.NewInt(3)).Mod(out[0], p)
				return nil
			}
			return tangentSlopeVal(p, x1, y1, nil, out[0])
		}
		dx.ModInverse(dx, p)
		out[0].Sub(y2, y1)
		out[0].Mul(out[0], dx).Mod(out[0], p)
		return nil
	})
}

// bjSlopeHint computes the Brier-Joye unified slope
// ((x1+x2)² − x1·x2 + a)/(y1 + y2) used on j ≠ 0 curves. When y1 + y2 ≡ 0 it
// returns the numerator itself, matching the dummy-1-denominator semantics of
// the caller (the result is then discarded by a select). Inputs: x1, y1, x2,
// y2, a.
func bjSlopeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		x1 := new(big.Int).Mod(in[0], p)
		y1 := new(big.Int).Mod(in[1], p)
		x2 := new(big.Int).Mod(in[2], p)
		y2 := new(big.Int).Mod(in[3], p)
		num := new(big.Int).Add(x1, x2)
		num.Mul(num, num)
		tmp := new(big.Int).Mul(x1, x2)
		num.Sub(num, tmp)
		num.Add(num, in[4])
		num.Mod(num, p)
		den := new(big.Int).Add(y1, y2)
		den.Mod(den, p)
		if den.Sign() == 0 {
			out[0].Set(num)
			return nil
		}
		den.ModInverse(den, p)
		out[0].Mul(num, den).Mod(out[0], p)
		return nil
	})
}

// implicitAcc carries the accumulator of a double-and-add chain with its
// y-coordinate in implicit form
//
//	y = lam·(xT − x) − yT
//
// where (xT, yT) is the last added point and lam the slope of that addition.
// The expression is degree-1 in materialized values, so consecutive chain
// steps can consume it inside their deferred zero-assertions instead of
// materializing y at every iteration (one Eval saved per iteration). The
// encoding resets at every addition — the implicit form always references
// only the most recent slope — so expressions do not grow with chain length.
type implicitAcc[B emulated.FieldParams] struct {
	x   *emulated.Element[B]
	lam *emulated.Element[B]
	xT  *emulated.Element[B]
	yT  *emulated.Element[B]
}

// implicitFromAffine encodes a materialized point: with xT = x the lam term
// vanishes identically for any lam, and yT = −y recovers y.
func (c *Curve[B, S]) implicitFromAffine(p *AffinePoint[B]) *implicitAcc[B] {
	return &implicitAcc[B]{x: &p.X, lam: &p.X, xT: &p.X, yT: c.baseApi.Neg(&p.Y)}
}

// implicitToAffine materializes the accumulator y-coordinate.
func (c *Curve[B, S]) implicitToAffine(acc *implicitAcc[B]) *AffinePoint[B] {
	y := c.baseApi.Eval(
		[][]*emulated.Element[B]{{acc.lam, c.baseApi.Sub(acc.xT, acc.x)}, {acc.yT}},
		[]int{1, -1},
	)
	return &AffinePoint[B]{X: *acc.x, Y: *y}
}

// implicitDoubleAndAdd sets acc = 2·acc + q using incomplete formulas with
// the accumulator y kept implicit throughout: the doubling tangent and the
// addition chord are each certified by a single deferred zero-assertion which
// consumes the implicit y, and only the two x-coordinates are materialized.
//
// ⚠️  Incomplete: requires j-invariant 0 (a = 0), acc not 2-torsion and
// q ≠ ±[2]acc — the same exceptional envelope as the ELM-based doubleAndAdd
// it replaces in the incomplete scalar-multiplication loops, where the
// accumulator anchoring excludes these cases for honest witnesses.
func (c *Curve[B, S]) implicitDoubleAndAdd(acc *implicitAcc[B], q *AffinePoint[B]) {
	// tangent: λd·2y = 3x² with y = lam·(xT − x) − yT:
	//   2·λd·lam·(xT − x) − 2·λd·yT − 3·x² ≡ 0
	lamDs, err := c.baseApi.NewHint(implicitTangentHint, 1, acc.lam, acc.x, acc.xT, acc.yT)
	if err != nil {
		panic(fmt.Sprintf("implicit tangent hint: %v", err))
	}
	lamD := lamDs[0]
	dxPrev := c.baseApi.Sub(acc.xT, acc.x)
	c.baseApi.AssertEvalIsZero(
		[][]*emulated.Element[B]{{lamD, acc.lam, dxPrev}, {lamD, acc.yT}, {acc.x, acc.x}},
		[]int{2, -2, -3},
	)
	// xd = λd² − 2x
	xd := c.baseApi.Eval([][]*emulated.Element[B]{{lamD, lamD}, {acc.x}}, []int{1, -2})

	// chord through q: λa·(xq − xd) = yq − yd with
	// yd = λd·(x − xd) − y = λd·(x − xd) − lam·(xT − x) + yT:
	//   λa·(xq − xd) + λd·(x − xd) − lam·(xT − x) + yT − yq ≡ 0
	lamAs, err := c.baseApi.NewHint(implicitChordHint, 1, acc.lam, acc.x, acc.xT, acc.yT, lamD, xd, &q.X, &q.Y)
	if err != nil {
		panic(fmt.Sprintf("implicit chord hint: %v", err))
	}
	lamA := lamAs[0]
	dxq := c.baseApi.Sub(&q.X, xd)
	dxd := c.baseApi.Sub(acc.x, xd)
	c.baseApi.AssertEvalIsZero(
		[][]*emulated.Element[B]{{lamA, dxq}, {lamD, dxd}, {acc.lam, dxPrev}, {acc.yT}, {&q.Y}},
		[]int{1, 1, -1, 1, -1},
	)
	// xa = λa² − xd − xq
	xa := c.baseApi.Eval([][]*emulated.Element[B]{{lamA, lamA}, {xd}, {&q.X}}, []int{1, -1, -1})

	// the new implicit y references only this addition: y = λa·(xq − xa) − yq
	acc.x = xa
	acc.lam = lamA
	acc.xT = &q.X
	acc.yT = &q.Y
}

// implicitYVal recomputes the implicit accumulator y = lam·(xT − x) − yT.
func implicitYVal(p, lam, x, xT, yT *big.Int) *big.Int {
	y := new(big.Int).Sub(xT, x)
	y.Mul(y, lam).Sub(y, yT).Mod(y, p)
	return y
}

// implicitTangentHint computes the doubling slope 3x²/(2y) (a = 0 curves)
// with y in implicit form. Inputs: lam, x, xT, yT. Returns 0 when y ≡ 0.
func implicitTangentHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 4 || len(out) != 1 {
			return errors.New("expecting four inputs and one output")
		}
		lam := new(big.Int).Mod(in[0], p)
		x := new(big.Int).Mod(in[1], p)
		xT := new(big.Int).Mod(in[2], p)
		yT := new(big.Int).Mod(in[3], p)
		y := implicitYVal(p, lam, x, xT, yT)
		return tangentSlopeVal(p, x, y, nil, out[0])
	})
}

// implicitChordHint computes the second slope of the implicit double-and-add:
// λa = (yq − yd)/(xq − xd) with yd = λd·(x − xd) − y and y in implicit form.
// Inputs: lam, x, xT, yT, λd, xd, xq, yq. Returns 0 when xq ≡ xd.
func implicitChordHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(p *big.Int, in, out []*big.Int) error {
		if len(in) != 8 || len(out) != 1 {
			return errors.New("expecting eight inputs and one output")
		}
		lam := new(big.Int).Mod(in[0], p)
		x := new(big.Int).Mod(in[1], p)
		xT := new(big.Int).Mod(in[2], p)
		yT := new(big.Int).Mod(in[3], p)
		lamD := new(big.Int).Mod(in[4], p)
		xd := new(big.Int).Mod(in[5], p)
		xq := new(big.Int).Mod(in[6], p)
		yq := new(big.Int).Mod(in[7], p)
		y := implicitYVal(p, lam, x, xT, yT)
		yd := new(big.Int).Sub(x, xd)
		yd.Mul(yd, lamD).Sub(yd, y).Mod(yd, p)
		den := new(big.Int).Sub(xq, xd)
		den.Mod(den, p)
		if den.Sign() == 0 {
			out[0].SetInt64(0)
			return nil
		}
		den.ModInverse(den, p)
		out[0].Sub(yq, yd)
		out[0].Mul(out[0], den).Mod(out[0], p)
		return nil
	})
}
