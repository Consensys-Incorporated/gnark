package sw_emulated

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fp_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// classicGLVDecomposition is a (possibly dishonest) classic-GLV decomposition
// s = σ1·s1 + λ·σ2·s2 mod r with s1, s2 ≥ 0.
type classicGLVDecomposition struct {
	s1, s2         *big.Int
	neg1, neg2     bool
	s              *big.Int // the scalar it decomposes
	exceptionIndex int      // loop index i at which 2·Acc == T (informational)
}

// forgedDecomposeScalarG1 replaces decomposeScalarG1 and returns a fixed
// decomposition regardless of the input scalar.
func forgedDecomposeScalarG1(d classicGLVDecomposition) solver.Hint {
	return func(mod *big.Int, inputs, outputs []*big.Int) error {
		return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
			moduli := hc.EmulatedModuli()
			_, nativeOutputs := hc.NativeInputsOutputs()
			_, emuOutputs := hc.InputsOutputs(moduli[0])
			emuOutputs[0].Set(d.s1)
			emuOutputs[1].Set(d.s2)
			nativeOutputs[0].SetUint64(0)
			nativeOutputs[1].SetUint64(0)
			if d.neg1 {
				nativeOutputs[0].SetUint64(1)
			}
			if d.neg2 {
				nativeOutputs[1].SetUint64(1)
			}
			return nil
		})
	}
}

// findExceptionalClassicGLVDecomposition builds a bounded decomposition that
// drives the last merged iteration (i = 2) of scalarMulGLV into
// doubleAndAdd(U, U).
//
// Before the last iteration the accumulator is [σ1·A1]Q + [σ2·A2]Φ(Q) with
// A = 2⌊s/8⌋+1, and the table entry is T = [σ1·t1]Q + [σ2·t2]Φ(Q) with
// t = 2·d2 + d1, dj = 2·bit_j − 1. doubleAndAdd([2]Acc, T) has equal inputs
// iff (σ1(2A1−t1), σ2(2A2−t2)) lies in the GLV lattice
// L = {(u, v) : u + λv ≡ 0 mod r}. Any (u, v) ∈ L with both coordinates odd
// and |u|, |v| ≲ 2^(nbits−1) yields such a decomposition, and the reduced GLV
// basis has vectors of size ≈ √r, so they fit the 2^nbits range check.
func findExceptionalClassicGLVDecomposition(t *testing.T, r, lambda *big.Int, nbits int) classicGLVDecomposition {
	t.Helper()
	var lat ecc.Lattice
	ecc.PrecomputeLattice(r, lambda, &lat)

	// subscalar s ≥ 0 and table digit t such that 2A − t = U, U > 0 odd.
	split := func(U *big.Int) (*big.Int, bool) {
		for _, tt := range []int64{3, 1, -1, -3} {
			A := new(big.Int).Add(U, big.NewInt(tt))
			if A.Bit(0) != 0 {
				return nil, false
			}
			A.Rsh(A, 1)
			if A.Sign() <= 0 || A.Bit(0) != 1 {
				continue
			}
			// t = 2·d2 + d1 with dj = ±1  <=>  (bit2, bit1)
			var low int64
			switch tt {
			case 3:
				low = 0b110
			case 1:
				low = 0b100
			case -1:
				low = 0b010
			case -3:
				low = 0b000
			}
			low |= 1 // bit 0: no final correction
			s := new(big.Int).Sub(A, big.NewInt(1))
			s.Lsh(s, 2) // 8·(A−1)/2
			s.Add(s, big.NewInt(low))
			return s, true
		}
		return nil, false
	}

	for a := int64(-3); a <= 3; a++ {
		for b := int64(-3); b <= 3; b++ {
			u := new(big.Int).Mul(big.NewInt(a), &lat.V1[0])
			u.Add(u, new(big.Int).Mul(big.NewInt(b), &lat.V2[0]))
			v := new(big.Int).Mul(big.NewInt(a), &lat.V1[1])
			v.Add(v, new(big.Int).Mul(big.NewInt(b), &lat.V2[1]))
			if u.Bit(0) == 0 || v.Bit(0) == 0 {
				continue // also excludes zero coordinates
			}
			chk := new(big.Int).Mul(v, lambda)
			chk.Add(chk, u).Mod(chk, r)
			if chk.Sign() != 0 {
				t.Fatalf("lattice vector (%s, %s) not in GLV lattice", u, v)
			}
			s1, ok1 := split(new(big.Int).Abs(u))
			s2, ok2 := split(new(big.Int).Abs(v))
			if !ok1 || !ok2 || s1.BitLen() > nbits || s2.BitLen() > nbits {
				continue
			}
			d := classicGLVDecomposition{s1: s1, s2: s2, neg1: u.Sign() < 0, neg2: v.Sign() < 0, exceptionIndex: 2}
			sv1 := new(big.Int).Set(s1)
			if d.neg1 {
				sv1.Neg(sv1)
			}
			sv2 := new(big.Int).Set(s2)
			if d.neg2 {
				sv2.Neg(sv2)
			}
			d.s = new(big.Int).Mul(sv2, lambda)
			d.s.Add(d.s, sv1).Mod(d.s, r)
			return d
		}
	}
	t.Fatal("no exceptional decomposition found")
	return classicGLVDecomposition{}
}

// classicGLVForgeryCircuit proves that ScalarMul(P, S) differs from the honest
// [S]P. It must be unsatisfiable for every witness.
type classicGLVForgeryCircuit[T, S emulated.FieldParams] struct {
	P, Honest AffinePoint[T]
	S         emulated.Element[S]
}

func (c *classicGLVForgeryCircuit[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	cr.AssertIsOnCurve(&c.P)
	res := cr.ScalarMul(&c.P, &c.S)
	eqX := cr.baseApi.IsZero(cr.baseApi.Sub(&res.X, &c.Honest.X))
	eqY := cr.baseApi.IsZero(cr.baseApi.Sub(&res.Y, &c.Honest.Y))
	api.AssertIsEqual(api.And(eqX, eqY), 0)
	return nil
}

// TestClassicGLVExceptionalAddForgery is a regression test for the classic-GLV
// main loop calling the incomplete doubleAndAdd on equal inputs. The prover
// only replaces the GLV decomposition hint with a bounded but non-honest
// decomposition that satisfies s1 + λ·s2 ≡ s mod r; the chord slope is then
// unconstrained and ScalarMul returns a value different from [s]P.
func TestClassicGLVExceptionalAddForgery(t *testing.T) {
	t.Run("BLS12-381/reporter", func(t *testing.T) {
		// s = 9(λ+1), s1 = 2λ+9, s2 = 7 (from the report).
		params := GetBLS12381Params()
		var fr emulated.BLS12381Fr
		lambda := params.Eigenvalue
		s1 := new(big.Int).Lsh(lambda, 1)
		s1.Add(s1, big.NewInt(9))
		s := new(big.Int).Add(lambda, big.NewInt(1))
		s.Mul(s, big.NewInt(9)).Mod(s, fr.Modulus())
		testClassicGLVForgeryBLS12381(t, classicGLVDecomposition{s1: s1, s2: big.NewInt(7), s: s})
	})
	t.Run("BLS12-381/lattice", func(t *testing.T) {
		var fr emulated.BLS12381Fr
		d := findExceptionalClassicGLVDecomposition(t, fr.Modulus(), GetBLS12381Params().Eigenvalue, fr.Modulus().BitLen()>>1+2)
		testClassicGLVForgeryBLS12381(t, d)
	})
	t.Run("BW6-761/lattice", func(t *testing.T) {
		var fr emulated.BW6761Fr
		d := findExceptionalClassicGLVDecomposition(t, fr.Modulus(), GetBW6761Params().Eigenvalue, fr.Modulus().BitLen()>>1+2)
		_, _, g, _ := bw6761.Generators()
		var honest bw6761.G1Affine
		honest.ScalarMultiplication(&g, d.s)
		circuit := classicGLVForgeryCircuit[emulated.BW6761Fp, emulated.BW6761Fr]{}
		witness := classicGLVForgeryCircuit[emulated.BW6761Fp, emulated.BW6761Fr]{
			P:      AffinePoint[emulated.BW6761Fp]{X: emulated.ValueOf[emulated.BW6761Fp](g.X), Y: emulated.ValueOf[emulated.BW6761Fp](g.Y)},
			Honest: AffinePoint[emulated.BW6761Fp]{X: emulated.ValueOf[emulated.BW6761Fp](honest.X), Y: emulated.ValueOf[emulated.BW6761Fp](honest.Y)},
			S:      emulated.ValueOf[emulated.BW6761Fr](d.s),
		}
		if err := test.IsSolved(&circuit, &witness, testCurve.ScalarField()); err == nil {
			t.Fatal("sanity: honest decomposition must give [s]P")
		}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(),
			test.WithReplacementHint(solver.GetHintID(decomposeScalarG1), forgedDecomposeScalarG1(d)))
		if err == nil {
			t.Fatalf("ScalarMul returned a point != [s]P for s1=%s s2=%s (neg %v,%v)", d.s1, d.s2, d.neg1, d.neg2)
		}
	})
}

func testClassicGLVForgeryBLS12381(t *testing.T, d classicGLVDecomposition) {
	t.Helper()
	_, _, g, _ := bls12381.Generators()
	var honest bls12381.G1Affine
	honest.ScalarMultiplication(&g, d.s)
	circuit := classicGLVForgeryCircuit[emulated.BLS12381Fp, emulated.BLS12381Fr]{}
	witness := classicGLVForgeryCircuit[emulated.BLS12381Fp, emulated.BLS12381Fr]{
		P:      AffinePoint[emulated.BLS12381Fp]{X: emulated.ValueOf[emulated.BLS12381Fp](g.X), Y: emulated.ValueOf[emulated.BLS12381Fp](g.Y)},
		Honest: AffinePoint[emulated.BLS12381Fp]{X: emulated.ValueOf[emulated.BLS12381Fp](honest.X), Y: emulated.ValueOf[emulated.BLS12381Fp](honest.Y)},
		S:      emulated.ValueOf[emulated.BLS12381Fr](d.s),
	}
	if err := test.IsSolved(&circuit, &witness, testCurve.ScalarField()); err == nil {
		t.Fatal("sanity: honest decomposition must give [s]P")
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(decomposeScalarG1), forgedDecomposeScalarG1(d)))
	if err == nil {
		t.Fatalf("ScalarMul returned a point != [s]P for s1=%s s2=%s (neg %v,%v)", d.s1, d.s2, d.neg1, d.neg2)
	}
}

// classicGLVOffSubgroupCircuit is the pattern from the second report:
// on-curve check, ScalarMul, equality with a claimed result.
type classicGLVOffSubgroupCircuit[T, S emulated.FieldParams] struct {
	P, Q AffinePoint[T]
	S    emulated.Element[S]
}

func (c *classicGLVOffSubgroupCircuit[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	cr.AssertIsOnCurve(&c.P)
	res := cr.ScalarMul(&c.P, &c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// TestClassicGLVOffSubgroupInput is a regression test for the classic-GLV
// branch accepting an on-curve point outside the prime-order subgroup. With
// honest hints the gadget computes [s1]P + [s2]Φ(P), which differs from [s]P
// because Φ does not act as [λ] on the torsion part of P; a circuit
// constraining ScalarMul(P, s) == Q thus accepts Q != [s]P.
func TestClassicGLVOffSubgroupInput(t *testing.T) {
	t.Run("BLS12-381", func(t *testing.T) {
		var fr emulated.BLS12381Fr
		params := GetBLS12381Params()
		P := bls12381OffSubgroupPoint(t)
		s := big.NewInt(0).SetBytes([]byte("classic glv off-subgroup scalar"))
		s.Mod(s, fr.Modulus())
		var omega fp_bls381.Element
		omega.SetBigInt(params.ThirdRootOne)
		phiP := P
		phiP.X.Mul(&phiP.X, &omega)
		var glvRes, want bls12381.G1Affine
		glvRes = glvCombineBLS12381(t, &P, &phiP, s, fr.Modulus(), params.Eigenvalue)
		want = mulNaiveBLS12381(&P, s)
		if glvRes.Equal(&want) {
			t.Fatal("test vector does not distinguish [s1]P+[s2]Φ(P) from [s]P")
		}
		circuit := classicGLVOffSubgroupCircuit[emulated.BLS12381Fp, emulated.BLS12381Fr]{}
		witness := classicGLVOffSubgroupCircuit[emulated.BLS12381Fp, emulated.BLS12381Fr]{
			P: AffinePoint[emulated.BLS12381Fp]{X: emulated.ValueOf[emulated.BLS12381Fp](P.X), Y: emulated.ValueOf[emulated.BLS12381Fp](P.Y)},
			Q: AffinePoint[emulated.BLS12381Fp]{X: emulated.ValueOf[emulated.BLS12381Fp](glvRes.X), Y: emulated.ValueOf[emulated.BLS12381Fp](glvRes.Y)},
			S: emulated.ValueOf[emulated.BLS12381Fr](s),
		}
		if err := solveCatchingPanic(&circuit, &witness); err == nil {
			t.Fatal("ScalarMul accepted an off-subgroup input and returned Q != [s]P")
		}
	})
	t.Run("BW6-761", func(t *testing.T) {
		var fr emulated.BW6761Fr
		params := GetBW6761Params()
		P := bw6761OffSubgroupPoint(t)
		s := big.NewInt(0).SetBytes([]byte("classic glv off-subgroup scalar"))
		s.Mod(s, fr.Modulus())
		var lat ecc.Lattice
		ecc.PrecomputeLattice(fr.Modulus(), params.Eigenvalue, &lat)
		sp := ecc.SplitScalar(s, &lat)
		var Pj, phiPj, a, b, want bw6761.G1Jac
		Pj.FromAffine(&P)
		phi := P
		var omega fp_bw6761.Element
		omega.SetBigInt(params.ThirdRootOne)
		phi.X.Mul(&phi.X, &omega)
		phiPj.FromAffine(&phi)
		a = mulNaiveBW6761(&Pj, &sp[0])
		b = mulNaiveBW6761(&phiPj, &sp[1])
		a.AddAssign(&b)
		want = mulNaiveBW6761(&Pj, s)
		if a.Equal(&want) {
			t.Fatal("test vector does not distinguish [s1]P+[s2]Φ(P) from [s]P")
		}
		var glvRes bw6761.G1Affine
		glvRes.FromJacobian(&a)
		circuit := classicGLVOffSubgroupCircuit[emulated.BW6761Fp, emulated.BW6761Fr]{}
		witness := classicGLVOffSubgroupCircuit[emulated.BW6761Fp, emulated.BW6761Fr]{
			P: AffinePoint[emulated.BW6761Fp]{X: emulated.ValueOf[emulated.BW6761Fp](P.X), Y: emulated.ValueOf[emulated.BW6761Fp](P.Y)},
			Q: AffinePoint[emulated.BW6761Fp]{X: emulated.ValueOf[emulated.BW6761Fp](glvRes.X), Y: emulated.ValueOf[emulated.BW6761Fp](glvRes.Y)},
			S: emulated.ValueOf[emulated.BW6761Fr](s),
		}
		if err := solveCatchingPanic(&circuit, &witness); err == nil {
			t.Fatal("ScalarMul accepted an off-subgroup input and returned Q != [s]P")
		}
	})
}

// classicGLVFoldOffSubgroupCircuit folds P with [algopts.WithFoldingScalarMul]
// (result Σ γⁱ·P[i]) and constrains the result to Q.
type classicGLVFoldOffSubgroupCircuit[T, S emulated.FieldParams] struct {
	P     []AffinePoint[T]
	Q     AffinePoint[T]
	Gamma emulated.Element[S]
}

func (c *classicGLVFoldOffSubgroupCircuit[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	ps := make([]*AffinePoint[T], len(c.P))
	for i := range c.P {
		cr.AssertIsOnCurve(&c.P[i])
		ps[i] = &c.P[i]
	}
	res, err := cr.MultiScalarMul(ps, []*emulated.Element[S]{&c.Gamma}, algopts.WithFoldingScalarMul())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// TestClassicGLVFoldOffSubgroupFirstPoint is a regression test for the folding
// MultiScalarMul on a classic-GLV curve not checking p[0]: p[0] is only added
// to the result, so an off-subgroup p[0] gave an off-subgroup result although
// the result is documented to be in the subgroup.
func TestClassicGLVFoldOffSubgroupFirstPoint(t *testing.T) {
	var fr emulated.BLS12381Fr
	_, _, g, _ := bls12381.Generators()
	off := bls12381OffSubgroupPoint(t)
	gamma := big.NewInt(0).SetBytes([]byte("classic glv fold gamma"))
	gamma.Mod(gamma, fr.Modulus())
	toAff := func(P bls12381.G1Affine) AffinePoint[emulated.BLS12381Fp] {
		return AffinePoint[emulated.BLS12381Fp]{X: emulated.ValueOf[emulated.BLS12381Fp](P.X), Y: emulated.ValueOf[emulated.BLS12381Fp](P.Y)}
	}
	// fold returns P[0] + [γ]P[1] (or P[0] alone). It uses complete
	// arithmetic, so it is the honest result for any on-curve points.
	fold := func(P ...bls12381.G1Affine) bls12381.G1Affine {
		var res bls12381.G1Jac
		res.FromAffine(&P[0])
		if len(P) == 2 {
			gP := mulNaiveBLS12381(&P[1], gamma)
			var gPj bls12381.G1Jac
			gPj.FromAffine(&gP)
			res.AddAssign(&gPj)
		}
		var aff bls12381.G1Affine
		aff.FromJacobian(&res)
		return aff
	}
	for _, tc := range []struct {
		name    string
		points  []bls12381.G1Affine
		wantErr bool
	}{
		{"in-subgroup", []bls12381.G1Affine{g, g}, false},
		{"p0-off-subgroup", []bls12381.G1Affine{off, g}, true},
		{"single-off-subgroup", []bls12381.G1Affine{off}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			circuit := classicGLVFoldOffSubgroupCircuit[emulated.BLS12381Fp, emulated.BLS12381Fr]{
				P: make([]AffinePoint[emulated.BLS12381Fp], len(tc.points)),
			}
			witness := classicGLVFoldOffSubgroupCircuit[emulated.BLS12381Fp, emulated.BLS12381Fr]{
				Q:     toAff(fold(tc.points...)),
				Gamma: emulated.ValueOf[emulated.BLS12381Fr](gamma),
			}
			for _, P := range tc.points {
				witness.P = append(witness.P, toAff(P))
			}
			err := solveCatchingPanic(&circuit, &witness)
			if tc.wantErr && err == nil {
				t.Fatal("folding MultiScalarMul accepted an off-subgroup p[0]")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("folding MultiScalarMul rejected in-subgroup inputs: %v", err)
			}
		})
	}
}

// bls12381OffSubgroupPoint returns an on-curve BLS12-381 G1 point outside the
// prime-order subgroup and without small order.
func bls12381OffSubgroupPoint(t *testing.T) bls12381.G1Affine {
	t.Helper()
	for x := uint64(1); x < 1000; x++ {
		var X, y2, Y fp_bls381.Element
		X.SetUint64(x)
		y2.Square(&X).Mul(&y2, &X).Add(&y2, new(fp_bls381.Element).SetUint64(4))
		if y2.Legendre() != 1 {
			continue
		}
		Y.Sqrt(&y2)
		P := bls12381.G1Affine{X: X, Y: Y}
		if !P.IsOnCurve() || P.IsInSubGroup() {
			continue
		}
		return P
	}
	t.Fatal("no off-subgroup point found")
	return bls12381.G1Affine{}
}

func glvCombineBLS12381(t *testing.T, P, phiP *bls12381.G1Affine, s, r, lambda *big.Int) bls12381.G1Affine {
	t.Helper()
	var lat ecc.Lattice
	ecc.PrecomputeLattice(r, lambda, &lat)
	sp := ecc.SplitScalar(s, &lat)
	a := mulNaiveBLS12381(P, &sp[0])
	b := mulNaiveBLS12381(phiP, &sp[1])
	var aj bls12381.G1Jac
	aj.FromAffine(&a)
	aj.AddMixed(&b)
	var res bls12381.G1Affine
	res.FromJacobian(&aj)
	return res
}

// mulNaiveBLS12381 is a plain double-and-add (gnark-crypto's ScalarMultiplication
// uses GLV, which assumes subgroup membership).
func mulNaiveBLS12381(P *bls12381.G1Affine, k *big.Int) bls12381.G1Affine {
	var acc, base bls12381.G1Jac
	base.FromAffine(P)
	kk := new(big.Int).Set(k)
	if kk.Sign() < 0 {
		kk.Neg(kk)
		base.Neg(&base)
	}
	acc.Set(&bls12381.G1Jac{})
	acc.X.SetOne()
	acc.Y.SetOne() // Z = 0: infinity
	for i := kk.BitLen() - 1; i >= 0; i-- {
		acc.DoubleAssign()
		if kk.Bit(i) == 1 {
			acc.AddAssign(&base)
		}
	}
	var res bls12381.G1Affine
	res.FromJacobian(&acc)
	return res
}

func mulNaiveBW6761(P *bw6761.G1Jac, k *big.Int) bw6761.G1Jac {
	var acc, base bw6761.G1Jac
	base.Set(P)
	kk := new(big.Int).Set(k)
	if kk.Sign() < 0 {
		kk.Neg(kk)
		base.Neg(&base)
	}
	acc.X.SetOne()
	acc.Y.SetOne() // Z = 0: infinity
	for i := kk.BitLen() - 1; i >= 0; i-- {
		acc.DoubleAssign()
		if kk.Bit(i) == 1 {
			acc.AddAssign(&base)
		}
	}
	return acc
}
