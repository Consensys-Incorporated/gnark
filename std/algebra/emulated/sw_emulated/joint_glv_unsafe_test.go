package sw_emulated

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// keyedDecomposeScalarG1 replaces decomposeScalarG1, returning a fixed
// decomposition for each listed input scalar (keyed by its value mod r).
func keyedDecomposeScalarG1(ds map[string]classicGLVDecomposition) solver.Hint {
	return func(mod *big.Int, inputs, outputs []*big.Int) error {
		return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
			moduli := hc.EmulatedModuli()
			_, nativeOutputs := hc.NativeInputsOutputs()
			emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
			d, ok := ds[new(big.Int).Mod(emuInputs[0], moduli[0]).String()]
			if !ok {
				return decomposeScalarG1(mod, inputs, outputs)
			}
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

// jointUnsafeSubscalar returns x ≥ 0 with e(x) = 4⌊x/4⌋ + 3 − 2·bit₁(x) = e
// for an odd e > 0. At the last loop iteration (i = 1) of
// jointScalarMulGLVUnsafe the accumulator coefficient is A = 2⌊x/4⌋ + 1 and the
// table digit is d = 2·bit₁(x) − 1, so e(x) = 2A − d: implicitDoubleAndAdd
// computes [2]Acc + Bi as a doubling followed by a chord, whose slope is free
// when [2]Acc == Bi. We take bit₀ = 1.
func jointUnsafeSubscalar(e *big.Int) *big.Int {
	b1 := int64(0)
	if e.Bit(1) == 0 { // e ≡ 1 mod 4
		b1 = 1
	}
	q := new(big.Int).Sub(e, big.NewInt(3-2*b1))
	q.Rsh(q, 2)
	x := q.Lsh(q, 2)
	return x.Add(x, big.NewInt(2*b1+1))
}

// findJointUnsafeDecomposition returns a decomposition (σ1 s1, σ2 s2) whose
// last-iteration values (σ1·e(s1), σ2·e(s2)) = (X, Y) satisfy
// X + λ·Y ≡ c mod r, with X, Y odd and |s1|, |s2| < 2^nbits.
func findJointUnsafeDecomposition(t *testing.T, r, lambda, c *big.Int, nbits int) classicGLVDecomposition {
	t.Helper()
	var lat ecc.Lattice
	ecc.PrecomputeLattice(r, lambda, &lat)
	v1, v2 := lat.V1, lat.V2
	// Babai rounding of (c, 0) in the basis (v1, v2)
	det := new(big.Int).Sub(new(big.Int).Mul(&v1[0], &v2[1]), new(big.Int).Mul(&v1[1], &v2[0]))
	round := func(n, d *big.Int) *big.Int {
		q, m := new(big.Int).DivMod(new(big.Int).Lsh(n, 1), d, new(big.Int))
		_ = m
		q.Add(q, big.NewInt(1)).Rsh(q, 1)
		return q
	}
	alpha := round(new(big.Int).Mul(c, &v2[1]), det)
	beta := round(new(big.Int).Neg(new(big.Int).Mul(c, &v1[1])), det)
	for da := int64(-4); da <= 4; da++ {
		for db := int64(-4); db <= 4; db++ {
			a := new(big.Int).Add(alpha, big.NewInt(da))
			b := new(big.Int).Add(beta, big.NewInt(db))
			X := new(big.Int).Sub(c, new(big.Int).Add(new(big.Int).Mul(a, &v1[0]), new(big.Int).Mul(b, &v2[0])))
			Y := new(big.Int).Neg(new(big.Int).Add(new(big.Int).Mul(a, &v1[1]), new(big.Int).Mul(b, &v2[1])))
			if X.Bit(0) == 0 || Y.Bit(0) == 0 {
				continue // e(·) is odd (also excludes zero)
			}
			chk := new(big.Int).Mul(Y, lambda)
			chk.Add(chk, X).Sub(chk, c).Mod(chk, r)
			if chk.Sign() != 0 {
				t.Fatal("internal: CVP solution does not satisfy the congruence")
			}
			s1 := jointUnsafeSubscalar(new(big.Int).Abs(X))
			s2 := jointUnsafeSubscalar(new(big.Int).Abs(Y))
			if s1.BitLen() > nbits || s2.BitLen() > nbits {
				continue
			}
			d := classicGLVDecomposition{s1: s1, s2: s2, neg1: X.Sign() < 0, neg2: Y.Sign() < 0}
			sv1, sv2 := new(big.Int).Set(s1), new(big.Int).Set(s2)
			if d.neg1 {
				sv1.Neg(sv1)
			}
			if d.neg2 {
				sv2.Neg(sv2)
			}
			d.s = new(big.Int).Mul(sv2, lambda)
			d.s.Add(d.s, sv1).Mod(d.s, r)
			return d
		}
	}
	t.Fatalf("no decomposition found for c = %s", c)
	return classicGLVDecomposition{}
}

type jointUnsafeForgeryCircuit[T, S emulated.FieldParams] struct {
	P, Honest AffinePoint[T]
	S1, S2    emulated.Element[S]
}

func (c *jointUnsafeForgeryCircuit[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	// [S1]G + [S2]P, incomplete: Q = G, R = P in jointScalarMulGLVUnsafe
	res := cr.JointScalarMulBase(&c.P, &c.S2, &c.S1, algopts.WithIncompleteArithmetic())
	eqX := cr.baseApi.IsZero(cr.baseApi.Sub(&res.X, &c.Honest.X))
	eqY := cr.baseApi.IsZero(cr.baseApi.Sub(&res.Y, &c.Honest.Y))
	api.AssertIsEqual(api.And(eqX, eqY), 0)
	return nil
}

// jointUnsafeVectors returns decompositions for (s, t) that make
// [2]Acc == Bi at the last iteration of jointScalarMulGLVUnsafe with Q = G.
func jointUnsafeVectors(t *testing.T, r, lambda *big.Int) (ds, dt classicGLVDecomposition) {
	nbits := r.BitLen()>>1 + 2
	// before iteration i = 1 the offset is [2^(nbits−2)]G, doubled to
	// [2^(nbits−1)]G before the chord
	c := new(big.Int).Lsh(big.NewInt(1), uint(nbits-1))
	c.Neg(c).Mod(c, r)
	ds = findJointUnsafeDecomposition(t, r, lambda, c, nbits)
	dt = findJointUnsafeDecomposition(t, r, lambda, new(big.Int), nbits)
	return
}

func checkJointUnsafeForgery[T, S emulated.FieldParams](t *testing.T, ds, dt classicGLVDecomposition, p, honest [2]*big.Int) {
	t.Helper()
	w := jointUnsafeForgeryCircuit[T, S]{
		P:      AffinePoint[T]{X: emulated.ValueOf[T](p[0]), Y: emulated.ValueOf[T](p[1])},
		Honest: AffinePoint[T]{X: emulated.ValueOf[T](honest[0]), Y: emulated.ValueOf[T](honest[1])},
		S1:     emulated.ValueOf[S](ds.s),
		S2:     emulated.ValueOf[S](dt.s),
	}
	if err := test.IsSolved(&jointUnsafeForgeryCircuit[T, S]{}, &w, testCurve.ScalarField()); err == nil {
		t.Fatal("sanity: honest decomposition must give [s]G + [t]P")
	}
	hint := keyedDecomposeScalarG1(map[string]classicGLVDecomposition{ds.s.String(): ds, dt.s.String(): dt})
	err := test.IsSolved(&jointUnsafeForgeryCircuit[T, S]{}, &w, testCurve.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(decomposeScalarG1), hint))
	if err == nil {
		t.Fatalf("JointScalarMulBase (incomplete) returned a point != [s]G + [t]P\n s=(%s,%s,%v,%v)\n t=(%s,%s,%v,%v)",
			ds.s1, ds.s2, ds.neg1, ds.neg2, dt.s1, dt.s2, dt.neg1, dt.neg2)
	}
}

// TestJointScalarMulGLVUnsafeForgery is a regression test for the incomplete
// joint GLV scalar multiplication (JointScalarMulBase/MultiScalarMul with
// WithIncompleteArithmetic): a prover that only replaces the two GLV
// decomposition hints with bounded, non-honest decompositions satisfying
// s1 + λ·s2 ≡ s mod r makes the last loop iteration compute [2]Acc + Bi with
// [2]Acc == Bi, whose chord slope is unconstrained, so the result differs from
// [s]G + [t]P. Affects every GLV curve, including prime-order ones.
func TestJointScalarMulGLVUnsafeForgery(t *testing.T) {
	pubScalar := new(big.Int).SetBytes([]byte("public key scalar"))
	t.Run("secp256k1", func(t *testing.T) {
		var fr emulated.Secp256k1Fr
		ds, dt := jointUnsafeVectors(t, fr.Modulus(), GetSecp256k1Params().Eigenvalue)
		_, g := secp256k1.Generators()
		var P, a, b secp256k1.G1Affine
		P.ScalarMultiplication(&g, pubScalar)
		a.ScalarMultiplication(&g, ds.s)
		b.ScalarMultiplication(&P, dt.s)
		a.Add(&a, &b)
		checkJointUnsafeForgery[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t, ds, dt,
			[2]*big.Int{P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int))},
			[2]*big.Int{a.X.BigInt(new(big.Int)), a.Y.BigInt(new(big.Int))})
	})
	t.Run("BN254", func(t *testing.T) {
		var fr emulated.BN254Fr
		ds, dt := jointUnsafeVectors(t, fr.Modulus(), GetBN254Params().Eigenvalue)
		_, _, g, _ := bn254.Generators()
		var P, a, b bn254.G1Affine
		P.ScalarMultiplication(&g, pubScalar)
		a.ScalarMultiplication(&g, ds.s)
		b.ScalarMultiplication(&P, dt.s)
		a.Add(&a, &b)
		checkJointUnsafeForgery[emulated.BN254Fp, emulated.BN254Fr](t, ds, dt,
			[2]*big.Int{P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int))},
			[2]*big.Int{a.X.BigInt(new(big.Int)), a.Y.BigInt(new(big.Int))})
	})
	t.Run("BLS12-381", func(t *testing.T) {
		var fr emulated.BLS12381Fr
		ds, dt := jointUnsafeVectors(t, fr.Modulus(), GetBLS12381Params().Eigenvalue)
		_, _, g, _ := bls12381.Generators()
		var P, a, b bls12381.G1Affine
		P.ScalarMultiplication(&g, pubScalar)
		a.ScalarMultiplication(&g, ds.s)
		b.ScalarMultiplication(&P, dt.s)
		a.Add(&a, &b)
		checkJointUnsafeForgery[emulated.BLS12381Fp, emulated.BLS12381Fr](t, ds, dt,
			[2]*big.Int{P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int))},
			[2]*big.Int{a.X.BigInt(new(big.Int)), a.Y.BigInt(new(big.Int))})
	})
}

type msmMergeCircuit[T, S emulated.FieldParams] struct {
	P      [3]AffinePoint[T]
	S      [3]emulated.Element[S]
	Honest AffinePoint[T]
}

func (c *msmMergeCircuit[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res, err := cr.MultiScalarMul(
		[]*AffinePoint[T]{&c.P[0], &c.P[1], &c.P[2]},
		[]*emulated.Element[S]{&c.S[0], &c.S[1], &c.S[2]},
		algopts.WithIncompleteArithmetic())
	if err != nil {
		return err
	}
	eqX := cr.baseApi.IsZero(cr.baseApi.Sub(&res.X, &c.Honest.X))
	eqY := cr.baseApi.IsZero(cr.baseApi.Sub(&res.Y, &c.Honest.Y))
	api.AssertIsEqual(api.And(eqX, eqY), 0)
	return nil
}

// TestMultiScalarMulIncompleteMergeForgery is a regression test for the
// incomplete MultiScalarMul merging partial results with an unguarded chord:
// with n = 3 it computes [s2]P2 + ([s0]P0 + [s1]P1), and when both partial
// results are equal the chord slope is unconstrained, so a wrong result
// satisfies the circuit (even with honest hints).
func TestMultiScalarMulIncompleteMergeForgery(t *testing.T) {
	var fr emulated.Secp256k1Fr
	_, g := secp256k1.Generators()
	var p1, p2, honest secp256k1.G1Affine
	p1.ScalarMultiplication(&g, big.NewInt(2))
	k := new(big.Int).ModInverse(big.NewInt(2), fr.Modulus())
	k.Mul(k, big.NewInt(3)).Mod(k, fr.Modulus()) // P2 = [3/2]G, [2]P2 = [3]G = G + [2]G
	p2.ScalarMultiplication(&g, k)
	honest.ScalarMultiplication(&g, big.NewInt(6))
	pt := func(p secp256k1.G1Affine) AffinePoint[emulated.Secp256k1Fp] {
		return AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](p.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](p.Y),
		}
	}
	w := msmMergeCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P:      [3]AffinePoint[emulated.Secp256k1Fp]{pt(g), pt(p1), pt(p2)},
		S:      [3]emulated.Element[emulated.Secp256k1Fr]{emulated.ValueOf[emulated.Secp256k1Fr](1), emulated.ValueOf[emulated.Secp256k1Fr](1), emulated.ValueOf[emulated.Secp256k1Fr](2)},
		Honest: pt(honest),
	}
	if err := test.IsSolved(&msmMergeCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}, &w, testCurve.ScalarField()); err == nil {
		t.Fatal("incomplete MultiScalarMul returned a point != [6]G")
	}
}
