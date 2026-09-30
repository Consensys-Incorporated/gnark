package twistededwards

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	edbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		rationalReconstruct,
		scalarMulHint,
		doubleBaseScalarMulHint,
		multiRationalReconstructHint,
		multiRationalReconstructExtHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

// rationalReconstruct decomposes a scalar s ∈ Fr into (s1, s2, signBit, k) such
// that s1 + s2·s = k·r in the integers, with |s1|, |s2| < γ₂·√r ≈ 1.15·√r
// (proven LLL/Hermite bound). Replaces the older heuristic-bound HalfGCD.
//
// The bit-decomposition convention: s1 ≥ 0 always, s2 = ±|s2| with signBit = 1
// iff the underlying signed s2 was negative.
func rationalReconstruct(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs (s, r)")
	}
	if len(outputs) != 3 {
		return errors.New("expecting three outputs (s1, |s2|, signBit)")
	}
	// Zero scalar: trivial (s1=s2=0). The in-circuit IsZero(s2)=0 guard
	// rejects this; the caller must pre-route scalar=1 (mirrors the existing
	// scalarMulFakeGLV: checkedScalar = Select(isScalarZero, 1, scalar)).
	if inputs[0].Sign() == 0 {
		for i := range outputs {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	// lattice.RationalReconstruct returns (x, z) with x ≡ z·s mod r.
	// Map onto our convention: s1 + s2·s = 0 mod r ⇒ s1 = x, s2 = −z.
	res := lattice.RationalReconstruct(inputs[0], inputs[1])
	x, z := new(big.Int).Set(res[0]), new(big.Int).Set(res[1])

	// Normalise so s1 ≥ 0. Flipping signs of (x, z) preserves x − z·s = m·r
	// (with m negated).
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}
	outputs[0].Set(x) // s1 = x ≥ 0

	// s2 = −z, encoded as |s2| + signBit. signBit = 1 iff −z < 0 iff z > 0.
	outputs[1].Abs(z)
	outputs[2].SetUint64(0)
	if z.Sign() > 0 {
		outputs[2].SetUint64(1)
	}
	return nil
}

// scalarMulHint computes q = [s]P together with a prime-order-subgroup preimage
// S of q satisfying [cofactor]S = q.
//
// Inputs:  P.X, P.Y, s, order, cofactor.
// Outputs: q.X, q.Y, S.X, S.Y  with S = [cofactor⁻¹ mod order]·q.
//
// The in-circuit check [cofactor]S == q forces q into the prime-order subgroup:
// since the cofactor is a power of two, [cofactor]·E equals the subgroup, so a
// torsion-shifted q (e.g. q + (0,-1)) has no preimage. This binds the hinted
// result against a torsion forgery that the relation [s1]P + [s2]q = O alone
// would accept when s2 is even.
func scalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 5 {
		return errors.New("expecting five inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	order, cofactor := inputs[3], inputs[4]
	m := new(big.Int).ModInverse(cofactor, order)
	if m == nil {
		return errors.New("cofactor not invertible modulo order")
	}
	// compute the resulting point q = [s]P and its subgroup preimage S = [m]q
	if field.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		bandersnatchOrder, _ := new(big.Int).SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		if inputs[3].Cmp(bandersnatchOrder) == 0 {
			var P, S bandersnatch.PointAffine
			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			P.ScalarMultiplication(&P, inputs[2])
			S.ScalarMultiplication(&P, m)
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
			S.X.BigInt(outputs[2])
			S.Y.BigInt(outputs[3])
		} else {
			var P, S jubjub.PointAffine
			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			P.ScalarMultiplication(&P, inputs[2])
			S.ScalarMultiplication(&P, m)
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
			S.X.BigInt(outputs[2])
			S.Y.BigInt(outputs[3])
		}
	} else if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		var P, S babyjubjub.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		S.ScalarMultiplication(&P, m)
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
		S.X.BigInt(outputs[2])
		S.Y.BigInt(outputs[3])
	} else if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		var P, S edbls12377.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		S.ScalarMultiplication(&P, m)
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
		S.X.BigInt(outputs[2])
		S.Y.BigInt(outputs[3])
	} else if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		var P, S edbw6761.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		S.ScalarMultiplication(&P, m)
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
		S.X.BigInt(outputs[2])
		S.Y.BigInt(outputs[3])
	} else {
		return errors.New("scalarMulHint: unknown curve")
	}
	return nil
}

// doubleBaseScalarMulHint computes Q1=[s1]P1 and Q2=[s2]P2 separately, together
// with a prime-order-subgroup preimage S of R = Q1+Q2 satisfying [cofactor]S = R.
//
// Inputs:  P1.X, P1.Y, s1, P2.X, P2.Y, s2, order, cofactor.
// Outputs: Q1.X, Q1.Y, Q2.X, Q2.Y, S.X, S.Y.
//
// S = [cofactor⁻¹ mod order]·R. Since the honest R lies in the prime-order
// subgroup, [cofactor]S = R and the in-circuit check [cofactor]S == R forces R
// into the subgroup (any torsion component would make R = [cofactor]S
// unsatisfiable, because [cofactor]·E = the prime-order subgroup for these
// power-of-two cofactors). This is what binds the hinted R against a
// torsion-shifted forgery in the scaled MSM relation.
//
// Used by `doubleBaseScalarMul3MSMLogUp` and `doubleBaseScalarMul6MSMLogUp`.
func doubleBaseScalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 8 {
		return errors.New("expecting eight inputs")
	}
	if len(outputs) != 6 {
		return errors.New("expecting six outputs")
	}
	order, cofactor := inputs[6], inputs[7]
	m := new(big.Int).ModInverse(cofactor, order)
	if m == nil {
		return errors.New("cofactor not invertible modulo order")
	}
	if field.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		bandersnatchOrder, _ := new(big.Int).SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		if inputs[6].Cmp(bandersnatchOrder) == 0 {
			var P1, P2, R, S bandersnatch.PointAffine
			P1.X.SetBigInt(inputs[0])
			P1.Y.SetBigInt(inputs[1])
			P1.ScalarMultiplication(&P1, inputs[2])
			P2.X.SetBigInt(inputs[3])
			P2.Y.SetBigInt(inputs[4])
			P2.ScalarMultiplication(&P2, inputs[5])
			R.Add(&P1, &P2)
			S.ScalarMultiplication(&R, m)
			P1.X.BigInt(outputs[0])
			P1.Y.BigInt(outputs[1])
			P2.X.BigInt(outputs[2])
			P2.Y.BigInt(outputs[3])
			S.X.BigInt(outputs[4])
			S.Y.BigInt(outputs[5])
		} else {
			var P1, P2, R, S jubjub.PointAffine
			P1.X.SetBigInt(inputs[0])
			P1.Y.SetBigInt(inputs[1])
			P1.ScalarMultiplication(&P1, inputs[2])
			P2.X.SetBigInt(inputs[3])
			P2.Y.SetBigInt(inputs[4])
			P2.ScalarMultiplication(&P2, inputs[5])
			R.Add(&P1, &P2)
			S.ScalarMultiplication(&R, m)
			P1.X.BigInt(outputs[0])
			P1.Y.BigInt(outputs[1])
			P2.X.BigInt(outputs[2])
			P2.Y.BigInt(outputs[3])
			S.X.BigInt(outputs[4])
			S.Y.BigInt(outputs[5])
		}
	} else if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		var P1, P2, R, S babyjubjub.PointAffine
		P1.X.SetBigInt(inputs[0])
		P1.Y.SetBigInt(inputs[1])
		P1.ScalarMultiplication(&P1, inputs[2])
		P2.X.SetBigInt(inputs[3])
		P2.Y.SetBigInt(inputs[4])
		P2.ScalarMultiplication(&P2, inputs[5])
		R.Add(&P1, &P2)
		S.ScalarMultiplication(&R, m)
		P1.X.BigInt(outputs[0])
		P1.Y.BigInt(outputs[1])
		P2.X.BigInt(outputs[2])
		P2.Y.BigInt(outputs[3])
		S.X.BigInt(outputs[4])
		S.Y.BigInt(outputs[5])
	} else if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		var P1, P2, R, S edbls12377.PointAffine
		P1.X.SetBigInt(inputs[0])
		P1.Y.SetBigInt(inputs[1])
		P1.ScalarMultiplication(&P1, inputs[2])
		P2.X.SetBigInt(inputs[3])
		P2.Y.SetBigInt(inputs[4])
		P2.ScalarMultiplication(&P2, inputs[5])
		R.Add(&P1, &P2)
		S.ScalarMultiplication(&R, m)
		P1.X.BigInt(outputs[0])
		P1.Y.BigInt(outputs[1])
		P2.X.BigInt(outputs[2])
		P2.Y.BigInt(outputs[3])
		S.X.BigInt(outputs[4])
		S.Y.BigInt(outputs[5])
	} else if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		var P1, P2, R, S edbw6761.PointAffine
		P1.X.SetBigInt(inputs[0])
		P1.Y.SetBigInt(inputs[1])
		P1.ScalarMultiplication(&P1, inputs[2])
		P2.X.SetBigInt(inputs[3])
		P2.Y.SetBigInt(inputs[4])
		P2.ScalarMultiplication(&P2, inputs[5])
		R.Add(&P1, &P2)
		S.ScalarMultiplication(&R, m)
		P1.X.BigInt(outputs[0])
		P1.Y.BigInt(outputs[1])
		P2.X.BigInt(outputs[2])
		P2.Y.BigInt(outputs[3])
		S.X.BigInt(outputs[4])
		S.Y.BigInt(outputs[5])
	} else {
		return errors.New("doubleBaseScalarMulHint: unknown curve")
	}
	return nil
}

// multiRationalReconstructHint decomposes (k1, k2) jointly via 3-D LLL
// reconstruction: finds (x1, x2, z) with a shared denominator z such that
//
//	k1 ≡ x1 / z   (mod r)
//	k2 ≡ x2 / z   (mod r)
//
// with each component bounded by ~r^(2/3). Used by the non-GLV
// `doubleBaseScalarMul3MSMLogUp` path.
//
// inputs: k1, k2, order
// outputs[0..2]: |x1|, |x2|, |z|
// outputs[3..5]: signX1, signX2, signZ
func multiRationalReconstructHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return errors.New("expecting three inputs: k1, k2, order")
	}
	if len(outputs) != 6 {
		return errors.New("expecting six outputs")
	}
	k1, k2, order := inputs[0], inputs[1], inputs[2]

	if k1.Sign() == 0 && k2.Sign() == 0 {
		for i := range outputs {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	res := lattice.NewReconstructor(order).MultiRationalReconstruct(k1, k2)
	x1, x2, z := res[0], res[1], res[2]

	outputs[0].Abs(x1)
	outputs[1].Abs(x2)
	outputs[2].Abs(z)

	setSign := func(out *big.Int, val *big.Int) {
		if val.Sign() < 0 {
			out.SetUint64(1)
		} else {
			out.SetUint64(0)
		}
	}
	setSign(outputs[3], x1)
	setSign(outputs[4], x2)
	setSign(outputs[5], z)

	return nil
}

// multiRationalReconstructExtHint decomposes (k1, k2) jointly via 6-D LLL
// reconstruction: finds (x1, y1, x2, y2, z, t) with shared denominator
// (z + λ·t) such that
//
//	k1 ≡ (x1 + λ·y1) / (z + λ·t)   (mod r)
//	k2 ≡ (x2 + λ·y2) / (z + λ·t)   (mod r)
//
// with each component bounded by ~r^(1/3). Used by the GLV-curve
// `doubleBaseScalarMul6MSMLogUp` path.
//
// inputs: k1, k2, order, lambda
// outputs[0..5]:  |x1|, |y1|, |x2|, |y2|, |z|, |t|
// outputs[6..11]: signX1, signY1, signX2, signY2, signZ, signT
func multiRationalReconstructExtHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return errors.New("expecting four inputs: k1, k2, order, lambda")
	}
	if len(outputs) != 12 {
		return errors.New("expecting 12 outputs")
	}
	k1, k2, order, lambda := inputs[0], inputs[1], inputs[2], inputs[3]

	if k1.Sign() == 0 && k2.Sign() == 0 {
		for i := range outputs {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	rc := lattice.NewReconstructor(order).SetLambda(lambda)
	res := rc.MultiRationalReconstructExt(k1, k2)
	x1, y1, x2, y2, z, t := res[0], res[1], res[2], res[3], res[4], res[5]

	outputs[0].Abs(x1)
	outputs[1].Abs(y1)
	outputs[2].Abs(x2)
	outputs[3].Abs(y2)
	outputs[4].Abs(z)
	outputs[5].Abs(t)

	setSign := func(out *big.Int, val *big.Int) {
		if val.Sign() < 0 {
			out.SetUint64(1)
		} else {
			out.SetUint64(0)
		}
	}
	setSign(outputs[6], x1)
	setSign(outputs[7], y1)
	setSign(outputs[8], x2)
	setSign(outputs[9], y2)
	setSign(outputs[10], z)
	setSign(outputs[11], t)

	return nil
}
