package sw_emulated

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bw6_fp "github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secp256k1_fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	secp256r1_fp "github.com/consensys/gnark-crypto/ecc/secp256r1/fp"
	stark_curve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	stark_fp "github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		scalarMulPreimageHint,
		decomposeScalarG1,
		scalarMulHint,
		rationalReconstruct,
		rationalReconstructExt,
		combRecodeHint,
		combChainLambdaHint,
		ratioHint,
		tangentHint,
		tangentHintA,
		unifiedSlopeHint,
		bjSlopeHint,
		implicitTangentHint,
		implicitChordHint,
	}
}

func decomposeScalarG1(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 2 {
			return fmt.Errorf("expecting two outputs, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 2 {
			return fmt.Errorf("expecting two inputs, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 2 {
			return fmt.Errorf("expecting two outputs, got %d", len(emuOutputs))
		}
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(moduli[0], emuInputs[1], glvBasis)
		sp := ecc.SplitScalar(emuInputs[0], glvBasis)
		emuOutputs[0].Set(&(sp[0]))
		emuOutputs[1].Set(&(sp[1]))
		// we need the absolute values for the in-circuit computations,
		// otherwise the negative values will be reduced modulo the SNARK scalar
		// field and not the emulated field.
		// 		output0 = |s0| mod r
		// 		output1 = |s1| mod r
		nativeOutputs[0].SetUint64(0) // set the sign
		if emuOutputs[0].Sign() == -1 {
			emuOutputs[0].Neg(emuOutputs[0])
			nativeOutputs[0].SetUint64(1) // we return the sign of the first subscalar
		}
		nativeOutputs[1].SetUint64(0) // set the sign
		if emuOutputs[1].Sign() == -1 {
			emuOutputs[1].Neg(emuOutputs[1])
			nativeOutputs[1].SetUint64(1) // we return the sign of the second subscalar
		}
		return nil
	})
}

// scalarMulPreimageHint computes [m]P exactly like scalarMulHint but is a
// distinct hint (distinct ID) so the cofactor-subgroup-binding preimage can be
// overridden independently of the main scalar-mul output in soundness tests.
func scalarMulPreimageHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return scalarMulHint(field, inputs, outputs)
}

func scalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 2 {
			return fmt.Errorf("expecting two base inputs, got %d", len(baseInputs))
		}
		if len(baseOutputs) != 2 {
			return fmt.Errorf("expecting two base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 1 {
			return fmt.Errorf("expecting one scalar input, got %d", len(scalarInputs))
		}
		Px := baseInputs[0]
		Py := baseInputs[1]
		S := scalarInputs[0]
		if baseModulus.Cmp(secp256r1_fp.Modulus()) == 0 {
			// compute the resulting point [s]P
			var P secp256r1.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(elliptic.P384().Params().P) == 0 {
			curve := elliptic.P384()
			// compute the resulting point [s]P
			Qx, Qy := curve.ScalarMult(Px, Py, S.Bytes()) //nolint:staticcheck // we don't have counterpart in gnark-crypto, and crypto/ecdh doesn't suffice
			baseOutputs[0].Set(Qx)
			baseOutputs[1].Set(Qy)
		} else if baseModulus.Cmp(stark_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P stark_curve.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(bn_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P bn254.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(bls12381_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P bls12381.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(secp256k1_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P secp256k1.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else if baseModulus.Cmp(bw6_fp.Modulus()) == 0 {
			// compute the resulting point [s]Q
			var P bw6761.G1Affine
			P.X.SetBigInt(Px)
			P.Y.SetBigInt(Py)
			P.ScalarMultiplication(&P, S)
			P.X.BigInt(baseOutputs[0])
			P.Y.BigInt(baseOutputs[1])
		} else {
			return errors.New("unsupported curve")
		}
		return nil
	})
}

// rationalReconstruct decomposes a scalar s ∈ Fr into (s1, |s2|, signBit) such
// that s1 ≡ s2·s (mod r), with |s1|, |s2| < γ₂·√r ≈ 1.15·√r (proven LLL/Hermite
// bound from gnark-crypto/algebra/lattice). Replaces the older heuristic
// HalfGCD-based decomposition.
//
// In-circuit: 1 native sign bit + 2 emulated outputs (s1, |s2|). The caller
// reconstructs the signed s2 as ±|s2| based on the sign bit and asserts
// s1 + s·s2 ≡ 0 (mod r).
func rationalReconstruct(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 1 {
			return fmt.Errorf("expecting one output, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 1 {
			return fmt.Errorf("expecting one input, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 2 {
			return fmt.Errorf("expecting two outputs, got %d", len(emuOutputs))
		}
		// lattice.RationalReconstruct returns (x, z) with x ≡ z·s (mod r),
		// i.e., x − z·s ≡ 0 (mod r). The circuit expects: s1 + s·_s2 ≡ 0
		// (mod r), so s1 = x and _s2 = −z.
		rc := lattice.NewReconstructor(moduli[0])
		res := rc.RationalReconstruct(emuInputs[0])
		x, z := new(big.Int).Set(res[0]), new(big.Int).Set(res[1])

		// Normalise so s1 ≥ 0; flipping (x, z) preserves x ≡ z·s mod r.
		if x.Sign() < 0 {
			x.Neg(x)
			z.Neg(z)
		}
		emuOutputs[0].Set(x)
		emuOutputs[1].Abs(z)

		// signBit = 1 iff −z < 0 iff z > 0 (so the in-circuit code negates
		// |z| to recover s2 = −z).
		nativeOutputs[0].SetUint64(0)
		if z.Sign() > 0 {
			nativeOutputs[0].SetUint64(1)
		}
		return nil
	})
}

// rationalReconstructExt is the 4-D Eisenstein-style decomposition: given a
// scalar s and GLV eigenvalue λ, finds (u1, u2, v1, v2) such that
// s·(v1 + λ·v2) + u1 + λ·u2 ≡ 0 (mod r), with |u_i|, |v_i| < γ₄·r^(1/4) ≈
// 1.25·r^(1/4) (proven LLL bound). Replaces the older Eisenstein HalfGCD.
//
// In-circuit: 4 native sign bits + 4 emulated absolute values.
func rationalReconstructExt(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 4 {
			return fmt.Errorf("expecting four outputs, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 2 {
			return fmt.Errorf("expecting two inputs, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 4 {
			return fmt.Errorf("expecting four outputs, got %d", len(emuOutputs))
		}

		// Inputs: emuInputs[0] = s, emuInputs[1] = λ.
		// In-circuit we check Q − [s]P = 0, equivalently [−s]P + Q = 0, so we
		// negate the scalar before reconstruction (matches the previous
		// halfGCDEisenstein convention).
		k := new(big.Int).Neg(emuInputs[0])
		k.Mod(k, moduli[0])

		rc := lattice.NewReconstructor(moduli[0]).SetLambda(emuInputs[1])
		res := rc.RationalReconstructExt(k)
		// res = (x, y, z, t) with k = (x + λ·y)/(z + λ·t) mod r,
		// i.e., (x + λ·y) − k·(z + λ·t) ≡ 0 (mod r).
		// Mapping onto our convention u1 + λ·u2 + s·(v1 + λ·v2) ≡ 0 with k = −s:
		// u1 = x, u2 = y, v1 = z, v2 = t.
		u1 := new(big.Int).Set(res[0])
		u2 := new(big.Int).Set(res[1])
		v1 := new(big.Int).Set(res[2])
		v2 := new(big.Int).Set(res[3])

		emuOutputs[0].Abs(u1)
		emuOutputs[1].Abs(u2)
		emuOutputs[2].Abs(v1)
		emuOutputs[3].Abs(v2)

		nativeOutputs[0].SetUint64(0)
		nativeOutputs[1].SetUint64(0)
		nativeOutputs[2].SetUint64(0)
		nativeOutputs[3].SetUint64(0)
		if u1.Sign() < 0 {
			nativeOutputs[0].SetUint64(1)
		}
		if u2.Sign() < 0 {
			nativeOutputs[1].SetUint64(1)
		}
		if v1.Sign() < 0 {
			nativeOutputs[2].SetUint64(1)
		}
		if v2.Sign() < 0 {
			nativeOutputs[3].SetUint64(1)
		}
		return nil
	})
}
