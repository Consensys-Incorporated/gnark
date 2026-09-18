package sw_bls12381

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		finalExpHint,
		pairingCheckHint,
		millerLoopAndCheckFinalExpHint,
		scalarMulG2Hint,
		scalarMulG2CofactorPreimageHint,
		g2CombRecodeHint,
		g2CombChainLambdaHint,
		rationalReconstructExtG2,
		g1SqrtRatioHint,
		g2SqrtRatioHint,
		unmarshalG1,
	}
}

func finalExpHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This is inspired from https://eprint.iacr.org/2024/640.pdf
	// and based on a personal communication with the author Andrija Novakovic.
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var millerLoop bls12381.E12

			millerLoop.C0.B0.A0.SetBigInt(inputs[0])
			millerLoop.C0.B0.A1.SetBigInt(inputs[1])
			millerLoop.C0.B1.A0.SetBigInt(inputs[2])
			millerLoop.C0.B1.A1.SetBigInt(inputs[3])
			millerLoop.C0.B2.A0.SetBigInt(inputs[4])
			millerLoop.C0.B2.A1.SetBigInt(inputs[5])
			millerLoop.C1.B0.A0.SetBigInt(inputs[6])
			millerLoop.C1.B0.A1.SetBigInt(inputs[7])
			millerLoop.C1.B1.A0.SetBigInt(inputs[8])
			millerLoop.C1.B1.A1.SetBigInt(inputs[9])
			millerLoop.C1.B2.A0.SetBigInt(inputs[10])
			millerLoop.C1.B2.A1.SetBigInt(inputs[11])

			residueWitness, scalingFactor := finalExpWitness(&millerLoop)

			// return the witness residue
			residueWitness.C0.B0.A0.BigInt(outputs[0])
			residueWitness.C0.B0.A1.BigInt(outputs[1])
			residueWitness.C0.B1.A0.BigInt(outputs[2])
			residueWitness.C0.B1.A1.BigInt(outputs[3])
			residueWitness.C0.B2.A0.BigInt(outputs[4])
			residueWitness.C0.B2.A1.BigInt(outputs[5])
			residueWitness.C1.B0.A0.BigInt(outputs[6])
			residueWitness.C1.B0.A1.BigInt(outputs[7])
			residueWitness.C1.B1.A0.BigInt(outputs[8])
			residueWitness.C1.B1.A1.BigInt(outputs[9])
			residueWitness.C1.B2.A0.BigInt(outputs[10])
			residueWitness.C1.B2.A1.BigInt(outputs[11])

			// return the scaling factor
			scalingFactor.C0.B0.A0.BigInt(outputs[12])
			scalingFactor.C0.B0.A1.BigInt(outputs[13])
			scalingFactor.C0.B1.A0.BigInt(outputs[14])
			scalingFactor.C0.B1.A1.BigInt(outputs[15])
			scalingFactor.C0.B2.A0.BigInt(outputs[16])
			scalingFactor.C0.B2.A1.BigInt(outputs[17])

			return nil
		})
}

func pairingCheckHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This is inspired from https://eprint.iacr.org/2024/640.pdf
	// and based on a personal communication with the author Andrija Novakovic.
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var P bls12381.G1Affine
			var Q bls12381.G2Affine
			n := len(inputs)
			p := make([]bls12381.G1Affine, 0, n/6)
			q := make([]bls12381.G2Affine, 0, n/6)
			// first one-third is G1 points
			for k := 0; k < n/3; k += 2 {
				P.X.SetBigInt(inputs[k])
				P.Y.SetBigInt(inputs[k+1])
				p = append(p, P)
			}
			// subsequent two-thirds are G2 points
			for k := n / 3; k < n; k += 4 {
				Q.X.A0.SetBigInt(inputs[k])
				Q.X.A1.SetBigInt(inputs[k+1])
				Q.Y.A0.SetBigInt(inputs[k+2])
				Q.Y.A1.SetBigInt(inputs[k+3])
				q = append(q, Q)
			}

			lines := make([][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff, 0, len(q))
			for _, qi := range q {
				lines = append(lines, bls12381.PrecomputeLines(qi))
			}
			millerLoop, err := bls12381.MillerLoopFixedQ(p, lines)
			if err != nil {
				return err
			}
			millerLoop.Conjugate(&millerLoop)

			residueWitnessInv, scalingFactor := finalExpWitness(&millerLoop)
			residueWitnessInv.Inverse(&residueWitnessInv)

			// return the witness residue
			residueWitnessInv.C0.B0.A0.BigInt(outputs[0])
			residueWitnessInv.C0.B0.A1.BigInt(outputs[1])
			residueWitnessInv.C0.B1.A0.BigInt(outputs[2])
			residueWitnessInv.C0.B1.A1.BigInt(outputs[3])
			residueWitnessInv.C0.B2.A0.BigInt(outputs[4])
			residueWitnessInv.C0.B2.A1.BigInt(outputs[5])
			residueWitnessInv.C1.B0.A0.BigInt(outputs[6])
			residueWitnessInv.C1.B0.A1.BigInt(outputs[7])
			residueWitnessInv.C1.B1.A0.BigInt(outputs[8])
			residueWitnessInv.C1.B1.A1.BigInt(outputs[9])
			residueWitnessInv.C1.B2.A0.BigInt(outputs[10])
			residueWitnessInv.C1.B2.A1.BigInt(outputs[11])

			// return the scaling factor
			scalingFactor.C0.B0.A0.BigInt(outputs[12])
			scalingFactor.C0.B0.A1.BigInt(outputs[13])
			scalingFactor.C0.B1.A0.BigInt(outputs[14])
			scalingFactor.C0.B1.A1.BigInt(outputs[15])
			scalingFactor.C0.B2.A0.BigInt(outputs[16])
			scalingFactor.C0.B2.A1.BigInt(outputs[17])

			return nil

		})

}

func finalExpWitness(millerLoop *bls12381.E12) (residueWitness, scalingFactor bls12381.E12) {

	var root, rootPthInverse, root27thInverse bls12381.E12
	var order3rd, order3rdPower, exponent, exponentInv, finalExpFactor, polyFactor big.Int
	// polyFactor = (1-x)/3
	polyFactor.SetString("5044125407647214251", 10)
	// finalExpFactor = ((q^12 - 1) / r) / (27 * polyFactor)
	finalExpFactor.SetString("2366356426548243601069753987687709088104621721678962410379583120840019275952471579477684846670499039076873213559162845121989217658133790336552276567078487633052653005423051750848782286407340332979263075575489766963251914185767058009683318020965829271737924625612375201545022326908440428522712877494557944965298566001441468676802477524234094954960009227631543471415676620753242466901942121887152806837594306028649150255258504417829961387165043999299071444887652375514277477719817175923289019181393803729926249507024121957184340179467502106891835144220611408665090353102353194448552304429530104218473070114105759487413726485729058069746063140422361472585604626055492939586602274983146215294625774144156395553405525711143696689756441298365274341189385646499074862712688473936093315628166094221735056483459332831845007196600723053356837526749543765815988577005929923802636375670820616189737737304893769679803809426304143627363860243558537831172903494450556755190448279875942974830469855835666815454271389438587399739607656399812689280234103023464545891697941661992848552456326290792224091557256350095392859243101357349751064730561345062266850238821755009430903520645523345000326783803935359711318798844368754833295302563158150573540616830138810935344206231367357992991289265295323280", 10)

	// 1. get pth-root inverse
	exponent.Mul(&finalExpFactor, big.NewInt(27))
	root.Exp(*millerLoop, &exponent)
	if root.IsOne() {
		rootPthInverse.SetOne()
	} else {
		exponentInv.ModInverse(&exponent, &polyFactor)
		exponent.Neg(&exponentInv).Mod(&exponent, &polyFactor)
		rootPthInverse.Exp(root, &exponent)
	}

	// 2.1. get order of 3rd primitive root
	var three big.Int
	three.SetUint64(3)
	exponent.Mul(&polyFactor, &finalExpFactor)
	root.Exp(*millerLoop, &exponent)
	if root.IsOne() {
		order3rdPower.SetUint64(0)
	}
	root.Exp(root, &three)
	if root.IsOne() {
		order3rdPower.SetUint64(1)
	}
	root.Exp(root, &three)
	if root.IsOne() {
		order3rdPower.SetUint64(2)
	}
	root.Exp(root, &three)
	if root.IsOne() {
		order3rdPower.SetUint64(3)
	}

	// 2.2. get 27th root inverse
	if order3rdPower.Uint64() == 0 {
		root27thInverse.SetOne()
	} else {
		order3rd.Exp(&three, &order3rdPower, nil)
		exponent.Mul(&polyFactor, &finalExpFactor)
		root.Exp(*millerLoop, &exponent)
		exponentInv.ModInverse(&exponent, &order3rd)
		exponent.Neg(&exponentInv).Mod(&exponent, &order3rd)
		root27thInverse.Exp(root, &exponent)
	}

	// 2.3. shift the Miller loop result so that millerLoop * scalingFactor
	// is of order finalExpFactor
	scalingFactor.Mul(&rootPthInverse, &root27thInverse)
	millerLoop.Mul(millerLoop, &scalingFactor)

	// 3. get the witness residue
	//
	// lambda = q - u, the optimal exponent
	var lambda big.Int
	lambda.SetString("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129030796414117214202539", 10)
	exponent.ModInverse(&lambda, &finalExpFactor)
	residueWitness.Exp(*millerLoop, &exponent)

	return residueWitness, scalingFactor
}

func millerLoopAndCheckFinalExpHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var P bls12381.G1Affine
			var Q bls12381.G2Affine
			var previous bls12381.E12

			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			Q.X.A0.SetBigInt(inputs[2])
			Q.X.A1.SetBigInt(inputs[3])
			Q.Y.A0.SetBigInt(inputs[4])
			Q.Y.A1.SetBigInt(inputs[5])

			previous.C0.B0.A0.SetBigInt(inputs[6])
			previous.C0.B0.A1.SetBigInt(inputs[7])
			previous.C0.B1.A0.SetBigInt(inputs[8])
			previous.C0.B1.A1.SetBigInt(inputs[9])
			previous.C0.B2.A0.SetBigInt(inputs[10])
			previous.C0.B2.A1.SetBigInt(inputs[11])
			previous.C1.B0.A0.SetBigInt(inputs[12])
			previous.C1.B0.A1.SetBigInt(inputs[13])
			previous.C1.B1.A0.SetBigInt(inputs[14])
			previous.C1.B1.A1.SetBigInt(inputs[15])
			previous.C1.B2.A0.SetBigInt(inputs[16])
			previous.C1.B2.A1.SetBigInt(inputs[17])

			if previous.IsZero() {
				return errors.New("previous Miller loop result is zero")
			}

			lines := bls12381.PrecomputeLines(Q)
			millerLoop, err := bls12381.MillerLoopFixedQ(
				[]bls12381.G1Affine{P},
				[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{lines},
			)
			if err != nil {
				return err
			}
			millerLoop.Conjugate(&millerLoop)

			millerLoop.Mul(&millerLoop, &previous)

			residueWitnessInv, scalingFactor := finalExpWitness(&millerLoop)
			residueWitnessInv.Inverse(&residueWitnessInv)

			residueWitnessInv.C0.B0.A0.BigInt(outputs[0])
			residueWitnessInv.C0.B0.A1.BigInt(outputs[1])
			residueWitnessInv.C0.B1.A0.BigInt(outputs[2])
			residueWitnessInv.C0.B1.A1.BigInt(outputs[3])
			residueWitnessInv.C0.B2.A0.BigInt(outputs[4])
			residueWitnessInv.C0.B2.A1.BigInt(outputs[5])
			residueWitnessInv.C1.B0.A0.BigInt(outputs[6])
			residueWitnessInv.C1.B0.A1.BigInt(outputs[7])
			residueWitnessInv.C1.B1.A0.BigInt(outputs[8])
			residueWitnessInv.C1.B1.A1.BigInt(outputs[9])
			residueWitnessInv.C1.B2.A0.BigInt(outputs[10])
			residueWitnessInv.C1.B2.A1.BigInt(outputs[11])

			// return the scaling factor
			scalingFactor.C0.B0.A0.BigInt(outputs[12])
			scalingFactor.C0.B0.A1.BigInt(outputs[13])
			scalingFactor.C0.B1.A0.BigInt(outputs[14])
			scalingFactor.C0.B1.A1.BigInt(outputs[15])
			scalingFactor.C0.B2.A0.BigInt(outputs[16])
			scalingFactor.C0.B2.A1.BigInt(outputs[17])

			return nil
		})
}

// g1SqrtRatio computes the square root of u/v and returns 0 iff u/v was indeed a quadratic residue
// if not, we get sqrt(Z * u / v). Recall that Z is non-residue
// If v = 0, u/v is meaningless and the output is unspecified, without raising an error.
// The main idea is that since the computation of the square root involves taking large powers of u/v, the inversion of v can be avoided.
//
// nativeInputs[0] = u, nativeInputs[1]=v
// nativeOutput[0] = 0 if u/v is a QR, 1 otherwise, emulatedOutput[0]=sqrt(u/v) or sqrt(Z u/v)
func g1SqrtRatioHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintContext(nativeMod, nativeInputs, nativeOutputs, func(hc emulated.HintContext) error {
		m := hc.EmulatedModuli()
		if len(m) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(m))
		}
		inputs, outputsEm := hc.InputsOutputs(m[0])
		if len(inputs) != 2 {
			return fmt.Errorf("expecting 2 inputs, got %d", len(inputs))
		}
		if len(outputsEm) != 1 {
			return fmt.Errorf("expecting 1 output, got %d", len(outputsEm))
		}
		_, outputsN := hc.NativeInputsOutputs()
		if len(outputsN) != 1 {
			return fmt.Errorf("expecting 1 native output, got %d", len(outputsN))
		}
		var u, v, z fp.Element
		u.SetBigInt(inputs[0])
		v.SetBigInt(inputs[1])

		isQNr := hash_to_curve.G1SqrtRatio(&z, &u, &v)
		if isQNr != 0 {
			isQNr = 1
		}
		z.BigInt(outputsEm[0])
		outputsN[0].SetInt64(int64(isQNr))
		return nil
	})
}

// g2SqrtRatioHint computes the square root of u/v for E2 field elements and returns 0 iff u/v was indeed a quadratic residue
// if not, we get sqrt(Z * u / v). Recall that Z is non-residue
// If v = 0, u/v is meaningless and the output is unspecified, without raising an error.
//
// nativeInputs: u.A0, u.A1, v.A0, v.A1 (where u and v are E2 elements)
// nativeOutput[0] = 0 if u/v is a QR, 1 otherwise
// emulatedOutput[0], emulatedOutput[1] = sqrt(u/v) or sqrt(Z*u/v) as an E2 element
func g2SqrtRatioHint(nativeMod *big.Int, nativeInputs []*big.Int, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintContext(nativeMod, nativeInputs, nativeOutputs, func(hc emulated.HintContext) error {
		m := hc.EmulatedModuli()
		if len(m) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(m))
		}
		inputs, outputsEm := hc.InputsOutputs(m[0])
		if len(inputs) != 4 {
			return fmt.Errorf("expecting 4 inputs, got %d", len(inputs))
		}
		if len(outputsEm) != 2 {
			return fmt.Errorf("expecting 2 outputs, got %d", len(outputsEm))
		}
		_, outputsN := hc.NativeInputsOutputs()
		if len(outputsN) != 1 {
			return fmt.Errorf("expecting 1 native output, got %d", len(outputsN))
		}
		var u, v, z bls12381.E2
		u.A0.SetBigInt(inputs[0])
		u.A1.SetBigInt(inputs[1])
		v.A0.SetBigInt(inputs[2])
		v.A1.SetBigInt(inputs[3])

		isQNr := hash_to_curve.G2SqrtRatio(&z, &u, &v)
		if isQNr != 0 {
			isQNr = 1
		}
		z.A0.BigInt(outputsEm[0])
		z.A1.BigInt(outputsEm[1])
		outputsN[0].SetInt64(int64(isQNr))
		return nil
	})
}

// unmarshalG1 unmarshals the y coordinate of a compressed BLS12-381 G1 point.
// It takes as input the bytes of the compressed point and returns the y
// coordinate. It uses non-native methods for outputting non-native value.
func unmarshalG1(mod *big.Int, nativeInputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeInput(nativeInputs, outputs, func(emulatedMod *big.Int, nativeInputs, outputs []*big.Int) error {
		nbBytes := fp.Bytes
		xCoord := make([]byte, nbBytes)
		if len(nativeInputs) != nbBytes {
			return fmt.Errorf("expecting %d inputs, got %d", nbBytes, len(nativeInputs))
		}
		for i := range nbBytes {
			if !nativeInputs[i].IsUint64() || ((nativeInputs[i].Uint64() &^ 0xff) > 0) {
				return fmt.Errorf("input %d is not a byte: %s", i, nativeInputs[i].String())
			}
			xCoord[i] = byte(nativeInputs[i].Uint64())
		}

		var point bls12381.G1Affine
		_, err := point.SetBytes(xCoord)
		// we have an error. However, as we have already checked the mask to be
		// valid (0b100, 0b101, 0b110), and additionally checked that if mask is
		// for infinity then also X is infinity, then in practice we can have
		// only errors if x does not allow to encode valid point on a curve. In
		// this case, we return a random point not on curve ourselves and then
		// it is later checked in circuit indeed not to be on a curve.
		if err != nil {
			var sign int64
			switch (xCoord[0] & mMask) >> 5 {
			case 0b100:
				sign = 1
			case 0b101:
				sign = -1
			default:
				return fmt.Errorf("invalid mask %b for unmarshalG1: %w", (xCoord[0]&mMask)>>5, err)
			}
			for i := 1; i < 100; i++ { // we have probability 1/2 for each i to find a point not on curve
				point.Y.SetInt64(int64(i) * sign)
				if !point.IsOnCurve() {
					break
				}
			}
		}
		point.Y.BigInt(outputs[0])
		return nil
	})
}

func scalarMulG2Hint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 4 {
			return fmt.Errorf("expecting four base inputs (Q.X.A0, Q.X.A1, Q.Y.A0, Q.Y.A1), got %d", len(baseInputs))
		}
		if len(baseOutputs) != 4 {
			return fmt.Errorf("expecting four base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 1 {
			return fmt.Errorf("expecting one scalar input, got %d", len(scalarInputs))
		}

		// compute the resulting point [s]Q on G2
		var Q bls12381.G2Affine
		Q.X.A0.SetBigInt(baseInputs[0])
		Q.X.A1.SetBigInt(baseInputs[1])
		Q.Y.A0.SetBigInt(baseInputs[2])
		Q.Y.A1.SetBigInt(baseInputs[3])
		Q.ScalarMultiplication(&Q, scalarInputs[0])
		Q.X.A0.BigInt(baseOutputs[0])
		Q.X.A1.BigInt(baseOutputs[1])
		Q.Y.A0.BigInt(baseOutputs[2])
		Q.Y.A1.BigInt(baseOutputs[3])
		return nil
	})
}

// g2CofactorClearingConstant is the cofactor-clearing constant for BLS12-381 G2:
// the product of every cofactor prime-power < 2^nbits (h = 13²·23²·2713·11953·
// 262069·(448-bit prime)). These are exactly the cofactor primes reachable by the
// r^(1/4) sub-scalars, so [c]·E'(𝔽ₚ²) removes exactly the exploitable torsion; the
// 448-bit prime part has order ≫ 2^nbits. Every reachable prime power must appear:
// omitting e.g. 262069 leaves an order-262069 chosen-scalar torsion forgery open,
// since [c] stays invertible on that torsion.
var g2CofactorClearingConstant = func() *big.Int {
	c := big.NewInt(13 * 13 * 23 * 23) // 89401
	c.Mul(c, big.NewInt(2713))
	c.Mul(c, big.NewInt(11953))
	c.Mul(c, big.NewInt(262069))
	return c
}()

// scalarMulG2CofactorPreimageHint returns S = [s · c⁻¹ mod r]·Q, a preimage of
// R = [s]Q under multiplication by the cofactor-clearing constant c. The
// in-circuit check [c]S == R with S constrained on-curve forces R into the
// prime-order subgroup: a torsion-shifted R' = [s]Q + T (ord(T) | c) has no
// on-curve preimage under [c], so no satisfying S exists.
func scalarMulG2CofactorPreimageHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 4 {
			return fmt.Errorf("expecting four base inputs (Q.X.A0, Q.X.A1, Q.Y.A0, Q.Y.A1), got %d", len(baseInputs))
		}
		if len(baseOutputs) != 4 {
			return fmt.Errorf("expecting four base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 1 {
			return fmt.Errorf("expecting one scalar input, got %d", len(scalarInputs))
		}

		cInv := new(big.Int).ModInverse(g2CofactorClearingConstant, scalarModulus)
		if cInv == nil {
			return fmt.Errorf("cofactor-clearing constant not invertible mod r")
		}
		m := new(big.Int).Mul(scalarInputs[0], cInv)
		m.Mod(m, scalarModulus)

		// S = [s · c⁻¹ mod r]·Q, so [c]S = [s]Q = R.
		var Q bls12381.G2Affine
		Q.X.A0.SetBigInt(baseInputs[0])
		Q.X.A1.SetBigInt(baseInputs[1])
		Q.Y.A0.SetBigInt(baseInputs[2])
		Q.Y.A1.SetBigInt(baseInputs[3])
		Q.ScalarMultiplication(&Q, m)
		Q.X.A0.BigInt(baseOutputs[0])
		Q.X.A1.BigInt(baseOutputs[1])
		Q.Y.A0.BigInt(baseOutputs[2])
		Q.Y.A1.BigInt(baseOutputs[3])
		return nil
	})
}

func rationalReconstructExtG2(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
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

		// Use lattice reduction to find (x, y, z, t) such that
		// k ≡ (x + λ*y) / (z + λ*t) (mod r)
		//
		// in-circuit we check that R - [s]Q = 0 or equivalently R + [-s]Q = 0
		// so here we use k = -s.
		k := new(big.Int).Neg(emuInputs[0])
		k.Mod(k, moduli[0])
		rc := lattice.NewReconstructor(moduli[0]).SetLambda(emuInputs[1])
		res := rc.RationalReconstructExt(k)
		x, y, z, t := res[0], res[1], res[2], res[3]

		// u1 = x, u2 = y, v1 = z, v2 = t
		emuOutputs[0].Abs(x)
		emuOutputs[1].Abs(y)
		emuOutputs[2].Abs(z)
		emuOutputs[3].Abs(t)

		// signs
		nativeOutputs[0].SetUint64(0)
		nativeOutputs[1].SetUint64(0)
		nativeOutputs[2].SetUint64(0)
		nativeOutputs[3].SetUint64(0)

		if x.Sign() < 0 {
			nativeOutputs[0].SetUint64(1)
		}
		if y.Sign() < 0 {
			nativeOutputs[1].SetUint64(1)
		}
		if z.Sign() < 0 {
			nativeOutputs[2].SetUint64(1)
		}
		if t.Sign() < 0 {
			nativeOutputs[3].SetUint64(1)
		}
		return nil
	})
}
