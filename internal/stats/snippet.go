package stats

import (
	"math"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	sw_emulated_maptocurve "github.com/consensys/gnark/std/algebra/emulated/sw_emulated/maptocurve_increment"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	sw_bls12377_maptocurve "github.com/consensys/gnark/std/algebra/native/sw_bls12377/maptocurve_increment"
	sw_grumpkin_maptocurve "github.com/consensys/gnark/std/algebra/native/sw_grumpkin/maptocurve_increment"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/selector"
)

var (
	initOnce sync.Once
	snippets = make(map[string]Circuit)
)

func GetSnippets() map[string]Circuit {
	initOnce.Do(initSnippets)
	return snippets
}

type snippet func(api frontend.API, newVariable func() frontend.Variable)

func registerSnippet(name string, snippet snippet, curves ...ecc.ID) {
	if _, ok := snippets[name]; ok {
		panic("circuit " + name + " already registered")
	}
	if len(curves) == 0 {
		curves = gnark.Curves()
	}
	snippets[name] = Circuit{makeSnippetCircuit(snippet), curves}
}

func initSnippets() {
	// add api snippets
	registerSnippet("api/IsZero", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = api.IsZero(newVariable())
	})

	registerSnippet("api/Lookup2", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = api.Lookup2(newVariable(), newVariable(), newVariable(), newVariable(), newVariable(), newVariable())
	})

	registerSnippet("api/AssertIsLessOrEqual", func(api frontend.API, newVariable func() frontend.Variable) {
		api.AssertIsLessOrEqual(newVariable(), newVariable())
	})
	registerSnippet("api/AssertIsLessOrEqual/constant_bound_64_bits", func(api frontend.API, newVariable func() frontend.Variable) {
		bound := uint64(math.MaxUint64)
		api.AssertIsLessOrEqual(newVariable(), bound)
	})

	registerSnippet("api/AssertIsCrumb", func(api frontend.API, newVariable func() frontend.Variable) {
		api.AssertIsCrumb(newVariable())
	})

	// add std snippets
	registerSnippet("math/bits.ToBinary", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToBinary(api, newVariable())
	})
	registerSnippet("math/bits.ToBinary/unconstrained", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToBinary(api, newVariable(), bits.WithUnconstrainedOutputs())
	})
	registerSnippet("math/bits.ToTernary", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToTernary(api, newVariable())
	})
	registerSnippet("math/bits.ToTernary/unconstrained", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToTernary(api, newVariable(), bits.WithUnconstrainedOutputs())
	})

	registerSnippet("hash/mimc", func(api frontend.API, newVariable func() frontend.Variable) {
		mimc, _ := mimc.NewMiMC(api)
		mimc.Write(newVariable())
		_ = mimc.Sum()
	})
	registerSnippet("math/emulated/secp256k1_64", func(api frontend.API, newVariable func() frontend.Variable) {
		secp256k1, _ := emulated.NewField[emulated.Secp256k1Fp](api)

		newElement := func() *emulated.Element[emulated.Secp256k1Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return secp256k1.NewElement(limbs)
		}

		x13 := secp256k1.Mul(newElement(), newElement())
		x13 = secp256k1.Mul(x13, newElement())
		five := secp256k1.NewElement(5)
		fx2 := secp256k1.Mul(five, newElement())
		nom := secp256k1.Sub(fx2, x13)
		denom := secp256k1.Add(newElement(), newElement())
		denom = secp256k1.Add(denom, newElement())
		denom = secp256k1.Add(denom, newElement())
		free := secp256k1.Div(nom, denom)
		res := secp256k1.Add(x13, fx2)
		res = secp256k1.Add(res, free)
		secp256k1.AssertIsEqual(res, newElement())
	})

	registerSnippet("pairing_bls12377", func(api frontend.API, newVariable func() frontend.Variable) {

		var dummyG1 sw_bls12377.G1Affine
		var dummyG2 sw_bls12377.G2Affine
		dummyG1.X = newVariable()
		dummyG1.Y = newVariable()
		dummyG2.P.X.A0 = newVariable()
		dummyG2.P.X.A1 = newVariable()
		dummyG2.P.Y.A0 = newVariable()
		dummyG2.P.Y.A1 = newVariable()

		_, _ = sw_bls12377.Pair(api, []sw_bls12377.G1Affine{dummyG1}, []sw_bls12377.G2Affine{dummyG2})

	}, ecc.BW6_761)

	registerSnippet("pairing_bls12381", func(api frontend.API, newVariable func() frontend.Variable) {

		bls12381, _ := emulated.NewField[emulated.BLS12381Fp](api)
		newElement := func() *emulated.Element[emulated.BLS12381Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BLS12381Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bls12381.NewElement(limbs)
		}
		var dummyG1 sw_bls12381.G1Affine
		var dummyG2 sw_bls12381.G2Affine
		dummyG1.X = *newElement()
		dummyG1.Y = *newElement()
		dummyG2.P.X.A0 = *newElement()
		dummyG2.P.X.A1 = *newElement()
		dummyG2.P.Y.A0 = *newElement()
		dummyG2.P.Y.A1 = *newElement()

		pr, err := sw_bls12381.NewPairing(api)
		if err != nil {
			panic(err)
		}
		_, _ = pr.Pair([]*sw_bls12381.G1Affine{&dummyG1}, []*sw_bls12381.G2Affine{&dummyG2})

	}, ecc.BN254)

	registerSnippet("pairing_bn254", func(api frontend.API, newVariable func() frontend.Variable) {

		bn254, _ := emulated.NewField[emulated.BN254Fp](api)
		newElement := func() *emulated.Element[emulated.BN254Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn254.NewElement(limbs)
		}
		var dummyG1 sw_bn254.G1Affine
		var dummyG2 sw_bn254.G2Affine
		dummyG1.X = *newElement()
		dummyG1.Y = *newElement()
		dummyG2.P.X.A0 = *newElement()
		dummyG2.P.X.A1 = *newElement()
		dummyG2.P.Y.A0 = *newElement()
		dummyG2.P.Y.A1 = *newElement()

		pr, err := sw_bn254.NewPairing(api)
		if err != nil {
			panic(err)
		}
		_, _ = pr.Pair([]*sw_bn254.G1Affine{&dummyG1}, []*sw_bn254.G2Affine{&dummyG2})

	}, ecc.BN254)

	registerSnippet("pairing_bw6761", func(api frontend.API, newVariable func() frontend.Variable) {

		bw6761, _ := emulated.NewField[emulated.BW6761Fp](api)
		newElement := func() *emulated.Element[emulated.BW6761Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BW6761Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bw6761.NewElement(limbs)
		}
		var dummyG1 sw_bw6761.G1Affine
		var dummyG2 sw_bw6761.G2Affine
		dummyG1.X = *newElement()
		dummyG1.Y = *newElement()
		dummyG2.P.X = *newElement()
		dummyG2.P.Y = *newElement()

		pr, err := sw_bw6761.NewPairing(api)
		if err != nil {
			panic(err)
		}
		_, _ = pr.Pair([]*sw_bw6761.G1Affine{&dummyG1}, []*sw_bw6761.G2Affine{&dummyG2})

	}, ecc.BN254)

	registerSnippet("scalar_mul_G1_bn254", func(api frontend.API, newVariable func() frontend.Variable) {

		cr, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetCurveParams[emulated.BN254Fp]())
		if err != nil {
			panic(err)
		}
		bn_fr, _ := emulated.NewField[emulated.BN254Fr](api)
		newFr := func() *emulated.Element[emulated.BN254Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fr.NewElement(limbs)
		}
		bn_fp, _ := emulated.NewField[emulated.BN254Fp](api)
		newFp := func() *emulated.Element[emulated.BN254Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fp.NewElement(limbs)
		}
		var dummyG1 sw_emulated.AffinePoint[emulated.BN254Fp]
		dummyG1.X = *newFp()
		dummyG1.Y = *newFp()
		_ = cr.ScalarMul(
			&dummyG1,
			newFr(),
		)

	}, ecc.BN254)

	registerSnippet("scalar_mul_G1_bn254_incomplete", func(api frontend.API, newVariable func() frontend.Variable) {

		cr, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetCurveParams[emulated.BN254Fp]())
		if err != nil {
			panic(err)
		}
		bn_fr, _ := emulated.NewField[emulated.BN254Fr](api)
		newFr := func() *emulated.Element[emulated.BN254Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fr.NewElement(limbs)
		}
		bn_fp, _ := emulated.NewField[emulated.BN254Fp](api)
		newFp := func() *emulated.Element[emulated.BN254Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fp.NewElement(limbs)
		}
		var dummyG1 sw_emulated.AffinePoint[emulated.BN254Fp]
		dummyG1.X = *newFp()
		dummyG1.Y = *newFp()
		_ = cr.ScalarMul(
			&dummyG1,
			newFr(),
			algopts.WithIncompleteArithmetic(),
		)

	}, ecc.BN254)

	registerSnippet("scalar_mul_secp256k1", func(api frontend.API, newVariable func() frontend.Variable) {

		cr, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
		if err != nil {
			panic(err)
		}
		bn_fr, _ := emulated.NewField[emulated.Secp256k1Fr](api)
		newFr := func() *emulated.Element[emulated.Secp256k1Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fr.NewElement(limbs)
		}
		bn_fp, _ := emulated.NewField[emulated.Secp256k1Fp](api)
		newFp := func() *emulated.Element[emulated.Secp256k1Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fp.NewElement(limbs)
		}
		var dummyG1 sw_emulated.AffinePoint[emulated.Secp256k1Fp]
		dummyG1.X = *newFp()
		dummyG1.Y = *newFp()
		_ = cr.ScalarMul(
			&dummyG1,
			newFr(),
		)

	}, ecc.BN254)

	registerSnippet("scalar_mul_secp256k1_incomplete", func(api frontend.API, newVariable func() frontend.Variable) {

		cr, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
		if err != nil {
			panic(err)
		}
		bn_fr, _ := emulated.NewField[emulated.Secp256k1Fr](api)
		newFr := func() *emulated.Element[emulated.Secp256k1Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fr.NewElement(limbs)
		}
		bn_fp, _ := emulated.NewField[emulated.Secp256k1Fp](api)
		newFp := func() *emulated.Element[emulated.Secp256k1Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fp.NewElement(limbs)
		}
		var dummyG1 sw_emulated.AffinePoint[emulated.Secp256k1Fp]
		dummyG1.X = *newFp()
		dummyG1.Y = *newFp()
		_ = cr.ScalarMul(
			&dummyG1,
			newFr(),
			algopts.WithIncompleteArithmetic(),
		)

	}, ecc.BN254)

	registerSnippet("scalar_mul_P256", func(api frontend.API, newVariable func() frontend.Variable) {

		cr, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, sw_emulated.GetCurveParams[emulated.P256Fp]())
		if err != nil {
			panic(err)
		}
		bn_fr, _ := emulated.NewField[emulated.P256Fr](api)
		newFr := func() *emulated.Element[emulated.P256Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.P256Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fr.NewElement(limbs)
		}
		bn_fp, _ := emulated.NewField[emulated.P256Fp](api)
		newFp := func() *emulated.Element[emulated.P256Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.P256Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fp.NewElement(limbs)
		}
		var dummyG1 sw_emulated.AffinePoint[emulated.P256Fp]
		dummyG1.X = *newFp()
		dummyG1.Y = *newFp()
		_ = cr.ScalarMul(
			&dummyG1,
			newFr(),
		)

	}, ecc.BN254)

	registerSnippet("scalar_mul_P256_incomplete", func(api frontend.API, newVariable func() frontend.Variable) {

		cr, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, sw_emulated.GetCurveParams[emulated.P256Fp]())
		if err != nil {
			panic(err)
		}
		bn_fr, _ := emulated.NewField[emulated.P256Fr](api)
		newFr := func() *emulated.Element[emulated.P256Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.P256Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fr.NewElement(limbs)
		}
		bn_fp, _ := emulated.NewField[emulated.P256Fp](api)
		newFp := func() *emulated.Element[emulated.P256Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.P256Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn_fp.NewElement(limbs)
		}
		var dummyG1 sw_emulated.AffinePoint[emulated.P256Fp]
		dummyG1.X = *newFp()
		dummyG1.Y = *newFp()
		_ = cr.ScalarMul(
			&dummyG1,
			newFr(),
			algopts.WithIncompleteArithmetic(),
		)

	}, ecc.BN254)

	// G2 scalar mul snippets — exercise the GLV+FakeGLV path to track its cost.
	registerSnippet("scalar_mul_G2_bls12381", func(api frontend.API, newVariable func() frontend.Variable) {
		bls12381fp, _ := emulated.NewField[emulated.BLS12381Fp](api)
		newFp := func() *emulated.Element[emulated.BLS12381Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BLS12381Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := range limbs {
				limbs[i] = newVariable()
			}
			return bls12381fp.NewElement(limbs)
		}
		bls12381fr, _ := emulated.NewField[emulated.BLS12381Fr](api)
		newFr := func() *emulated.Element[emulated.BLS12381Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BLS12381Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := range limbs {
				limbs[i] = newVariable()
			}
			return bls12381fr.NewElement(limbs)
		}
		g2, _ := sw_bls12381.NewG2(api)
		var dummyQ sw_bls12381.G2Affine
		dummyQ.P.X.A0 = *newFp()
		dummyQ.P.X.A1 = *newFp()
		dummyQ.P.Y.A0 = *newFp()
		dummyQ.P.Y.A1 = *newFp()
		_ = g2.ScalarMul(&dummyQ, newFr())
	}, ecc.BN254)

	registerSnippet("scalar_mul_G2_bn254", func(api frontend.API, newVariable func() frontend.Variable) {
		bn254fp, _ := emulated.NewField[emulated.BN254Fp](api)
		newFp := func() *emulated.Element[emulated.BN254Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := range limbs {
				limbs[i] = newVariable()
			}
			return bn254fp.NewElement(limbs)
		}
		bn254fr, _ := emulated.NewField[emulated.BN254Fr](api)
		newFr := func() *emulated.Element[emulated.BN254Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BN254Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := range limbs {
				limbs[i] = newVariable()
			}
			return bn254fr.NewElement(limbs)
		}
		g2, _ := sw_bn254.NewG2(api)
		var dummyQ sw_bn254.G2Affine
		dummyQ.P.X.A0 = *newFp()
		dummyQ.P.X.A1 = *newFp()
		dummyQ.P.Y.A0 = *newFp()
		dummyQ.P.Y.A1 = *newFp()
		_ = g2.ScalarMul(&dummyQ, newFr())
	}, ecc.BN254)

	registerSnippet("scalar_mul_G2_bw6761", func(api frontend.API, newVariable func() frontend.Variable) {
		bw6fp, _ := emulated.NewField[emulated.BW6761Fp](api)
		newFp := func() *emulated.Element[emulated.BW6761Fp] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BW6761Fp](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := range limbs {
				limbs[i] = newVariable()
			}
			return bw6fp.NewElement(limbs)
		}
		bw6fr, _ := emulated.NewField[emulated.BW6761Fr](api)
		newFr := func() *emulated.Element[emulated.BW6761Fr] {
			nbLimbs, _ := emulated.GetEffectiveFieldParams[emulated.BW6761Fr](api.Compiler().Field())
			limbs := make([]frontend.Variable, nbLimbs)
			for i := range limbs {
				limbs[i] = newVariable()
			}
			return bw6fr.NewElement(limbs)
		}
		g2, _ := sw_bw6761.NewG2(api)
		var dummyQ sw_bw6761.G2Affine
		dummyQ.P.X = *newFp()
		dummyQ.P.Y = *newFp()
		_ = g2.ScalarMul(&dummyQ, newFr())
	}, ecc.BN254)

	registerSnippet("selector/mux_3", func(api frontend.API, newVariable func() frontend.Variable) {
		selector.Mux(api, newVariable(), newVariable(), newVariable(), newVariable())
	})

	registerSnippet("selector/mux_4", func(api frontend.API, newVariable func() frontend.Variable) {
		selector.Mux(api, newVariable(), newVariable(), newVariable(), newVariable(), newVariable())
	})

	registerSnippet("selector/mux_5", func(api frontend.API, newVariable func() frontend.Variable) {
		selector.Mux(api, newVariable(), newVariable(), newVariable(), newVariable(), newVariable(), newVariable())
	})

	registerSnippet("selector/binaryMux_4", func(api frontend.API, newVariable func() frontend.Variable) {
		selector.BinaryMux(api, []frontend.Variable{newVariable(), newVariable()}, []frontend.Variable{newVariable(), newVariable(), newVariable(), newVariable()})
	})

	registerSnippet("selector/binaryMux_8", func(api frontend.API, newVariable func() frontend.Variable) {
		selector.BinaryMux(api, []frontend.Variable{newVariable(), newVariable(), newVariable()}, []frontend.Variable{newVariable(), newVariable(), newVariable(), newVariable(), newVariable(), newVariable(), newVariable(), newVariable()})
	})

	// --- map-to-curve increment-and-check gadgets ---

	registerEmulatedMaptocurveSnippet[emulated.BN254Fp, emulated.BN254Fr]("maptocurve_increment/x_bn254", true, ecc.BN254)
	registerEmulatedMaptocurveSnippet[emulated.BN254Fp, emulated.BN254Fr]("maptocurve_increment/y_bn254", false, ecc.BN254)
	registerEmulatedMaptocurveSnippet[emulated.Secp256k1Fp, emulated.Secp256k1Fr]("maptocurve_increment/x_secp256k1", true, ecc.BN254)
	registerEmulatedMaptocurveSnippet[emulated.Secp256k1Fp, emulated.Secp256k1Fr]("maptocurve_increment/y_secp256k1", false, ecc.BN254)
	registerEmulatedMaptocurveSnippet[emulated.P256Fp, emulated.P256Fr]("maptocurve_increment/x_p256", true, ecc.BN254)
	registerEmulatedMaptocurveSnippet[emulated.P256Fp, emulated.P256Fr]("maptocurve_increment/y_p256", false, ecc.BN254)

	registerSnippet("maptocurve_increment/y_grumpkin", func(api frontend.API, newVariable func() frontend.Variable) {
		_, _, _ = sw_grumpkin_maptocurve.YIncrement(api, newVariable())
	}, ecc.BN254)

	registerSnippet("maptocurve_increment/y_bls12377", func(api frontend.API, newVariable func() frontend.Variable) {
		_, _, _ = sw_bls12377_maptocurve.YIncrement(api, newVariable())
	}, ecc.BW6_761)
}

// registerEmulatedMaptocurveSnippet wires up an emulated map-to-curve
// increment-and-check gadget snippet for the given base/scalar field pair.
// When xVariant is true, it exercises [Mapper.XIncrement]; otherwise it
// exercises [Mapper.YIncrement].
func registerEmulatedMaptocurveSnippet[B, S emulated.FieldParams](name string, xVariant bool, curves ...ecc.ID) {
	registerSnippet(name, func(api frontend.API, newVariable func() frontend.Variable) {
		crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
		if err != nil {
			panic(err)
		}
		m, err := sw_emulated_maptocurve.NewMapper[B, S](api, crv)
		if err != nil {
			panic(err)
		}
		field, err := emulated.NewField[B](api)
		if err != nil {
			panic(err)
		}
		nbLimbs, _ := emulated.GetEffectiveFieldParams[B](api.Compiler().Field())
		limbs := make([]frontend.Variable, nbLimbs)
		for i := range limbs {
			limbs[i] = newVariable()
		}
		msg := field.NewElement(limbs)
		if xVariant {
			_, _ = m.XIncrement(msg)
		} else {
			_, _ = m.YIncrement(msg)
		}
	}, curves...)
}

type snippetCircuit struct {
	V      [1024]frontend.Variable
	s      snippet
	vIndex int
}

func (d *snippetCircuit) Define(api frontend.API) error {
	d.s(api, d.newVariable)
	return nil
}

func (d *snippetCircuit) newVariable() frontend.Variable {
	d.vIndex++
	return d.V[(d.vIndex-1)%len(d.V)]
}

func makeSnippetCircuit(s snippet) frontend.Circuit {
	return &snippetCircuit{s: s}
}
