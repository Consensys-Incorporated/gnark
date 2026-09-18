package sw_grumpkin

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalar,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func decomposeScalar(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHintContext(nativeMod, nativeInputs, nativeOutputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return errors.New("expecting one modulus")
		}
		nativeInputs, _ := hc.NativeInputsOutputs()
		if len(nativeInputs) != 1 {
			return errors.New("expecting one native input")
		}
		_, nnOutputs := hc.InputsOutputs(moduli[0])
		if len(nnOutputs) != 2 {
			return errors.New("expecting two outputs")
		}
		cc := getInnerCurveConfig(nativeMod)
		sp := ecc.SplitScalar(nativeInputs[0], cc.glvBasis)
		nnOutputs[0].Set(&(sp[0]))
		nnOutputs[1].Neg(&(sp[1]))

		return nil
	})
}

func callDecomposeScalar(api frontend.API, s frontend.Variable) (s1, s2 frontend.Variable) {
	cc := getInnerCurveConfig(api.Compiler().Field())
	sapi, err := emulated.NewField[emparams.GrumpkinFr](api)
	if err != nil {
		panic(err)
	}
	// compute the decomposition using a hint. We have to use the emulated
	// version which takes native input and outputs non-native outputs.
	//
	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	_, sd, err := sapi.NewHintGeneric(decomposeScalar, 0, 2, []frontend.Variable{s}, nil, emulated.WithHintOutputRangeCheckBits(map[int]int{0: 127, 1: 127}))
	if err != nil {
		panic(err)
	}
	// lambda as nonnative element
	lambdaEmu := sapi.NewElement(cc.lambda)
	// Bind the decomposition to the actual scalar s. We build semu = s as a
	// GrumpkinFr element from the canonical bit-decomposition of the native s:
	// api.ToBinary emits FieldBitLen bits and, since it decomposes to the full
	// field bit-length, enforces reducedness (the recomposed value is ≤ r_native−1).
	// Hence semu equals s exactly. This is sound because s < r_native < r_grumpkin,
	// so there is no s+r_native wraparound into a distinct GrumpkinFr element.
	//
	// Without this binding, semu is an unconstrained hint value and the sole
	// relation s1 − λ·s2 ≡ semu ties the sub-scalars to a free semu unrelated to s,
	// letting a prover prove [semu]Q for an arbitrary semu ≠ s.
	sBits := api.ToBinary(s)
	semu := sapi.FromBits(sBits...)
	_, nbBits := emulated.GetEffectiveFieldParams[emparams.GrumpkinFr](api.Compiler().Field())
	// s1 − λ·s2 == s mod r
	lhs := sapi.MulNoReduce(sd[1], lambdaEmu)
	lhs = sapi.Sub(sd[0], lhs)

	sapi.AssertIsEqual(lhs, semu)

	s1 = 0
	s2 = 0
	b := big.NewInt(1)
	for i := range sd[0].Limbs {
		s1 = api.Add(s1, api.Mul(sd[0].Limbs[i], b))
		s2 = api.Add(s2, api.Mul(sd[1].Limbs[i], b))
		b.Lsh(b, nbBits)
	}
	return s1, s2
}
