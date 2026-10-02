package emulated

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

// TODO @gbotrel hint[T FieldParams] would simplify this . Issue is when registering hint, if QuoRem[T] was declared
// inside a func, then it becomes anonymous and hint identification is screwed.

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		DivHint,
		InverseHint,
		SqrtHint,
		mulHint,
		subPaddingHint,
		polyMvHint,
		smallMulHint,
		smallCheckZeroHint,
	}
}

// nbMultiplicationResLimbs returns the number of limbs which fit the
// multiplication result.
func nbMultiplicationResLimbs(lenLeft, lenRight int) int {
	res := lenLeft + lenRight - 1
	if res < 0 {
		res = 0
	}
	return res
}

// computeInverseHint packs the inputs for the InverseHint hint function.
func (f *Field[T]) computeInverseHint(inLimbs []frontend.Variable) (inverseLimbs []frontend.Variable, err error) {
	hintInputs := []frontend.Variable{
		f.fParams.BitsPerLimb(),
		f.fParams.NbLimbs(),
	}
	p := f.Modulus()
	hintInputs = append(hintInputs, p.Limbs...)
	hintInputs = append(hintInputs, inLimbs...)
	// InverseHint expects the input on NbLimbs limbs, but an element may be
	// stored on fewer limbs (e.g. a constant or a selection between small
	// constants). Pad it with zero limbs.
	for i := len(inLimbs); i < int(f.fParams.NbLimbs()); i++ {
		hintInputs = append(hintInputs, 0)
	}
	return f.api.NewHint(InverseHint, int(f.fParams.NbLimbs()), hintInputs...)
}

// InverseHint computes the inverse x^-1 for the input x and stores it in outputs.
func InverseHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 2 {
		return errors.New("input must be at least two elements")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	if len(inputs[2:]) < 2*nbLimbs {
		return errors.New("inputs missing")
	}
	if len(outputs) != nbLimbs {
		return errors.New("result does not fit into output")
	}
	p := new(big.Int)
	if err := limbs.Recompose(inputs[2:2+nbLimbs], nbBits, p); err != nil {
		return fmt.Errorf("recompose emulated order: %w", err)
	}
	x := new(big.Int)
	if err := limbs.Recompose(inputs[2+nbLimbs:], nbBits, x); err != nil {
		return fmt.Errorf("recompose value: %w", err)
	}
	if x.ModInverse(x, p) == nil {
		return errors.New("input and modulus not relatively primes")
	}
	if err := limbs.Decompose(x, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose: %w", err)
	}
	return nil
}

// computeDivisionHint packs the inputs for DivisionHint hint function.
func (f *Field[T]) computeDivisionHint(nomLimbs, denomLimbs []frontend.Variable) (divLimbs []frontend.Variable, err error) {
	hintInputs := []frontend.Variable{
		f.fParams.BitsPerLimb(),
		f.fParams.NbLimbs(),
		len(denomLimbs),
		len(nomLimbs),
	}
	p := f.Modulus()
	hintInputs = append(hintInputs, p.Limbs...)
	hintInputs = append(hintInputs, nomLimbs...)
	hintInputs = append(hintInputs, denomLimbs...)
	return f.api.NewHint(DivHint, int(f.fParams.NbLimbs()), hintInputs...)
}

// DivHint computes the value z = x/y for inputs x and y and stores z in
// outputs.
func DivHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 3 {
		return errors.New("input must be at least three elements")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	nbDenomLimbs := int(inputs[2].Int64())
	// nominator does not have to be reduced and can be more than nbLimbs.
	// Denominator and order have to be nbLimbs long.
	nbNomLimbs := int(inputs[3].Int64())
	if len(inputs[4:]) != nbLimbs+nbNomLimbs+nbDenomLimbs {
		return errors.New("input length mismatch")
	}
	if len(outputs) != nbLimbs {
		return errors.New("result does not fit into output")
	}
	p := new(big.Int)
	if err := limbs.Recompose(inputs[4:4+nbLimbs], nbBits, p); err != nil {
		return fmt.Errorf("recompose emulated order: %w", err)
	}
	nominator := new(big.Int)
	if err := limbs.Recompose(inputs[4+nbLimbs:4+nbLimbs+nbNomLimbs], nbBits, nominator); err != nil {
		return fmt.Errorf("recompose nominator: %w", err)
	}
	denominator := new(big.Int)
	if err := limbs.Recompose(inputs[4+nbLimbs+nbNomLimbs:], nbBits, denominator); err != nil {
		return fmt.Errorf("recompose denominator: %w", err)
	}
	res := new(big.Int).ModInverse(denominator, p)
	if res == nil {
		return errors.New("no modular inverse")
	}
	res.Mul(res, nominator)
	res.Mod(res, p)
	if err := limbs.Decompose(res, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose division: %w", err)
	}
	return nil
}

// SqrtHint compute square root of the input.
func SqrtHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return UnwrapHint(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 1 {
			return errors.New("expecting single input")
		}
		if len(outputs) != 1 {
			return errors.New("expecting single output")
		}
		res := new(big.Int)
		if res.ModSqrt(inputs[0], field) == nil {
			return errors.New("no square root")
		}
		outputs[0].Set(res)
		return nil
	})
}
