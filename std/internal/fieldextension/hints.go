package fieldextension

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	mamabearextensions "github.com/consensys/gnark-crypto/field/mamabear/extensions"
	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns the hints defined in this package. Can be used for
// registering the hints when solving/proving serialized circuits. The hints are
// automatically registered when importing current package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		inverseE2Hint,
		inverseE4Hint,
		inverseE3Hint,
	}
}

func inverseE2Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("inverseE2Hint: expected 2 inputs, got %d", len(inputs))
	}
	if len(res) != 2 {
		return fmt.Errorf("inverseE2Hint: expected 2 outputs, got %d", len(res))
	}
	var a, c extensions.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])

	c.Inverse(&a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func inverseE4Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("inverseE4Hint: expected 4 inputs, got %d", len(inputs))
	}
	if len(res) != 4 {
		return fmt.Errorf("inverseE4Hint: expected 4 outputs, got %d", len(res))
	}
	var a, c extensions.E4

	a.B0.A0.SetBigInt(inputs[0])
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])

	c.Inverse(&a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])

	return nil
}

func inverseE3Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("inverseE3Hint: expected 3 inputs, got %d", len(inputs))
	}
	if len(res) != 3 {
		return fmt.Errorf("inverseE3Hint: expected 3 outputs, got %d", len(res))
	}
	var a, c mamabearextensions.E3

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])
	a.A2.SetBigInt(inputs[2])

	c.Inverse(&a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])
	c.A2.BigInt(res[2])

	return nil
}
