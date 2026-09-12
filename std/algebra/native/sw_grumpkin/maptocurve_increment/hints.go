package maptocurve_increment

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		yIncrementHint,
	}
}

// yIncrementHint computes the y-increment witness for Grumpkin (y² = x³ − 17).
//
// Inputs:  [msg]
// Outputs: [K, X] such that Y = msg·T + K, X = cbrt(Y² + 17).
func yIncrementHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("y-increment hint: expected 1 input, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("y-increment hint: expected 2 outputs, got %d", len(outputs))
	}

	var msg, y, y2, rhs, b17, tFp, yBase fp.Element
	msg.SetBigInt(inputs[0])
	b17.SetUint64(17)
	tFp.SetUint64(T)
	yBase.Mul(&msg, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		// X³ = Y² + 17
		y2.Square(&y)
		rhs.Add(&y2, &b17)

		var x fp.Element
		if x.Cbrt(&rhs) == nil {
			continue
		}

		outputs[0].SetUint64(k)
		x.BigInt(outputs[1])
		return nil
	}
	return fmt.Errorf("y-increment hint: no valid k found for Grumpkin")
}
