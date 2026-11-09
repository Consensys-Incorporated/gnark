package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECG1ScalarMulSumBLS computes the scalar multiplication of a point P by a
// scalar s, adds it to a previous point prev, and checks that the result is
// equal to expected. It is used to implement the [BLS12_G1MSM] precompile
// contract at address 0x0c.
//
// [BLS12_G1MSM]: https://eips.ethereum.org/EIPS/eip-2537
func ECG1ScalarMulSumBLS(api frontend.API, prev, P *sw_bls12381.G1Affine, s *emulated.Element[sw_bls12381.ScalarField], expected *sw_bls12381.G1Affine) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}
	// Check the point is in G1
	g1.AssertIsOnG1(P)
	// Compute the scalar multiplication. P was checked to be in G1 above, so
	// skip ScalarMul's own (identical) subgroup check.
	res := curve.ScalarMul(P, s, algopts.WithNoSubgroupMembershipCheck())
	// Compute the aggregate
	sum := curve.AddUnified(prev, res)
	// Assert that the sum is as expected
	g1.AssertIsEqual(sum, expected)
	return nil
}
