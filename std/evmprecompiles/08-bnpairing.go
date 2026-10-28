package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// ECPair implements [ALT_BN128_PAIRING_CHECK] precompile contract at address 0x08.
//
// To have a fixed-circuit regardless of the number of inputs, we need 2 fixed circuits:
//   - MillerLoopAndMul:
//     A Miller loop of fixed size 1 followed by a multiplication in 𝔽p¹².
//   - MillerLoopAndFinalExpCheck:
//     A Miller loop of fixed size 1 followed by a multiplication in 𝔽p¹², and
//     a check that the result lies in the same equivalence class as the
//     reduced pairing purported to be 1. This check replaces the final
//     exponentiation step in-circuit and follows Section 4 of [On Proving
//     Pairings] paper by A. Novakovic and L. Eagen.
//
// N.B.: This is a sub-optimal routine but defines a fixed circuit regardless
// of the number of inputs.  We can extend this routine to handle a 2-by-2
// logic but we prefer a minimal number of circuits (2).
//
// See the methods [ECPairMillerLoopAndMul] and [ECPairMillerLoopAndFinalExpCheck] for the fixed circuits.
// See the method [ECPairIsOnG2] for the check that Qᵢ are on G2.
//
// [ALT_BN128_PAIRING_CHECK]: https://github.com/ethereum/execution-specs/blob/master/src/ethereum/cancun/vm/precompiled_contracts/alt_bn128.py
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func ECPair(api frontend.API, P []*sw_bn254.G1Affine, Q []*sw_bn254.G2Affine) {
	if len(P) != len(Q) {
		panic("P and Q length mismatch")
	}
	if len(P) < 1 {
		panic("invalid multipairing size bound")
	}
	n := len(P)
	pair, err := sw_bn254.NewPairing(api)
	if err != nil {
		panic(err)
	}
	// 1- Check that Pᵢ are on G1 (done in the zkEVM ⚠️)
	// N.B.: BN254 has a prime order so G1 membership boils down to curve
	// membership only, which is checked in the zkEVM.
	//
	// 2- Check that Qᵢ are on G2 (done in `computeLines` in `MillerLoopAndMul` and `MillerLoopAndFinalExpCheck`)

	// 3- Check that ∏ᵢ e(Pᵢ, Qᵢ) == 1
	ml := pair.Ext12.One()
	for i := 0; i < n-1; i++ {
		// fixed circuit 1
		ml, err = pair.MillerLoopAndMul(P[i], Q[i], ml)
		if err != nil {
			panic(err)
		}
	}

	// fixed circuit 2
	pair.AssertMillerLoopAndFinalExpIsOne(P[n-1], Q[n-1], ml)
}

// ECPairIsOnG2 implements the fixed circuit for checking G2 membership and non-membership.
func ECPairIsOnG2(api frontend.API, Q *sw_bn254.G2Affine, expectedIsOnG2 frontend.Variable) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	isOnG2 := pairing.IsOnG2(Q)
	api.AssertIsEqual(expectedIsOnG2, isOnG2)
	return nil
}

// ECPairMillerLoopAndMul implements the fixed circuit for a Miller loop of
// fixed size 1 followed by a multiplication with an accumulator in 𝔽p¹². It
// asserts that the result corresponds to the expected result.
func ECPairMillerLoopAndMul(api frontend.API, accumulator *sw_bn254.GTEl, P *sw_bn254.G1Affine, Q *sw_bn254.G2Affine, expected *sw_bn254.GTEl) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	ml, err := pairing.MillerLoopAndMul(P, Q, accumulator)
	if err != nil {
		return fmt.Errorf("miller loop and mul: %w", err)
	}
	pairing.AssertIsEqual(expected, ml)
	return nil
}

// ECPairMillerLoopAndFinalExpCheck implements the fixed circuit for a Miller
// loop of fixed size 1 followed by a multiplication with an accumulator in
// 𝔽p¹², and a check that the result corresponds to the expected result.
func ECPairMillerLoopAndFinalExpCheck(api frontend.API, accumulator *sw_bn254.GTEl, P *sw_bn254.G1Affine, Q *sw_bn254.G2Affine, expectedIsSuccess frontend.Variable) error {
	api.AssertIsBoolean(expectedIsSuccess)
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	isSuccess := pairing.IsMillerLoopAndFinalExpOne(P, Q, accumulator)
	api.AssertIsEqual(expectedIsSuccess, isSuccess)
	return nil
}
