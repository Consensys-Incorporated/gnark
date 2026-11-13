package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

// ECPairBLS implements [BLS12_PAIRING_CHECK] precompile contract at address 0x0f.
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
// See the methods [ECPairBLSMillerLoopAndMul] and [ECPairBLSMillerLoopAndFinalExpCheck] for the fixed circuits.
// See the methods [ECPairBLSIsOnG1] and [ECPairBLSIsOnG2] for the check that Pᵢ and Qᵢ are on G1 and resp. G2.
//
// SECURITY: the bit returned by [ECPairBLSMillerLoopAndFinalExpCheck] is
// one-sided and must not be used to attest a pairing-check *failure*; see the
// note on that method and the sound pair
// [ECPairBLSMillerLoopAndFinalExpCheckSuccess] /
// [ECPairBLSMillerLoopAndFinalExpCheckFailure]. [ECPairBLS] itself is
// unaffected: it asserts the product is 1 and never consumes the bit.
//
// [BLS12_PAIRING_CHECK]: https://eips.ethereum.org/EIPS/eip-2537
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func ECPairBLS(api frontend.API, P []*sw_bls12381.G1Affine, Q []*sw_bls12381.G2Affine) {
	if len(P) != len(Q) {
		panic("P and Q length mismatch")
	}
	if len(P) < 2 {
		panic("invalid multipairing size bound")
	}
	n := len(P)
	pair, err := sw_bls12381.NewPairing(api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		// 1- Check that Pᵢ are on G1
		pair.AssertIsOnG1(P[i])
		// N.B.: curve membership cannot be done in the zkEVM for BLS12-381
		// because the prime occupies 48 bytes and the zkEVM modular arithmetic
		// module only supports 32 byte operations.
		//
		// 2- Check that Qᵢ are on G2 (done in `computeLines` in `MillerLoopAndMul` and `MillerLoopAndFinalExpCheck`)
	}

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

// ECPairBLSIsOnG2 implements the fixed circuit for checking G2 membership and non-membership.
func ECPairBLSIsOnG2(api frontend.API, Q *sw_bls12381.G2Affine, expectedIsOnG2 frontend.Variable) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	isOnG2 := pairing.IsOnG2(Q)
	api.AssertIsEqual(expectedIsOnG2, isOnG2)
	return nil
}

// ECPairBLSIsOnG1 implements the fixed circuit for checking G1 membership and non-membership.
func ECPairBLSIsOnG1(api frontend.API, Q *sw_bls12381.G1Affine, expectedIsOnG1 frontend.Variable) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	isOnG1 := pairing.IsOnG1(Q)
	api.AssertIsEqual(expectedIsOnG1, isOnG1)
	return nil
}

// ECPairMillerLoopAndMul implements the fixed circuit for a Miller loop of
// fixed size 1 followed by a multiplication with an accumulator in 𝔽p¹². It
// asserts that the result corresponds to the expected result.
func ECPairBLSMillerLoopAndMul(api frontend.API, accumulator *sw_bls12381.GTEl, P *sw_bls12381.G1Affine, Q *sw_bls12381.G2Affine, expected *sw_bls12381.GTEl) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	// Miller loop below already checks that Q is in G2, but doesn't check that
	// P is. So we do it manually.
	pairing.AssertIsOnG1(P)
	ml, err := pairing.MillerLoopAndMul(P, Q, accumulator)
	if err != nil {
		return fmt.Errorf("miller loop and mul: %w", err)
	}
	pairing.AssertIsEqual(expected, ml)
	return nil
}

// ECPairBLSMillerLoopAndFinalExpCheck implements the fixed circuit for a Miller
// loop of fixed size 1 followed by a multiplication with an accumulator in
// 𝔽p¹², and a check that the result corresponds to the expected result.
//
// SECURITY: the returned bit is one-sided. A return value of 1 proves the
// product is 1. A return value of 0 proves NOTHING: the residue witness is
// only constrained to be invertible, so a prover can always force 0. Do not
// use this result to attest a pairing-check failure.
//
// In other words, this circuit only binds expectedIsSuccess == 1 to the
// pairing product being 1. With expectedIsSuccess == 0 a malicious prover can
// satisfy the circuit for *any* input, including one whose pairing product is
// 1. Since the pairing-check precompile returning false is an observable EVM
// outcome, a caller that trusts this bit can be made to attest a failure for a
// check that in fact succeeds.
//
// Deprecated: use the two sound fixed circuits
// [ECPairBLSMillerLoopAndFinalExpCheckSuccess] and
// [ECPairBLSMillerLoopAndFinalExpCheckFailure] instead, selecting between them
// on the (public) precompile return value.
func ECPairBLSMillerLoopAndFinalExpCheck(api frontend.API, accumulator *sw_bls12381.GTEl, P *sw_bls12381.G1Affine, Q *sw_bls12381.G2Affine, expectedIsSuccess frontend.Variable) error {
	api.AssertIsBoolean(expectedIsSuccess)
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	// Miller loop below already checks that Q is in G2, but doesn't check that
	// P is. So we do it manually.
	pairing.AssertIsOnG1(P)
	isSuccess := pairing.IsMillerLoopAndFinalExpOne(P, Q, accumulator)
	api.AssertIsEqual(expectedIsSuccess, isSuccess)
	return nil
}

// ECPairBLSMillerLoopAndFinalExpCheckSuccess implements the fixed circuit for
// the *success* branch of the final step of [ECPairBLS]: a Miller loop of
// fixed size 1, a multiplication with the accumulator in 𝔽p¹², and an
// assertion that the resulting multi-pairing is 1.
//
// It uses the residue-witness argument of Section 4 of [On Proving Pairings],
// which is sound for the == 1 direction: the circuit is satisfiable if and
// only if ∏ᵢ e(Pᵢ, Qᵢ) == 1.
//
// Together with [ECPairBLSMillerLoopAndFinalExpCheckFailure] this replaces the
// one-sided [ECPairBLSMillerLoopAndFinalExpCheck]: the caller selects the
// circuit matching the precompile's return value, which is public, and so pays
// the cost of a real final exponentiation only on the (rarer) failure branch.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func ECPairBLSMillerLoopAndFinalExpCheckSuccess(api frontend.API, accumulator *sw_bls12381.GTEl, P *sw_bls12381.G1Affine, Q *sw_bls12381.G2Affine) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	// Miller loop below already checks that Q is in G2, but doesn't check that
	// P is. So we do it manually.
	pairing.AssertIsOnG1(P)
	pairing.AssertMillerLoopAndFinalExpIsOne(P, Q, accumulator)
	return nil
}

// ECPairBLSMillerLoopAndFinalExpCheckFailure implements the fixed circuit for
// the *failure* branch of the final step of [ECPairBLS]: a Miller loop of
// fixed size 1, a multiplication with the accumulator in 𝔽p¹², a real final
// exponentiation, and an assertion that the resulting multi-pairing is *not*
// 1.
//
// Unlike [ECPairBLSMillerLoopAndFinalExpCheck] this is sound: the circuit is
// satisfiable if and only if ∏ᵢ e(Pᵢ, Qᵢ) != 1. Proving the != 1 direction
// requires the order-r component of the Miller loop output, so the cheap
// residue-witness argument cannot be used here and a full final
// exponentiation is unavoidable.
func ECPairBLSMillerLoopAndFinalExpCheckFailure(api frontend.API, accumulator *sw_bls12381.GTEl, P *sw_bls12381.G1Affine, Q *sw_bls12381.G2Affine) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	// Miller loop below already checks that Q is in G2, but doesn't check that
	// P is. So we do it manually.
	pairing.AssertIsOnG1(P)
	isSuccess := pairing.IsMillerLoopAndFinalExpOneSound(P, Q, accumulator)
	api.AssertIsEqual(isSuccess, 0)
	return nil
}
