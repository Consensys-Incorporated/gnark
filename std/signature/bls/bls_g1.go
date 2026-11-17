package bls

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

const g2_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

// PublicKeyG1 is the public key for BLS signature scheme for minimal public key
// variant. The corresponding signature is [SignatureG2].
type PublicKeyG1 sw_bls12381.G1Affine

// SignatureG2 is the signature for BLS signature scheme for minimal public key
// variant. The corresponding public key is [PublicKeyG1].
type SignatureG2 sw_bls12381.G2Affine

// VerifyG2 asserts that the signature sig is valid for the prehashed message for the public key pk.
//
// The public key pk and the hashed message prehashed must both be different
// from the point at infinity; the circuit is unsatisfiable otherwise. The
// check on prehashed is required because a caller-supplied prehashed = O
// together with sig = O degenerates the pairing check into 1 == 1, which would
// otherwise verify against every public key. As a consequence sig = O is also
// rejected: it would require e(pk, prehashed) = 1 with both points of prime
// order and non-infinity, which is impossible.
//
// Callers must also leave sig.Lines unset. When lines are precomputed, they
// are trusted input and [sw_bls12381.Pairing.PairingCheck] performs no
// curve-membership or subgroup check on the corresponding point.
func (pk PublicKeyG1) VerifyG2(api frontend.API, sig *SignatureG2, prehashed *sw_bls12381.G2Affine) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	ext2 := fields_bls12381.NewExt2(api)

	// public key cannot be infinity. Thus either coordinate has to be non-zero.
	xtest := fp.IsZero(&pk.X)
	ytest := fp.IsZero(&pk.Y)
	pubTest := api.And(xtest, ytest)
	api.AssertIsEqual(pubTest, 0)

	// The hashed message cannot be infinity either. Verify cannot hit this as
	// HashToG2 never returns O, but VerifyG2 is exported and takes prehashed
	// from the caller. Without this check prehashed = O and sig = O make the
	// pairing check e(-G₁, O)·e(pk, O) = 1·1 = 1 hold for any public key, i.e.
	// a universal forgery. Note that (0,0) is deliberately accepted as the G2
	// identity by the curve equation and the subgroup check, so it has to be
	// excluded explicitly here.
	msgTest := api.And(ext2.IsZero(&prehashed.P.X), ext2.IsZero(&prehashed.P.Y))
	api.AssertIsEqual(msgTest, 0)

	// prime order subgroup checks
	pairing.AssertIsOnG1((*sw_bls12381.G1Affine)(&pk))
	// we omit subgroup check for the G2 point as computeLines function inside
	// PairingCheck later already does it (it can reuse existing computation
	// during Miller loop). Thus this check is redundant.
	//
	// NB! This only holds when sig.Lines == nil, which is the case for any
	// signature coming from the witness: lineEvaluations is unexported, so the
	// witness parser cannot populate it and a caller has to opt in explicitly
	// in the circuit definition. See the precondition on VerifyG2 above.
	// pairing.AssertIsOnG2((*sw_bls12381.G2Affine)(sig))

	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)
	g1GN := sw_bls12381.NewG1Affine(g1GNeg)

	if err := pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&g1GN, (*sw_bls12381.G1Affine)(&pk)},
		[]*sw_bls12381.G2Affine{(*sw_bls12381.G2Affine)(sig), prehashed}); err != nil {
		return fmt.Errorf("pairing check failed: %w", err)
	}
	return nil
}

// Verify asserts that the signature sig verifies for the message msg and public
// key pk. Message is not assumed to be prehashed, it will be hashed to G2 using
// message expansion and hash to G2.
func (pk PublicKeyG1) Verify(api frontend.API, sig *SignatureG2, msg []uints.U8) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2: %w", err)
	}
	h, err := g2.HashToG2(msg, []byte(g2_dst))
	if err != nil {
		return fmt.Errorf("hash to G2: %w", err)
	}
	if err := pk.VerifyG2(api, sig, h); err != nil {
		return fmt.Errorf("verify G2: %w", err)
	}
	return nil
}
