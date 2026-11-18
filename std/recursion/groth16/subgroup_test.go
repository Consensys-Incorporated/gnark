package groth16

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/test"
)

// bls12377G1Torsion2 returns T = (-1, 0), the unique rational point of order 2
// on the BLS12-377 G1 curve y² = x³ + 1: 2-torsion means y = 0, i.e. x³ = -1,
// whose only root in F_p is x = -1. The G1 cofactor (x₀-1)²/3 is even, so T is
// a rational point outside the prime-order subgroup G1.
func bls12377G1Torsion2() bls12377.G1Affine {
	var t bls12377.G1Affine
	t.X.SetOne()
	t.X.Neg(&t.X)
	t.Y.SetZero()
	return t
}

// TestGroth16RecursionRejectsTorsionAr is the soundness regression test for the
// missing G1 subgroup check on proof.Ar.
//
// The forgery: replace Ar by Ar + T with T the 2-torsion point above. Ar+T is a
// perfectly valid curve point, so an on-curve check alone does not catch it;
// only a subgroup check does. The pairing value is unchanged, because the ate
// pairing is a homomorphism in its G1 argument into µ_r and r is odd, so T —
// having order 2 — maps to 1. The native verifier rejects (it subgroup-checks
// Ar unconditionally), and before this fix the in-circuit verifier accepted:
// a genuine divergence, not an incidentally invalid proof.
func TestGroth16RecursionRejectsTorsionAr(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	tProof, ok := innerProof.(*groth16backend_bls12377.Proof)
	assert.True(ok, "expected *groth16backend_bls12377.Proof, got %T", innerProof)

	// sanity: T is on the curve but not in the subgroup.
	torsion := bls12377G1Torsion2()
	assert.True(torsion.IsOnCurve(), "T must be on the curve")
	assert.False(torsion.IsInSubGroup(), "T must not be in G1")

	forged := *tProof
	forged.Commitments = append([]bls12377.G1Affine(nil), tProof.Commitments...)

	var arJac, tJac bls12377.G1Jac
	arJac.FromAffine(&tProof.Ar)
	tJac.FromAffine(&torsion)
	arJac.AddAssign(&tJac)
	forged.Ar.FromJacobian(&arJac)

	assert.True(forged.Ar.IsOnCurve(), "Ar+T must still be on the curve")
	assert.False(forged.Ar.IsInSubGroup(), "Ar+T must be outside G1")

	// oracle: the native verifier rejects the forged proof.
	assert.Error(groth16.Verify(&forged, innerVK, innerWitness),
		"native verifier must reject Ar+T")

	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](&forged)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.Error(err, "recursive verifier must reject Ar+T")
}

// TestGroth16RecursionHonestStillVerifies is the completeness counterpart.
func TestGroth16RecursionHonestStillVerifies(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	assert.NoError(test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField()))
}
