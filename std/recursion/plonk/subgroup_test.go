package plonk

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// offCurveYZero returns an off-curve point (x, 0). The in-circuit Miller loop
// treats y == 0 as the point at infinity, so such a point contributes a factor
// of 1 to every pairing unless it is validated first.
func offCurveYZero(x uint64) bls12377.G1Affine {
	var p bls12377.G1Affine
	p.X.SetUint64(x)
	p.Y.SetZero()
	return p
}

func clonePlonkProof(p *plonk_bls12377.Proof) *plonk_bls12377.Proof {
	cp := *p
	cp.Bsb22Commitments = append([]bls12377.G1Affine(nil), p.Bsb22Commitments...)
	cp.BatchedProof.ClaimedValues = append(cp.BatchedProof.ClaimedValues[:0:0], p.BatchedProof.ClaimedValues...)
	return &cp
}

// prepareOnlyCircuit runs PrepareVerification and discards its output.
//
// This isolates the point validation from the rest of the verification
// equation. Mutating a proof point also perturbs the Fiat-Shamir transcript, so
// a full AssertProof rejects any mutated proof *incidentally* — it is simply no
// longer a valid proof — which makes AssertProof useless as an oracle for
// whether the point is actually constrained. PrepareVerification only derives
// challenges and folds commitments; it contains no equation that a wrong
// challenge can break. So it is satisfiable for an arbitrary off-curve point
// exactly when the on-curve assertion is missing.
type prepareOnlyCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[FR, G1El, G2El]
	VerifyingKey VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	InnerWitness Witness[FR]                  `gnark:",public"`
}

func (c *prepareOnlyCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	_, _, _, err = verifier.PrepareVerification(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

// TestPlonkRecursionConstrainsProofPoints checks, field by field, that every
// prover-supplied G1 point in a PLONK proof is constrained to be on the curve
// by PrepareVerification, matching the 9 points the native verifier validates
// (backend/plonk/bls12-377/verify.go). The native verifier is the oracle.
func TestPlonkRecursionConstrainsProofPoints(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	tInnerProof, ok := innerProof.(*plonk_bls12377.Proof)
	assert.True(ok, "expected *plonk_bls12377.Proof, got %T", innerProof)
	assert.True(len(tInnerProof.Bsb22Commitments) > 0, "expected at least one BSB22 commitment")

	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)

	mutations := []struct {
		name  string
		apply func(p *plonk_bls12377.Proof)
	}{
		{"LRO[0]", func(p *plonk_bls12377.Proof) { p.LRO[0] = offCurveYZero(1001) }},
		{"LRO[1]", func(p *plonk_bls12377.Proof) { p.LRO[1] = offCurveYZero(1002) }},
		{"LRO[2]", func(p *plonk_bls12377.Proof) { p.LRO[2] = offCurveYZero(1003) }},
		{"H[0]", func(p *plonk_bls12377.Proof) { p.H[0] = offCurveYZero(1004) }},
		{"H[1]", func(p *plonk_bls12377.Proof) { p.H[1] = offCurveYZero(1005) }},
		{"H[2]", func(p *plonk_bls12377.Proof) { p.H[2] = offCurveYZero(1006) }},
		{"Bsb22Commitments[0]", func(p *plonk_bls12377.Proof) { p.Bsb22Commitments[0] = offCurveYZero(1007) }},
	}

	for _, m := range mutations {
		assert.Run(func(assert *test.Assert) {
			mutated := clonePlonkProof(tInnerProof)
			m.apply(mutated)

			// oracle: the native verifier must reject.
			nativeErr := native_plonk.Verify(mutated, innerVK, innerWitness,
				GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
			assert.Error(nativeErr, "native verifier must reject mutated %s", m.name)

			circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](mutated)
			assert.NoError(err)

			outerCircuit := &prepareOnlyCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
				Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
				VerifyingKey: circuitVk,
			}
			outerAssignment := &prepareOnlyCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				InnerWitness: circuitWitness,
				Proof:        circuitProof,
			}
			err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
			assert.Error(err, "PrepareVerification must constrain %s to be on the curve", m.name)
		}, m.name)
	}
}

// TestPlonkRecursionRejectsOffCurvePoints is a weaker end-to-end check: the
// full AssertProof must reject every mutated proof. It passes both before and
// after the fix (see prepareOnlyCircuit for why) and is kept as a guard against
// a regression that would make a mutated proof *accepted*.
func TestPlonkRecursionRejectsOffCurvePoints(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	tInnerProof, ok := innerProof.(*plonk_bls12377.Proof)
	assert.True(ok, "expected *plonk_bls12377.Proof, got %T", innerProof)
	assert.True(len(tInnerProof.Bsb22Commitments) > 0, "expected at least one BSB22 commitment")

	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)

	mutations := []struct {
		name  string
		apply func(p *plonk_bls12377.Proof)
	}{
		{"LRO[0]", func(p *plonk_bls12377.Proof) { p.LRO[0] = offCurveYZero(1001) }},
		{"LRO[1]", func(p *plonk_bls12377.Proof) { p.LRO[1] = offCurveYZero(1002) }},
		{"LRO[2]", func(p *plonk_bls12377.Proof) { p.LRO[2] = offCurveYZero(1003) }},
		{"H[0]", func(p *plonk_bls12377.Proof) { p.H[0] = offCurveYZero(1004) }},
		{"H[1]", func(p *plonk_bls12377.Proof) { p.H[1] = offCurveYZero(1005) }},
		{"H[2]", func(p *plonk_bls12377.Proof) { p.H[2] = offCurveYZero(1006) }},
		{"Bsb22Commitments[0]", func(p *plonk_bls12377.Proof) { p.Bsb22Commitments[0] = offCurveYZero(1007) }},
	}

	for _, m := range mutations {
		assert.Run(func(assert *test.Assert) {
			mutated := clonePlonkProof(tInnerProof)
			m.apply(mutated)

			// oracle: the native verifier must reject.
			nativeErr := native_plonk.Verify(mutated, innerVK, innerWitness,
				GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
			assert.Error(nativeErr, "native verifier must reject mutated %s", m.name)

			circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](mutated)
			assert.NoError(err)

			outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
				Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
				VerifyingKey: circuitVk,
			}
			outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				InnerWitness: circuitWitness,
				Proof:        circuitProof,
			}
			err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
			assert.Error(err, "recursive verifier must reject mutated %s", m.name)
		}, m.name)
	}
}

// TestPlonkRecursionHonestStillVerifies is the completeness counterpart: the
// unmutated proof must keep verifying after the added checks.
func TestPlonkRecursionHonestStillVerifies(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	assert.NoError(test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField()))
}
