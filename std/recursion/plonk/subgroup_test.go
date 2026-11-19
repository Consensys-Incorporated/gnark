package plonk

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
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

// optOuterCircuit is OuterCircuit with the verifier options under test. opts is
// unexported, so the frontend schema walker ignores it.
type optOuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[FR, G1El, G2El]
	VerifyingKey VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	InnerWitness Witness[FR]                  `gnark:",public"`

	opts []VerifierOption
}

func (c *optOuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness, c.opts...)
}

// TestPlonkRecursionSubgroupChecksAreCompiledIn pins the point validation added
// to PrepareVerification by its cost: compiling the recursive verifier with the
// default options must emit strictly more constraints than compiling the same
// circuit with [WithNoSubgroupCheck], which reproduces the previous behaviour.
//
// This is the discriminating test for the PLONK half of this change. A proof
// mutation test cannot play that role: all seven points (LRO, H, the BSB22
// commitments) are absorbed into the Fiat-Shamir transcript and every challenge
// derived from them feeds the linearised-polynomial identity, so a mutated
// proof is rejected whether or not the points are checked. The checks are
// parity with the native verifier and defence in depth, not the closing of a
// demonstrated hole.
func TestPlonkRecursionSubgroupChecksAreCompiledIn(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, _, _ := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	circuitVk, err := ValueOfVerifyingKeyFixed[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)

	newCircuit := func(opts ...VerifierOption) frontend.Circuit {
		return &optOuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
			Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
			VerifyingKey: circuitVk,
			opts:         opts,
		}
	}

	var newR1CS, newSCS frontend.NewBuilder = r1cs.NewBuilder, scs.NewBuilder
	for _, builder := range []struct {
		name string
		new  frontend.NewBuilder
	}{
		{"r1cs", newR1CS},
		{"scs", newSCS},
	} {
		assert.Run(func(assert *test.Assert) {
			withChecks, err := frontend.Compile(ecc.BW6_761.ScalarField(), builder.new, newCircuit())
			assert.NoError(err)
			withoutChecks, err := frontend.Compile(ecc.BW6_761.ScalarField(), builder.new, newCircuit(WithNoSubgroupCheck()))
			assert.NoError(err)

			nWith := withChecks.GetNbConstraints()
			nWithout := withoutChecks.GetNbConstraints()
			t.Logf("%s: default %d constraints, WithNoSubgroupCheck %d (delta %+d)", builder.name, nWith, nWithout, nWith-nWithout)
			assert.True(nWith > nWithout,
				"default compilation must contain the point checks: got %d constraints, same circuit with WithNoSubgroupCheck has %d", nWith, nWithout)
		}, builder.name)
	}
}

// TestPlonkRecursionRejectsOffCurvePoints is an end-to-end regression guard: the
// full AssertProof must reject a proof in which any of the seven points is
// replaced by an off-curve (x, 0).
//
// It is NOT a reproduction of a soundness break: it passes both before and
// after this change, because mutating any of these points also perturbs the
// Fiat-Shamir challenges and so breaks the linearisation identity asserted at
// the end of PrepareVerification. It only guards against a regression that
// would make such a proof accepted. The native verifier is used as the oracle.
func TestPlonkRecursionRejectsOffCurvePoints(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	tInnerProof, ok := innerProof.(*plonk_bls12377.Proof)
	assert.True(ok, "expected *plonk_bls12377.Proof, got %T", innerProof)
	assert.True(len(tInnerProof.Bsb22Commitments) > 0, "expected at least one BSB22 commitment")

	circuitVk, err := ValueOfVerifyingKeyFixed[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
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
// unmutated proof must keep verifying after the added checks, with and without
// WithNoSubgroupCheck.
func TestPlonkRecursionHonestStillVerifies(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	circuitVk, err := ValueOfVerifyingKeyFixed[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	for _, tc := range []struct {
		name string
		opts []VerifierOption
	}{
		{"default", nil},
		{"WithNoSubgroupCheck", []VerifierOption{WithNoSubgroupCheck()}},
	} {
		assert.Run(func(assert *test.Assert) {
			outerCircuit := &optOuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
				Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
				VerifyingKey: circuitVk,
				opts:         tc.opts,
			}
			outerAssignment := &optOuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				InnerWitness: circuitWitness,
				Proof:        circuitProof,
			}
			assert.NoError(test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField()))
		}, tc.name)
	}
}
