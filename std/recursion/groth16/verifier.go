package groth16

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16backend_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	groth16backend_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
)

// Proof is a typed Groth16 proof of SNARK. Use [ValueOfProof] to initialize the
// witness from the native proof.
type Proof[G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	Ar, Krs       G1El
	Bs            G2El
	Commitments   []pedersen.Commitment[G1El]
	CommitmentPok pedersen.KnowledgeProof[G1El]
}

// ValueOfProof returns the typed witness of the native proof. It returns an
// error if there is a mismatch between the type parameters and the provided
// native proof. For witness creation use the method [ValueOfProof] and for
// stub placeholder use [PlaceholderProof].
func ValueOfProof[G1El algebra.G1ElementT, G2El algebra.G2ElementT](proof groth16.Proof) (Proof[G1El, G2El], error) {
	var err error
	var ret Proof[G1El, G2El]
	switch ar := any(&ret).(type) {
	case *Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tProof, ok := proof.(*groth16backend_bn254.Proof)
		if !ok {
			return ret, fmt.Errorf("expected bn254.Proof, got %T", proof)
		}
		ar.Ar = sw_bn254.NewG1Affine(tProof.Ar)
		ar.Krs = sw_bn254.NewG1Affine(tProof.Krs)
		ar.Bs = sw_bn254.NewG2Affine(tProof.Bs)
		ar.Commitments = make([]pedersen.Commitment[sw_bn254.G1Affine], len(tProof.Commitments))
		for i := range tProof.Commitments {
			ar.Commitments[i], err = pedersen.ValueOfCommitment[sw_bn254.G1Affine](tProof.Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("commitment[%d]: %w", i, err)
			}
		}
		ar.CommitmentPok, err = pedersen.ValueOfKnowledgeProof[sw_bn254.G1Affine](tProof.CommitmentPok)
		if err != nil {
			return ret, fmt.Errorf("commitment pok: %w", err)
		}
	case *Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tProof, ok := proof.(*groth16backend_bls12377.Proof)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.Proof, got %T", proof)
		}
		ar.Ar = sw_bls12377.NewG1Affine(tProof.Ar)
		ar.Krs = sw_bls12377.NewG1Affine(tProof.Krs)
		ar.Bs = sw_bls12377.NewG2Affine(tProof.Bs)
		ar.Commitments = make([]pedersen.Commitment[sw_bls12377.G1Affine], len(tProof.Commitments))
		for i := range tProof.Commitments {
			ar.Commitments[i], err = pedersen.ValueOfCommitment[sw_bls12377.G1Affine](tProof.Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("commitment[%d]: %w", i, err)
			}
		}
		ar.CommitmentPok, err = pedersen.ValueOfKnowledgeProof[sw_bls12377.G1Affine](tProof.CommitmentPok)
		if err != nil {
			return ret, fmt.Errorf("commitment pok: %w", err)
		}
	case *Proof[sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		tProof, ok := proof.(*groth16backend_bls12381.Proof)
		if !ok {
			return ret, fmt.Errorf("expected bls12381.Proof, got %T", proof)
		}
		ar.Ar = sw_bls12381.NewG1Affine(tProof.Ar)
		ar.Krs = sw_bls12381.NewG1Affine(tProof.Krs)
		ar.Bs = sw_bls12381.NewG2Affine(tProof.Bs)
		ar.Commitments = make([]pedersen.Commitment[sw_bls12381.G1Affine], len(tProof.Commitments))
		for i := range tProof.Commitments {
			ar.Commitments[i], err = pedersen.ValueOfCommitment[sw_bls12381.G1Affine](tProof.Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("commitment[%d]: %w", i, err)
			}
		}
		ar.CommitmentPok, err = pedersen.ValueOfKnowledgeProof[sw_bls12381.G1Affine](tProof.CommitmentPok)
		if err != nil {
			return ret, fmt.Errorf("commitment pok: %w", err)
		}
	case *Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		tProof, ok := proof.(*groth16backend_bw6761.Proof)
		if !ok {
			return ret, fmt.Errorf("expected bw6761.Proof, got %T", proof)
		}
		ar.Ar = sw_bw6761.NewG1Affine(tProof.Ar)
		ar.Krs = sw_bw6761.NewG1Affine(tProof.Krs)
		ar.Bs = sw_bw6761.NewG2Affine(tProof.Bs)
		ar.Commitments = make([]pedersen.Commitment[sw_bw6761.G1Affine], len(tProof.Commitments))
		for i := range tProof.Commitments {
			ar.Commitments[i], err = pedersen.ValueOfCommitment[sw_bw6761.G1Affine](tProof.Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("commitment[%d]: %w", i, err)
			}
		}
		ar.CommitmentPok, err = pedersen.ValueOfKnowledgeProof[sw_bw6761.G1Affine](tProof.CommitmentPok)
		if err != nil {
			return ret, fmt.Errorf("commitment pok: %w", err)
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

func PlaceholderProof[G1El algebra.G1ElementT, G2El algebra.G2ElementT](ccs constraint.ConstraintSystem) Proof[G1El, G2El] {
	return Proof[G1El, G2El]{
		Commitments: make([]pedersen.Commitment[G1El], len(ccs.GetCommitments().(constraint.Groth16Commitments))),
	}
}

// VerifyingKey is a typed Groth16 verifying key for checking SNARK proofs. For
// witness creation use the method [ValueOfVerifyingKey] and for stub
// placeholder use [PlaceholderVerifyingKey].
type VerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	E                            GtEl
	G1                           struct{ K []G1El }
	G2                           struct{ GammaNeg, DeltaNeg G2El }
	CommitmentKeys               []pedersen.VerifyingKey[G2El]
	PublicAndCommitmentCommitted [][]int
}

// PlaceholderVerifyingKey returns an empty verifying key for a given compiled
// constraint system. The size of the verifying key depends on the number of
// public inputs and commitments used, this method allocates sufficient space
// regardless of the actual verifying key.
func PlaceholderVerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](ccs constraint.ConstraintSystem) VerifyingKey[G1El, G2El, GtEl] {
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	commitmentWires := commitments.CommitmentIndexes()

	return VerifyingKey[G1El, G2El, GtEl]{
		G1: struct{ K []G1El }{
			K: make([]G1El, ccs.GetNbPublicVariables()+len(ccs.GetCommitments().(constraint.Groth16Commitments))),
		},
		PublicAndCommitmentCommitted: commitments.GetPublicAndCommitmentCommitted(commitmentWires, ccs.GetNbPublicVariables()),
		CommitmentKeys:               make([]pedersen.VerifyingKey[G2El], len(commitments)),
	}
}

// ValueOfVerifyingKey initializes witness from the given Groth16 verifying key.
// It returns an error if there is a mismatch between the type parameters and
// the provided native verifying key.
func ValueOfVerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vk groth16.VerifyingKey) (VerifyingKey[G1El, G2El, GtEl], error) {
	var ret VerifyingKey[G1El, G2El, GtEl]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]:
		tVk, ok := vk.(*groth16backend_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bn254.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bn254.Pair([]bn254.G1Affine{tVk.G1.Alpha}, []bn254.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bn254.NewGTEl(e)
		s.G1.K = make([]sw_bn254.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bn254.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bn254.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bn254.NewG2Affine(deltaNeg)
		s.G2.GammaNeg = sw_bn254.NewG2Affine(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bn254.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKey[sw_bn254.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		ret.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]:
		tVk, ok := vk.(*groth16backend_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bls12377.Pair([]bls12377.G1Affine{tVk.G1.Alpha}, []bls12377.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bls12377.NewGTEl(e)
		s.G1.K = make([]sw_bls12377.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bls12377.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bls12377.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bls12377.NewG2Affine(deltaNeg)
		s.G2.GammaNeg = sw_bls12377.NewG2Affine(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bls12377.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKey[sw_bls12377.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		ret.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	case *VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]:
		tVk, ok := vk.(*groth16backend_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12381.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bls12381.Pair([]bls12381.G1Affine{tVk.G1.Alpha}, []bls12381.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bls12381.NewGTEl(e)
		s.G1.K = make([]sw_bls12381.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bls12381.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bls12381.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bls12381.NewG2Affine(deltaNeg)
		s.G2.GammaNeg = sw_bls12381.NewG2Affine(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bls12381.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKey[sw_bls12381.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		ret.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	case *VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]:
		tVk, ok := vk.(*groth16backend_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bw6761.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bw6761.Pair([]bw6761.G1Affine{tVk.G1.Alpha}, []bw6761.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bw6761.NewGTEl(e)
		s.G1.K = make([]sw_bw6761.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bw6761.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bw6761.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bw6761.NewG2Affine(deltaNeg)
		s.G2.GammaNeg = sw_bw6761.NewG2Affine(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bw6761.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKey[sw_bw6761.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		ret.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// ValueOfVerifyingKey initializes witness from the given Groth16 verifying key.
// It returns an error if there is a mismatch between the type parameters and
// the provided native verifying key.
func ValueOfVerifyingKeyFixed[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vk groth16.VerifyingKey) (VerifyingKey[G1El, G2El, GtEl], error) {
	var ret VerifyingKey[G1El, G2El, GtEl]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]:
		tVk, ok := vk.(*groth16backend_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bn254.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bn254.Pair([]bn254.G1Affine{tVk.G1.Alpha}, []bn254.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bn254.NewGTEl(e)
		s.G1.K = make([]sw_bn254.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bn254.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bn254.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bn254.NewG2AffineFixed(deltaNeg)
		s.G2.GammaNeg = sw_bn254.NewG2AffineFixed(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bn254.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKeyFixed[sw_bn254.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		s.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]:
		tVk, ok := vk.(*groth16backend_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bls12377.Pair([]bls12377.G1Affine{tVk.G1.Alpha}, []bls12377.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bls12377.NewGTEl(e)
		s.G1.K = make([]sw_bls12377.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bls12377.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bls12377.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bls12377.NewG2AffineFixed(deltaNeg)
		s.G2.GammaNeg = sw_bls12377.NewG2AffineFixed(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bls12377.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKeyFixed[sw_bls12377.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		s.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	case *VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]:
		tVk, ok := vk.(*groth16backend_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12381.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bls12381.Pair([]bls12381.G1Affine{tVk.G1.Alpha}, []bls12381.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bls12381.NewGTEl(e)
		s.G1.K = make([]sw_bls12381.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bls12381.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bls12381.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bls12381.NewG2AffineFixed(deltaNeg)
		s.G2.GammaNeg = sw_bls12381.NewG2AffineFixed(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bls12381.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKeyFixed[sw_bls12381.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		s.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	case *VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]:
		tVk, ok := vk.(*groth16backend_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bw6761.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bw6761.Pair([]bw6761.G1Affine{tVk.G1.Alpha}, []bw6761.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bw6761.NewGTEl(e)
		s.G1.K = make([]sw_bw6761.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bw6761.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bw6761.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bw6761.NewG2AffineFixed(deltaNeg)
		s.G2.GammaNeg = sw_bw6761.NewG2AffineFixed(gammaNeg)
		s.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bw6761.G2Affine], len(tVk.CommitmentKeys))
		for i := range tVk.CommitmentKeys {
			s.CommitmentKeys[i], err = pedersen.ValueOfVerifyingKeyFixed[sw_bw6761.G2Affine](&tVk.CommitmentKeys[i])
			if err != nil {
				return ret, fmt.Errorf("commitment key[%d]: %w", i, err)
			}
		}
		s.PublicAndCommitmentCommitted = tVk.PublicAndCommitmentCommitted
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// Witness is a public witness to verify the SNARK proof against. For assigning
// witness use [ValueOfWitness] and to create stub witness for compiling use
// [PlaceholderWitness].
type Witness[FR emulated.FieldParams] struct {
	// Public is the public inputs. The first element does not need to be one
	// wire and is added implicitly during verification.
	Public []emulated.Element[FR]
}

// PlaceholderWitness creates a stub witness which can be used to allocate the
// variables in the circuit if the actual witness is not yet known. It takes
// into account the number of public inputs and number of used commitments.
func PlaceholderWitness[FR emulated.FieldParams](ccs constraint.ConstraintSystem) Witness[FR] {
	return Witness[FR]{
		Public: make([]emulated.Element[FR], ccs.GetNbPublicVariables()-1),
	}
}

// ValueOfWitness assigns a outer-circuit witness from the inner circuit
// witness. If there is a field mismatch then this method represents the witness
// inputs using field emulation. It returns an error if there is a mismatch
// between the type parameters and provided witness.
func ValueOfWitness[FR emulated.FieldParams](w witness.Witness) (Witness[FR], error) {
	var ret Witness[FR]
	pubw, err := w.Public()
	if err != nil {
		return ret, fmt.Errorf("get public witness: %w", err)
	}
	vec := pubw.Vector()
	switch s := any(&ret).(type) {
	case *Witness[sw_bn254.ScalarField]:
		vect, ok := vec.(fr_bn254.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bn254.NewScalar(vect[i]))
		}
	case *Witness[sw_bls12377.ScalarField]:
		vect, ok := vec.(fr_bls12377.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12377.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls12377.NewScalar(vect[i]))
		}
	case *Witness[sw_bls12381.ScalarField]:
		vect, ok := vec.(fr_bls12381.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12381.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls12381.NewScalar(vect[i]))
		}
	case *Witness[sw_bw6761.ScalarField]:
		vect, ok := vec.(fr_bw6761.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bw6761.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bw6761.NewScalar(vect[i]))
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// Verifier verifies Groth16 proofs.
type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api        frontend.API
	scalarApi  *emulated.Field[FR]
	curve      algebra.Curve[FR, G1El]
	pairing    algebra.Pairing[G1El, G2El, GtEl]
	commitment *pedersen.Verifier[FR, G1El, G2El, GtEl]
}

// NewVerifier returns a new [Verifier] instance using the curve and pairing
// interfaces. Use methods [algebra.GetCurve] and [algebra.GetPairing] to
// initialize the instances.
func NewVerifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) (*Verifier[FR, G1El, G2El, GtEl], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("get field: %w", err)
	}
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return nil, fmt.Errorf("get curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("get pairing: %w", err)
	}
	commitment, err := pedersen.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("get commitment: %w", err)
	}
	return &Verifier[FR, G1El, G2El, GtEl]{
		api:        api,
		scalarApi:  f,
		curve:      curve,
		pairing:    pairing,
		commitment: commitment,
	}, nil
}

// AssertProof asserts that the SNARK proof holds for the given witness and
// verifying key.
func (v *Verifier[FR, G1El, G2El, GtEl]) AssertProof(vk VerifyingKey[G1El, G2El, GtEl], proof Proof[G1El, G2El], witness Witness[FR], opts ...VerifierOption) error {
	isValid, err := v.IsValidProof(vk, proof, witness, opts...)
	if err != nil {
		return err
	}
	v.api.AssertIsEqual(isValid, 1)
	return nil
}

// IsValidProof returns a variable that is 1 if the proof is valid and 0 otherwise.
func (v *Verifier[FR, G1El, G2El, GtEl]) IsValidProof(vk VerifyingKey[G1El, G2El, GtEl], proof Proof[G1El, G2El], witness Witness[FR], opts ...VerifierOption) (frontend.Variable, error) {
	if len(vk.CommitmentKeys) != len(proof.Commitments) {
		return 0, fmt.Errorf("invalid number of commitments, got %d, expected %d", len(proof.Commitments), len(vk.CommitmentKeys))
	}
	if len(vk.CommitmentKeys) != len(vk.PublicAndCommitmentCommitted) {
		return 0, fmt.Errorf("invalid number of commitment keys, got %d, expected %d", len(vk.CommitmentKeys), len(vk.PublicAndCommitmentCommitted))
	}
	var fr FR
	nbPublicVars := len(vk.G1.K) - len(vk.PublicAndCommitmentCommitted)
	if len(witness.Public) != nbPublicVars-1 {
		return 0, fmt.Errorf("invalid witness size, got %d, expected %d (public - ONE_WIRE)", len(witness.Public), len(vk.G1.K)-1)
	}

	inP := make([]*G1El, len(vk.G1.K)-1) // first is for the one wire, we add it manually after MSM
	for i := range inP {
		inP[i] = &vk.G1.K[i+1]
	}
	inS := make([]*emulated.Element[FR], len(witness.Public)+len(vk.PublicAndCommitmentCommitted))
	for i := range witness.Public {
		inS[i] = &witness.Public[i]
	}

	opt, err := newCfg(opts...)
	if err != nil {
		return 0, fmt.Errorf("apply options: %w", err)
	}
	hashToField, err := recursion.NewHash(v.api, fr.Modulus(), true)
	if err != nil {
		return 0, fmt.Errorf("hash to field: %w", err)
	}

	maxNbPublicCommitted := 0
	for _, s := range vk.PublicAndCommitmentCommitted { // iterate over commitments
		maxNbPublicCommitted = max(maxNbPublicCommitted, len(s))
	}

	commitmentAuxData := make([]*emulated.Element[FR], len(vk.PublicAndCommitmentCommitted))
	for i := range vk.PublicAndCommitmentCommitted { // solveCommitmentWire
		hashToField.Write(v.curve.MarshalG1(proof.Commitments[i].G1El)...)
		for j := range vk.PublicAndCommitmentCommitted[i] {
			hashToField.Write(v.curve.MarshalScalar(*inS[vk.PublicAndCommitmentCommitted[i][j]-1])...)
		}

		h := hashToField.Sum()
		hashToField.Reset()

		res := v.scalarApi.FromBits(v.api.ToBinary(h)...)

		inS[nbPublicVars-1+i] = res
		commitmentAuxData[i] = res
	}

	switch len(vk.CommitmentKeys) {
	case 0:
		// explicitly do not verify the commitment as there is nothing
	case 1:
		if err = v.commitment.AssertCommitment(proof.Commitments[0], proof.CommitmentPok, vk.CommitmentKeys[0], opt.pedopt...); err != nil {
			return 0, fmt.Errorf("assert commitment: %w", err)
		}
	default:
		// TODO: we support only a single commitment in the recursion for now
		return 0, fmt.Errorf("multiple commitments are not supported")
	}

	kSum, err := v.curve.MultiScalarMul(inP, inS, opt.algopt...)
	if err != nil {
		return 0, fmt.Errorf("multi scalar mul: %w", err)
	}
	// kSum is the point at infinity when there are no public inputs or when all
	// of them are zero, so we need complete addition here.
	kSum = v.curve.AddUnified(kSum, &vk.G1.K[0])

	for i := range proof.Commitments {
		kSum = v.curve.Add(kSum, &proof.Commitments[i].G1El)
	}

	if opt.forceSubgroupCheck {
		v.pairing.AssertIsOnG1(&proof.Ar)
		v.pairing.AssertIsOnG1(&proof.Krs)
		v.pairing.AssertIsOnG2(&proof.Bs)
	}
	pairing, err := v.pairing.Pair([]*G1El{kSum, &proof.Krs, &proof.Ar}, []*G2El{&vk.G2.GammaNeg, &vk.G2.DeltaNeg, &proof.Bs})
	if err != nil {
		return 0, fmt.Errorf("pairing: %w", err)
	}
	return v.pairing.IsEqual(pairing, &vk.E), nil
}

// SwitchVerification key switches the verification key based on the provided
// index idx. Can be used for recursive verification based on the verification
// key index.
func (v *Verifier[FR, G1El, G2El, GtEl]) SwitchVerificationKey(idx frontend.Variable, vks []VerifyingKey[G1El, G2El, GtEl]) (VerifyingKey[G1El, G2El, GtEl], error) {
	var ret VerifyingKey[G1El, G2El, GtEl]
	if len(vks) == 0 {
		return ret, fmt.Errorf("no verifying keys provided")
	}
	if len(vks) == 1 {
		v.api.AssertIsEqual(idx, 0)
		return vks[0], nil
	}
	// commitment info
	for i := 1; i < len(vks); i++ {
		if len(vks[i].PublicAndCommitmentCommitted) != len(vks[0].PublicAndCommitmentCommitted) {
			return ret, fmt.Errorf("invalid number of commitments")
		}
		for j := range vks[i].PublicAndCommitmentCommitted {
			if len(vks[i].PublicAndCommitmentCommitted[j]) != len(vks[0].PublicAndCommitmentCommitted[j]) {
				return ret, fmt.Errorf("invalid number of public committed variables")
			}
			for k := range vks[i].PublicAndCommitmentCommitted[j] {
				if vks[i].PublicAndCommitmentCommitted[j][k] != vks[0].PublicAndCommitmentCommitted[j][k] {
					return ret, fmt.Errorf("invalid public committed variable index")
				}
			}
		}
		if len(vks[i].CommitmentKeys) != len(vks[0].CommitmentKeys) {
			return ret, fmt.Errorf("invalid number of commitment keys")
		}
	}
	ret.PublicAndCommitmentCommitted = make([][]int, len(vks[0].PublicAndCommitmentCommitted))
	for i := range vks[0].PublicAndCommitmentCommitted {
		ret.PublicAndCommitmentCommitted[i] = make([]int, len(vks[0].PublicAndCommitmentCommitted[i]))
		copy(ret.PublicAndCommitmentCommitted[i], vks[0].PublicAndCommitmentCommitted[i])
	}

	ret.CommitmentKeys = make([]pedersen.VerifyingKey[G2El], len(vks[0].CommitmentKeys))
	for i := range ret.CommitmentKeys {
		cmtBss := make([]*G2El, len(vks))
		cmtBexs := make([]*G2El, len(vks))
		for j := range vks {
			cmtBss[j] = &vks[j].CommitmentKeys[i].G
			cmtBexs[j] = &vks[j].CommitmentKeys[i].GSigmaNeg
		}
		ret.CommitmentKeys[i].G = *v.pairing.MuxG2(idx, cmtBss...)
		ret.CommitmentKeys[i].GSigmaNeg = *v.pairing.MuxG2(idx, cmtBexs...)
	}
	// switch E
	Es := make([]*GtEl, len(vks))
	for i := range vks {
		Es[i] = &vks[i].E
	}
	ret.E = *v.pairing.MuxGt(idx, Es...)

	// Switch K
	for i := 1; i < len(vks); i++ {
		if len(vks[i].G1.K) != len(vks[0].G1.K) {
			return ret, fmt.Errorf("invalid number of K elements")
		}
	}
	ret.G1.K = make([]G1El, len(vks[0].G1.K))
	for i := range ret.G1.K {
		Ks := make([]*G1El, len(vks))
		for j := range vks {
			Ks[j] = &vks[j].G1.K[i]
		}
		ret.G1.K[i] = *v.curve.Mux(idx, Ks...)
	}

	// Switch G2
	gammaNegs := make([]*G2El, len(vks))
	deltaNegs := make([]*G2El, len(vks))
	for i := range vks {
		gammaNegs[i] = &vks[i].G2.GammaNeg
		deltaNegs[i] = &vks[i].G2.DeltaNeg
	}
	ret.G2.GammaNeg = *v.pairing.MuxG2(idx, gammaNegs...)
	ret.G2.DeltaNeg = *v.pairing.MuxG2(idx, deltaNegs...)

	return ret, nil
}
