// Package kzg implements KZG polynomial commitment verification.
//
// KZG polynomial commitment allows for the prover to commit to a polynomial and
// then selectively prove evaluations of the said polynomial. The size of the
// commitment is a single G1 element and the size of the evaluation proof is
// also a single G1 element. However, KZG polynomial commitment scheme requires
// a trusted SRS.
//
// This package supersedes previous type-specific implementations and allows to
// use any implemented pairing-friendly curve implementation, being defined over
// a 2-chain (native implementation) or using field emulation.
package kzg

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
)

// ValueOfScalar initializes a scalar in a witness from a native scalar (Fr) point.
// The scalars are always emulated.
func ValueOfScalar[FR emulated.FieldParams](scalar any) (emulated.Element[FR], error) {
	var ret emulated.Element[FR]
	switch s := any(&ret).(type) {
	case *emulated.Element[sw_bn254.ScalarField]:
		tScalar, ok := scalar.(fr_bn254.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bn254.NewScalar(tScalar)
	case *emulated.Element[sw_bls12377.ScalarField]:
		tScalar, ok := scalar.(fr_bls12377.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bls12377.NewScalar(tScalar)
	case *emulated.Element[sw_bls12381.ScalarField]:
		tScalar, ok := scalar.(fr_bls12381.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bls12381.NewScalar(tScalar)
	case *emulated.Element[sw_bw6761.ScalarField]:
		tScalar, ok := scalar.(fr_bw6761.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bw6761.NewScalar(tScalar)
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// Commitment is an KZG commitment to a polynomial. Use [ValueOfCommitment] to
// initialize a witness from the native commitment.
type Commitment[G1El algebra.G1ElementT] struct {
	G1El G1El
}

// ValueOfCommitment initializes a KZG commitment witness from a native
// commitment. It returns an error if there is a conflict between the type
// parameters and provided native commitment type.
func ValueOfCommitment[G1El algebra.G1ElementT](cmt any) (Commitment[G1El], error) {
	var ret Commitment[G1El]
	switch s := any(&ret).(type) {
	case *Commitment[sw_bn254.G1Affine]:
		tCmt, ok := cmt.(bn254.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bn254.NewG1Affine(tCmt)
	case *Commitment[sw_bls12377.G1Affine]:
		tCmt, ok := cmt.(bls12377.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bls12377.NewG1Affine(tCmt)
	case *Commitment[sw_bls12381.G1Affine]:
		tCmt, ok := cmt.(bls12381.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bls12381.NewG1Affine(tCmt)
	case *Commitment[sw_bw6761.G1Affine]:
		tCmt, ok := cmt.(bw6761.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bw6761.NewG1Affine(tCmt)
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// OpeningProof embeds the opening proof that polynomial evaluated at Point is
// equal to ClaimedValue. Use [ValueOfOpeningProof] to initialize a witness from
// a native opening proof.
type OpeningProof[FR emulated.FieldParams, G1El algebra.G1ElementT] struct {
	Quotient     G1El
	ClaimedValue emulated.Element[FR]
}

// ValueOfOpeningProof initializes an opening proof from the given proof and
// point. It returns an error if there is a mismatch between the type parameters
// and types of the provided point and proof.
func ValueOfOpeningProof[FR emulated.FieldParams, G1El algebra.G1ElementT](proof any) (OpeningProof[FR, G1El], error) {
	var ret OpeningProof[FR, G1El]
	switch s := any(&ret).(type) {
	case *OpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine]:
		tProof, ok := proof.(kzg_bn254.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bn254.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bn254.NewScalar(tProof.ClaimedValue)
	case *OpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine]:
		tProof, ok := proof.(kzg_bls12377.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bls12377.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bls12377.NewScalar(tProof.ClaimedValue)
	case *OpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine]:
		tProof, ok := proof.(kzg_bls12381.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bls12381.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bls12381.NewScalar(tProof.ClaimedValue)
	case *OpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine]:
		tProof, ok := proof.(kzg_bw6761.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bw6761.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bw6761.NewScalar(tProof.ClaimedValue)
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

type BatchOpeningProof[FR emulated.FieldParams, G1El algebra.G1ElementT] struct {
	Quotient      G1El
	ClaimedValues []emulated.Element[FR]
}

func ValueOfBatchOpeningProof[FR emulated.FieldParams, G1El any](proof any) (BatchOpeningProof[FR, G1El], error) {
	var ret BatchOpeningProof[FR, G1El]
	switch s := any(&ret).(type) {
	case *BatchOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine]:
		tProof, ok := proof.(kzg_bn254.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bn254.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[sw_bn254.ScalarField], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bn254.NewScalar(tProof.ClaimedValues[i])
		}
	case *BatchOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine]:
		tProof, ok := proof.(kzg_bls12377.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bls12377.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[sw_bls12377.ScalarField], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bls12377.NewScalar(tProof.ClaimedValues[i])
		}
	case *BatchOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine]:
		tProof, ok := proof.(kzg_bls12381.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bls12381.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[sw_bls12381.ScalarField], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bls12381.NewScalar(tProof.ClaimedValues[i])
		}
	case *BatchOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine]:
		tProof, ok := proof.(kzg_bw6761.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bw6761.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[sw_bw6761.ScalarField], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bw6761.NewScalar(tProof.ClaimedValues[i])
		}
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// VerifyingKey is the trusted setup for KZG polynomial commitment scheme. Use
// [ValueOfVerifyingKey] to initialize a witness from the native VerifyingKey.
type VerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	G2 [2]G2El
	G1 G1El
}

// PlaceholderVerifyingKey returns a placeholder value for the verifying key for
// compiling if the witness is going to be in precomputed form using [ValueOfVerifyingKeyFixed].
func PlaceholderVerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT]() VerifyingKey[G1El, G2El] {
	var ret VerifyingKey[G1El, G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine]:
		s.G2[0] = sw_bn254.NewG2AffineFixedPlaceholder()
		s.G2[1] = sw_bn254.NewG2AffineFixedPlaceholder()
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		s.G2[0] = sw_bls12377.NewG2AffineFixedPlaceholder()
		s.G2[1] = sw_bls12377.NewG2AffineFixedPlaceholder()
	case *VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		s.G2[0] = sw_bls12381.NewG2AffineFixedPlaceholder()
		s.G2[1] = sw_bls12381.NewG2AffineFixedPlaceholder()
	case *VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		s.G2[0] = sw_bw6761.NewG2AffineFixedPlaceholder()
		s.G2[1] = sw_bw6761.NewG2AffineFixedPlaceholder()
	default:
		panic("not supported")
	}
	return ret
}

// ValueOfVerifyingKey initializes verifying key witness from the native
// verifying key. It returns an error if there is a mismatch between the type
// parameters and the provided verifying key type.
func ValueOfVerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT](vk any) (VerifyingKey[G1El, G2El], error) {
	var ret VerifyingKey[G1El, G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tVk, ok := vk.(kzg_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bn254.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bn254.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bn254.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tVk, ok := vk.(kzg_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls12377.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls12377.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bls12377.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		tVk, ok := vk.(kzg_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls12381.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls12381.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bls12381.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		tVk, ok := vk.(kzg_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bw6761.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bw6761.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bw6761.NewG2Affine(tVk.G2[1])
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// ValueOfVerifyingKeyFixed initializes verifying key witness from the native
// verifying key and perform pre-computations for G2 elements. It returns an
// error if there is a mismatch between the type parameters and the provided
// verifying key type. Such witness is significantly larger than without
// precomputations. If witness size is important, then use [ValueOfVerifyingKey]
// instead.
func ValueOfVerifyingKeyFixed[G1El algebra.G1ElementT, G2El algebra.G2ElementT](vk any) (VerifyingKey[G1El, G2El], error) {
	var ret VerifyingKey[G1El, G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tVk, ok := vk.(kzg_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bn254.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bn254.NewG2AffineFixed(tVk.G2[0])
		s.G2[1] = sw_bn254.NewG2AffineFixed(tVk.G2[1])
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tVk, ok := vk.(kzg_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls12377.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls12377.NewG2AffineFixed(tVk.G2[0])
		s.G2[1] = sw_bls12377.NewG2AffineFixed(tVk.G2[1])
	case *VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		tVk, ok := vk.(kzg_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls12381.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls12381.NewG2AffineFixed(tVk.G2[0])
		s.G2[1] = sw_bls12381.NewG2AffineFixed(tVk.G2[1])
	case *VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		tVk, ok := vk.(kzg_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bw6761.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bw6761.NewG2AffineFixed(tVk.G2[0])
		s.G2[1] = sw_bw6761.NewG2AffineFixed(tVk.G2[1])
	default:
		return ret, fmt.Errorf("precomputation not supported")
	}
	return ret, nil
}

// Verifier allows verifying KZG opening proofs.
type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api       frontend.API
	scalarApi *emulated.Field[FR]
	curve     algebra.Curve[FR, G1El]
	pairing   algebra.Pairing[G1El, G2El, GtEl]
}

// NewVerifier initializes a new Verifier instance.
func NewVerifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) (*Verifier[FR, G1El, G2El, GtEl], error) {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return nil, err
	}
	scalarApi, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, err
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return nil, err
	}
	return &Verifier[FR, G1El, G2El, GtEl]{
		api:       api,
		scalarApi: scalarApi,
		curve:     curve,
		pairing:   pairing,
	}, nil
}

// CheckOpeningProof asserts the validity of the opening proof for the given
// commitment at point.
func (v *Verifier[FR, G1El, G2El, GTEl]) CheckOpeningProof(commitment Commitment[G1El], proof OpeningProof[FR, G1El], point emulated.Element[FR], vk VerifyingKey[G1El, G2El]) error {

	// Subgroup-check the adversarial G1 witnesses before the pairing, mirroring
	// the native verifier (which rejects with ErrCommitmentNotInSubgroup /
	// ErrQuotientNotNotInSubgroup). Cofactor torsion is invisible to the pairing
	// (e([T]G₁, G₂)=1 for ord(T) coprime to r), so without these checks the
	// verifier accepts torsion-shifted commitments/quotients that are not valid
	// group elements — a soundness gap w.r.t. the intended KZG relation.
	v.pairing.AssertIsOnG1(&commitment.G1El)
	v.pairing.AssertIsOnG1(&proof.Quotient)

	// [f(a)]G1 + [-a]([H(α)]G₁) = [f(a) - a*H(α)]G₁
	pointNeg := v.scalarApi.Neg(&point)
	totalG1, err := v.curve.MultiScalarMul([]*G1El{&vk.G1, &proof.Quotient}, []*emulated.Element[FR]{&proof.ClaimedValue, pointNeg})
	if err != nil {
		return fmt.Errorf("check opening proof: %w", err)
	}

	// [f(a) - a*H(α)]G₁ + [-f(α)]G₁  = [f(a) - f(α) - a*H(α)]G₁
	commitmentNeg := v.curve.Neg(&commitment.G1El)
	totalG1 = v.curve.AddUnified(totalG1, commitmentNeg)

	// e([f(a)-f(α)-a*H(α)]G₁], G₂).e([H(α)]G₁, [α]G₂) == 1
	if err := v.pairing.PairingCheck(
		[]*G1El{totalG1, &proof.Quotient},
		[]*G2El{&vk.G2[0], &vk.G2[1]},
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}
	return nil
}

// BatchVerifySinglePoint verifies multiple opening proofs at a single point.
func (v *Verifier[FR, G1El, G2El, GTEl]) BatchVerifySinglePoint(digests []Commitment[G1El], batchOpeningProof BatchOpeningProof[FR, G1El], point emulated.Element[FR], vk VerifyingKey[G1El, G2El], dataTranscript ...emulated.Element[FR]) error {
	// Subgroup-check the raw digests before folding (matching the native
	// verifier). A per-input check is required: folding is linear, so an
	// in-subgroup folded digest does not imply each summand is in-subgroup.
	// The quotient is checked inside CheckOpeningProof below (FoldProof passes
	// batchOpeningProof.Quotient through unchanged).
	for i := range digests {
		v.pairing.AssertIsOnG1(&digests[i].G1El)
	}
	// fold the proof
	foldedProof, foldedDigest, err := v.FoldProof(digests, batchOpeningProof, point, dataTranscript...)
	if err != nil {
		return fmt.Errorf("fold proofs: %w", err)
	}
	// verify the foldedProof against the foldedDigest
	err = v.CheckOpeningProof(foldedDigest, foldedProof, point, vk)
	if err != nil {
		return fmt.Errorf("check opening proof: %w", err)
	}
	return nil
}

// FoldProofsMultiPoint folds multiple proofs with openings at multiple points.
// Used for batch verification of different opening proofs. See also
// [Verifier.BatchVerifyMultiPoints].
func (v *Verifier[FR, G1El, G2El, GTEl]) FoldProofsMultiPoint(digests []Commitment[G1El], proofs []OpeningProof[FR, G1El], points []emulated.Element[FR], vk VerifyingKey[G1El, G2El]) (*G1El, *G1El, error) {

	var fr FR

	// check consistency nb proogs vs nb digests
	if len(digests) != len(proofs) {
		return nil, nil, fmt.Errorf("number of commitments doesn't match number of proofs")
	}
	if len(digests) != len(points) {
		return nil, nil, fmt.Errorf("number of commitments doesn't match number of points ")
	}

	// len(digests) should be nonzero because of randomNumbers
	if len(digests) == 0 {
		return nil, nil, fmt.Errorf("number of digests should be nonzero")
	}

	// sample random numbers λᵢ for sampling
	randomNumbers := make([]*emulated.Element[FR], len(digests))
	randomNumbers[0] = v.scalarApi.One()
	whSnark, err := recursion.NewHash(v.api, fr.Modulus(), true)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < len(digests); i++ {
		marshalledG1 := v.curve.MarshalG1(digests[i].G1El)
		whSnark.Write(marshalledG1...)
		marshalledG1 = v.curve.MarshalG1(proofs[i].Quotient)
		whSnark.Write(marshalledG1...)
		marshalledScalar := v.curve.MarshalScalar(proofs[i].ClaimedValue)
		whSnark.Write(marshalledScalar...)
		marshalledScalar = v.curve.MarshalScalar(points[i])
		whSnark.Write(marshalledScalar...)
	}

	seed := whSnark.Sum()
	binSeed := bits.ToBinary(v.api, seed, bits.WithNbDigits(fr.Modulus().BitLen()))
	randomNumbers[1] = v.scalarApi.FromBits(binSeed...)

	for i := 2; i < len(randomNumbers); i++ {
		// TODO: we can also use random number from the higher level transcript
		// instead of computing it from the inputs. Currently it is inefficient
		// as it computes hash of something for which we already have a hash.
		// Maybe add an option to provide the folding coefficient? See issue
		// https://github.com/Consensys/gnark/issues/1108
		randomNumbers[i] = v.scalarApi.Mul(randomNumbers[1], randomNumbers[i-1])
	}
	randomPointNumbers := make([]*emulated.Element[FR], len(randomNumbers))
	randomPointNumbers[0] = &points[0]
	for i := 1; i < len(randomPointNumbers); i++ {
		randomPointNumbers[i] = v.scalarApi.Mul(randomNumbers[i], &points[i])
	}

	// fold the committed quotients compute ∑ᵢλᵢ[Hᵢ(α)]G₁ and
	// ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	quotients := make([]*G1El, len(proofs))
	for i := 0; i < len(randomNumbers); i++ {
		quotients[i] = &proofs[i].Quotient
	}
	foldedQuotients, err := v.curve.MultiScalarMul(quotients[1:], randomNumbers[1:])
	if err != nil {
		return nil, nil, fmt.Errorf("fold quotients: %w", err)
	}
	foldedQuotients = v.curve.Add(foldedQuotients, quotients[0])
	foldedPointsQuotients, err := v.curve.MultiScalarMul(quotients, randomPointNumbers)
	if err != nil {
		return nil, nil, fmt.Errorf("fold point quotients: %w", err)
	}

	// fold digests and evals
	evals := make([]emulated.Element[FR], len(digests))

	// fold the digests: ∑ᵢλᵢ[f_i(α)]G₁
	// fold the evals  : ∑ᵢλᵢfᵢ(aᵢ)
	for i := 0; i < len(digests); i++ {
		evals[i] = proofs[i].ClaimedValue
	}

	foldedDigests, foldedEvals, err := v.fold(digests, evals, randomNumbers)
	if err != nil {
		return nil, nil, fmt.Errorf("fold: %w", err)
	}

	// compute commitment to folded Eval  [∑ᵢλᵢfᵢ(aᵢ)]G₁
	foldedEvalsCommit := v.curve.ScalarMul(&vk.G1, foldedEvals)

	// compute foldedDigests = ∑ᵢλᵢ[fᵢ(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁
	tmp := v.curve.Neg(foldedEvalsCommit)
	var foldedDigest *G1El
	foldedDigest = v.curve.Add(&foldedDigests.G1El, tmp)

	// ∑ᵢλᵢ[f_i(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁ + ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	// = [∑ᵢλᵢf_i(α) - ∑ᵢλᵢfᵢ(aᵢ) + ∑ᵢλᵢpᵢHᵢ(α)]G₁
	foldedDigest = v.curve.Add(foldedDigest, foldedPointsQuotients)

	// -∑ᵢλᵢ[Qᵢ(α)]G₁
	// foldedQuotients.Neg(&foldedQuotients)
	foldedQuotients = v.curve.Neg(foldedQuotients)

	return foldedDigest, foldedQuotients, nil
}

// BatchVerifyMultiPoints verifies multiple opening proofs at different points.
func (v *Verifier[FR, G1El, G2El, GTEl]) BatchVerifyMultiPoints(digests []Commitment[G1El], proofs []OpeningProof[FR, G1El], points []emulated.Element[FR], vk VerifyingKey[G1El, G2El]) error {

	// if only one proof go to base case
	if len(digests) == 1 {
		return v.CheckOpeningProof(digests[0], proofs[0], points[0], vk)
	}

	// Subgroup-check the raw digests and quotients before folding (matching the
	// native verifier). This path does not go through CheckOpeningProof, so the
	// checks must be done here. A per-input check is required: folding is linear,
	// so in-subgroup folded points do not imply each summand is in-subgroup.
	for i := range digests {
		v.pairing.AssertIsOnG1(&digests[i].G1El)
		v.pairing.AssertIsOnG1(&proofs[i].Quotient)
	}

	// fold the proofs
	foldedDigest, foldedQuotients, err := v.FoldProofsMultiPoint(digests, proofs, points, vk)
	if err != nil {
		return err
	}

	// pairing check
	err = v.pairing.PairingCheck(
		[]*G1El{foldedDigest, foldedQuotients},
		[]*G2El{&vk.G2[0], &vk.G2[1]},
	)
	if err != nil {
		return fmt.Errorf("pairingcheck: %w", err)
	}

	return err
}

// FoldProof folds multiple commitments and a batch opening proof for a single opening check.
func (v *Verifier[FR, G1El, G2El, GTEl]) FoldProof(digests []Commitment[G1El], batchOpeningProof BatchOpeningProof[FR, G1El], point emulated.Element[FR], dataTranscript ...emulated.Element[FR]) (OpeningProof[FR, G1El], Commitment[G1El], error) {
	var retP OpeningProof[FR, G1El]
	var retC Commitment[G1El]
	// we assume the short hash output size is full byte fitting into the modulus length.
	nbDigests := len(digests)

	// check consistency between numbers of claims vs number of digests
	if nbDigests != len(batchOpeningProof.ClaimedValues) {
		return retP, retC, fmt.Errorf("length mismatch for digests and claimed values")
	}

	// derive the challenge γ, binded to the point and the commitments
	gamma, err := v.deriveGamma(point, digests, batchOpeningProof.ClaimedValues, dataTranscript...)
	if err != nil {
		return retP, retC, fmt.Errorf("derive gamma: %w", err)
	}
	// gammai = [1,γ,γ²,..,γⁿ⁻¹]
	gammai := make([]*emulated.Element[FR], nbDigests)
	gammai[0] = v.scalarApi.One()
	if nbDigests > 1 {
		gammai[1] = gamma
	}
	for i := 2; i < nbDigests; i++ {
		gammai[i] = v.scalarApi.Mul(gammai[i-1], gamma)
	}
	// fold the claimed values and digests
	// compute ∑ᵢ γ^i C_i = C_0 + γ(C_1 + γ(C2 ...)), allowing to bound the scalar multiplication iterations
	digestsP := make([]*G1El, len(digests))
	for i := range digestsP {
		digestsP[i] = &digests[i].G1El
	}
	foldedDigests, err := v.curve.MultiScalarMul(digestsP[1:], gammai[1:])
	if err != nil {
		return retP, retC, fmt.Errorf("multi scalar mul: %w", err)
	}
	foldedDigests = v.curve.Add(foldedDigests, digestsP[0])

	foldedEvaluations := &batchOpeningProof.ClaimedValues[0]
	for i := 1; i < nbDigests; i++ {
		tmp := v.scalarApi.Mul(&batchOpeningProof.ClaimedValues[i], gammai[i])
		foldedEvaluations = v.scalarApi.Add(foldedEvaluations, tmp)
	}
	return OpeningProof[FR, G1El]{
			Quotient:     batchOpeningProof.Quotient,
			ClaimedValue: *foldedEvaluations,
		}, Commitment[G1El]{
			G1El: *foldedDigests,
		}, nil

}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
// dataTranscript are supposed to be bits.
func (v *Verifier[FR, G1El, G2El, GTEl]) deriveGamma(point emulated.Element[FR], digests []Commitment[G1El], claimedValues []emulated.Element[FR], dataTranscript ...emulated.Element[FR]) (*emulated.Element[FR], error) {
	var fr FR
	fs, err := recursion.NewTranscript(v.api, fr.Modulus(), []string{"gamma"})
	if err != nil {
		return nil, fmt.Errorf("new transcript: %w", err)
	}
	if err := fs.Bind("gamma", v.curve.MarshalScalar(point)); err != nil {
		return nil, fmt.Errorf("bind point: %w", err)
	}

	for i := range digests {
		if err := fs.Bind("gamma", v.curve.MarshalG1(digests[i].G1El)); err != nil {
			return nil, fmt.Errorf("bind %d-th commitment: %w", i, err)
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", v.curve.MarshalScalar(claimedValues[i])); err != nil {
			return nil, fmt.Errorf("bing %d-th claimed value: %w", i, err)
		}
	}

	for i := range dataTranscript {
		if err := fs.Bind("gamma", v.curve.MarshalScalar(dataTranscript[i])); err != nil {
			return nil, fmt.Errorf("bind %d-ith data transcript: %w", i, err)
		}
	}

	gamma, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return nil, fmt.Errorf("compute challenge: %w", err)
	}
	bGamma := bits.ToBinary(v.api, gamma, bits.WithNbDigits(fr.Modulus().BitLen()))
	gammaS := v.scalarApi.FromBits(bGamma...)

	return gammaS, nil
}

func (v *Verifier[FR, G1El, G2El, GTEl]) fold(digests []Commitment[G1El], fai []emulated.Element[FR], ci []*emulated.Element[FR], algopts ...algopts.AlgebraOption) (Commitment[G1El], *emulated.Element[FR], error) {
	// length inconsistency between digests and evaluations should have been done before calling this function
	nbDigests := len(digests)

	// fold the claimed values ∑ᵢcᵢf(aᵢ)
	var tmp *emulated.Element[FR]
	foldedEvaluations := &fai[0]
	for i := 1; i < nbDigests; i++ {
		tmp = v.scalarApi.Mul(&fai[i], ci[i])
		foldedEvaluations = v.scalarApi.Add(foldedEvaluations, tmp)
	}

	// fold the digests ∑ᵢ[cᵢ]([fᵢ(α)]G₁)
	digestPoints := make([]*G1El, len(digests))
	for i := range digestPoints {
		digestPoints[i] = &digests[i].G1El
	}
	foldedDigest, err := v.curve.MultiScalarMul(digestPoints[1:], ci[1:])
	if err != nil {
		return Commitment[G1El]{}, nil, fmt.Errorf("fold digests: %w", err)
	}
	foldedDigest = v.curve.Add(foldedDigest, digestPoints[0])

	// folding done
	return Commitment[G1El]{
		G1El: *foldedDigest,
	}, foldedEvaluations, nil

}
