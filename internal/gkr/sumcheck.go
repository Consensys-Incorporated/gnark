package gkr

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/polynomial"
)

// A SNARK gadget capable of verifying sumcheck proofs

// sumcheckLazyClaims is the Claims data structure on the verifier side. It is "lazy" in that it has to compute fewer things.
type sumcheckLazyClaims interface {
	varsNum() int
	degree(i int) int
	verifyFinalEval(api frontend.API, r []frontend.Variable, purportedValue frontend.Variable, proof []frontend.Variable) error
}

// sumcheckProof of a multi-sumcheck statement.
type sumcheckProof struct {
	PartialSumPolys []polynomial.Polynomial
	FinalEvalProof  []frontend.Variable
}

// transcript is a Fiat-Shamir transcript backed by a running hash.
// Field elements are written via Absorb; challenges are derived via Squeeze.
// The hash is never reset — all previous data is implicitly part of future challenges.
type transcript struct {
	h     hash.FieldHasher
	bound bool
}

func (t *transcript) Absorb(elements ...frontend.Variable) {
	if len(elements) == 0 {
		return
	}
	t.h.Write(elements...)
	t.bound = true
}

func (t *transcript) Squeeze(elements ...frontend.Variable) frontend.Variable {
	t.Absorb(elements...)
	if !t.bound {
		t.h.Write(0) // separator to prevent repeated values
	}
	t.bound = false
	return t.h.Sum()
}

func verifySumcheck(api frontend.API, claims sumcheckLazyClaims, proof sumcheckProof, claimedSum frontend.Variable, degree int, t *transcript) error {
	r := make([]frontend.Variable, claims.varsNum())

	gJ := make(polynomial.Polynomial, degree+1)
	gJR := claimedSum

	for j := range claims.varsNum() {
		partialSumPoly := proof.PartialSumPolys[j]
		if len(partialSumPoly) != degree {
			return errors.New("malformed proof")
		}
		copy(gJ[1:], partialSumPoly)
		gJ[0] = api.Sub(gJR, partialSumPoly[0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)

		r[j] = t.Squeeze(proof.PartialSumPolys[j]...)

		gJR = polynomial.InterpolateLDE(api, r[j], gJ[:(degree+1)])
	}

	return claims.verifyFinalEval(api, r, gJR, proof.FinalEvalProof)
}
