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
	PartialSumPolys []polynomial.Polynomial // for each round j, the coefficients c₁, ..., c_d of gⱼ(X) = ∑ᵢ cᵢXⁱ; c₀ is derived by the verifier
	FinalEvalProof  []frontend.Variable
}

// transcript is a Fiat-Shamir transcript backed by a running hash.
// Absorb writes field elements; Squeeze derives challenges from them.
// The hash is never reset — all previous data is implicitly part of future challenges.
type transcript struct {
	h        hash.FieldHasher
	absorbed bool
}

func (t *transcript) Absorb(elements ...frontend.Variable) {
	if len(elements) == 0 {
		return
	}
	t.h.Write(elements...)
	t.absorbed = true
}

func (t *transcript) Squeeze(elements ...frontend.Variable) frontend.Variable {
	t.Absorb(elements...)
	if !t.absorbed {
		t.h.Write(0) // separator to prevent repeated values
	}
	t.absorbed = false
	return t.h.Sum()
}

func verifySumcheck(api frontend.API, claims sumcheckLazyClaims, proof sumcheckProof, claimedSum frontend.Variable, degree int, t *transcript) error {
	r := make([]frontend.Variable, claims.varsNum())

	gJR := claimedSum

	// gⱼ(0) + gⱼ(1) = gⱼ₋₁(rⱼ₋₁) and gⱼ(1) = ∑ᵢ₌₀ cᵢ give c₀ = (gⱼ₋₁(rⱼ₋₁) - ∑ᵢ₌₁ cᵢ) / 2.
	for j := range claims.varsNum() {
		partialSumPoly := proof.PartialSumPolys[j]
		if len(partialSumPoly) != degree {
			return errors.New("malformed proof")
		}
		c0 := api.Div(api.Sub(gJR, partialSumPoly.Eval(api, 1)), 2)

		r[j] = t.Squeeze(proof.PartialSumPolys[j]...)

		gJR = api.Add(api.Mul(partialSumPoly.Eval(api, r[j]), r[j]), c0)
	}

	return claims.verifyFinalEval(api, r, gJR, proof.FinalEvalProof)
}
