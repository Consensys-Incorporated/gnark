package gkrcore

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/gkr"
)

// EvaluationClaim is an assertion that a wire's multilinear extension evaluates to Evaluation at
// EvaluationPoint. See gkr.EvaluationClaim.
type EvaluationClaim[F any] = gkr.EvaluationClaim[F]

// AppendOutputClaims appends (point, evals[i]) to claims[w] for every output wire w of c that
// include selects, in c.Outputs() order.
func AppendOutputClaims[F any, G any](claims map[int][]EvaluationClaim[F], c Circuit[G], point []F, evals []F, include func(wI int) bool) {
	for i, w := range c.Outputs() {
		if !include(w) {
			continue
		}
		claims[w] = append(claims[w], EvaluationClaim[F]{EvaluationPoint: point, Evaluation: evals[i]})
	}
}

// AppendLevelClaims appends, for each unique gate input of level that include selects and each of
// level's outgoing points, an evaluation claim read from finalEvalProof.
func AppendLevelClaims[F any, G any](claims map[int][]EvaluationClaim[F], c Circuit[G], level constraint.GkrProvingLevel, finalEvalProof []F, outgoingPoints [][]F, include func(wI int) bool) {
	for uI, wI := range c.UniqueGateInputs(level) {
		if !include(wI) {
			continue
		}
		for k, point := range outgoingPoints {
			claims[wI] = append(claims[wI], EvaluationClaim[F]{EvaluationPoint: point, Evaluation: finalEvalProof[level.FinalEvalProofIndex(uI, k)]})
		}
	}
}
