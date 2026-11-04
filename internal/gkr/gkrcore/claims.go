package gkrcore

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/gkr"
)

// AppendOutputClaims appends (point, evals[i]) to claims[w] for every output wire w of c that
// include selects, in c.Outputs() order.
func AppendOutputClaims[F any, G any](claims map[int][]gkr.EvaluationClaim[F], c gkr.Circuit[G], point []F, evals []F, include func(wI int) bool) {
	for i, w := range c.Outputs() {
		if !include(w) {
			continue
		}
		claims[w] = append(claims[w], gkr.EvaluationClaim[F]{EvaluationPoint: point, Evaluation: evals[i]})
	}
}

// AppendLevelClaims appends, for each unique gate input of level that include selects and each of
// level's outgoing points, an evaluation claim read from finalEvalProof.
func AppendLevelClaims[F any, G any](claims map[int][]gkr.EvaluationClaim[F], c gkr.Circuit[G], level constraint.GkrProvingLevel, finalEvalProof []F, outgoingPoints [][]F, include func(wI int) bool) {
	for uI, wI := range UniqueGateInputs(c, level) {
		if !include(wI) {
			continue
		}
		for k, point := range outgoingPoints {
			claims[wI] = append(claims[wI], gkr.EvaluationClaim[F]{EvaluationPoint: point, Evaluation: finalEvalProof[level.FinalEvalProofIndex(uI, k)]})
		}
	}
}
