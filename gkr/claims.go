package gkr

// EvaluationClaim is an assertion that a wire's multilinear extension evaluates to Evaluation at
// EvaluationPoint. EvaluationPoint may be aliased across claims; callers must not modify it.
type EvaluationClaim[E any] struct {
	EvaluationPoint []E
	Evaluation      E
}
