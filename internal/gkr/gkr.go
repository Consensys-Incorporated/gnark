package gkr

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/polynomial"
)

// Type aliases for gadget circuit types
type (
	Wire    = gkrcore.GadgetWire
	Circuit = gkrcore.GadgetCircuit
)

// WireAssignment is an assignment of values to the same wire across many instances of the circuit
type WireAssignment []polynomial.MultiLin

func (a WireAssignment) NbInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignment) NbVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

// A SNARK gadget capable of verifying a GKR proof
// The goal is to prove/verify evaluations of many instances of the same circuit.

type Proof []sumcheckProof // for each schedule level, a sumcheck proof

// EvaluationClaim is an assertion that a wire's multilinear extension evaluates to Evaluation at
// EvaluationPoint.
type EvaluationClaim = gkrcore.EvaluationClaim[frontend.Variable]

// Claims are the evaluation claims on circuit inputs and outputs that Verify returns, by wire.
type Claims map[int][]EvaluationClaim

// Check asserts that every claim in c holds against assignment. Wires are visited in increasing
// order, so that the constraints Check emits do not depend on map iteration order.
func (c Claims) Check(api frontend.API, assignment WireAssignment) {
	for _, wI := range slices.Sorted(maps.Keys(c)) {
		for _, claim := range c[wI] {
			eval := assignment[wI].Evaluate(api, claim.EvaluationPoint)
			api.AssertIsEqual(eval, claim.Evaluation)
		}
	}
}

// resources holds all shared state for gadget GKR verification.
type resources struct {
	api                frontend.API
	t                  *transcript
	circuit            Circuit
	schedule           constraint.GkrProvingSchedule
	outgoingEvalPoints [][][]frontend.Variable // [levelI][outgoingClaimI] → eval point
	nbVars             int
	claimValueIndices  [][]int // [wI][claimI]: index of w's claimI-th claimed value in its source level's FinalEvalProof
	claims             Claims
	consolidated       []bool // the wires of schedule[0], indexed by wire
}

// identityGate is the identity gate LevelCircuit and ConsolidationView use to build level 0's view
// of the circuit.
func identityGate() gkrcore.GadgetGate {
	return gkrcore.GadgetGate{Evaluate: gkrcore.Identity, NbIn: 1, Degree: 1}
}

// zeroCheckLazyClaims is a lazy claim for sumcheck (verifier side).
// It checks that the polynomial ∑ᵢ cⁱ eq(-, xᵢ) wᵢ(-) sums to the expected value,
// where the sum runs over all (wire v, claim source s) pairs in the level.
type zeroCheckLazyClaims struct {
	foldingCoeff frontend.Variable
	r            *resources
	levelI       int
}

func (e *zeroCheckLazyClaims) varsNum() int {
	return e.r.nbVars
}

func (e *zeroCheckLazyClaims) degree(int) int {
	return e.r.circuit.ZeroCheckDegree(e.r.schedule[e.levelI])
}

// verifyFinalEval finalizes the verification of a level at the sumcheck evaluation point r.
// The sumcheck protocol has already reduced the per-wire claims to verifying
// ∑ᵢ cⁱ eq(xᵢ, r) · wᵢ(r) = purportedValue, where the sum runs over all
// claims on each wire and c is foldingCoeff.
// Both purportedValue and the vector r have been randomized during sumcheck.
//
// The prover claims evaluations of each wire's gate inputs at r via uniqueInputEvaluations; those
// claims are verified by lower levels' sumchecks.
func (e *zeroCheckLazyClaims) verifyFinalEval(api frontend.API, r []frontend.Variable, purportedValue frontend.Variable, uniqueInputEvaluations []frontend.Variable) error {
	e.r.outgoingEvalPoints[e.levelI] = [][]frontend.Variable{r}
	level := e.r.schedule[e.levelI]
	perWireInputEvals := gkrcore.ReduplicateInputs(level, e.r.circuit, uniqueInputEvaluations)

	var terms []frontend.Variable
	levelWireI := 0
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			wire := e.r.circuit[wI]

			gateEval := wire.Gate.Evaluate(FrontendAPIWrapper{api}, perWireInputEvals[levelWireI]...)

			for _, src := range group.ClaimSources {
				eq := polynomial.EvalEq(api, e.r.outgoingEvalPoints[src.Level][src.OutgoingClaimIndex], r)
				term := api.Mul(eq, gateEval)
				terms = append(terms, term)
			}
			levelWireI++
		}
	}

	claimedEvals := polynomial.Polynomial(terms)
	total := claimedEvals.Eval(api, e.foldingCoeff)
	api.AssertIsEqual(total, purportedValue)
	return nil
}

// verifySkipLevel checks that the proof's finalEvalProof is consistent with the gate evaluations,
// and records outgoing eval points.
func (r *resources) verifySkipLevel(levelI int, proof Proof) {
	level := r.schedule[levelI].(*constraint.GkrSkipLevel)
	gkrcore.CollectOutgoingEvalPoints(level, levelI, r.outgoingEvalPoints)

	finalEval := proof[levelI].FinalEvalProof
	_, inputIndices := r.circuit.InputMapping(level)
	group := constraint.GkrClaimGroup(*level)

	for levelWireI, wI := range group.Wires {
		wire := r.circuit[wI]
		gateIns := make([]frontend.Variable, len(wire.Inputs))
		for claimI, src := range group.ClaimSources {
			for i, inI := range inputIndices[levelWireI] {
				gateIns[i] = finalEval[level.FinalEvalProofIndex(inI, claimI)]
			}
			gateEval := wire.Gate.Evaluate(FrontendAPIWrapper{r.api}, gateIns...)
			claimedEval := proof[src.Level].FinalEvalProof[r.claimValueIndices[wI][claimI]]
			r.api.AssertIsEqual(claimedEval, gateEval)
		}
	}
}

// verifyLevelSetup derives the folding coefficient, collects all claimed wire
// evaluations from the proof or the initial assignment, computes the batched
// claimed sum, and builds the lazy-claims object shared by both verifiers.
func (r *resources) verifyLevelSetup(levelI int, proof Proof) (frontend.Variable, *zeroCheckLazyClaims) {
	level := r.schedule[levelI]

	foldingCoeff := frontend.Variable(0)
	if level.NbClaims() >= 2 {
		foldingCoeff = r.t.getChallenge()
	}

	var claimedEvals []frontend.Variable
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			for claimI, src := range group.ClaimSources {
				claimedEvals = append(claimedEvals, proof[src.Level].FinalEvalProof[r.claimValueIndices[wI][claimI]])
			}
		}
	}

	return polynomial.Polynomial(claimedEvals).Eval(r.api, foldingCoeff), &zeroCheckLazyClaims{
		foldingCoeff: foldingCoeff,
		r:            r,
		levelI:       levelI,
	}
}

func (r *resources) verifySumcheckLevel(levelI int, proof Proof) error {
	claimedSum, lazyClaims := r.verifyLevelSetup(levelI, proof)
	if err := verifySumcheck(r.api, lazyClaims, proof[levelI], claimedSum,
		r.circuit.ZeroCheckDegree(r.schedule[levelI]), r.t); err != nil {
		return fmt.Errorf("sumcheck proof rejected at level %d: %v", levelI, err)
	}
	return nil
}

func (r *resources) verifySingleSourceZeroCheckLevel(levelI int, proof Proof) error {
	claimedSum, lazyClaims := r.verifyLevelSetup(levelI, proof)

	level := r.schedule[levelI].(*constraint.GkrSingleSourceZeroCheckLevel)
	src := level.ClaimSources[0]
	q := r.outgoingEvalPoints[src.Level][src.OutgoingClaimIndex]
	degree := r.circuit.ZeroCheckDegree(level)

	challenges := make([]frontend.Variable, r.nbVars)
	gPrime := make(polynomial.Polynomial, degree+1)

	for j := range r.nbVars {
		partialSumPoly := proof[levelI].PartialSumPolys[j]
		if len(partialSumPoly) != degree {
			return errors.New("malformed proof")
		}

		// Recover g'(0) from (1-q_j)*g'(0) + q_j*g'(1) = claimedSum
		// g'(0) = (claimedSum - q_j * g'(1)) / (1 - q_j)
		qjTimesGPrime1 := r.api.Mul(q[j], partialSumPoly[0]) // partialSumPoly[0] = g'(1)
		numerator := r.api.Sub(claimedSum, qjTimesGPrime1)
		oneMinusQj := r.api.Sub(1, q[j])
		gPrime[0] = r.api.Div(numerator, oneMinusQj)

		copy(gPrime[1:], partialSumPoly)

		challenges[j] = r.t.getChallenge(proof[levelI].PartialSumPolys[j]...)
		claimedSum = polynomial.InterpolateLDE(r.api, challenges[j], gPrime[:(degree+1)])
	}

	// claimedSum is now Σ_w c^w · gate_w(inputs(r)), without the eq factor.
	// verifyFinalEval expects Σ_w c^w · eq(q, r) · gate_w(inputs(r)), so multiply.
	eqAtQR := polynomial.EvalEq(r.api, q, challenges)
	claimedSum = r.api.Mul(eqAtQR, claimedSum)

	return lazyClaims.verifyFinalEval(r.api, challenges, claimedSum, proof[levelI].FinalEvalProof)
}

// levelPredicates returns the bind and include predicates for level levelI's unique gate inputs.
// Level 0 binds nothing and returns every one of its wires (self-referencing on the consolidation
// view); every other level binds every unique gate input that is not an unconsolidated circuit
// input, and returns claims for exactly those it withholds from binding.
func (r *resources) levelPredicates(levelI int) (bind, include func(wI int) bool) {
	if levelI == 0 {
		return func(int) bool { return false }, func(int) bool { return true }
	}
	return func(wI int) bool { return !r.circuit.IsInput(wI) || r.consolidated[wI] },
		func(wI int) bool { return r.circuit.IsInput(wI) && !r.consolidated[wI] }
}

// verifyLevel verifies level levelI: checks its proof entry, binds its values, and appends its claims.
func (r *resources) verifyLevel(levelI int, proof Proof) error {
	switch r.schedule[levelI].(type) {
	case *constraint.GkrSkipLevel:
		r.verifySkipLevel(levelI, proof)
	case *constraint.GkrSingleSourceZeroCheckLevel:
		if err := r.verifySingleSourceZeroCheckLevel(levelI, proof); err != nil {
			return err
		}
	default:
		if err := r.verifySumcheckLevel(levelI, proof); err != nil {
			return err
		}
	}
	bind, include := r.levelPredicates(levelI)
	constraint.BindGkrFinalEvalProof(r.t, proof[levelI].FinalEvalProof, r.circuit.UniqueGateInputs(r.schedule[levelI]), bind, r.schedule[levelI])
	gkrcore.AppendLevelClaims(r.claims, r.circuit, r.schedule[levelI], proof[levelI].FinalEvalProof, r.outgoingEvalPoints[levelI], include)
	return nil
}

// Verify the consistency of the claimed output with the claimed input, and return the evaluation
// claims on the circuit's inputs and outputs. A nil error means nothing until the returned Claims
// are checked: Verify reads no assignment, so the caller must call Claims.Check itself. The claim
// values returned to the caller, the output evaluations among them, are not bound into the
// transcript.
func Verify(api frontend.API, c Circuit, schedule constraint.GkrProvingSchedule, logNbInstances int, proof Proof, h hash.FieldHasher) (Claims, error) {
	r := &resources{
		api:                api,
		t:                  &transcript{h: h},
		circuit:            c,
		schedule:           schedule,
		outgoingEvalPoints: make([][][]frontend.Variable, len(schedule)+1),
		nbVars:             logNbInstances,
		claimValueIndices:  c.ClaimValueIndices(schedule),
		claims:             make(Claims),
		consolidated:       c.LevelWires(schedule[0]),
	}

	initialChallengeI := len(schedule)
	if len(proof) != initialChallengeI+1 {
		return nil, fmt.Errorf("proof has %d levels, expected %d", len(proof), initialChallengeI+1)
	}
	outputLevel := proof[initialChallengeI]
	if len(outputLevel.PartialSumPolys) != 0 {
		return nil, errors.New("output level has partial sum polynomials")
	}
	if len(outputLevel.FinalEvalProof) != len(c.Outputs()) {
		return nil, fmt.Errorf("output level has %d evaluations, expected %d", len(outputLevel.FinalEvalProof), len(c.Outputs()))
	}

	view := c.LevelCircuit(schedule, 0, identityGate())
	for levelI, level := range schedule {
		levelCircuit := c
		if levelI == 0 {
			levelCircuit = view
		}
		nbUniqueInputs := len(levelCircuit.UniqueGateInputs(level))
		wantFinalEvalLen := nbUniqueInputs * level.NbOutgoingEvalPoints()
		if len(proof[levelI].FinalEvalProof) != wantFinalEvalLen {
			return nil, fmt.Errorf("level %d: got %d final evaluations, expected %d", levelI, len(proof[levelI].FinalEvalProof), wantFinalEvalLen)
		}
		if _, isSkip := level.(*constraint.GkrSkipLevel); isSkip {
			if len(proof[levelI].PartialSumPolys) != 0 {
				return nil, fmt.Errorf("level %d: skip level has partial sum polynomials", levelI)
			}
		} else if len(proof[levelI].PartialSumPolys) != logNbInstances {
			return nil, fmt.Errorf("level %d: got %d partial sum polynomials, expected %d", levelI, len(proof[levelI].PartialSumPolys), logNbInstances)
		}
	}

	firstChallenge := make([]frontend.Variable, logNbInstances)
	for j := range logNbInstances {
		firstChallenge[j] = r.t.getChallenge()
	}
	r.outgoingEvalPoints[initialChallengeI] = [][]frontend.Variable{firstChallenge}
	var boundOutputEvals []frontend.Variable
	for i, w := range c.Outputs() {
		if r.consolidated[w] {
			boundOutputEvals = append(boundOutputEvals, outputLevel.FinalEvalProof[i])
		}
	}
	r.t.Bind(boundOutputEvals...)
	gkrcore.AppendOutputClaims(r.claims, c, firstChallenge, outputLevel.FinalEvalProof, func(wI int) bool { return !r.consolidated[wI] })

	for levelI := len(schedule) - 1; levelI >= 1; levelI-- {
		if err := r.verifyLevel(levelI, proof); err != nil {
			return nil, err
		}
	}
	r.circuit = view
	if err := r.verifyLevel(0, proof); err != nil {
		return nil, err
	}
	return r.claims, nil
}

func (p Proof) Serialize() []frontend.Variable {
	res := make([]frontend.Variable, 0)
	for i := range p {
		for j := range p[i].PartialSumPolys {
			res = append(res, p[i].PartialSumPolys[j]...)
		}
		res = append(res, p[i].FinalEvalProof...)
	}

	return res
}

// ComputeLogNbInstances derives n such that the number of instances is 2ⁿ
// from the size of the proof and the circuit/schedule structure.
func ComputeLogNbInstances(circuit Circuit, schedule constraint.GkrProvingSchedule, serializedProofLen int) int {
	serializedProofLen -= len(circuit.Outputs())
	identity := identityGate()
	perVar := 0
	for levelI, level := range schedule {
		levelCircuit := circuit.LevelCircuit(schedule, levelI, identity)
		nbUniqueInputs := len(levelCircuit.UniqueGateInputs(level))
		switch level.(type) {
		case *constraint.GkrSkipLevel:
			serializedProofLen -= nbUniqueInputs * level.NbOutgoingEvalPoints()
		default:
			perVar += levelCircuit.ZeroCheckDegree(level)
			serializedProofLen -= nbUniqueInputs
		}
	}
	if perVar == 0 {
		if serializedProofLen == 0 {
			return -1
		}
	} else {
		res := serializedProofLen / perVar
		if res*perVar == serializedProofLen {
			return res
		}
	}

	panic("cannot compute logNbInstances")
}

type variablesReader []frontend.Variable

func (r *variablesReader) nextN(n int) []frontend.Variable {
	res := (*r)[:n]
	*r = (*r)[n:]
	return res
}

func (r *variablesReader) hasNextN(n int) bool {
	return len(*r) >= n
}

func DeserializeProof(circuit Circuit, schedule constraint.GkrProvingSchedule, serializedProof []frontend.Variable) (Proof, error) {
	proof := make(Proof, len(schedule)+1)
	logNbInstances := ComputeLogNbInstances(circuit, schedule, len(serializedProof))

	identity := identityGate()
	reader := variablesReader(serializedProof)
	for levelI, level := range schedule {
		levelCircuit := circuit.LevelCircuit(schedule, levelI, identity)
		nbUniqueInputs := len(levelCircuit.UniqueGateInputs(level))
		if _, isSkip := level.(*constraint.GkrSkipLevel); isSkip {
			proof[levelI].FinalEvalProof = reader.nextN(nbUniqueInputs * level.NbOutgoingEvalPoints())
		} else {
			degree := levelCircuit.ZeroCheckDegree(level)
			proof[levelI].PartialSumPolys = make([]polynomial.Polynomial, logNbInstances)
			for j := range proof[levelI].PartialSumPolys {
				proof[levelI].PartialSumPolys[j] = reader.nextN(degree)
			}
			proof[levelI].FinalEvalProof = reader.nextN(nbUniqueInputs)
		}
	}
	proof[len(schedule)].FinalEvalProof = reader.nextN(len(circuit.Outputs()))
	if reader.hasNextN(1) {
		return nil, fmt.Errorf("proof too long: expected %d encountered %d", len(serializedProof)-len(reader), len(serializedProof))
	}
	return proof, nil
}

type FrontendAPIWrapper struct {
	frontend.API
}

func (api FrontendAPIWrapper) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	i := api.Add(a, b, c)
	res := api.Mul(i, i)    // i^2
	res = api.Mul(res, res) // i^4
	res = api.Mul(res, res) // i^8
	res = api.Mul(res, res) // i^16
	return api.Mul(res, i)  // i^17
}
