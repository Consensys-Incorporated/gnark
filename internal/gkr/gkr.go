package gkr

import (
	"errors"
	"fmt"

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

// resources holds all shared state for gadget GKR verification.
type resources struct {
	api                frontend.API
	t                  *transcript
	circuit            Circuit
	schedule           constraint.GkrProvingSchedule
	assignment         WireAssignment
	outgoingEvalPoints [][][]frontend.Variable // [levelI][outgoingClaimI] → eval point
	nbVars             int
	uniqueInputIndices [][]int // [wI][claimI]: w's unique-input index in the layer its claimI-th evaluation is coming from
	wireLevels         []constraint.GkrProvingLevel
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
// For input wires, w(r) is computed directly from the assignment and the claimed
// evaluation in uniqueInputEvaluations is asserted equal to it.
// For non-input wires, the prover claims evaluations of their gate inputs at r via
// uniqueInputEvaluations; those claims are verified by lower levels' sumchecks.
func (e *zeroCheckLazyClaims) verifyFinalEval(api frontend.API, r []frontend.Variable, purportedValue frontend.Variable, uniqueInputEvaluations []frontend.Variable) error {
	e.r.outgoingEvalPoints[e.levelI] = [][]frontend.Variable{r}
	level := e.r.schedule[e.levelI]
	perWireInputEvals := gkrcore.ReduplicateInputs(level, e.r.circuit, uniqueInputEvaluations)

	var terms []frontend.Variable
	levelWireI := 0
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			wire := e.r.circuit[wI]

			var gateEval frontend.Variable
			if wire.IsInput() {
				gateEval = e.r.assignment[wI].Evaluate(api, r)
				api.AssertIsEqual(perWireInputEvals[levelWireI][0], gateEval)
			} else {
				gateEval = wire.Gate.Evaluate(FrontendAPIWrapper{api}, perWireInputEvals[levelWireI]...)
			}

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

func (r *resources) verifySkipLevel(levelI int, proof Proof) {
	level := r.schedule[levelI].(*constraint.GkrSkipLevel)
	outPoints := gkrcore.CollectOutgoingEvalPoints(level, levelI, r.outgoingEvalPoints)

	finalEval := proof[levelI].FinalEvalProof
	_, inputIndices := r.circuit.InputMapping(level)
	group := constraint.GkrClaimGroup(*level)
	initialChallengeI := len(r.schedule)

	for levelWireI, wI := range group.Wires {
		wire := r.circuit[wI]
		gateIns := make([]frontend.Variable, len(wire.Inputs))
		for claimI, src := range group.ClaimSources {
			point := outPoints[claimI]
			var gateEval frontend.Variable
			if wire.IsInput() {
				gateEval = r.assignment[wI].Evaluate(r.api, point)
				claimed := finalEval[level.FinalEvalProofIndex(inputIndices[levelWireI][0], claimI)]
				r.api.AssertIsEqual(claimed, gateEval)
			} else {
				for i, inI := range inputIndices[levelWireI] {
					gateIns[i] = finalEval[level.FinalEvalProofIndex(inI, claimI)]
				}
				gateEval = wire.Gate.Evaluate(FrontendAPIWrapper{r.api}, gateIns...)
			}
			var claimedEval frontend.Variable
			if src.Level == initialChallengeI {
				claimedEval = r.assignment[wI].Evaluate(r.api, point)
			} else {
				claimedEval = proof[src.Level].FinalEvalProof[r.schedule[src.Level].FinalEvalProofIndex(r.uniqueInputIndices[wI][claimI], src.OutgoingClaimIndex)]
			}
			r.api.AssertIsEqual(claimedEval, gateEval)
		}
	}
}

// verifyLevelSetup derives the folding coefficient, collects all claimed wire
// evaluations from the proof or the initial assignment, computes the batched
// claimed sum, and builds the lazy-claims object shared by both verifiers.
func (r *resources) verifyLevelSetup(levelI int, proof Proof) (frontend.Variable, *zeroCheckLazyClaims) {
	level := r.schedule[levelI]
	initialChallengeI := len(r.schedule)

	foldingCoeff := frontend.Variable(0)
	if level.NbClaims() >= 2 {
		foldingCoeff = r.t.getChallenge()
	}

	var claimedEvals []frontend.Variable
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			for claimI, src := range group.ClaimSources {
				var claimedEval frontend.Variable
				if src.Level == initialChallengeI {
					claimedEval = r.assignment[wI].Evaluate(r.api, r.outgoingEvalPoints[src.Level][src.OutgoingClaimIndex])
				} else {
					i := r.schedule[src.Level].FinalEvalProofIndex(r.uniqueInputIndices[wI][claimI], src.OutgoingClaimIndex)
					claimedEval = proof[src.Level].FinalEvalProof[i]
				}
				claimedEvals = append(claimedEvals, claimedEval)
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

// Verify the consistency of the claimed output with the claimed input.
func Verify(api frontend.API, c Circuit, schedule constraint.GkrProvingSchedule, assignment WireAssignment, proof Proof, h hash.FieldHasher) error {
	nbVars := assignment.NbVars()
	if 1<<nbVars != assignment.NbInstances() {
		return errors.New("number of instances must be a power of 2")
	}

	r := &resources{
		api:                api,
		t:                  &transcript{h: h},
		circuit:            c,
		schedule:           schedule,
		assignment:         assignment,
		outgoingEvalPoints: make([][][]frontend.Variable, len(schedule)+1),
		nbVars:             nbVars,
		uniqueInputIndices: c.UniqueInputIndices(schedule),
		wireLevels:         schedule.WireLevels(),
	}

	initialChallengeI := len(schedule)
	firstChallenge := make([]frontend.Variable, nbVars)
	for j := range nbVars {
		firstChallenge[j] = r.t.getChallenge()
	}
	r.outgoingEvalPoints[initialChallengeI] = [][]frontend.Variable{firstChallenge}

	for levelI := len(schedule) - 1; levelI >= 0; levelI-- {
		switch schedule[levelI].(type) {
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
		constraint.BindGkrFinalEvalProof(r.t, proof[levelI].FinalEvalProof,
			c.UniqueGateInputs(schedule[levelI]), c.IsInput, schedule[levelI], r.wireLevels)
	}
	return nil
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
	perVar := 0
	for _, level := range schedule {
		nbUniqueInputs := len(circuit.UniqueGateInputs(level))
		switch level.(type) {
		case *constraint.GkrSkipLevel:
			serializedProofLen -= nbUniqueInputs * level.NbOutgoingEvalPoints()
		default:
			perVar += circuit.ZeroCheckDegree(level)
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
	proof := make(Proof, len(schedule))
	logNbInstances := ComputeLogNbInstances(circuit, schedule, len(serializedProof))

	reader := variablesReader(serializedProof)
	for levelI, level := range schedule {
		nbUniqueInputs := len(circuit.UniqueGateInputs(level))
		if _, isSkip := level.(*constraint.GkrSkipLevel); isSkip {
			proof[levelI].FinalEvalProof = reader.nextN(nbUniqueInputs * level.NbOutgoingEvalPoints())
		} else {
			degree := circuit.ZeroCheckDegree(level)
			proof[levelI].PartialSumPolys = make([]polynomial.Polynomial, logNbInstances)
			for j := range proof[levelI].PartialSumPolys {
				proof[levelI].PartialSumPolys[j] = reader.nextN(degree)
			}
			proof[levelI].FinalEvalProof = reader.nextN(nbUniqueInputs)
		}
	}
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
