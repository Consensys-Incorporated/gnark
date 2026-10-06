package gkr

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark/constraint"
)

// InputMapping returns as uniqueInputs the deduplicated list of inputs to the level,
// and as inputIndices for every wire in the level the list of positions for each of its
// inputs in the uniqueInputs list.
func (c Circuit[G]) InputMapping(level constraint.GkrProvingLevel) (uniqueInputs []int, inputIndices [][]int) {
	seen := make(map[int]int) // wire index → position in uniqueInputs
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			wire := c[wI]
			indices := make([]int, len(wire.Inputs))
			for inWI, inW := range wire.Inputs {
				pos, ok := seen[inW]
				if !ok {
					pos = len(uniqueInputs)
					seen[inW] = pos
					uniqueInputs = append(uniqueInputs, inW)
				}
				indices[inWI] = pos
			}
			inputIndices = append(inputIndices, indices)
		}
	}
	return
}

// UniqueGateInputs returns the unique gate input wire indices for all wires in the level,
// deduplicated in batch-then-wire-then-input order (first occurrence wins).
func (c Circuit[G]) UniqueGateInputs(level constraint.GkrProvingLevel) []int {
	uniqueInputs, _ := c.InputMapping(level)
	return uniqueInputs
}

func (c Circuit[G]) ZeroCheckDegree(level constraint.GkrProvingLevel) int {
	maxDeg := 0
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			maxDeg = max(maxDeg, c[wI].Gate.Degree)
		}
	}

	switch level.(type) {
	case *constraint.GkrSumcheckLevel:
		return maxDeg + 1
	case *constraint.GkrSingleSourceZeroCheckLevel:
		return maxDeg
	case *constraint.GkrSkipLevel:
		return 0
	}
	panic(fmt.Sprintf("ZeroCheckDegree: unknown proving level type %T", level))
}

// ConsolidationView returns a copy of c in which every wire of level is its own sole input,
// through the identity gate, whatever its own gate was. Only level 0 uses this view; everything
// else, c.Outputs() and ClaimValueIndices included, uses c itself.
func (c Circuit[G]) ConsolidationView(level constraint.GkrProvingLevel, identity Gate[G]) Circuit[G] {
	view := slices.Clone(c)
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			view[wI] = Wire[G]{Gate: identity, Inputs: []int{wI}}
		}
	}
	return view
}

// LevelWires returns a boolean slice, indexed by wire, marking every wire of level.
func (c Circuit[G]) LevelWires(level constraint.GkrProvingLevel) []bool {
	wires := make([]bool, len(c))
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			wires[wI] = true
		}
	}
	return wires
}

// LevelCircuit returns c, except at level 0, whose ConsolidationView it returns instead: on c, a
// level-0 wire keeps its own gate's inputs, or has none, while on the view every level-0 wire is
// its own sole input. InputMapping and ZeroCheckDegree need the view to size or execute level 0.
func (c Circuit[G]) LevelCircuit(schedule constraint.GkrProvingSchedule, levelI int, identity Gate[G]) Circuit[G] {
	if levelI != 0 {
		return c
	}
	return c.ConsolidationView(schedule[0], identity)
}

// ProofSize returns the total number of field elements in a GKR proof. The identity's Evaluate is
// never called, so its zero value does for G.
func (c Circuit[G]) ProofSize(schedule constraint.GkrProvingSchedule, logNbInstances int) int {
	size := len(c.Outputs())
	identity := Gate[G]{Degree: 1, NbIn: 1}
	for levelI, level := range schedule {
		lc := c.LevelCircuit(schedule, levelI, identity)
		// For every outgoing claim and unique input wire, there will be
		// an outgoing evaluation claim included in finalEvalProof.
		size += len(lc.UniqueGateInputs(level)) * level.NbOutgoingEvalPoints()
		size += lc.ZeroCheckDegree(level) * logNbInstances
	}
	return size
}

// ReduplicateInputs expands unique evaluations to per-wire gate input evaluation lists.
func ReduplicateInputs[F any, G any](level constraint.GkrProvingLevel, c Circuit[G], uniqueEvals []F) [][]F {
	_, inputIndices := c.InputMapping(level)
	result := make([][]F, len(inputIndices))
	for wireInLevel := range inputIndices {
		wireInputs := make([]F, len(inputIndices[wireInLevel]))
		for gateInputJ, uniqueI := range inputIndices[wireInLevel] {
			wireInputs[gateInputJ] = uniqueEvals[uniqueI]
		}
		result[wireInLevel] = wireInputs
	}
	return result
}

// ClaimValueIndices returns claimValueIndices[wI][claimI], the index of the value of wire wI's
// claimI-th claim in the finalEvalProof of that claim's source level.
// For the sentinel initial-challenge claim, it is wI's position in c.Outputs().
// A wire in two levels gets the row of the higher one; the lower one's sources must be its prefix.
func (c Circuit[G]) ClaimValueIndices(schedule constraint.GkrProvingSchedule) [][]int {
	cache := make([]map[int]int, len(schedule)) // cache[levelI][wireI] is the unique input index of wireI in levelI.
	res := make([][]int, len(c))

	outputPos := make(map[int]int) // outputPos[wireI] is wireI's position in c.Outputs()
	for i, wI := range c.Outputs() {
		outputPos[wI] = i
	}

	// This loop weaves the level's treatment both as a claim source and as the collection of input wires
	for levelI := len(schedule) - 1; levelI >= 0; levelI-- {
		level := schedule[levelI]
		cache[levelI] = make(map[int]int)

		for _, group := range level.ClaimGroups() {
			for _, wI := range group.Wires {

				for _, inputWI := range c[wI].Inputs {
					if _, ok := cache[levelI][inputWI]; !ok {
						cache[levelI][inputWI] = len(cache[levelI])
					}
				}

				if res[wI] != nil {
					continue
				}
				for _, claimSource := range group.ClaimSources {
					if claimSource.Level == len(schedule) { // output
						res[wI] = append(res[wI], outputPos[wI])
					} else {
						res[wI] = append(res[wI], schedule[claimSource.Level].FinalEvalProofIndex(cache[claimSource.Level][wI], claimSource.OutgoingClaimIndex))
					}
				}
			}
		}
	}
	return res
}

// CollectOutgoingEvalPoints sets the outgoing evaluation points of a skip level, equal to its incoming ones.
func CollectOutgoingEvalPoints[F any](level *constraint.GkrSkipLevel, levelI int, outgoingEvalPoints [][][]F) [][]F {
	outPoints := make([][]F, level.NbOutgoingEvalPoints())
	for k, src := range level.ClaimSources {
		outPoints[k] = outgoingEvalPoints[src.Level][src.OutgoingClaimIndex]
	}
	outgoingEvalPoints[levelI] = outPoints
	return outPoints
}

// ComputeLogNbInstances derives n such that the number of instances is 2ⁿ from the length of the
// serialized proof and the circuit/schedule structure, identity being the gate that level 0's view
// of the circuit uses. It returns -1 if the schedule has no level that runs a sumcheck, as then
// the proof's length does not depend on n, and an error if no n matches the length.
func ComputeLogNbInstances[G any](c Circuit[G], schedule constraint.GkrProvingSchedule, serializedProofLen int, identity Gate[G]) (int, error) {
	serializedProofLen -= len(c.Outputs())
	perVar := 0
	for levelI, level := range schedule {
		levelCircuit := c.LevelCircuit(schedule, levelI, identity)
		nbUniqueInputs := len(levelCircuit.UniqueGateInputs(level))
		switch level.(type) {
		case *constraint.GkrSkipLevel:
			serializedProofLen -= nbUniqueInputs * level.NbOutgoingEvalPoints()
		default:
			perVar += levelCircuit.ZeroCheckDegree(level)
			serializedProofLen -= nbUniqueInputs
		}
	}
	if serializedProofLen < 0 {
		return 0, errors.New("proof too short")
	}
	if perVar == 0 {
		if serializedProofLen == 0 {
			return -1, nil
		}
	} else if serializedProofLen%perVar == 0 {
		return serializedProofLen / perVar, nil
	}
	return 0, errors.New("proof length matches no number of instances")
}
