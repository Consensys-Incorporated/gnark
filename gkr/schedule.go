package gkr

import (
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

// ZeroCheckDegree returns the number of values per round polynomial in the level's proof; 0 at a
// skip level.
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

// consolidationView returns a copy of c in which every wire of level is its own sole input,
// through the identity gate, whatever its own gate was. Only level 0 uses this view; everything
// else, c.Outputs() and ClaimValueIndices included, uses c itself.
func (c Circuit[G]) consolidationView(level constraint.GkrProvingLevel, identity Gate[G]) Circuit[G] {
	view := slices.Clone(c)
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			view[wI] = Wire[G]{Gate: identity, Inputs: []int{wI}}
		}
	}
	return view
}

// LevelCircuit returns c, except at level 0, whose consolidationView it returns instead: on c, a
// level-0 wire keeps its own gate's inputs, or has none, while on the view every level-0 wire is
// its own sole input. InputMapping and ZeroCheckDegree need the view to size or execute level 0.
func (c Circuit[G]) LevelCircuit(schedule constraint.GkrProvingSchedule, levelI int, identity Gate[G]) Circuit[G] {
	if levelI != 0 {
		return c
	}
	return c.consolidationView(schedule[0], identity)
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
