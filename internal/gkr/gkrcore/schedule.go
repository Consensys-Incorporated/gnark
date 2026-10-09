package gkrcore

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/consensys/gnark/gkr"

	"github.com/consensys/gnark/constraint"
)

// scheduleBuilder accumulates topology and per-wire claim sources while a schedule is being built.
// Steps are appended in out-to-in (topological) order and reversed by finalize.
// Claim source level values are stored as their index in the levels slice, with -1 as the
// sentinel for the initial challenge. finalize will map each src.Level to its final absolute index via
// n-1-src.level, where n = len(levels), so -1 → n (initial challenge) and i → n-1-i (real levels).
type scheduleBuilder[G any] struct {
	circuit              gkr.Circuit[G]
	wireOutputs          [][]int // wireOutputs[i] indices of wires that wire i feeds into, in increasing order and deduplicated.
	wireLevels           []int   // wireLevels[i] which level wire i has been put in
	wireProcessed        []bool
	claimSourcesCache    [][]constraint.GkrClaimSource // claimSourcesCache[i] is the result of claimSources(i), or nil if not yet computed.
	firstUnprocessedWire int
	levels               constraint.GkrProvingSchedule
}

// newScheduleBuilder initialises a builder for the given circuit.
// It computes the outputs inverse-adjacency list.
func newScheduleBuilder[G any](c gkr.Circuit[G]) scheduleBuilder[G] {
	b := scheduleBuilder[G]{
		circuit:              c,
		wireOutputs:          make([][]int, len(c)),
		wireLevels:           make([]int, len(c)),
		wireProcessed:        make([]bool, len(c)),
		claimSourcesCache:    make([][]constraint.GkrClaimSource, len(c)),
		firstUnprocessedWire: len(c) - 1,
	}
	seen := make(map[int]bool, len(c))
	for i := range c {
		for k := range seen {
			delete(seen, k)
		}
		for _, in := range c[i].Inputs {
			b.wireOutputs[in] = append(b.wireOutputs[in], i)
			seen[in] = true
		}
	}
	return b
}

// addSumcheckLevel appends a GkrSumcheckLevel to the schedule. Each batch is a set of wire indices
// to be proven together in a single zerocheck; all wires in a batch must share the same claim sources.
// All wires across all batches must be ready.
func (b *scheduleBuilder[G]) addSumcheckLevel(batches ...[]int) error {
	claimGroups, err := b.buildClaimGroups(batches)
	if err != nil {
		return err
	}
	lvl := constraint.GkrSumcheckLevel(claimGroups)
	b.levels = append(b.levels, &lvl)
	return nil
}

// addSingleSourceZeroCheckLevel appends a GkrSingleSourceZeroCheckLevel to the schedule.
// All wires must share the same single claim source and must be ready.
func (b *scheduleBuilder[G]) addSingleSourceZeroCheckLevel(wireIndices []int) error {
	claimGroups, err := b.buildClaimGroups([][]int{wireIndices})
	if err != nil {
		return err
	}
	if len(claimGroups[0].ClaimSources) != 1 {
		return fmt.Errorf("single source zerocheck level requires exactly 1 claim source, got %d", len(claimGroups[0].ClaimSources))
	}
	lvl := constraint.GkrSingleSourceZeroCheckLevel(claimGroups[0])
	b.levels = append(b.levels, &lvl)
	return nil
}

// addSkipLevel appends a GkrSkipLevel to the schedule for a single set of wire indices.
// All wires in the batch must share the same claim sources and must be ready.
func (b *scheduleBuilder[G]) addSkipLevel(wireIndices []int) error {
	claimGroups, err := b.buildClaimGroups([][]int{wireIndices})
	if err != nil {
		return err
	}
	lvl := constraint.GkrSkipLevel(claimGroups[0])
	b.levels = append(b.levels, &lvl)
	return nil
}

// markProcessed records that wire wI has been assigned to level levelIdx (or -1, for a wire
// that gets no level), and advances firstUnprocessedWire past it.
func (b *scheduleBuilder[G]) markProcessed(wI, levelIdx int) {
	b.wireLevels[wI] = levelIdx
	b.wireProcessed[wI] = true
	if wI == b.firstUnprocessedWire {
		for b.firstUnprocessedWire--; b.firstUnprocessedWire >= 0 && b.wireProcessed[b.firstUnprocessedWire]; b.firstUnprocessedWire-- {
		}
	}
}

// buildClaimGroups processes a set of batches, validates claim source consistency within each
// batch, marks each wire processed, and returns the resulting GkrClaimGroups.
// Every ClaimSources slice follows GkrClaimGroup's order once finalize has run.
func (b *scheduleBuilder[G]) buildClaimGroups(batches [][]int) ([]constraint.GkrClaimGroup, error) {
	levelIdx := len(b.levels)
	claimGroups := make([]constraint.GkrClaimGroup, len(batches))
	for i, wireIndices := range batches {
		var claimSources []constraint.GkrClaimSource
		for j, wI := range wireIndices {
			wireClaims, ok := b.claimSources(wI)
			if !ok {
				return nil, fmt.Errorf("wire %d is not ready", wI)
			}
			if j == 0 {
				claimSources = wireClaims
			} else if !slices.Equal(claimSources, wireClaims) {
				return nil, fmt.Errorf("wires %d and %d in the same batch have different claim sources", wireIndices[0], wI)
			}
			b.markProcessed(wI, levelIdx)
		}
		claimGroups[i] = constraint.GkrClaimGroup{Wires: slices.Clone(wireIndices), ClaimSources: claimSources}
	}
	return claimGroups, nil
}

// nextReady returns the highest wire index in the contiguous ready suffix starting at
// firstUnprocessedWire, along with each wire's claim sources in descending wire-index order
// (sources[0] belongs to firstUnprocessedWire, sources[i] to firstUnprocessedWire-i).
// Returns firstUnprocessedWire, nil if no wires are ready.
func (b *scheduleBuilder[G]) nextReady() (highestWireI int, sources [][]constraint.GkrClaimSource) {
	for lowestWireI := b.firstUnprocessedWire; lowestWireI >= 0; lowestWireI-- {
		if b.wireProcessed[lowestWireI] {
			break
		}
		src, ok := b.claimSources(lowestWireI)
		if !ok {
			break
		}
		sources = append(sources, src)
	}
	return b.firstUnprocessedWire, sources
}

// claimSources checks whether all consumers of wire wI have already been processed.
// If so, it returns the deduplicated claim sources for wI and true.
// If not, it returns nil and false. Results are cached.
// SkipLevels are proper claim targets: a wire feeding into a SkipLevel L with M inherited
// evaluation points gets M claim sources {L, 0}, {L, 1}, ..., {L, M-1}.
// Sorted in increasing (Level, OutgoingClaimIndex) order; finalize mirrors.
func (b *scheduleBuilder[G]) claimSources(wI int) ([]constraint.GkrClaimSource, bool) {
	if b.claimSourcesCache[wI] != nil {
		return b.claimSourcesCache[wI], true
	}
	var wireClaims []constraint.GkrClaimSource
	if b.circuit[wI].Exported || len(b.wireOutputs[wI]) == 0 {
		wireClaims = append(wireClaims, constraint.GkrClaimSource{Level: -1, OutgoingClaimIndex: 0})
	}
	for _, consumerWI := range b.wireOutputs[wI] {
		if !b.wireProcessed[consumerWI] {
			return nil, false
		}
		consumerLevel := b.wireLevels[consumerWI]
		switch b.levels[consumerLevel].(type) {
		case *constraint.GkrSkipLevel:
			// SkipLevel inherits M evaluation points from its own claim sources.
			M := b.levels[consumerLevel].NbOutgoingEvalPoints()
			for k := range M {
				wireClaims = append(wireClaims, constraint.GkrClaimSource{Level: consumerLevel, OutgoingClaimIndex: k})
			}
		default:
			wireClaims = append(wireClaims, constraint.GkrClaimSource{Level: consumerLevel, OutgoingClaimIndex: 0})
		}
	}
	slices.SortFunc(wireClaims, func(a, b constraint.GkrClaimSource) int {
		return cmp.Or(cmp.Compare(a.Level, b.Level), cmp.Compare(a.OutgoingClaimIndex, b.OutgoingClaimIndex))
	})
	wireClaims = slices.Compact(wireClaims)
	b.claimSourcesCache[wI] = wireClaims
	return wireClaims, true
}

// finalize reverses the schedule into in-to-out order and fixes up Level indices in all
// ClaimSources. It errors if any wire has not been processed.
func (b *scheduleBuilder[G]) finalize() (constraint.GkrProvingSchedule, error) {
	for i, processed := range b.wireProcessed {
		if !processed {
			return nil, fmt.Errorf("wire %d has not been processed", i)
		}
	}

	n := len(b.levels)
	slices.Reverse(b.levels)
	// Fix up ClaimSources: pre-reversal Level index src maps to n-1-src,
	// and the initial-challenge sentinel -1 maps to n.
	for _, level := range b.levels {
		for _, group := range level.ClaimGroups() {
			mirrorClaimSources(group.ClaimSources, n)
		}
	}

	return b.levels, nil
}

// mirrorClaimSources maps each pre-reversal Level index src.Level in-place to its post-reversal
// absolute index n-1-src.Level. The initial-challenge sentinel -1 maps to n.
func mirrorClaimSources(s []constraint.GkrClaimSource, n int) {
	n--
	for j := range s {
		s[j].Level = n - s[j].Level
	}
}

type levelType uint8

const (
	SkipLevel levelType = iota
	SumcheckLevel
	SingleSourceZeroCheckLevel
)

func batchForWire[G any](c gkr.Circuit[G], highWI int, readyWireClaimSources [][]constraint.GkrClaimSource) (batchWires []int, levelType levelType) {
	batchWires = []int{highWI}
	for len(batchWires) < len(readyWireClaimSources) {
		nextWI := highWI - len(batchWires)
		if c[nextWI].IsInput() || c[highWI].Gate.Degree != c[nextWI].Gate.Degree || !slices.Equal(readyWireClaimSources[0], readyWireClaimSources[len(batchWires)]) {
			break
		}
		batchWires = append(batchWires, nextWI)
	}

	batchClaimSources := readyWireClaimSources[0]
	levelType = SumcheckLevel
	if c[highWI].Gate.Degree == 1 && len(batchClaimSources) == 1 { // certain that skipping won't cause a claim blowup
		levelType = SkipLevel
	} else if len(batchClaimSources) == 1 {
		levelType = SingleSourceZeroCheckLevel
	}
	return
}

// ConsolidationMode selects which wires DefaultProvingSchedule consolidates into level 0.
type ConsolidationMode int

const (
	// ConsolidateAll consolidates every circuit input and every output.
	ConsolidateAll ConsolidationMode = iota
	// ConsolidateMultiClaimInputsOnly consolidates every circuit input with at least 2 claims.
	// A non-input wire never has more than one, so no output is ever consolidated.
	ConsolidateMultiClaimInputsOnly
	// ConsolidateNone consolidates nothing; level 0 is always the empty skip level.
	ConsolidateNone
)

// SNARKConsolidationMode is the mode std/gkrapi compiles circuits with.
const SNARKConsolidationMode = ConsolidateMultiClaimInputsOnly

// level0Groups selects the wires DefaultProvingSchedule consolidates into level 0 under mode, and
// groups them: a circuit input keeps its full claim-source list computed by the builder, while a
// non-input output is reduced to its output-level source alone, since its other claim sources are
// already reduced by its own gate level. Wires with equal claim-source lists share a group. Wires
// are visited in decreasing index order, so within a group wires come out in decreasing order, and
// groups come out in decreasing order of their first (highest) wire.
func (b *scheduleBuilder[G]) level0Groups(mode ConsolidationMode) []constraint.GkrClaimGroup {
	if mode == ConsolidateNone {
		return nil
	}

	var groups []constraint.GkrClaimGroup
	for wI := len(b.circuit) - 1; wI >= 0; wI-- {
		w := b.circuit[wI]
		var sources []constraint.GkrClaimSource
		switch {
		case w.IsInput():
			sources, _ = b.claimSources(wI)
			if mode == ConsolidateMultiClaimInputsOnly && len(sources) < 2 {
				continue
			}
		case mode == ConsolidateAll && (w.Exported || len(b.wireOutputs[wI]) == 0):
			sources = []constraint.GkrClaimSource{{Level: -1, OutgoingClaimIndex: 0}}
		default:
			continue
		}

		i := slices.IndexFunc(groups, func(g constraint.GkrClaimGroup) bool {
			return slices.Equal(g.ClaimSources, sources)
		})
		if i == -1 {
			groups = append(groups, constraint.GkrClaimGroup{ClaimSources: sources})
			i = len(groups) - 1
		}
		groups[i].Wires = append(groups[i].Wires, wI)
	}
	return groups
}

// newLevel0 builds level 0 from its claim groups: the empty GkrSkipLevel{} when there is nothing
// to consolidate, or the consolidated claims already share one point (one group, with a single
// source) and so have nothing to gain from a level of their own, a GkrSumcheckLevel otherwise.
func newLevel0(groups []constraint.GkrClaimGroup) constraint.GkrProvingLevel {
	if len(groups) == 0 || (len(groups) == 1 && len(groups[0].ClaimSources) == 1) {
		return &constraint.GkrSkipLevel{}
	}
	lvl := constraint.GkrSumcheckLevel(groups)
	return &lvl
}

// DefaultProvingSchedule generates a schedule that gives every input wire no level, and greedily
// batches non-input wires of matching degree and claim sources into shared levels. Level 0, always
// present, is the consolidation level, built per mode.
func DefaultProvingSchedule[G any](c gkr.Circuit[G], mode ConsolidationMode) (constraint.GkrProvingSchedule, error) {
	b := newScheduleBuilder(c)

	for b.firstUnprocessedWire >= 0 {
		highWI, readyWireClaimSources := b.nextReady()
		w := c[highWI]
		if w.IsInput() {
			b.markProcessed(highWI, -1)
			continue
		}

		// there is an actual "gate" in question
		// try and make a homogenous (same degree, same claims) batchWires
		batchWires, levelType := batchForWire(c, highWI, readyWireClaimSources)
		var err error
		switch levelType {
		case SkipLevel:
			err = b.addSkipLevel(batchWires)
		case SingleSourceZeroCheckLevel:
			err = b.addSingleSourceZeroCheckLevel(batchWires)
		default:
			batches := [][]int{batchWires}
			nbLevelWires := len(batchWires)
			for nbLevelWires < len(readyWireClaimSources) {
				newBatchHighWI := highWI - nbLevelWires
				if c[newBatchHighWI].IsInput() || c[newBatchHighWI].Gate.Degree != c[highWI].Gate.Degree {
					break
				}
				batchWires, levelType = batchForWire(c, newBatchHighWI, readyWireClaimSources[nbLevelWires:])
				if levelType != SumcheckLevel {
					break
				}
				batches = append(batches, batchWires)
				nbLevelWires += len(batchWires)
			}
			err = b.addSumcheckLevel(batches...)
		}
		if err != nil {
			return nil, err
		}
	}

	b.levels = append(b.levels, newLevel0(b.level0Groups(mode)))
	return b.finalize()
}
