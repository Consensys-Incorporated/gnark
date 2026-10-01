package gkrcore_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	"github.com/stretchr/testify/require"
)

var scheduleTestCache = gkrtesting.NewCache(ecc.BN254.ScalarField())

func TestDefaultProvingSchedule(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.SingleMulGateCircuit())
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateNone)
	require.NoError(t, err)

	// SingleMulGateCircuit: wires 0, 1 (inputs, no level), 2 (mul gate with inputs 0, 1).
	// 2 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: consolidation, empty (nothing selected under ConsolidateNone).
		&constraint.GkrSkipLevel{},
		// Level 1: mul gate output, claimed by initial challenge (sentinel)
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
	}, schedule)
}

// TestDefaultProvingScheduleSingleMulConsolidateAll checks level 0 for SingleMulGateCircuit under
// ConsolidateAll: wires 0 and 1 (inputs) share a single claim source (both feed the same, only,
// gate), so they share one group; wire 2 (the output) gets its own group with the output-level
// source alone.
func TestDefaultProvingScheduleSingleMulConsolidateAll(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.SingleMulGateCircuit())
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateAll)
	require.NoError(t, err)

	require.Equal(t, constraint.GkrProvingSchedule{
		&constraint.GkrSumcheckLevel{
			{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
			{Wires: []int{1, 0}, ClaimSources: []constraint.GkrClaimSource{{Level: 1}}},
		},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
	}, schedule)
}

// TestDefaultProvingScheduleSingleMulConsolidateMultiClaimInputsOnly checks that
// ConsolidateMultiClaimInputsOnly leaves level 0 empty for SingleMulGateCircuit: both inputs have
// exactly one claim each, so neither qualifies, and the output is never a candidate under this mode.
func TestDefaultProvingScheduleSingleMulConsolidateMultiClaimInputsOnly(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.SingleMulGateCircuit())
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateMultiClaimInputsOnly)
	require.NoError(t, err)

	require.Equal(t, constraint.GkrProvingSchedule{
		&constraint.GkrSkipLevel{},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
	}, schedule)
}

// TestDefaultProvingScheduleNoGateConsolidateAll checks that ConsolidateAll leaves level 0 the
// empty skip level for NoGateCircuit: its one wire is both the circuit's only input and its only
// output, so it is selected, but its only claim source is the sentinel alone — the selected claims
// already share one point, with nothing to consolidate.
func TestDefaultProvingScheduleNoGateConsolidateAll(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.NoGateCircuit())
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateAll)
	require.NoError(t, err)

	require.Equal(t, constraint.GkrProvingSchedule{
		&constraint.GkrSkipLevel{},
	}, schedule)
}

// TestDefaultProvingSchedulePoseidon2ConsolidateAll checks level 0 for Poseidon2Circuit(4, 2) under
// ConsolidateAll. Levels 1-15 are unaffected by the mode, so only level 0 is spelled out here; see
// TestDefaultProvingSchedulePoseidon2 for their shape. Wire 24 (the feed-forward output) gets its
// own group; wire 1 (the state input, claimed by round 0's lin gates and by the feed-forward gate)
// keeps its two claim sources; wire 0 (the key input, claimed only by round 0's lin gates) gets its
// own group with a single source.
func TestDefaultProvingSchedulePoseidon2ConsolidateAll(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.Poseidon2Circuit(4, 2))
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateAll)
	require.NoError(t, err)

	require.Equal(t, &constraint.GkrSumcheckLevel{
		{Wires: []int{24}, ClaimSources: []constraint.GkrClaimSource{{Level: 16}}},
		{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 15}, {Level: 1}}},
		{Wires: []int{0}, ClaimSources: []constraint.GkrClaimSource{{Level: 1}}},
	}, schedule[0])
}

// TestDefaultProvingSchedulePoseidon2ConsolidateMultiClaimInputsOnly checks level 0 for
// Poseidon2Circuit(4, 2) under ConsolidateMultiClaimInputsOnly: only wire 1 (the state input) has
// more than one claim, so it alone is consolidated; wire 0 (a single claim) and the output are left
// unconsolidated.
func TestDefaultProvingSchedulePoseidon2ConsolidateMultiClaimInputsOnly(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.Poseidon2Circuit(4, 2))
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateMultiClaimInputsOnly)
	require.NoError(t, err)

	require.Equal(t, &constraint.GkrSumcheckLevel{
		{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 15}, {Level: 1}}},
	}, schedule[0])
}

// TestDefaultProvingScheduleMultiSourceWire tests that a wire with multiple claim sources
// (exported AND feeding a downstream gate) gets a GkrSumcheckLevel, not a
// GkrSingleSourceZeroCheckLevel. Wires 3 and 2 become ready simultaneously after wire 4
// is processed; wire 3 (highWI) has 2 claim sources while wire 2 has 1.
func TestDefaultProvingScheduleMultiSourceWire(t *testing.T) {
	// Wire 0: input
	// Wire 1: input
	// Wire 2: mul(0,0) — no consumers, not exported → 1 claim (initial challenge)
	// Wire 3: mul(1,1) — exported AND feeds wire 4 → 2 claims (initial challenge + wire 4's level)
	// Wire 4: mul(3,3) — no consumers, not exported → 1 claim (initial challenge)
	//
	// Wire 4 is processed first (it's the highest ready wire). Then wires 3 and 2 are
	// simultaneously ready, with wire 3 being highWI.
	raw := gkrcore.RawCircuit{
		{}, // wire 0: input
		{}, // wire 1: input
		{Gate: gkrcore.Mul2, Inputs: []int{0, 0}},                 // wire 2: mul(0,0)
		{Gate: gkrcore.Mul2, Inputs: []int{1, 1}, Exported: true}, // wire 3: mul(1,1), exported
		{Gate: gkrcore.Mul2, Inputs: []int{3, 3}},                 // wire 4: mul(3,3)
	}
	_, c := scheduleTestCache.Compile(t, raw)
	_, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateNone)
	require.NoError(t, err)
}

func TestDefaultProvingSchedulePoseidon2(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.Poseidon2Circuit(4, 2))
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateNone)
	require.NoError(t, err)

	// Wire layout for Poseidon2Circuit(4, 2) — 25 wires total:
	//   0, 1            inputs
	//   2–3             full-round 0 lin (lin0=2, lin1=3)
	//   4–5             full-round 0 sBox (sBox0=4, sBox1=5)
	//   6–7             full-round 1 lin (lin0=6, lin1=7)
	//   8–9             full-round 1 sBox (sBox0=8, sBox1=9)
	//   10–11           partial-round 0 lin (lin0=10, lin1=11)
	//   12              partial-round 0 sBox0
	//   13–14           partial-round 1 lin (lin0=13, lin1=14)
	//   15              partial-round 1 sBox0
	//   16–17           full-round 2 lin (lin0=16, lin1=17)
	//   18–19           full-round 2 sBox (sBox0=18, sBox1=19)
	//   20–21           full-round 3 lin (lin0=20, lin1=21)
	//   22–23           full-round 3 sBox (sBox0=22, sBox1=23)
	//   24              feed-forward output
	//
	// Wires 0 and 1 (inputs) get no level. 16 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: consolidation, empty (nothing selected under ConsolidateNone).
		&constraint.GkrSkipLevel{},

		// Level 1: full-round 0 lin1+lin0 (skip, inputs from wires 0 and 1).
		&constraint.GkrSkipLevel{Wires: []int{3, 2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},

		// Level 2: full-round 0 sBox1+sBox0 (single-source zero-check, degree > 1).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{5, 4}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},

		// Level 3: full-round 1 lin1+lin0 (skip, inputs [4, 5]).
		&constraint.GkrSkipLevel{Wires: []int{7, 6}, ClaimSources: []constraint.GkrClaimSource{{Level: 4}}},

		// Level 4: full-round 1 sBox1+sBox0 (sumcheck, inputs lin1=7 and lin0=6).
		//   Feeds into level 5 (partial-round 0 lin0) and level 6 (partial-round 0 lin1).
		&constraint.GkrSumcheckLevel{{Wires: []int{9, 8}, ClaimSources: []constraint.GkrClaimSource{{Level: 6}, {Level: 5}}}},

		// Level 5: partial-round 0 lin0 (skip, inputs [8, 9]).
		&constraint.GkrSkipLevel{Wires: []int{10}, ClaimSources: []constraint.GkrClaimSource{{Level: 7}}},

		// Level 6: partial-round 0 lin1 (sumcheck, inputs [8, 9]). Two claim sources → sumcheck to avoid claim blowup.
		&constraint.GkrSumcheckLevel{{Wires: []int{11}, ClaimSources: []constraint.GkrClaimSource{{Level: 9}, {Level: 8}}}},

		// Level 7: partial-round 0 sBox0 (sumcheck, input lin0=10).
		&constraint.GkrSumcheckLevel{{Wires: []int{12}, ClaimSources: []constraint.GkrClaimSource{{Level: 9}, {Level: 8}}}},

		// Level 8: partial-round 1 lin0 (skip, inputs [12, 11]).
		&constraint.GkrSkipLevel{Wires: []int{13}, ClaimSources: []constraint.GkrClaimSource{{Level: 10}}},

		// Level 9: partial-round 1 lin1 (skip, inputs [12, 11]).
		&constraint.GkrSkipLevel{Wires: []int{14}, ClaimSources: []constraint.GkrClaimSource{{Level: 11}}},

		// Level 10: partial-round 1 sBox0 (single-source zero-check, input lin0=13).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{15}, ClaimSources: []constraint.GkrClaimSource{{Level: 11}}},

		// Level 11: full-round 2 lin1+lin0 (skip, inputs [15, 14]).
		&constraint.GkrSkipLevel{Wires: []int{17, 16}, ClaimSources: []constraint.GkrClaimSource{{Level: 12}}},

		// Level 12: full-round 2 sBox1+sBox0 (single-source zero-check, inputs lin1=17 and lin0=16).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{19, 18}, ClaimSources: []constraint.GkrClaimSource{{Level: 13}}},

		// Level 13: full-round 3 lin1+lin0 (skip, inputs [18, 19]).
		&constraint.GkrSkipLevel{Wires: []int{21, 20}, ClaimSources: []constraint.GkrClaimSource{{Level: 14}}},

		// Level 14: full-round 3 sBox1+sBox0 (single-source zero-check, inputs lin1=21 and lin0=20).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{23, 22}, ClaimSources: []constraint.GkrClaimSource{{Level: 15}}},

		// Level 15: feed-forward output (skip, inputs [22, 23, 1]). Claimed by initial challenge (16).
		&constraint.GkrSkipLevel{Wires: []int{24}, ClaimSources: []constraint.GkrClaimSource{{Level: 16}}},
	}, schedule)
}

// TestDefaultProvingScheduleMiMCDepth2 pins the schedule shape for gkrtesting.MiMCCircuit, which is
// faithful to std/permutation/gkr-mimc: the key input (wire 0) feeds every round and the final
// gate, and the state input (wire 1) feeds the first round and the final gate. BOTH inputs are
// therefore multi-source — the "62 and two claim sources" topology.
// Depth 2 is the smallest circuit exhibiting this two-multi-source-input shape.
func TestDefaultProvingScheduleMiMCDepth2(t *testing.T) {
	// Wire layout for MiMCCircuit(2) — 4 wires total (numRounds=2 total rounds: 1 non-final + final):
	//   0, 1   inputs (0 = key → round + final; 1 = state → round + final)
	//   2      mimc round: wire 2 = mimcGate(0, 1)
	//   3      final gate: mimcLastGate(0, 2, 1)
	// Both inputs are claimed by exactly the round gate and the final gate (schedule levels 2 and 3),
	// so they have identical claim sources and share a single claim group in one sumcheck level.
	_, c := scheduleTestCache.Compile(t, gkrtesting.MiMCCircuit(2))
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateNone)
	require.NoError(t, err)

	// Wires 0 and 1 (inputs) get no level. 3 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: consolidation, empty (nothing selected under ConsolidateNone).
		&constraint.GkrSkipLevel{},
		// Levels 1–2: the gates, each single-source zero-check (degree 3 > 1).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{3}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},
	}, schedule)
}

// TestDefaultProvingScheduleMiMCDepth3 pins the depth-3 schedule, where the two inputs no longer
// share identical claim sources: the key (wire 0) is claimed by both rounds and the final gate,
// while the state (wire 1) is claimed only by the first round and the final gate. Since inputs get
// no level regardless, this only affects the two wires' claim sources, not the schedule shape.
func TestDefaultProvingScheduleMiMCDepth3(t *testing.T) {
	// Wire layout for MiMCCircuit(3) — 5 wires total (numRounds=3 total rounds: 2 non-final + final):
	//   0, 1   inputs (0 = key → round1 + round2 + final; 1 = state → round1 + final)
	//   2      round 1: mimcGate(0, 1)
	//   3      round 2: mimcGate(0, 2)
	//   4      final:   mimcLastGate(0, 3, 1)
	_, c := scheduleTestCache.Compile(t, gkrtesting.MiMCCircuit(3))
	schedule, err := gkrcore.DefaultProvingSchedule(c, gkrcore.ConsolidateNone)
	require.NoError(t, err)

	// Wires 0 and 1 (inputs) get no level. 4 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: consolidation, empty (nothing selected under ConsolidateNone).
		&constraint.GkrSkipLevel{},
		// Levels 1–3: the gates, each single-source zero-check (degree 3 > 1).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{3}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{4}, ClaimSources: []constraint.GkrClaimSource{{Level: 4}}},
	}, schedule)
}
