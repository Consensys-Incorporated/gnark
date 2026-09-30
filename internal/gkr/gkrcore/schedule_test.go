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
	schedule, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)

	// SingleMulGateCircuit: wires 0, 1 (inputs), 2 (mul gate with inputs 0, 1).
	// UniqueGateInputs for level 2 (wire 2) = [0, 1].
	// 3 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: input wire 0, position 0 in mul gate's UniqueGateInputs [0, 1]
		&constraint.GkrSkipLevel{Wires: []int{0}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		// Level 1: input wire 1, position 1 in mul gate's UniqueGateInputs [0, 1]
		&constraint.GkrSkipLevel{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		// Level 2: mul gate output, claimed by initial challenge (sentinel)
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},
	}, schedule)
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
	_, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)
}

func TestDefaultProvingSchedulePoseidon2(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.Poseidon2Circuit(4, 2))
	schedule, err := gkrcore.DefaultProvingSchedule(c)
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
	// 17 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: input wire 0 — claimed by level 2 (full-round 0 lin1+lin0 skip).
		&constraint.GkrSkipLevel{Wires: []int{0}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},

		// Level 1: input wire 1 — claimed by level 2 and level 16 (feed-forward skip).
		// Multiple claim sources → sumcheck (evaluates multilin once instead of twice).
		&constraint.GkrSumcheckLevel{{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}, {Level: 16}}}},

		// Level 2: full-round 0 lin1+lin0 (skip, inputs from wires 0 and 1).
		&constraint.GkrSkipLevel{Wires: []int{3, 2}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},

		// Level 3: full-round 0 sBox1+sBox0 (single-source zero-check, degree > 1).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{5, 4}, ClaimSources: []constraint.GkrClaimSource{{Level: 4}}},

		// Level 4: full-round 1 lin1+lin0 (skip, inputs [4, 5]).
		&constraint.GkrSkipLevel{Wires: []int{7, 6}, ClaimSources: []constraint.GkrClaimSource{{Level: 5}}},

		// Level 5: full-round 1 sBox1+sBox0 (sumcheck, inputs lin1=7 and lin0=6).
		//   Feeds into level 6 (partial-round 0 lin0) and level 7 (partial-round 0 lin1).
		&constraint.GkrSumcheckLevel{{Wires: []int{9, 8}, ClaimSources: []constraint.GkrClaimSource{{Level: 6}, {Level: 7}}}},

		// Level 6: partial-round 0 lin0 (skip, inputs [8, 9]).
		&constraint.GkrSkipLevel{Wires: []int{10}, ClaimSources: []constraint.GkrClaimSource{{Level: 8}}},

		// Level 7: partial-round 0 lin1 (sumcheck, inputs [8, 9]). Two claim sources → sumcheck to avoid claim blowup.
		&constraint.GkrSumcheckLevel{{Wires: []int{11}, ClaimSources: []constraint.GkrClaimSource{{Level: 9}, {Level: 10}}}},

		// Level 8: partial-round 0 sBox0 (sumcheck, input lin0=10).
		&constraint.GkrSumcheckLevel{{Wires: []int{12}, ClaimSources: []constraint.GkrClaimSource{{Level: 9}, {Level: 10}}}},

		// Level 9: partial-round 1 lin0 (skip, inputs [12, 11]).
		&constraint.GkrSkipLevel{Wires: []int{13}, ClaimSources: []constraint.GkrClaimSource{{Level: 11}}},

		// Level 10: partial-round 1 lin1 (skip, inputs [12, 11]).
		&constraint.GkrSkipLevel{Wires: []int{14}, ClaimSources: []constraint.GkrClaimSource{{Level: 12}}},

		// Level 11: partial-round 1 sBox0 (single-source zero-check, input lin0=13).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{15}, ClaimSources: []constraint.GkrClaimSource{{Level: 12}}},

		// Level 12: full-round 2 lin1+lin0 (skip, inputs [15, 14]).
		&constraint.GkrSkipLevel{Wires: []int{17, 16}, ClaimSources: []constraint.GkrClaimSource{{Level: 13}}},

		// Level 13: full-round 2 sBox1+sBox0 (single-source zero-check, inputs lin1=17 and lin0=16).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{19, 18}, ClaimSources: []constraint.GkrClaimSource{{Level: 14}}},

		// Level 14: full-round 3 lin1+lin0 (skip, inputs [18, 19]).
		&constraint.GkrSkipLevel{Wires: []int{21, 20}, ClaimSources: []constraint.GkrClaimSource{{Level: 15}}},

		// Level 15: full-round 3 sBox1+sBox0 (single-source zero-check, inputs lin1=21 and lin0=20).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{23, 22}, ClaimSources: []constraint.GkrClaimSource{{Level: 16}}},

		// Level 16: feed-forward output (skip, inputs [22, 23, 1]). Claimed by initial challenge (17).
		&constraint.GkrSkipLevel{Wires: []int{24}, ClaimSources: []constraint.GkrClaimSource{{Level: 17}}},
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
	// Both inputs are claimed by exactly the round gate and the final gate (schedule levels 1 and 2),
	// so they have identical claim sources and share a single claim group in one sumcheck level.
	_, c := scheduleTestCache.Compile(t, gkrtesting.MiMCCircuit(2))
	schedule, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)

	// 3 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: both input wires 0 and 1, batched into one sumcheck level (identical claim sources).
		&constraint.GkrSumcheckLevel{{Wires: []int{1, 0}, ClaimSources: []constraint.GkrClaimSource{{Level: 1}, {Level: 2}}}},

		// Levels 1–2: the gates, each single-source zero-check (degree 3 > 1).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{3}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},
	}, schedule)
}

// TestDefaultProvingScheduleMiMCDepth3 pins the depth-3 schedule, where the two inputs NO LONGER share
// identical claim sources: the key (wire 0) is claimed by both rounds and the final gate, while the
// state (wire 1) is claimed only by the first round and the final gate. Their claim sources differ,
// so they form two separate claim groups — but the scheduler bunches them into a SINGLE
// GkrSumcheckLevel (one sumcheck invocation) rather than two separate levels.
func TestDefaultProvingScheduleMiMCDepth3(t *testing.T) {
	// Wire layout for MiMCCircuit(3) — 5 wires total (numRounds=3 total rounds: 2 non-final + final):
	//   0, 1   inputs (0 = key → round1 + round2 + final; 1 = state → round1 + final)
	//   2      round 1: mimcGate(0, 1)
	//   3      round 2: mimcGate(0, 2)
	//   4      final:   mimcLastGate(0, 3, 1)
	_, c := scheduleTestCache.Compile(t, gkrtesting.MiMCCircuit(3))
	schedule, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)

	// 4 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: both inputs bunched into one sumcheck level as two claim groups (sources differ).
		//   state wire 1 — claimed by round1 (level 1) and final (level 3).
		//   key wire 0 — claimed by round1 (level 1), round2 (level 2) and final (level 3).
		&constraint.GkrSumcheckLevel{
			{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 1}, {Level: 3}}},
			{Wires: []int{0}, ClaimSources: []constraint.GkrClaimSource{{Level: 1}, {Level: 2}, {Level: 3}}},
		},

		// Levels 1–3: the gates, each single-source zero-check (degree 3 > 1).
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{3}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},
		&constraint.GkrSingleSourceZeroCheckLevel{Wires: []int{4}, ClaimSources: []constraint.GkrClaimSource{{Level: 4}}},
	}, schedule)
}
