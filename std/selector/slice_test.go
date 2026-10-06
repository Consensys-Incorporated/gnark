package selector_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
	"github.com/consensys/gnark/test"
)

type partitionerCircuit struct {
	Pivot     frontend.Variable    `gnark:",public"`
	In        [6]frontend.Variable `gnark:",public"`
	WantLeft  [6]frontend.Variable `gnark:",public"`
	WantRight [6]frontend.Variable `gnark:",public"`
}

func (c *partitionerCircuit) Define(api frontend.API) error {
	gotLeft := selector.Partition(api, c.Pivot, false, c.In[:])
	for i, want := range c.WantLeft {
		api.AssertIsEqual(gotLeft[i], want)
	}

	gotRight := selector.Partition(api, c.Pivot, true, c.In[:])
	for i, want := range c.WantRight {
		api.AssertIsEqual(gotRight[i], want)
	}

	return nil
}

type ignoredOutputPartitionerCircuit struct {
	Pivot frontend.Variable    `gnark:",public"`
	In    [2]frontend.Variable `gnark:",public"`
}

func (c *ignoredOutputPartitionerCircuit) Define(api frontend.API) error {
	_ = selector.Partition(api, c.Pivot, false, c.In[:])
	_ = selector.Partition(api, c.Pivot, true, c.In[:])
	return nil
}

func TestPartition(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     3,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 0, 0, 0},
		WantRight: [6]frontend.Variable{0, 0, 0, 40, 50, 60},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     1,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 0, 0, 0, 0, 0},
		WantRight: [6]frontend.Variable{0, 20, 30, 40, 50, 60},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     5,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 50, 0},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 60},
	})

	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     5,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 0, 0},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 0},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     6,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 0},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     0,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{0, 0, 0, 0, 0, 0},
		WantRight: [6]frontend.Variable{10, 20, 30, 40, 50, 60},
	})

	// Pivot is outside and the prover fails:
	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     7,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 0},
	})

	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     -1,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{0, 0, 0, 0, 0, 0},
		WantRight: [6]frontend.Variable{10, 20, 30, 40, 50, 60},
	})

	// tests by ignoring the output:
	assert.ProverSucceeded(&ignoredOutputPartitionerCircuit{}, &ignoredOutputPartitionerCircuit{
		Pivot: 1,
		In:    [2]frontend.Variable{10, 20},
	})

	assert.ProverFailed(&ignoredOutputPartitionerCircuit{}, &ignoredOutputPartitionerCircuit{
		Pivot: -1,
		In:    [2]frontend.Variable{10, 20},
	})

	assert.ProverFailed(&ignoredOutputPartitionerCircuit{}, &ignoredOutputPartitionerCircuit{
		Pivot: 3,
		In:    [2]frontend.Variable{10, 20},
	})
}

type slicerCircuit struct {
	Start, End frontend.Variable    `gnark:",public"`
	In         [7]frontend.Variable `gnark:",public"`
	WantSlice  [7]frontend.Variable `gnark:",public"`
}

func (c *slicerCircuit) Define(api frontend.API) error {
	gotSlice := selector.Slice(api, c.Start, c.End, c.In[:])
	for i, want := range c.WantSlice {
		api.AssertIsEqual(gotSlice[i], want)
	}
	return nil
}

func TestSlice(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     2,
		End:       5,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 2, 3, 4, 0, 0},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     3,
		End:       4,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 0, 3, 0, 0, 0},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     3,
		End:       3,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 0, 0, 0, 0, 0},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     3,
		End:       1,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 0, 0, 0, 0, 0},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     3,
		End:       6,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 0, 3, 4, 5, 0},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     3,
		End:       7,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 0, 3, 4, 5, 6},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     0,
		End:       2,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 1, 0, 0, 0, 0, 0},
	})

	assert.ProverSucceeded(&slicerCircuit{}, &slicerCircuit{
		Start:     0,
		End:       7,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
	})

	assert.ProverFailed(&slicerCircuit{}, &slicerCircuit{
		Start:     3,
		End:       8,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 0, 0, 3, 4, 5, 6},
	})

	assert.ProverFailed(&slicerCircuit{}, &slicerCircuit{
		Start:     -1,
		End:       2,
		In:        [7]frontend.Variable{0, 1, 2, 3, 4, 5, 6},
		WantSlice: [7]frontend.Variable{0, 1, 0, 0, 0, 0, 0},
	})
}

// oneElementPartitionerCircuit partitions a single-element input array. The
// documented contract of Partition only requires 0 <= pivotPosition <=
// len(input), so pivotPosition is either 0 or 1 here.
type oneElementPartitionerCircuit struct {
	Pivot     frontend.Variable `gnark:",public"`
	In        frontend.Variable `gnark:",public"`
	WantLeft  frontend.Variable `gnark:",public"`
	WantRight frontend.Variable `gnark:",public"`
}

func (c *oneElementPartitionerCircuit) Define(api frontend.API) error {
	gotLeft := selector.Partition(api, c.Pivot, false, []frontend.Variable{c.In})
	if len(gotLeft) != 1 {
		return fmt.Errorf("Partition returned %d outputs for a 1-element input, expected 1", len(gotLeft))
	}
	api.AssertIsEqual(gotLeft[0], c.WantLeft)

	gotRight := selector.Partition(api, c.Pivot, true, []frontend.Variable{c.In})
	if len(gotRight) != 1 {
		return fmt.Errorf("Partition returned %d outputs for a 1-element input, expected 1", len(gotRight))
	}
	api.AssertIsEqual(gotRight[0], c.WantRight)

	return nil
}

// emptyPartitionerCircuit partitions an empty input array. The only pivot
// position inside [0, len(input)] is 0.
type emptyPartitionerCircuit struct {
	Pivot frontend.Variable `gnark:",public"`
}

func (c *emptyPartitionerCircuit) Define(api frontend.API) error {
	gotLeft := selector.Partition(api, c.Pivot, false, []frontend.Variable{})
	if len(gotLeft) != 0 {
		return fmt.Errorf("Partition returned %d outputs for an empty input, expected 0", len(gotLeft))
	}

	gotRight := selector.Partition(api, c.Pivot, true, []frontend.Variable{})
	if len(gotRight) != 0 {
		return fmt.Errorf("Partition returned %d outputs for an empty input, expected 0", len(gotRight))
	}

	return nil
}

func TestPartitionSmallInputs(t *testing.T) {
	assert := test.NewAssert(t)

	// len(input) == 1: pivotPosition == 0 keeps the element on the right side.
	assert.ProverSucceeded(&oneElementPartitionerCircuit{}, &oneElementPartitionerCircuit{
		Pivot:     0,
		In:        42,
		WantLeft:  0,
		WantRight: 42,
	})

	// len(input) == 1: pivotPosition == 1 keeps the element on the left side.
	assert.ProverSucceeded(&oneElementPartitionerCircuit{}, &oneElementPartitionerCircuit{
		Pivot:     1,
		In:        42,
		WantLeft:  42,
		WantRight: 0,
	})

	// pivotPosition is outside [0, len(input)]:
	assert.ProverFailed(&oneElementPartitionerCircuit{}, &oneElementPartitionerCircuit{
		Pivot:     2,
		In:        42,
		WantLeft:  42,
		WantRight: 0,
	})

	assert.ProverFailed(&oneElementPartitionerCircuit{}, &oneElementPartitionerCircuit{
		Pivot:     -1,
		In:        42,
		WantLeft:  0,
		WantRight: 42,
	})

	// len(input) == 0: the only valid pivotPosition is 0.
	assert.ProverSucceeded(&emptyPartitionerCircuit{}, &emptyPartitionerCircuit{Pivot: 0})

	assert.ProverFailed(&emptyPartitionerCircuit{}, &emptyPartitionerCircuit{Pivot: 1})
}

// oneElementSlicerCircuit slices a single-element input array.
type oneElementSlicerCircuit struct {
	Start, End frontend.Variable `gnark:",public"`
	In         frontend.Variable `gnark:",public"`
	WantSlice  frontend.Variable `gnark:",public"`
}

func (c *oneElementSlicerCircuit) Define(api frontend.API) error {
	gotSlice := selector.Slice(api, c.Start, c.End, []frontend.Variable{c.In})
	if len(gotSlice) != 1 {
		return fmt.Errorf("Slice returned %d outputs for a 1-element input, expected 1", len(gotSlice))
	}
	api.AssertIsEqual(gotSlice[0], c.WantSlice)

	return nil
}

// emptySlicerCircuit slices an empty input array.
type emptySlicerCircuit struct {
	Start, End frontend.Variable `gnark:",public"`
}

func (c *emptySlicerCircuit) Define(api frontend.API) error {
	gotSlice := selector.Slice(api, c.Start, c.End, []frontend.Variable{})
	if len(gotSlice) != 0 {
		return fmt.Errorf("Slice returned %d outputs for an empty input, expected 0", len(gotSlice))
	}

	return nil
}

func TestSliceSmallInputs(t *testing.T) {
	assert := test.NewAssert(t)

	// len(input) == 1: [0, 1) selects the only element, every other valid
	// range is empty.
	assert.ProverSucceeded(&oneElementSlicerCircuit{}, &oneElementSlicerCircuit{
		Start: 0, End: 1, In: 42, WantSlice: 42,
	})

	assert.ProverSucceeded(&oneElementSlicerCircuit{}, &oneElementSlicerCircuit{
		Start: 0, End: 0, In: 42, WantSlice: 0,
	})

	assert.ProverSucceeded(&oneElementSlicerCircuit{}, &oneElementSlicerCircuit{
		Start: 1, End: 1, In: 42, WantSlice: 0,
	})

	assert.ProverSucceeded(&oneElementSlicerCircuit{}, &oneElementSlicerCircuit{
		Start: 1, End: 0, In: 42, WantSlice: 0,
	})

	// start / end outside [0, len(input)]:
	assert.ProverFailed(&oneElementSlicerCircuit{}, &oneElementSlicerCircuit{
		Start: 2, End: 1, In: 42, WantSlice: 42,
	})

	assert.ProverFailed(&oneElementSlicerCircuit{}, &oneElementSlicerCircuit{
		Start: 0, End: 2, In: 42, WantSlice: 42,
	})

	// len(input) == 0: only start == end == 0 is valid.
	assert.ProverSucceeded(&emptySlicerCircuit{}, &emptySlicerCircuit{Start: 0, End: 0})

	assert.ProverFailed(&emptySlicerCircuit{}, &emptySlicerCircuit{Start: 1, End: 0})
}
