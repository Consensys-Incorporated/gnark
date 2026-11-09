package selector_test

import (
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

type smallPartitionerCircuit struct {
	Pivot, In, WantLeft, WantRight frontend.Variable
}

func (c *smallPartitionerCircuit) Define(api frontend.API) error {
	for _, rightSide := range []bool{false, true} {
		empty := selector.Partition(api, 0, rightSide, nil)
		api.AssertIsEqual(len(empty), 0)
	}
	input := []frontend.Variable{c.In}
	api.AssertIsEqual(selector.Partition(api, c.Pivot, false, input)[0], c.WantLeft)
	api.AssertIsEqual(selector.Partition(api, c.Pivot, true, input)[0], c.WantRight)
	return nil
}

func TestPartitionSmallInputs(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&smallPartitionerCircuit{}, &smallPartitionerCircuit{
		Pivot: 0, In: 42, WantLeft: 0, WantRight: 42,
	})
	assert.ProverSucceeded(&smallPartitionerCircuit{}, &smallPartitionerCircuit{
		Pivot: 1, In: 42, WantLeft: 42, WantRight: 0,
	})
}
