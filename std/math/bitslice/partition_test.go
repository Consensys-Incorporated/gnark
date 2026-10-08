package bitslice

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TODO: add option for choosing nbDigits

type partitionCircuit struct {
	Split                  uint
	In, ExpLower, ExpUpper frontend.Variable

	nbDigitsOpt int
}

func (c *partitionCircuit) Define(api frontend.API) error {
	var opts []Option
	if c.nbDigitsOpt > 0 {
		opts = append(opts, WithNbDigits(c.nbDigitsOpt))
	}
	lower, upper := Partition(api, c.In, c.Split, opts...)
	api.AssertIsEqual(lower, c.ExpLower)
	api.AssertIsEqual(upper, c.ExpUpper)
	return nil
}

func TestPartition(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&partitionCircuit{Split: 0}, test.WithValidAssignment(&partitionCircuit{Split: 0, ExpUpper: 0xffff1234, ExpLower: 0, In: 0xffff1234}))
	assert.CheckCircuit(&partitionCircuit{Split: 4}, test.WithValidAssignment(&partitionCircuit{Split: 4, ExpUpper: 0xffff123, ExpLower: 4, In: 0xffff1234}))
	assert.CheckCircuit(&partitionCircuit{Split: 16}, test.WithValidAssignment(&partitionCircuit{Split: 16, ExpUpper: 0xffff, ExpLower: 0x1234, In: 0xffff1234}))
	assert.CheckCircuit(&partitionCircuit{Split: 32}, test.WithValidAssignment(&partitionCircuit{Split: 32, ExpUpper: 0, ExpLower: 0xffff1234, In: 0xffff1234}))
}

func TestIssue1153(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&partitionCircuit{Split: 8, nbDigitsOpt: 16}, test.WithInvalidAssignment(&partitionCircuit{ExpUpper: 0xff1, ExpLower: 0x21, In: 0xff121}))
}

// TestPartitionOutOfRange checks that Partition stays well-defined when split is
// at or beyond the effective decomposition width, instead of panicking on a
// slice bound or feeding a negative width to the range checker.
func TestPartitionOutOfRange(t *testing.T) {
	assert := test.NewAssert(t)

	// No bound set: split larger than the field width must return (v, 0).
	assert.CheckCircuit(&partitionCircuit{Split: 300}, test.WithValidAssignment(&partitionCircuit{Split: 300, In: 0xffff1234, ExpLower: 0xffff1234, ExpUpper: 0}))

	// WithNbDigits set: split larger than nbDigits must return (v, 0).
	assert.CheckCircuit(&partitionCircuit{Split: 20, nbDigitsOpt: 16}, test.WithValidAssignment(&partitionCircuit{Split: 20, nbDigitsOpt: 16, In: 0x1234, ExpLower: 0x1234, ExpUpper: 0}))

	// The declared input bound is still enforced.
	assert.CheckCircuit(&partitionCircuit{Split: 20, nbDigitsOpt: 16}, test.WithInvalidAssignment(&partitionCircuit{Split: 20, nbDigitsOpt: 16, In: 0x1_2345, ExpLower: 0x1_2345, ExpUpper: 0}))
}
