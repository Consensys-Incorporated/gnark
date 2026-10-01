package uints

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// constFoldMixedCircuit chains compile-time constants with a witness operand
// so that both the folded and the lookup paths are exercised in one query
// chain: the leading constant pair folds, the witness operand forces a lookup
// and the trailing constant queries against a non-constant intermediate.
type constFoldMixedCircuit struct {
	In       U8
	Expected U8
	mode     int
}

func (c *constFoldMixedCircuit) Define(api frontend.API) error {
	uapi, err := NewBytes(api)
	if err != nil {
		return fmt.Errorf("NewBytes: %w", err)
	}
	var res U8
	switch c.mode {
	case 0:
		res = uapi.And(NewU8(0x3c), NewU8(0x5a), c.In, NewU8(0xf0))
	case 1:
		res = uapi.Or(NewU8(0x3c), NewU8(0x5a), c.In, NewU8(0xf0))
	case 2:
		res = uapi.Xor(NewU8(0x3c), NewU8(0x5a), c.In, NewU8(0xf0))
	}
	uapi.AssertIsEqual(res, c.Expected)
	return nil
}

func TestByteOpConstantFoldMixed(t *testing.T) {
	assert := test.NewAssert(t)
	in := uint8(0xa7)
	assert.Run(func(assert *test.Assert) {
		expected := 0x3c & 0x5a & in & 0xf0
		assert.CheckCircuit(&constFoldMixedCircuit{mode: 0}, test.WithValidAssignment(&constFoldMixedCircuit{In: NewU8(in), Expected: NewU8(expected)}))
		assert.CheckCircuit(&constFoldMixedCircuit{mode: 0}, test.WithInvalidAssignment(&constFoldMixedCircuit{In: NewU8(in), Expected: NewU8(expected ^ 1)}))
	}, "and")
	assert.Run(func(assert *test.Assert) {
		expected := 0x3c | 0x5a | in | 0xf0
		assert.CheckCircuit(&constFoldMixedCircuit{mode: 1}, test.WithValidAssignment(&constFoldMixedCircuit{In: NewU8(in), Expected: NewU8(expected)}))
		assert.CheckCircuit(&constFoldMixedCircuit{mode: 1}, test.WithInvalidAssignment(&constFoldMixedCircuit{In: NewU8(in), Expected: NewU8(expected ^ 1)}))
	}, "or")
	assert.Run(func(assert *test.Assert) {
		expected := 0x3c ^ 0x5a ^ in ^ 0xf0
		assert.CheckCircuit(&constFoldMixedCircuit{mode: 2}, test.WithValidAssignment(&constFoldMixedCircuit{In: NewU8(in), Expected: NewU8(expected)}))
		assert.CheckCircuit(&constFoldMixedCircuit{mode: 2}, test.WithInvalidAssignment(&constFoldMixedCircuit{In: NewU8(in), Expected: NewU8(expected ^ 1)}))
	}, "xor")
}

// constFoldOnlyCircuit performs byte operations exclusively on compile-time
// constants; with folding it must not emit any lookup query.
type constFoldOnlyCircuit struct {
	Dummy frontend.Variable
}

func (c *constFoldOnlyCircuit) Define(api frontend.API) error {
	uapi, err := NewBytes(api)
	if err != nil {
		return fmt.Errorf("NewBytes: %w", err)
	}
	and := uapi.And(NewU8(0x3c), NewU8(0x5a), NewU8(0xf0))
	or := uapi.Or(NewU8(0x3c), NewU8(0x5a), NewU8(0x0f))
	xor := uapi.Xor(NewU8(0x3c), NewU8(0x5a), NewU8(0xff))
	uapi.AssertIsEqual(and, NewU8(0x3c&0x5a&0xf0))
	uapi.AssertIsEqual(or, NewU8(0x3c|0x5a|0x0f))
	uapi.AssertIsEqual(xor, NewU8(0x3c^0x5a^0xff))
	return nil
}

// byteOpBaselineCircuit instantiates the same tables but performs no byte
// operations. Constant-only operations must not add constraints on top of it.
type byteOpBaselineCircuit struct {
	Dummy frontend.Variable
}

func (c *byteOpBaselineCircuit) Define(api frontend.API) error {
	if _, err := NewBytes(api); err != nil {
		return fmt.Errorf("NewBytes: %w", err)
	}
	return nil
}

func TestByteOpConstantFoldAddsNoConstraints(t *testing.T) {
	assert := test.NewAssert(t)
	folded, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &constFoldOnlyCircuit{})
	assert.NoError(err)
	baseline, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &byteOpBaselineCircuit{})
	assert.NoError(err)
	assert.Equal(baseline.GetNbConstraints(), folded.GetNbConstraints(), "constant-only byte operations added constraints")
}
