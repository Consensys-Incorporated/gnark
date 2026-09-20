package kvstore_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/test"
)

type ctxKey[T comparable] struct{}
type toStore[T comparable] struct {
	Value T
}

type Circuit[T comparable] struct {
	A frontend.Variable
}

func (c *Circuit[T]) Define(api frontend.API) error {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("builder should implement key-value store")
	}
	stored1 := kv.GetKeyValue(ctxKey[T]{})
	if stored1 != nil {
		// should be nil
		return fmt.Errorf("expected nil, got %v", stored1)
	}
	if tStored1, ok := stored1.(*toStore[T]); ok {
		// should be nil interface
		return fmt.Errorf("expected nil, got %v", tStored1)
	}
	// store something
	var t T
	stored2 := &toStore[T]{Value: t}
	kv.SetKeyValue(ctxKey[T]{}, stored2)
	stored3 := kv.GetKeyValue(ctxKey[T]{})
	if stored3 == nil {
		return fmt.Errorf("expected non nil, got nil")
	}
	tStored3, ok := stored3.(*toStore[T])
	if !ok {
		return fmt.Errorf("expected toStore[T], got %T", stored3)
	}
	if tStored3.Value != t {
		return fmt.Errorf("expected %v, got %v", t, tStored3.Value)
	}
	return nil
}

func TestKeyValue(t *testing.T) {
	assert := test.NewAssert(t)
	// test with int
	err := test.IsSolved(&Circuit[int]{}, &Circuit[int]{A: 1}, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test with uint
	err = test.IsSolved(&Circuit[uint]{}, &Circuit[uint]{A: 1}, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test with string
	err = test.IsSolved(&Circuit[string]{}, &Circuit[string]{A: "1234"}, ecc.BN254.ScalarField())
	assert.NoError(err)

	// test during compilation; the circuit exercises the key-value store and
	// never constrains its input.
	_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit[int]{}, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
	_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Circuit[int]{}, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}
