// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package test

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/widecommitter"
	gnarkio "github.com/consensys/gnark/io"
	"github.com/stretchr/testify/require"
)

var (
	ErrCompilationNotDeterministic = errors.New("compilation is not deterministic")
	ErrInvalidWitnessSolvedCS      = errors.New("invalid witness solved the constraint system")
	ErrInvalidWitnessVerified      = errors.New("invalid witness resulted in a valid proof")
)

// getUnexportedField uses unsafe to access an unexported struct field.
// Returns an invalid Value if the field is not addressable.
func getUnexportedField(v reflect.Value, i int) reflect.Value {
	field := v.Field(i)
	if !field.CanAddr() {
		return reflect.Value{} // Return invalid value if not addressable
	}
	// Use unsafe to bypass the exported field check
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

// deepEqualMismatch finds the first mismatch between two values using reflection.
// It returns the path to the mismatch and string representations of the differing values.
// If the values are equal, it returns empty strings.
func deepEqualMismatch(a, b interface{}) (path string, aVal string, bVal string) {
	return deepEqualMismatchValue(reflect.ValueOf(a), reflect.ValueOf(b), "")
}

func deepEqualMismatchValue(a, b reflect.Value, path string) (string, string, string) {
	// Handle invalid values
	if !a.IsValid() && !b.IsValid() {
		return "", "", ""
	}
	if !a.IsValid() || !b.IsValid() {
		return path, fmt.Sprintf("%v", a), fmt.Sprintf("%v", b)
	}

	// Types must match
	if a.Type() != b.Type() {
		return path, fmt.Sprintf("type %v", a.Type()), fmt.Sprintf("type %v", b.Type())
	}

	// Use DeepEqual as oracle - if equal, no need to recurse
	if a.CanInterface() && b.CanInterface() {
		if reflect.DeepEqual(a.Interface(), b.Interface()) {
			return "", "", ""
		}
	}

	// At this point, we know there's a mismatch at or below this path.
	// Try to find a more specific path; if we can't, return this path.
	bestPath := path
	if bestPath == "" {
		bestPath = fmt.Sprintf("(%v)", a.Type())
	}

	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() && b.IsNil() {
			return "", "", ""
		}
		if a.IsNil() || b.IsNil() {
			return path, fmt.Sprintf("%v", a), fmt.Sprintf("%v", b)
		}
		if p, av, bv := deepEqualMismatchValue(a.Elem(), b.Elem(), path); p != "" {
			return p, av, bv
		}
		return bestPath, "(pointer contents differ)", "(pointer contents differ)"

	case reflect.Interface:
		if a.IsNil() && b.IsNil() {
			return "", "", ""
		}
		if a.IsNil() || b.IsNil() {
			return path, fmt.Sprintf("%v", a), fmt.Sprintf("%v", b)
		}
		if p, av, bv := deepEqualMismatchValue(a.Elem(), b.Elem(), path); p != "" {
			return p, av, bv
		}
		return bestPath, "(interface contents differ)", "(interface contents differ)"

	case reflect.Struct:
		for i := range a.NumField() {
			field := a.Type().Field(i)
			fieldName := field.Name
			fieldPath := path + "." + fieldName
			if path == "" {
				fieldPath = fieldName
			}

			var aField, bField reflect.Value
			if field.IsExported() {
				aField, bField = a.Field(i), b.Field(i)
			} else {
				aField, bField = getUnexportedField(a, i), getUnexportedField(b, i)
				if !aField.IsValid() || !bField.IsValid() {
					continue
				}
			}

			if p, av, bv := deepEqualMismatchValue(aField, bField, fieldPath); p != "" {
				return p, av, bv
			}
		}
		// Couldn't find specific field - return best path
		return bestPath, "(struct differs)", "(struct differs)"

	case reflect.Slice, reflect.Array:
		if a.Kind() == reflect.Slice && a.IsNil() && b.IsNil() {
			return "", "", ""
		}
		if a.Kind() == reflect.Slice && (a.IsNil() || b.IsNil()) {
			return path, fmt.Sprintf("nil=%v len=%d", a.IsNil(), a.Len()), fmt.Sprintf("nil=%v len=%d", b.IsNil(), b.Len())
		}
		if a.Len() != b.Len() {
			return path, fmt.Sprintf("len=%d", a.Len()), fmt.Sprintf("len=%d", b.Len())
		}
		for i := 0; i < a.Len(); i++ {
			elem := a.Index(i)
			elemType := ""
			// For interface elements, show the concrete type
			if elem.Kind() == reflect.Interface && !elem.IsNil() {
				elemType = fmt.Sprintf("(%v)", elem.Elem().Type())
			}
			elemPath := fmt.Sprintf("%s[%d]%s", path, i, elemType)
			if p, av, bv := deepEqualMismatchValue(a.Index(i), b.Index(i), elemPath); p != "" {
				return p, av, bv
			}
		}
		return bestPath, "(slice/array differs)", "(slice/array differs)"

	case reflect.Map:
		if a.IsNil() && b.IsNil() {
			return "", "", ""
		}
		if a.IsNil() || b.IsNil() {
			return path, fmt.Sprintf("nil=%v", a.IsNil()), fmt.Sprintf("nil=%v", b.IsNil())
		}
		if a.Len() != b.Len() {
			return path, fmt.Sprintf("len=%d", a.Len()), fmt.Sprintf("len=%d", b.Len())
		}
		for _, key := range a.MapKeys() {
			aVal := a.MapIndex(key)
			bVal := b.MapIndex(key)
			if !bVal.IsValid() {
				return fmt.Sprintf("%s[%v]", path, key), "exists", "missing"
			}
			keyPath := fmt.Sprintf("%s[%v]", path, key)
			if p, av, bv := deepEqualMismatchValue(aVal, bVal, keyPath); p != "" {
				return p, av, bv
			}
		}
		return bestPath, "(map differs)", "(map differs)"

	case reflect.Func:
		if a.IsNil() && b.IsNil() {
			return "", "", ""
		}
		// Use DeepEqual for functions - it compares closure state, not just code pointer
		if a.CanInterface() && b.CanInterface() {
			if !reflect.DeepEqual(a.Interface(), b.Interface()) {
				return path, fmt.Sprintf("func@%p", a.UnsafePointer()), fmt.Sprintf("func@%p", b.UnsafePointer())
			}
		} else if a.Pointer() != b.Pointer() {
			// Fallback to pointer comparison if can't interface
			return path, fmt.Sprintf("func@%p", a.UnsafePointer()), fmt.Sprintf("func@%p", b.UnsafePointer())
		}
		return "", "", ""

	case reflect.Chan, reflect.UnsafePointer:
		if a.Pointer() != b.Pointer() {
			return path, fmt.Sprintf("%p", a.UnsafePointer()), fmt.Sprintf("%p", b.UnsafePointer())
		}
		return "", "", ""

	default:
		// Leaf node that differs
		if a.CanInterface() && b.CanInterface() {
			return bestPath, fmt.Sprintf("%v", a.Interface()), fmt.Sprintf("%v", b.Interface())
		}
		return bestPath, "(unexported)", "(unexported)"
	}
}

// Assert is a helper to test circuits
type Assert struct {
	t *testing.T
	b *testing.B
	*require.Assertions
}

// NewAssert returns an Assert helper embedding a testify/require object for convenience.
// It accepts either a *testing.T or *testing.B object.
//
// The Assert object caches the compiled circuit. This means that the first call
// to [Assert.CheckCircuit] will compile the circuit for n curves, m
// backends and subsequent calls will re-use the result of the compilation, if
// available. Be careful when benchmarking!
func NewAssert(tb testing.TB) *Assert {
	switch t := (tb).(type) {
	case *testing.T:
		return &Assert{t: t, Assertions: require.New(t)}
	case *testing.B:
		return &Assert{b: t, Assertions: require.New(t)}
	default:
		panic("unknown testing type")
	}
}

// Run runs the test function fn as a subtest. The subtest is parametrized by
// the description strings descs.
func (assert *Assert) Run(fn func(assert *Assert), descs ...string) {
	desc := strings.Join(descs, "/")
	if assert.b != nil {
		assert.b.Run(desc, func(b *testing.B) {
			assert := &Assert{b: b, Assertions: require.New(b)}
			fn(assert)
		})
	} else {
		assert.t.Run(desc, func(t *testing.T) {
			assert := &Assert{t: t, Assertions: require.New(t)}
			fn(assert)
		})
	}
}

// Log logs using the test instance logger.
func (assert *Assert) Log(v ...interface{}) {
	if assert.b != nil {
		assert.b.Log(v...)
		return
	} else {
		assert.t.Log(v...)
	}
}

// ProverSucceeded is deprecated: use [Assert.CheckCircuit] instead
func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validAssignment frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+2)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithValidAssignment(validAssignment))

	assert.CheckCircuit(circuit, newOpts...)
}

// ProverFailed is deprecated use [Assert.CheckCircuit] instead
func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidAssignment frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+2)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithInvalidAssignment(invalidAssignment))

	assert.CheckCircuit(circuit, newOpts...)
}

// SolvingSucceeded is deprecated: use [Assert.CheckCircuit] instead
func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...TestingOption) {

	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+1)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithValidAssignment(validWitness))

	assert.CheckCircuit(circuit, newOpts...)
}

// SolvingFailed is deprecated: use CheckCircuit instead
func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+1)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithInvalidAssignment(invalidWitness))

	assert.CheckCircuit(circuit, newOpts...)
}

func lazySchema(field *big.Int, circuit frontend.Circuit) func() *schema.Schema {
	return func() *schema.Schema {
		// we only parse the schema if we need to display the witness in json.
		s, err := schema.New(field, circuit, tVariable)
		if err != nil {
			panic("couldn't parse schema from circuit: " + err.Error())
		}
		return s
	}
}

// compile the given circuit for given curve and backend, if not already present in cache
func (assert *Assert) compile(circuit frontend.Circuit, field *big.Int, backendID backend.ID, compileOpts []frontend.CompileOption) (constraint.ConstraintSystem, error) {
	var newBuilder frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newBuilder = r1cs.NewBuilder
	case backend.PLONK:
		newBuilder = scs.NewBuilder
	default:
		panic("not implemented")
	}

	// else compile it and ensure it is deterministic
	ccs, err := frontend.Compile(field, newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.Compile(field, newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompilationNotDeterministic, err)
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		path, aVal, bVal := deepEqualMismatch(ccs, _ccs)
		if path != "" {
			return nil, fmt.Errorf("%w: mismatch at %s: first=%s, second=%s", ErrCompilationNotDeterministic, path, aVal, bVal)
		}
		// Debug: show types
		return nil, fmt.Errorf("%w (type: %T, could not determine path)", ErrCompilationNotDeterministic, ccs)
	}

	return ccs, nil
}

func (assert *Assert) compileU32(circuit frontend.Circuit, field *big.Int, compileOpts []frontend.CompileOption) (constraint.ConstraintSystemU32, error) {
	newBuilder := widecommitter.From(scs.NewBuilder)
	// else compile it and ensure it is deterministic
	ccs, err := frontend.CompileU32(field, newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.CompileU32(field, newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompilationNotDeterministic, err)
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		path, aVal, bVal := deepEqualMismatch(ccs, _ccs)
		if path != "" {
			return nil, fmt.Errorf("%w: mismatch at %s: first=%s, second=%s", ErrCompilationNotDeterministic, path, aVal, bVal)
		}
		return nil, fmt.Errorf("%w (type: %T, could not determine path)", ErrCompilationNotDeterministic, ccs)
	}

	return ccs, nil
}

// error ensure the error is set, else fails the test
// add a witness to the error message if provided
func (assert *Assert) error(field *big.Int, err error, w *_witness) {
	if err != nil {
		return
	}
	json := "<nil>"
	if w != nil {
		bjson, err := w.full.ToJSON(lazySchema(field, w.assignment)())
		if err != nil {
			json = err.Error()
		} else {
			json = string(bjson)
		}
	}

	e := fmt.Errorf("did not error (but should have)\nwitness:%s", json)
	assert.FailNow(e.Error())
}

// ensure the error is nil, else fails the test
// add a witness to the error message if provided
func (assert *Assert) noError(field *big.Int, err error, w *_witness) {
	if err == nil {
		return
	}

	e := err

	if w != nil {
		var json string
		bjson, err := w.full.ToJSON(lazySchema(field, w.assignment)())
		if err != nil {
			json = err.Error()
		} else {
			json = string(bjson)
		}
		e = fmt.Errorf("%w\nwitness:%s", e, json)
	}

	assert.FailNow(e.Error())
}

func (assert *Assert) marshalWitnessJSON(w witness.Witness, s *schema.Schema, field *big.Int, publicOnly bool) {
	var err error
	if publicOnly {
		w, err = w.Public()
		assert.NoError(err)
	}

	// serialize the vector to binary
	data, err := w.ToJSON(s)
	assert.NoError(err)

	// re-read
	witness, err := witness.New(field)
	assert.NoError(err)
	err = witness.FromJSON(s, data)
	assert.NoError(err)

	witnessMatch := reflect.DeepEqual(w, witness)
	assert.True(witnessMatch, "round trip marshaling failed")
}

func (assert *Assert) roundTripCheck(from any, builder func() any, descs ...string) {
	assert.Run(func(assert *Assert) {
		assert.NoError(gnarkio.RoundTripCheck(from, builder))
	}, descs...)
}
