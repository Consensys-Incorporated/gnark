// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package test

import (
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/bits-and-blooms/bitset"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/logger"
	"golang.org/x/crypto/sha3"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/pool"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/circuitdefer"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/internal/utils"
)

// engine implements frontend.API
//
// it is used for a faster verification of witness in tests
// and more importantly, for fuzzing purposes
//
// it converts the inputs to the API to big.Int (after a mod reduce using the curve base field)
type engine struct {
	curveID ecc.ID
	q       *big.Int // field modulus
	// mHintsFunctions map[hint.ID]hintFunction
	constVars bool
	// constant records which values are known to be constants. Constness is a
	// property of the value, so it cannot be answered by a single engine-wide flag:
	// a circuit can mix witness inputs and constants, and the compiler distinguishes
	// them.
	//
	// Absent means NON-constant, deliberately. Every operation that produces a value
	// must opt its result in, and there are around twenty-five of them. If one is
	// missed, the result degrades to non-constant, which is what master already
	// reports. The opposite default fails open: a witness-derived value that slipped
	// through an untracked operation would be announced as a constant, and callers
	// branch on that.
	constant map[*big.Int]struct{}
	kvstore.Store
	blueprints                []constraint.Blueprint
	internalVariables         []*big.Int
	noSmallFieldCompatibility bool
	hintMapping               map[solver.HintID]solver.Hint
}

// TestEngineOption defines an option for the test engine.
type TestEngineOption func(e *engine) error

// SetAllVariablesAsConstants is a test engine option which makes the calls to
// IsConstant() and ConstantValue() always return true. If this test engine
// option is not set, then all variables are considered as non-constant,
// regardless if it is constructed by a call to ConstantValue().
func SetAllVariablesAsConstants() TestEngineOption {
	return func(e *engine) error {
		e.constVars = true
		return nil
	}
}

// WithNoSmallFieldCompatibility prevents trying to make the test engine
// compatible with the different backends in case the circuit is compiled over
// a small field. Particularly, in the compatibility mode, the test engine
// would implement [frontend.WideCommitter] and [frontend.Rangechecker] interfaces.
// When this option is set, the test engine will not implement these interfaces.
//
// It is useful for checking edge cases.
func WithNoSmallFieldCompatibility() TestEngineOption {
	return func(e *engine) error {
		e.noSmallFieldCompatibility = true
		return nil
	}
}

// WithReplacementHint allows to replace a hint function in the test engine with
// a custom one, for a given hint ID. This is useful for testing edge cases,
// such as when the hint function returns incorrect values.
func WithReplacementHint(id solver.HintID, f solver.Hint) TestEngineOption {
	return func(e *engine) error {
		if e.hintMapping == nil {
			e.hintMapping = make(map[solver.HintID]solver.Hint)
		}
		// Later calls override earlier ones for the same hint ID, matching solver.OverrideHint behavior.
		e.hintMapping[id] = f
		return nil
	}
}

// IsSolved returns an error if the test execution engine failed to execute the given circuit
// with provided witness as input.
//
// The test execution engine implements frontend.API using big.Int operations.
//
// This is an experimental feature.
func IsSolved(circuit, witness frontend.Circuit, field *big.Int, opts ...TestEngineOption) (err error) {
	e := &engine{
		curveID:   utils.FieldToCurve(field),
		q:         new(big.Int).Set(field),
		constVars: false,
		constant:  make(map[*big.Int]struct{}),
		Store:     kvstore.New(),
	}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return fmt.Errorf("apply option: %w", err)
		}
	}

	// TODO handle opt.LoggerOut ?

	// we clone the circuit, in case the circuit has some attributes it uses in its Define function
	// set by the user.
	// then, we set all the variables values to the ones from the witness

	// clone the circuit
	c := shallowClone(circuit)

	// set the witness values
	e.copyWitness(c, witness)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, string(debug.Stack()))
		}
	}()

	log := logger.Logger()
	log.Debug().Msg("running circuit in test engine")
	cptAdd, cptMul, cptSub, cptToBinary, cptFromBinary, cptAssertIsEqual = 0, 0, 0, 0, 0, 0

	var apiEngine frontend.API
	if smallfields.IsSmallField(e.modulus()) && !e.noSmallFieldCompatibility {
		apiEngine = &smallfieldEngine{engine: e}
	} else {
		apiEngine = e
	}

	if err = c.Define(apiEngine); err != nil {
		return fmt.Errorf("define: %w", err)
	}
	if err = callDeferred(apiEngine); err != nil {
		return fmt.Errorf("deferred: %w", err)
	}

	log.Debug().Uint64("add", cptAdd).
		Uint64("sub", cptSub).
		Uint64("mul", cptMul).
		Uint64("equals", cptAssertIsEqual).
		Uint64("toBinary", cptToBinary).
		Uint64("fromBinary", cptFromBinary).Msg("counters")

	return
}

func callDeferred(builder frontend.API) error {
	// we get the compiler from the builder in case builder is already wrapped
	// and overwrites methods required in kvstore.Store (SetKeyValue and
	// GetKeyValue).
	//
	// However, as an API to the callbacks we still pass in the initial builder
	// as deferred methods may use wrapped methods (Commit, WideCommit).
	compiler := builder.Compiler()
	for i := 0; i < len(circuitdefer.GetAll[func(frontend.API) error](compiler)); i++ {
		if err := circuitdefer.GetAll[func(frontend.API) error](compiler)[i](builder); err != nil {
			return fmt.Errorf("defer fn %d: %w", i, err)
		}
	}
	return nil
}

var cptAdd, cptMul, cptSub, cptToBinary, cptFromBinary, cptAssertIsEqual uint64

func (e *engine) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	atomic.AddUint64(&cptAdd, 1)
	res := new(big.Int)
	res.Add(e.toBigInt(i1), e.toBigInt(i2))
	for i := 0; i < len(in); i++ {
		atomic.AddUint64(&cptAdd, 1)
		res.Add(res, e.toBigInt(in[i]))
	}
	res.Mod(res, e.modulus())
	return e.taint(res, append([]frontend.Variable{i1, i2}, in...)...)
}

func (e *engine) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	bc := pool.BigInt.Get()
	bc.Mul(e.toBigInt(b), e.toBigInt(c))

	res := new(big.Int)
	_a := e.toBigInt(a)
	res.Add(_a, bc).Mod(res, e.modulus())

	pool.BigInt.Put(bc)
	return e.taint(res, a, b, c)
}

func (e *engine) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	atomic.AddUint64(&cptSub, 1)
	res := new(big.Int)
	res.Sub(e.toBigInt(i1), e.toBigInt(i2))
	for i := 0; i < len(in); i++ {
		atomic.AddUint64(&cptSub, 1)
		res.Sub(res, e.toBigInt(in[i]))
	}
	res.Mod(res, e.modulus())
	return e.taint(res, append([]frontend.Variable{i1, i2}, in...)...)
}

func (e *engine) Neg(i1 frontend.Variable) frontend.Variable {
	res := new(big.Int)
	res.Neg(e.toBigInt(i1))
	res.Mod(res, e.modulus())
	return e.taint(res, i1)
}

func (e *engine) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	atomic.AddUint64(&cptMul, 1)
	b2 := e.toBigInt(i2)
	// The allocation shortcut returns before taint, so it may only be taken when i2 is
	// genuinely constant. Gated on the runtime value alone, a witness that happens to
	// solve to 0 or 1 would make the product read as constant, which is the over-claim
	// this file exists to avoid: neither builder can fold a product of two variables.
	if len(in) == 0 && e.isConstValue(i2) && b2.IsUint64() && b2.Uint64() <= 1 {
		// special path to avoid useless allocations
		if b2.Uint64() == 0 {
			return 0
		}
		return i1
	}
	b1 := e.toBigInt(i1)
	res := new(big.Int)
	res.Mul(b1, b2)
	res.Mod(res, e.modulus())
	for i := 0; i < len(in); i++ {
		atomic.AddUint64(&cptMul, 1)
		res.Mul(res, e.toBigInt(in[i]))
		res.Mod(res, e.modulus())
	}
	return e.taint(res, append([]frontend.Variable{i1, i2}, in...)...)
}

func (e *engine) Div(i1, i2 frontend.Variable) frontend.Variable {
	res := new(big.Int)
	if res.ModInverse(e.toBigInt(i2), e.modulus()) == nil {
		panic("no inverse")
	}
	res.Mul(res, e.toBigInt(i1))
	res.Mod(res, e.modulus())
	return e.taint(res, i1, i2)
}

func (e *engine) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	res := new(big.Int)
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Sign() == 0 && b2.Sign() == 0 {
		panic("DivUnchecked(0, 0) called: this leads to an unconstrained value in circuits and is unsupported in the test engine")
	}
	if res.ModInverse(b2, e.modulus()) == nil {
		panic("no inverse")
	}
	res.Mul(res, b1)
	res.Mod(res, e.modulus())
	return e.taint(res, i1, i2)
}

func (e *engine) Inverse(i1 frontend.Variable) frontend.Variable {
	res := new(big.Int)
	if res.ModInverse(e.toBigInt(i1), e.modulus()) == nil {
		panic("no inverse")
	}
	return e.taint(res, i1)
}

func (e *engine) BatchInvert(in []frontend.Variable) []frontend.Variable {
	// having a batch invert saves a lot of ops in the test engine (ModInverse is terribly inefficient)
	_in := make([]*big.Int, len(in))
	for i := 0; i < len(_in); i++ {
		_in[i] = e.toBigInt(in[i])
	}

	_out := e.batchInvert(_in)

	res := make([]frontend.Variable, len(in))
	for i := 0; i < len(in); i++ {
		res[i] = e.taint(_out[i], in[i])
	}
	return res
}

func (e *engine) batchInvert(a []*big.Int) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := range res {
		res[i] = new(big.Int)
	}
	if len(a) == 0 {
		return res
	}

	zeroes := bitset.New(uint(len(a)))
	accumulator := new(big.Int).SetUint64(1)

	for i := 0; i < len(a); i++ {
		if a[i].Sign() == 0 {
			zeroes.Set(uint(i))
			continue
		}
		res[i].Set(accumulator)

		accumulator.Mul(accumulator, a[i])
		accumulator.Mod(accumulator, e.modulus())
	}

	accumulator.ModInverse(accumulator, e.modulus())

	for i := len(a) - 1; i >= 0; i-- {
		if zeroes.Test(uint(i)) {
			continue
		}
		res[i].Mul(res[i], accumulator)
		res[i].Mod(res[i], e.modulus())
		accumulator.Mul(accumulator, a[i])
		accumulator.Mod(accumulator, e.modulus())
	}

	return res
}

func (e *engine) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	atomic.AddUint64(&cptToBinary, 1)
	nbBits := e.FieldBitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	b1 := e.toBigInt(i1)

	if b1.BitLen() > nbBits {
		panic(fmt.Sprintf("[ToBinary] decomposing %s (bitLen == %d) with %d bits", b1.String(), b1.BitLen(), nbBits))
	}

	r := make([]frontend.Variable, nbBits)
	ri := make([]frontend.Variable, nbBits)
	for i := 0; i < len(r); i++ {
		r[i] = e.taint(new(big.Int).SetUint64(uint64(b1.Bit(i))), i1)
		ri[i] = r[i]
	}

	// this is a sanity check, it should never happen
	value := e.toBigInt(e.FromBinary(ri...))
	if value.Cmp(b1) != 0 {

		panic(fmt.Sprintf("[ToBinary] decomposing %s (bitLen == %d) with %d bits reconstructs into %s", b1.String(), b1.BitLen(), nbBits, value.String()))
	}
	return r
}

func (e *engine) FromBinary(v ...frontend.Variable) frontend.Variable {
	atomic.AddUint64(&cptFromBinary, 1)
	bits := make([]bool, len(v))
	for i := 0; i < len(v); i++ {
		be := e.toBigInt(v[i])
		e.mustBeBoolean(be)
		bits[i] = be.Uint64() == 1

	}

	// Σ (2**i * bits[i]) == r
	c := new(big.Int)
	r := new(big.Int)
	c.SetUint64(1)

	for i := 0; i < len(bits); i++ {
		if bits[i] {
			r.Add(r, c)
		}
		c.Lsh(c, 1)
	}
	r.Mod(r, e.modulus())

	return e.taint(r, v...)
}

func (e *engine) Xor(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(b1)
	e.mustBeBoolean(b2)
	res := new(big.Int)
	res.Xor(b1, b2)
	return e.taint(res, i1, i2)
}

func (e *engine) Or(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(b1)
	e.mustBeBoolean(b2)
	res := new(big.Int)
	res.Or(b1, b2)
	return e.taint(res, i1, i2)
}

func (e *engine) And(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(b1)
	e.mustBeBoolean(b2)
	res := new(big.Int)
	res.And(b1, b2)
	return e.taint(res, i1, i2)
}

// Select if b is true, yields i1 else yields i2
func (e *engine) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(b)
	e.mustBeBoolean(b1)

	chosen := i2
	if b1.Uint64() == 1 {
		chosen = i1
	}
	res := new(big.Int).Set(e.toBigInt(chosen))
	return e.taint(res, b, i1, i2)
}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (e *engine) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	s0 := e.toBigInt(b0)
	s1 := e.toBigInt(b1)
	e.mustBeBoolean(s0)
	e.mustBeBoolean(s1)
	lookup := new(big.Int).Lsh(s1, 1)
	lookup.Or(lookup, s0)
	chosen := e.toBigInt([]frontend.Variable{i0, i1, i2, i3}[lookup.Uint64()])
	return e.taint(new(big.Int).Set(chosen), b0, b1, i0, i1, i2, i3)
}

// IsZero returns 1 if a is zero, 0 otherwise
func (e *engine) IsZero(i1 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(i1)

	if b1.IsUint64() && b1.Uint64() == 0 {
		return e.taint(big.NewInt(1), i1)
	}

	return e.taint(big.NewInt(0), i1)
}

// Cmp returns 1 if i1>i2, 0 if i1==i2, -1 if i1<i2
func (e *engine) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(i1)
	b2 := e.toBigInt(i2)
	res := big.NewInt(int64(b1.Cmp(b2)))
	res.Mod(res, e.modulus())
	return e.taint(res, i1, i2)
}

func (e *engine) AssertIsEqual(i1, i2 frontend.Variable) {
	atomic.AddUint64(&cptAssertIsEqual, 1)
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Cmp(b2) != 0 {
		panic(fmt.Sprintf("[assertIsEqual] %s == %s", b1.String(), b2.String()))
	}
}

func (e *engine) AssertIsDifferent(i1, i2 frontend.Variable) {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Cmp(b2) == 0 {
		panic(fmt.Sprintf("[assertIsDifferent] %s != %s", b1.String(), b2.String()))
	}
}

func (e *engine) AssertIsBoolean(i1 frontend.Variable) {
	b1 := e.toBigInt(i1)
	e.mustBeBoolean(b1)
}

func (e *engine) AssertIsCrumb(i1 frontend.Variable) {
	i1 = e.MulAcc(e.Mul(-3, i1), i1, i1)
	i1 = e.MulAcc(e.Mul(2, i1), i1, i1)
	e.AssertIsEqual(i1, 0)
}

func (e *engine) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {

	bValue := e.toBigInt(bound)

	if bValue.Sign() == -1 {
		panic(fmt.Sprintf("[assertIsLessOrEqual] bound (%s) must be positive", bValue.String()))
	}

	b1 := e.toBigInt(v)
	if b1.Cmp(bValue) == 1 {
		panic(fmt.Sprintf("[assertIsLessOrEqual] %s > %s", b1.String(), bValue.String()))
	}
}

func (e *engine) Println(a ...frontend.Variable) {
	var sbb strings.Builder
	sbb.WriteString("(test.engine) ")

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	for i := 0; i < len(a); i++ {
		e.print(&sbb, a[i])
		sbb.WriteByte(' ')
	}
	fmt.Println(sbb.String())
}

func (e *engine) print(sbb *strings.Builder, x interface{}) {
	switch v := x.(type) {
	case string:
		sbb.WriteString(v)
	case []frontend.Variable:
		sbb.WriteRune('[')
		for i := range v {
			e.print(sbb, v[i])
			if i+1 != len(v) {
				sbb.WriteRune(',')
			}
		}
		sbb.WriteRune(']')
	default:
		i := e.toBigInt(v)
		var iAsNeg big.Int
		iAsNeg.Sub(i, e.q)
		if iAsNeg.IsInt64() {
			sbb.WriteString(strconv.FormatInt(iAsNeg.Int64(), 10))
		} else {
			sbb.WriteString(i.String())
		}
	}
}

func (e *engine) NewHint(f solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {

	if nbOutputs <= 0 {
		return nil, fmt.Errorf("hint function must return at least one output")
	}
	hintFn := f
	if e.hintMapping != nil {
		if mappedFn, exists := e.hintMapping[solver.GetHintID(f)]; exists {
			hintFn = mappedFn
		}
	}

	in := make([]*big.Int, len(inputs))

	for i := 0; i < len(inputs); i++ {
		in[i] = e.toBigInt(inputs[i])
	}
	res := make([]*big.Int, nbOutputs)
	for i := range res {
		res[i] = new(big.Int)
	}

	err := hintFn(e.Field(), in, res)

	if err != nil {
		panic("NewHint: " + err.Error())
	}

	out := make([]frontend.Variable, len(res))
	for i := range res {
		res[i].Mod(res[i], e.q)
		out[i] = res[i]
	}

	return out, nil
}

func (e *engine) NewHintForId(id solver.HintID, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	if f := solver.GetRegisteredHint(id); f != nil {
		return e.NewHint(f, nbOutputs, inputs...)
	}

	return nil, fmt.Errorf("no hint registered with id #%d. Use solver.RegisterHint or solver.RegisterNamedHint", id)
}

// ConstantValue returns the big.Int value of v
func (e *engine) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	r := e.toBigInt(v)
	if e.constVars {
		// the legacy option still forces everything to read as constant
		return r, true
	}
	_, isConst := e.constant[r]
	return r, isConst
}

// taint marks res constant when every operand it was computed from is constant.
// An operation that never calls this leaves its result non-constant, which is the
// safe direction.
func (e *engine) taint(res *big.Int, inputs ...frontend.Variable) *big.Int {
	if e.constant == nil {
		e.constant = make(map[*big.Int]struct{})
	}
	for _, in := range inputs {
		if !e.isConstValue(in) {
			return res
		}
	}
	e.constant[res] = struct{}{}
	return res
}

// isConstValue reports whether v is a literal or a value derived only from
// literals. A Go value that is not a *big.Int reached the engine as a literal.
func (e *engine) isConstValue(v frontend.Variable) bool {
	if b, ok := v.(*big.Int); ok {
		_, isConst := e.constant[b]
		return isConst
	}
	return true
}

func (e *engine) IsBoolean(v frontend.Variable) bool {
	r := e.toBigInt(v)
	return r.IsUint64() && r.Uint64() <= 1
}

func (e *engine) MarkBoolean(v frontend.Variable) {
	if !e.IsBoolean(v) {
		panic("mark boolean a non-boolean value")
	}
}

func (e *engine) toBigInt(i1 frontend.Variable) *big.Int {
	switch vv := i1.(type) {
	case *big.Int:
		return vv
	case big.Int:
		return &vv
	default:
		// anything that is not already a *big.Int arrived as a Go literal
		b := utils.FromInterface(i1)
		b.Mod(&b, e.modulus())
		if e.constant == nil {
			e.constant = make(map[*big.Int]struct{})
		}
		e.constant[&b] = struct{}{}
		return &b
	}
}

// FieldBitLen returns the number of bits needed to represent a fr.Element
func (e *engine) FieldBitLen() int {
	return e.q.BitLen()
}

func (e *engine) mustBeBoolean(b *big.Int) {
	if b.IsUint64() {
		if v := b.Uint64(); v == 0 || v == 1 {
			return
		}
	}
	panic(fmt.Sprintf("[assertIsBoolean] %s", b.String()))
}

func (e *engine) modulus() *big.Int {
	return e.q
}

// shallowClone clones given circuit
// this is actually a shallow copy → if the circuits contains maps or slices
// only the reference is copied.
func shallowClone(circuit frontend.Circuit) frontend.Circuit {

	cValue := reflect.ValueOf(circuit).Elem()
	newCircuit := reflect.New(cValue.Type())
	newCircuit.Elem().Set(cValue)

	circuitCopy, ok := newCircuit.Interface().(frontend.Circuit)
	if !ok {
		panic("couldn't clone the circuit")
	}

	if !reflect.DeepEqual(circuitCopy, circuit) {
		panic("clone failed")
	}

	return circuitCopy
}

func (e *engine) copyWitness(to, from frontend.Circuit) {
	var wValues []reflect.Value

	collectHandler := func(f schema.LeafInfo, tInput reflect.Value) error {
		if tInput.IsNil() {
			// TODO @gbotrel test for missing assignment
			return fmt.Errorf("when parsing variable %s: missing assignment", f.FullName())
		}
		wValues = append(wValues, tInput)
		return nil
	}
	if _, err := schema.Walk(e.Field(), from, tVariable, collectHandler); err != nil {
		panic(err)
	}

	i := 0
	setHandler := func(f schema.LeafInfo, tInput reflect.Value) error {
		wValueIntf := wValues[i].Interface()
		val := utils.FromInterface(wValueIntf)
		if val.Cmp(e.modulus()) >= 0 {
			val.Mod(&val, e.modulus())
		}
		if val.Sign() < 0 {
			val.Add(&val, e.modulus())
		}
		// stored as a pointer so the value has a stable identity the engine can
		// track. As a big.Int value it would be copied into a fresh pointer on
		// every toBigInt call, and constness could not follow it.
		pv := new(big.Int).Set(&val)
		tInput.Set(reflect.ValueOf(pv))
		i++
		return nil
	}
	// this can't error.
	_, _ = schema.Walk(e.Field(), to, tVariable, setHandler)

}

func (e *engine) Field() *big.Int {
	return e.q
}

func (e *engine) Compiler() frontend.Compiler {
	return e
}

func (e *engine) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	if smallfields.IsSmallField(e.modulus()) {
		panic("commitment not supported for small fields")
	}
	nb := (e.FieldBitLen() + 7) / 8
	buf := make([]byte, nb)
	hasher := sha3.NewCShake128(nil, []byte("gnark test engine"))
	for i := range v {
		vs := e.toBigInt(v[i])
		bs := vs.FillBytes(buf)
		hasher.Write(bs)
	}
	hasher.Read(buf)
	res := new(big.Int).SetBytes(buf)
	res.Mod(res, e.modulus())
	if res.Sign() == 0 {
		// a commit == 0 is unlikely; happens quite often in tests
		// with tinyfield
		res.SetUint64(1)
	}
	return res, nil
}

func (e *engine) Defer(cb func(frontend.API) error) {
	// here we can use *engine as the type implementing frontend.API as test engine
	// is initialized in IsSolved and we know keystore isn't wrapped.
	circuitdefer.Put(e, cb)
}

func addInstructionGeneric[E constraint.Element](e *engine, bID constraint.BlueprintID, calldata []uint32) []uint32 {
	blueprint := e.blueprints[bID].(constraint.BlueprintSolvable[E])

	// create a dummy instruction
	inst := constraint.Instruction{
		Calldata:   calldata,
		WireOffset: uint32(len(e.internalVariables)),
	}

	// blueprint declared nbOutputs; add as many internal variables
	// and return their indices
	nbOutputs := blueprint.NbOutputs(inst)
	var r []uint32
	for i := 0; i < nbOutputs; i++ {
		r = append(r, uint32(len(e.internalVariables)))
		e.internalVariables = append(e.internalVariables, new(big.Int))
	}

	// solve the blueprint synchronously
	s := blueprintSolver[E]{
		internalVariables: e.internalVariables,
		blueprints:        e.blueprints,
		modulus:           newModulus[E](e.q),
	}
	if err := blueprint.Solve(&s, inst); err != nil {
		panic(err)
	}

	return r
}

// AddInstruction is used to add custom instructions to the constraint system.
// In constraint system, this is asynchronous. In here, we do it synchronously.
func (e *engine) AddInstruction(bID constraint.BlueprintID, calldata []uint32) []uint32 {
	if constraint.FitsElement[constraint.U32](e.q) {
		return addInstructionGeneric[constraint.U32](e, bID, calldata)
	}
	if constraint.FitsElement[constraint.U64](e.q) {
		return addInstructionGeneric[constraint.U64](e, bID, calldata)
	}
	panic("unsupported field")
}

// AddBlueprint adds a custom blueprint to the constraint system.
func (e *engine) AddBlueprint(b constraint.Blueprint) constraint.BlueprintID {
	if constraint.FitsElement[constraint.U32](e.q) {
		if _, ok := b.(constraint.BlueprintSolvable[constraint.U32]); !ok {
			panic("unsupported blueprint in test engine")
		}
	}
	if constraint.FitsElement[constraint.U64](e.q) {
		if _, ok := b.(constraint.BlueprintSolvable[constraint.U64]); !ok {
			panic("unsupported blueprint in test engine")
		}
	}

	e.blueprints = append(e.blueprints, b)

	if stateful, ok := b.(constraint.BlueprintStateful[constraint.U32]); ok {
		stateful.Reset()
	}
	if stateful, ok := b.(constraint.BlueprintStateful[constraint.U64]); ok {
		stateful.Reset()
	}

	return constraint.BlueprintID(len(e.blueprints) - 1)
}

// InternalVariable returns the value of an internal variable. This is used in custom blueprints.
// The variableID is the index of the variable in the internalVariables slice, as
// filled by AddInstruction.
func (e *engine) InternalVariable(vID uint32) frontend.Variable {
	if vID >= uint32(len(e.internalVariables)) {
		panic("internal variable not found")
	}
	return new(big.Int).Set(e.internalVariables[vID])
}

// ToCanonicalVariable converts a frontend.Variable to a frontend.CanonicalVariable
// this is used in custom blueprints to return a variable than can be encoded in blueprints
func (e *engine) ToCanonicalVariable(v frontend.Variable) frontend.CanonicalVariable {
	r := e.toBigInt(v)
	if smallfields.IsSmallField(e.q) {
		return wrappedBigInt[constraint.U32]{Int: r, modulus: newModulus[constraint.U32](e.q)}
	}
	return wrappedBigInt[constraint.U64]{Int: r, modulus: newModulus[constraint.U64](e.q)}
}

// MustBeLessOrEqCst implements method comparing value given by its bits aBits
// to a bound.
func (e *engine) MustBeLessOrEqCst(aBits []frontend.Variable, bound *big.Int, aForDebug frontend.Variable) {
	v := new(big.Int)
	for i, b := range aBits {
		bb, ok := b.(*big.Int)
		if !ok {
			panic("not big.Int bit")
		}
		if !bb.IsUint64() {
			panic("given bit large")
		}
		bbu := uint(bb.Uint64())
		if bbu > 1 {
			fmt.Println(bbu)
			panic("given bit is not a bit")
		}
		v.SetBit(v, i, bbu)
	}
	if v.Cmp(bound) > 0 {
		panic(fmt.Sprintf("%d > %d", v, bound))
	}
}

type smallfieldEngine struct {
	*engine
}

func (e *smallfieldEngine) WideCommit(width int, v ...frontend.Variable) ([]frontend.Variable, error) {
	nb := (e.FieldBitLen() + 7) / 8
	buf := make([]byte, nb)
	hasher := sha3.NewCShake128(nil, []byte("gnark test engine"))
	for i := range v {
		vs := e.toBigInt(v[i])
		bs := vs.FillBytes(buf)
		hasher.Write(bs)
	}
	res := make([]frontend.Variable, width)
	for i := 0; i < width; i++ {
		hasher.Read(buf)
		resi := new(big.Int).SetBytes(buf)
		resi.Mod(resi, e.modulus())
		res[i] = new(big.Int).Set(resi)
	}
	return res, nil
}

func (e *smallfieldEngine) Check(in frontend.Variable, width int) {
	bin := e.toBigInt(in)
	if bin.BitLen() > width {
		panic(fmt.Sprintf("range check failed: %s (bitLen == %d) with %d bits", bin.String(), bin.BitLen(), width))
	}
}
