package uints

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/internal/logderivprecomp"
	"github.com/consensys/gnark/std/rangecheck"
)

// ctxKey is used to store the API in the key-value store. In case we
// re-initialize using [NewBytes] method, then we can reuse the existing API. This
// ensures we don't rebuild any of the tables.
type ctxKey struct{}

// Bytes implements methods for manipulating bytes in circuit. Use [NewBytes] to
// create a new instance.
type Bytes struct {
	api             frontend.API
	xorT, andT, orT *logderivprecomp.Precomputed
	constrained     map[[16]byte]struct{} // used to store if a variable is already constrained
	rchecker        frontend.Rangechecker
	allOne          U8
}

// U8 represents a single byte (uint8) in the circuit. Users should not create
// [U8] values directly, but rather use [NewU8] (for in-circuit constant
// initialization or witness assignment) or [Bytes.ValueOf] (for in-circuit
// variable initialization).
//
// Users should not access the [U8.Val] field directly, but rather use
// [Bytes.Value] method to ensure that the value is range checked to be 8 bits.
type U8 struct {
	// Val is the value of the byte. It can be a constant or a variable.
	// NB! dont't access it directly!
	Val      frontend.Variable
	internal bool
}

// NewU8 creates a new [U8] value. It represents a single byte. It can both be
// used in-circuit to initialize a constant or as a witness assignment. For
// in-circuit initialization use [Bytes.ValueOf] method instead which ensures
// that the value is range checked.
func NewU8(v uint8) U8 {
	// if NewU8 is used inside the circuit, then this means that the input is a
	// constant and this ensures that the value is already range checked by
	// default (as the argument is uint8). If it is used as a witness
	// assignment, then the flag `internal` is not set for the actual witness
	// value inside the circuit, as witness parser only copies
	// [frontend.Variable] part of U8. And the `internal=false` is set in the
	// [U8.Initialize] method.
	return U8{Val: v, internal: true}
}

// NewBytes creates a new [Bytes] instance which can manipulate bytes and byte
// arrays. For manipulating long integers, use [BinaryField] instead.
//
// This is a caching constructor, meaning that it will return the same instance
// if called multiple times. This is useful as internally it uses lookup tables
// for bitwise operations and it amortizes the cost of creating these lookup
// tables.
func NewBytes(api frontend.API) (*Bytes, error) {
	if kv, ok := api.Compiler().(kvstore.Store); ok {
		uapi := kv.GetKeyValue(ctxKey{})
		if tuapi, ok := uapi.(*Bytes); ok {
			return tuapi, nil
		}
	} else {
		panic("compiler does not implement kvstore.Store")
	}
	xorT, err := logderivprecomp.New(api, xorHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new xor table: %w", err)
	}
	andT, err := logderivprecomp.New(api, andHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new and table: %w", err)
	}
	orT, err := logderivprecomp.New(api, orHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new or table: %w", err)
	}
	rchecker := rangecheck.New(api)
	bf := &Bytes{
		api:         api,
		xorT:        xorT,
		andT:        andT,
		orT:         orT,
		rchecker:    rchecker,
		constrained: make(map[[16]byte]struct{}),
		allOne:      NewU8(0xff),
	}

	// store the API in the key-value store so that can be easily reused
	if kv, ok := api.Compiler().(kvstore.Store); ok {
		kv.SetKeyValue(ctxKey{}, bf)
	} // other case is already checked above
	return bf, nil
}

func (bf *Bytes) packInternal(val frontend.Variable) U8 {
	return U8{Val: val, internal: true}
}

// ValueOf returns a constrainted [U8] variable. For a constant value, use
// [NewU8] instead.
func (bf *Bytes) ValueOf(a frontend.Variable) U8 {
	// we create the U8 value with internal=false, so that we can range check it
	// below.
	val := U8{Val: a, internal: false}
	bf.enforceWidth(val)
	// we now set internal=true as we have ensured that the value is in range
	// and we can use it in the circuit without further checks.
	val.internal = true
	return val
}

func (bf *Bytes) enforceWidth(a U8) {
	if a.internal {
		// it is internal variable, already constrained
		return
	}
	if a.Val == nil {
		// if Val is nil, then it means that this value is not assigned yet. In
		// practice we assume it is zero. This is useful for parsing values
		// which are not explicitly set (i.e. initializing slices).
		return
	}
	// value is constant. Usually when the constant U8 is created using NewU8
	// method then we already set internal flag to true, but maybe the user has
	// manually created a U8 value with a constant value.
	if ca, isConst := bf.api.ConstantValue(a.Val); isConst {
		if ca.BitLen() > 8 {
			panic(fmt.Sprintf("constant value %d is too large for U8, expected 0 <= x < 256", ca))
		}
		return
	}
	// it is not internal, not constant and not nil. We need to range check the
	// value but we cannot set internal flag here as it is not a pointer (and
	// all API methods below expect value, not a pointer). Instead, we check
	// that the hash of the value is in the database of constrained values. If
	// not, then we constrain and store it in the database.
	if vv, ok := a.Val.(interface{ HashCode() [16]byte }); ok {
		// we can use HashCode to get the hash of the value
		h := vv.HashCode()
		if _, ok := bf.constrained[h]; ok {
			// already constrained, nothing to do
			return
		}
		// not constrained, we need to constrain it. But we do it below unconditionally (above we return early if no need to constrain).
		// however, we store it in the map so that we don't do it again.
		bf.constrained[h] = struct{}{}
	}
	// if we reach here, then we always need to range check the value.
	bf.rchecker.Check(a.Val, 8)
}

func (bf *Bytes) twoArgFn(tbl *logderivprecomp.Precomputed, a ...U8) U8 {
	if len(a) == 0 {
		return NewU8(0)
	}
	for i := range a {
		bf.enforceWidth(a[i])
	}
	if len(a) == 1 {
		return a[0]
	}
	ret := tbl.Query(a[0].Val, a[1].Val)[0]
	// NB! we cannot assume that the query result is in range even if the inputs
	// are. The log-derivative lookup only constrains the packed value
	// a + 2^8*b + 2^16*c, and a malicious prover could commit to an out-of-range
	// c which makes the packed value collide with a valid table entry (e.g.
	// Xor(1,0) = 1/256 since 1 + 2^8*0 + 2^16/256 = 257 = 0x000101 is the entry
	// for Xor(1,0)=1). We therefore range check every intermediate result: an
	// out-of-range intermediate could be consumed by a subsequent query in this
	// same chain whose packed key collides, letting a forgery pass through.
	bf.rchecker.Check(ret, 8)
	for i := 2; i < len(a); i++ {
		ret = tbl.Query(ret, a[i].Val)[0]
		bf.rchecker.Check(ret, 8)
	}
	return bf.packInternal(ret)
}

func (bf *Bytes) Not(a U8) U8 {
	bf.enforceWidth(a)
	ret := bf.xorT.Query(a.Val, bf.allOne.Val)
	// the result of the lookup is not range checked by the table (the packed key
	// a + 2^8*b + 2^16*c can collide for out-of-range c), so range check it here.
	bf.rchecker.Check(ret[0], 8)
	return bf.packInternal(ret[0])
}

func (bf *Bytes) And(a ...U8) U8 { return bf.twoArgFn(bf.andT, a...) }
func (bf *Bytes) Or(a ...U8) U8  { return bf.twoArgFn(bf.orT, a...) }
func (bf *Bytes) Xor(a ...U8) U8 { return bf.twoArgFn(bf.xorT, a...) }

func (bf *Bytes) AssertIsEqual(a, b U8) {
	bf.api.AssertIsEqual(a.Val, b.Val)
}

// Value returns the value of the U8 variables, ensuring that it is range
// checked. It is preferrable to use this method instead of directly using the
// [U8.Val] field.
func (bf *Bytes) Value(a U8) frontend.Variable {
	bf.enforceWidth(a)
	return a.Val
}

// ValueUnchecked returns the value of the U8 variables without range
// checking.
func (bf *Bytes) ValueUnchecked(a U8) frontend.Variable {
	return a.Val
}

// Select returns a new [U8] value which is:
//   - if selector is true then a
//   - if selector is false then b
func (bf *Bytes) Select(selector frontend.Variable, a, b U8) U8 {
	bf.enforceWidth(a)
	bf.enforceWidth(b)
	ret := bf.api.Select(selector, bf.ValueUnchecked(a), bf.ValueUnchecked(b))
	// we have checked the inputs and select returns either of them. So the
	// result is also in range.
	return bf.packInternal(ret)
}
