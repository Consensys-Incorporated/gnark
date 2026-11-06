// Package logderivlookup implements append-only lookups using log-derivative
// argument.
//
// The lookup is based on log-derivative argument as described in [logderivarg].
// The lookup table is a matrix where first column is the index and the second
// column the stored values:
//
//	1 x_1
//	2 x_2
//	...
//	n x_n
//
// When performing a query for index i, the prover returns x_i from memory and
// stores (i, x_i) as a query. During the log-derivative argument building we
// check that all queried tuples (i, x_i) are included in the table.
//
// The complexity of the lookups is linear in the size of the table and the
// number of queries (O(n+m)).
package logderivlookup

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/internal/logderivarg"
)

// Table allows to insert and query values in a lookup table.
type Table interface {
	// Insert inserts a new entry into the lookup table and returns its index.
	// It panics if the table is already committed.
	Insert(val frontend.Variable) (index int)

	// Lookup looks up values from the lookup tables given by the indices inds. It
	// returns a variable for every index. It panics during compile time when
	// looking up from a committed or empty table. It panics during solving time
	// when the index is out of bounds.
	Lookup(inds ...frontend.Variable) (vals []frontend.Variable)
}

// table is the parametric implementation of the lookup table. For usage use
// [Table] instead to avoid referencing to the type parameter.
type table[E constraint.Element] struct {
	api frontend.API

	entries   []frontend.Variable
	immutable bool
	results   []result

	// each table has a unique blueprint
	// the blueprint stores the lookup table entries once
	// such that each query only need to store the indexes to lookup
	bID       constraint.BlueprintID
	blueprint constraint.BlueprintLookupHint[E]
}

type result struct {
	ind frontend.Variable
	val frontend.Variable
}

// New returns a new [*Table]. It additionally defers building the
// log-derivative argument.
func New(api frontend.API) Table {
	if constraint.FitsElement[constraint.U32](api.Compiler().Field()) {
		t := &table[constraint.U32]{api: api}
		api.Compiler().Defer(t.commit)

		// each table has a unique blueprint
		t.bID = api.Compiler().AddBlueprint(&t.blueprint)
		return t
	}
	if constraint.FitsElement[constraint.U64W1](api.Compiler().Field()) {
		t := &table[constraint.U64W1]{api: api}
		api.Compiler().Defer(t.commit)

		// each table has a unique blueprint
		t.bID = api.Compiler().AddBlueprint(&t.blueprint)
		return t
	}
	if constraint.FitsElement[constraint.U64](api.Compiler().Field()) {
		t := &table[constraint.U64]{api: api}
		api.Compiler().Defer(t.commit)

		// each table has a unique blueprint
		t.bID = api.Compiler().AddBlueprint(&t.blueprint)
		return t
	}
	panic("unsupported field type")
}

// Insert inserts variable val into the lookup table and returns its index as a
// constant. It panics if the table is already committed.
func (t *table[E]) Insert(val frontend.Variable) (index int) {
	if t.immutable {
		panic("inserting into committed lookup table")
	}
	t.entries = append(t.entries, val)

	// each time we insert a new entry, we update the blueprint
	v := t.api.Compiler().ToCanonicalVariable(val)
	v.Compress(&t.blueprint.EntriesCalldata)

	// Record constraints for profiling
	profile.RecordOperation("logderivlookup.Insert", 3)

	return len(t.entries) - 1
}

// Lookup lookups up values from the lookup tables given by the indices inds. It
// returns a variable for every index. It panics during compile time when
// looking up from a committed or empty table. It panics during solving time
// when the index is out of bounds.
func (t *table[E]) Lookup(inds ...frontend.Variable) (vals []frontend.Variable) {
	if t.immutable {
		panic("looking up from a committed lookup table")
	}
	if len(inds) == 0 {
		return nil
	}
	if len(t.entries) == 0 {
		panic("looking up from empty table")
	}

	// Record constraints for profiling
	profile.RecordOperation("logderivlookup.Lookup", 3*len(inds))

	return t.performLookup(inds)
}

// performLookup performs the lookup and returns the resulting variables.
// underneath, it does use the blueprint to encode the lookup hint.
func (t *table[E]) performLookup(inds []frontend.Variable) []frontend.Variable {
	// to build the instruction, we need to first encode its dependency as a calldata []uint32 slice.
	// * calldata[0] is the length of the calldata,
	// * calldata[1] is the number of entries in the table we consider.
	// * calldata[2] is the number of queries (which is the number of indices we are looking up and the number of outputs we expect)
	compiler := t.api.Compiler()

	calldata := make([]uint32, 3, 3+len(inds)*2+2)
	calldata[1] = uint32(len(t.entries))
	calldata[2] = uint32(len(inds))

	// encode inputs
	for _, in := range inds {
		v := compiler.ToCanonicalVariable(in)
		v.Compress(&calldata)
	}

	// by convention, first calldata is len of inputs
	calldata[0] = uint32(len(calldata))

	// now what we are left to do is add an instruction to the constraint system
	// such that at solving time the blueprint can properly execute the lookup logic.
	outputs := compiler.AddInstruction(t.bID, calldata)

	// sanity check
	if len(outputs) != len(inds) {
		panic("sanity check")
	}

	// we need to return the variables corresponding to the outputs
	internalVariables := make([]frontend.Variable, len(inds))
	lookupResult := make([]result, len(inds))

	// we need to store the result of the lookup in the table
	for i := range inds {
		internalVariables[i] = compiler.InternalVariable(outputs[i])
		lookupResult[i] = result{ind: inds[i], val: internalVariables[i]}
	}
	t.results = append(t.results, lookupResult...)
	return internalVariables
}

func (t *table[E]) entryTable() [][]frontend.Variable {
	tbl := make([][]frontend.Variable, len(t.entries))
	for i := range t.entries {
		tbl[i] = []frontend.Variable{i, t.entries[i]}
	}
	return tbl
}

func (t *table[E]) resultsTable() [][]frontend.Variable {
	tbl := make([][]frontend.Variable, len(t.results))
	for i := range t.results {
		tbl[i] = []frontend.Variable{t.results[i].ind, t.results[i].val}
	}
	return tbl
}

func (t *table[E]) commit(api frontend.API) error {
	if len(t.results) == 0 {
		// nothing was looked up, so there is nothing to prove
		return nil
	}
	return logderivarg.Build(api, t.entryTable(), t.resultsTable())
}
