package logderivlookup

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type LookupCircuit struct {
	Entries           [1000]frontend.Variable
	Queries, Expected [100]frontend.Variable
}

func (c *LookupCircuit) Define(api frontend.API) error {
	t := New(api)
	for i := range c.Entries {
		t.Insert(c.Entries[i])
	}
	results := t.Lookup(c.Queries[:]...)
	if len(results) != len(c.Expected) {
		return fmt.Errorf("length mismatch")
	}
	for i := range results {
		api.AssertIsEqual(results[i], c.Expected[i])
	}
	return nil
}

func TestLookup(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()
	witness := LookupCircuit{}
	bound := big.NewInt(int64(len(witness.Entries)))
	for i := range witness.Entries {
		witness.Entries[i], _ = rand.Int(rand.Reader, field)
	}
	for i := range witness.Queries {
		q, _ := rand.Int(rand.Reader, bound)
		witness.Queries[i] = q
		witness.Expected[i] = new(big.Int).Set(witness.Entries[q.Int64()].(*big.Int))
	}

	assert.CheckCircuit(&LookupCircuit{}, test.WithValidAssignment(&witness), test.WithSmallfieldCheck())
}

type LookupCircuitLarge struct {
	Entries           [32000 * 2]frontend.Variable
	Queries, Expected [32000 * 2]frontend.Variable
}

func (c *LookupCircuitLarge) Define(api frontend.API) error {
	t := New(api)
	for i := range c.Entries {
		t.Insert(c.Entries[i])
	}
	results := make([]frontend.Variable, len(c.Queries))
	for i := range c.Queries {
		results[i] = t.Lookup(c.Queries[i])[0]
	}
	if len(results) != len(c.Expected) {
		return fmt.Errorf("length mismatch")
	}
	for i := range results {
		api.AssertIsEqual(results[i], c.Expected[i])
	}
	return nil
}

func BenchmarkCompileManyLookup(b *testing.B) {
	b.Run("scs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &LookupCircuitLarge{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("r1cs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &LookupCircuitLarge{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// tableWithoutQueries fills a table but never reads from it, for instance when
// the number of lookups depends on a circuit parameter that happens to be 0.
type tableWithoutQueries struct {
	Entries [4]frontend.Variable
	X       frontend.Variable
}

func (c *tableWithoutQueries) Define(api frontend.API) error {
	t := New(api)
	for i := range c.Entries {
		t.Insert(c.Entries[i])
	}
	t.Lookup()
	api.AssertIsEqual(c.X, 1)
	// the table adds no constraints and PLONK setup needs at least two
	api.AssertIsEqual(api.Mul(c.X, c.X), 1)
	return nil
}

type emptyUnusedTable struct {
	X frontend.Variable
}

func (c *emptyUnusedTable) Define(api frontend.API) error {
	New(api)
	api.AssertIsEqual(c.X, 1)
	// the table adds no constraints and PLONK setup needs at least two
	api.AssertIsEqual(api.Mul(c.X, c.X), 1)
	return nil
}

func TestTableWithoutQueries(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&tableWithoutQueries{},
		test.WithValidAssignment(&tableWithoutQueries{Entries: [4]frontend.Variable{1, 2, 3, 4}, X: 1}),
		test.WithInvalidAssignment(&tableWithoutQueries{Entries: [4]frontend.Variable{1, 2, 3, 4}, X: 2}))
	assert.CheckCircuit(&emptyUnusedTable{},
		test.WithValidAssignment(&emptyUnusedTable{X: 1}),
		test.WithInvalidAssignment(&emptyUnusedTable{X: 2}))
}
