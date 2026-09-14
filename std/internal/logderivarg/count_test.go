package logderivarg_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/std/internal/logderivarg"
)

// field is one modulus to count over. A small field takes the wide-commitment path in
// [logderivarg.Build] — the field extension, a different folding code path — and no
// builder implements [frontend.WideCommitter] yet, so it needs the mocked one, as
// gnark's own small-field tests do. Its numbers therefore say "not regressed", not
// "this is what a small-field backend would charge".
type field struct {
	name  string
	mod   *big.Int
	small bool
}

var fields = []field{
	{"bn254", ecc.BN254.ScalarField(), false},
	{"bls12-381", ecc.BLS12_381.ScalarField(), false},
	{"koalabear", koalabear.Modulus(), true},
}

// count compiles c over f and returns the constraint count: R1CS constraints when
// plonkish is false, SCS gates when it is.
func count(t *testing.T, f field, plonkish bool, c frontend.Circuit) int {
	t.Helper()
	if f.small {
		nb := widecommitter.From(r1cs.NewBuilder)
		if plonkish {
			nb = widecommitter.From(scs.NewBuilder)
		}
		ccs, err := frontend.CompileU32(f.mod, nb, c)
		if err != nil {
			t.Fatalf("compile %s: %v", f.name, err)
		}
		return ccs.GetNbConstraints()
	}
	nb := frontend.NewBuilder(r1cs.NewBuilder[constraint.U64])
	if plonkish {
		nb = scs.NewBuilder[constraint.U64]
	}
	ccs, err := frontend.Compile(f.mod, nb, c)
	if err != nil {
		t.Fatalf("compile %s: %v", f.name, err)
	}
	return ccs.GetNbConstraints()
}

// countCircuit builds one argument over a constant table of nbTbl rows, each nbRow
// columns wide, queried by len(Q)/nbRow rows.
//
// Q holds one distinct wire per query cell and they are never reused: reuse lets the
// SCS builder fold the duplicate terms away, which reads as a far cheaper query than
// any real circuit gets.
type countCircuit struct {
	Q            []frontend.Variable
	nbRow, nbTbl int
}

func (c *countCircuit) Define(api frontend.API) error {
	table := make(logderivarg.Table, c.nbTbl)
	for i := range table {
		table[i] = make([]frontend.Variable, c.nbRow)
		for j := range table[i] {
			table[i][j] = i*c.nbRow + j + 1 // constants, rows pairwise distinct
		}
	}
	queries := make(logderivarg.Table, len(c.Q)/c.nbRow)
	for i := range queries {
		queries[i] = c.Q[i*c.nbRow : (i+1)*c.nbRow]
	}
	return logderivarg.Build(api, table, queries)
}

// TestMarginalCost reports what one table entry and one query cost, per field and row
// width. Run it once as it stands and once with the pristine file overlaid to get the
// before/after:
//
//	go test ./std/internal/logderivarg/ -run TestMarginalCost -v
//	go test -overlay=/path/to/overlay.json ./std/internal/logderivarg/ -run TestMarginalCost -v
//
// Both are read as marginals — the count at nbTbl+1 minus the count at nbTbl — so that
// the argument's fixed cost cancels: the MiMC hashes deriving rowCoeffs (one per column
// past the first), the commitment, and the shape of the summation tree all grow with the
// width but not with the table, and none of them is what the folding spelling changes.
//
// A marginal is blind to the i == 0 row, whose fold is free in either spelling because
// its index column is the constant 0. The saving over a whole table is therefore one
// gate per entry less one, which only an absolute count can confirm.
func TestMarginalCost(t *testing.T) {
	for _, f := range fields {
		for _, sys := range []struct {
			name     string
			plonkish bool
		}{{"r1cs", false}, {"scs", true}} {
			for nbRow := 1; nbRow <= 4; nbRow++ {
				at := func(nbTbl, nbQry int) int {
					return count(t, f, sys.plonkish, &countCircuit{
						Q: make([]frontend.Variable, nbQry*nbRow), nbRow: nbRow, nbTbl: nbTbl,
					})
				}
				base := at(64, 8)
				t.Logf("%-9s %-4s nbRow=%d: %2d per entry, %2d per query (64 entries + 8 queries = %d)",
					f.name, sys.name, nbRow, at(65, 8)-base, at(64, 9)-base, base)
			}
		}
	}
}

// spellCircuit folds nbRows rows of nbRow *variable* cells, the way the query side of
// the argument does, in one of the two spellings. Rho holds one distinct coefficient
// wire per column past the first, as randLinearCoefficients produces; rowCoeffs[0] is
// the constant 1, so a row's first cell enters the fold unscaled.
type spellCircuit struct {
	C   frontend.Variable
	Rho []frontend.Variable
	Q   []frontend.Variable
	// nbRow is the row width; variadic selects the folding spelling.
	nbRow    int
	variadic bool
}

func (c *spellCircuit) Define(api frontend.API) error {
	rowCoeffs := make([]frontend.Variable, c.nbRow)
	rowCoeffs[0] = 1
	copy(rowCoeffs[1:], c.Rho)

	terms := make([]frontend.Variable, c.nbRow)
	var total frontend.Variable = 0
	for i := 0; i < len(c.Q)/c.nbRow; i++ {
		row := c.Q[i*c.nbRow : (i+1)*c.nbRow]
		for j := range row {
			terms[j] = api.Mul(rowCoeffs[j], row[j])
		}
		var denom frontend.Variable
		if c.variadic {
			denom = api.Sub(c.C, terms[0], terms[1:]...)
		} else {
			acc := terms[0]
			for j := 1; j < len(terms); j++ {
				acc = api.Add(acc, terms[j])
			}
			denom = api.Sub(c.C, acc)
		}
		total = api.Add(total, denom) // keep denom live; costs the same in both spellings
	}
	api.AssertIsDifferent(total, -1)
	return nil
}

// TestQuerySideSpelling asks whether the folding rewrite that saves a gate per constant
// table row also saves one on a row of *variables*, as every query row is.
//
// It should not: the products rho_j*q_j are real gates in either spelling, and the
// flattened subtraction then spans one more wire than the accumulator did, so the
// splitting it needs costs exactly what the accumulator's materialisation cost. This
// test is here to measure that rather than assert it, since it is the claim that keeps
// the patch confined to the table side.
//
// Large fields only: over a small field the query side folds in the extension, through
// [fieldextension.Field] rather than the native api this models.
func TestQuerySideSpelling(t *testing.T) {
	for _, f := range fields {
		if f.small {
			continue
		}
		for _, sys := range []struct {
			name     string
			plonkish bool
		}{{"r1cs", false}, {"scs", true}} {
			for nbRow := 2; nbRow <= 4; nbRow++ {
				at := func(nbRows int, variadic bool) int {
					return count(t, f, sys.plonkish, &spellCircuit{
						Rho:      make([]frontend.Variable, nbRow-1),
						Q:        make([]frontend.Variable, nbRows*nbRow),
						nbRow:    nbRow,
						variadic: variadic,
					})
				}
				t.Logf("%-9s %-4s nbRow=%d: %2d per variable row accumulated, %2d variadic",
					f.name, sys.name, nbRow, at(33, false)-at(32, false), at(33, true)-at(32, true))
			}
		}
	}
}
