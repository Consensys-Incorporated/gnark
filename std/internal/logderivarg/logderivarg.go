// Package logderivarg implements log-derivative argument.
//
// The log-derivative argument was described in [Haböck22] as an improvement
// over [BCG+18]. In [BCG+18], it was shown that to show inclusion of a multiset
// S in T, one can show
//
//	∏_{f∈F} (x-f)^count(f, S) == ∏_{s∈S} x-s,
//
// where function `count` counts the number of occurrences of f in S. The problem
// with this approach is the high cost for exponentiating the left-hand side of
// the equation. However, in [Haböck22] it was shown that when avoiding the
// poles, we can perform the same check for the log-derivative variant of the
// equation:
//
//	∑_{f∈F} count(f,S)/(x-f) == ∑_{s∈S} 1/(x-s).
//
// Additionally, when the entries of both S and T are vectors, then instead we
// can check random linear combinations. So, when F is a matrix and S is a
// multiset of its rows, we first generate random linear coefficients (r_1, ...,
// r_n) and check
//
//	∑_{f∈F} count(f,S)/(x-∑_{i∈[n]}r_i*f_i) == ∑_{s∈S} 1/(x-∑_{i∈[n]}r_i*s_i).
//
// This package is a low-level primitive for building more extensive gadgets. It
// only checks the last equation, but the tables and queries should be built by
// the users.
//
// NB! The package doesn't check that the entries in table F are unique.
//
// [BCG+18]: https://eprint.iacr.org/2018/380
// [Haböck22]: https://eprint.iacr.org/2022/1530
package logderivarg

// TODO: we handle both constant and variable tables. But for variable tables we
// have to ensure that all the table entries differ! Right now isn't a problem
// because everywhere we build we also have indices which ensure uniqueness. I
// guess the best approach is to have safe and unsafe versions where the safe
// version performs additional sorting. But that is really really expensive as
// we have to show that all sorted values ara monotonically increasing.

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/std/internal/fieldextension"
	"github.com/consensys/gnark/std/internal/mimc"
	"github.com/consensys/gnark/std/multicommit"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hints used in this package
func GetHints() []solver.Hint {
	return []solver.Hint{countHint, batchDivBySubHint}
}

// Table is a vector of vectors.
type Table [][]frontend.Variable

// AsTable returns a vector as a single-column table.
func AsTable(vector []frontend.Variable) Table {
	ret := make([][]frontend.Variable, len(vector))
	for i := range vector {
		ret[i] = []frontend.Variable{vector[i]}
	}
	return ret
}

// Build builds the argument using the table and queries. If both table and
// queries are multiple-column, then also samples coefficients for the random
// linear combinations.
func Build(api frontend.API, table Table, queries Table) error {
	if len(table) == 0 {
		return errors.New("table empty")
	}
	nbRow := len(table[0])
	constTable := true
	countInputs := []frontend.Variable{len(table), nbRow}
	for i := range table {
		if len(table[i]) != nbRow {
			return errors.New("table row length mismatch")
		}
		if constTable {
			for j := range table[i] {
				if _, isConst := api.Compiler().ConstantValue(table[i][j]); !isConst {
					constTable = false
				}
			}
		}
		countInputs = append(countInputs, table[i]...)
	}
	for i := range queries {
		if len(queries[i]) != nbRow {
			return errors.New("query row length mismatch")
		}
		countInputs = append(countInputs, queries[i]...)
	}
	exps, err := api.NewHint(countHint, len(table), countInputs...)
	if err != nil {
		return fmt.Errorf("hint: %w", err)
	}

	var toCommit []frontend.Variable
	if !constTable {
		for i := range table {
			toCommit = append(toCommit, table[i]...)
		}
	}
	for i := range queries {
		toCommit = append(toCommit, queries[i]...)
	}
	toCommit = append(toCommit, exps...)

	if !smallfields.IsSmallField(api.Compiler().Field()) {
		// handle the commitment over large fields directly
		multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
			rowCoeffs, challenge := randLinearCoefficients(api, nbRow, commitment)
			var leftQuotients []frontend.Variable

			// For constant single-column tables with PlonkAPI, merge Sub+DivUnchecked
			// into a single PLONK gate per table entry (2 gates instead of 3).
			plonkAPI, useOptimizedTable := api.(frontend.PlonkAPI)
			if useOptimizedTable && constTable && nbRow == 1 {
				// verify all constant values fit in int (required by AddPlonkConstraint)
				for i := range table {
					cv, _ := api.Compiler().ConstantValue(table[i][0])
					if cv == nil || !cv.IsInt64() {
						useOptimizedTable = false
						break
					}
				}
			} else {
				useOptimizedTable = false
			}

			if useOptimizedTable {
				n := len(table)
				hintInputs := make([]frontend.Variable, 1+2*n)
				hintInputs[0] = challenge
				for i := range table {
					hintInputs[1+i] = exps[i]
					hintInputs[1+n+i] = table[i][0]
				}
				leftQuotients, err = api.NewHint(batchDivBySubHint, n, hintInputs...)
				if err != nil {
					return fmt.Errorf("batch div hint: %w", err)
				}
				for i := range table {
					constVal, _ := api.Compiler().ConstantValue(table[i][0])
					c := int(constVal.Int64())
					// Verify quotient[i] * (challenge - c) == exps[i] in one PLONK gate:
					// qM*q*ch + qL*q + qR*ch + qO*exps + qC = 0
					// 1*q*ch + (-c)*q + 0*ch + (-1)*exps + 0 = 0
					// => q*(ch - c) = exps
					plonkAPI.AddPlonkConstraint(leftQuotients[i], challenge, exps[i], -c, 0, -1, 1, 0)
				}
			} else {
				leftQuotients = make([]frontend.Variable, len(table))
				// Subtract the randomized table entries from the challenge directly
				// the constant term terms[0] is then moved to the coefficient slot
				terms := make([]frontend.Variable, nbRow)
				for i := range table {
					for j := range table[i] {
						terms[j] = api.Mul(rowCoeffs[j], table[i][j])
					}
					leftQuotients[i] = api.DivUnchecked(exps[i], api.Sub(challenge, terms[0], terms[1:]...))
				}
			}

			rightInverses := make([]frontend.Variable, len(queries))
			for i := range queries {
				rightInverses[i] = api.Sub(challenge, randLinearCombination(api, rowCoeffs, queries[i]))
			}

			if bapi, ok := api.(frontend.BatchInverter); ok {
				rightInverses = bapi.BatchInvert(rightInverses)
			} else {
				for i := range rightInverses {
					rightInverses[i] = api.Inverse(rightInverses[i])
				}
			}

			leftQuotientSum := sumVariables(api, leftQuotients)
			rightInversesSum := sumVariables(api, rightInverses)
			api.AssertIsEqual(leftQuotientSum, rightInversesSum)
			return nil
		}, toCommit...)
	} else {
		// when the native field is small field, then we need to use WithWideCommitment
		extapi, err := fieldextension.NewExtension(api)
		if err != nil {
			return fmt.Errorf("create field extension: %w", err)
		}
		multicommit.WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
			rowCoeffs, challenge := randLinearCofficientsExt(extapi, nbRow, fieldextension.Element(commitment))
			leftQuotientsTerms := make([]fieldextension.Element, len(table))
			tableEntriesExts := make([]fieldextension.Element, nbRow)
			for i := range table {
				for j := range tableEntriesExts {
					tableEntriesExts[j] = extapi.AsExtensionVariable(table[i][j])
				}
				tableComb := randLinearCombinationExt(extapi, rowCoeffs, tableEntriesExts)
				denom := extapi.Sub(challenge, tableComb)
				denom = extapi.Inverse(denom)
				expEntryExt := extapi.AsExtensionVariable(exps[i])
				leftQuotientsTerms[i] = extapi.Mul(expEntryExt, denom)
			}

			rightInversesTerms := make([]fieldextension.Element, len(queries))
			queryEntryExts := make([]fieldextension.Element, nbRow)
			for i := range queries {
				for j := range queryEntryExts {
					queryEntryExts[j] = extapi.AsExtensionVariable(queries[i][j])
				}
				queryEntryExt := randLinearCombinationExt(extapi, rowCoeffs, queryEntryExts)
				denom := extapi.Sub(challenge, queryEntryExt)
				denom = extapi.Inverse(denom)
				rightInversesTerms[i] = denom
			}
			leftQuotientsTermsSum := sumVariablesExt(extapi, leftQuotientsTerms)
			rightInversesTermsSum := sumVariablesExt(extapi, rightInversesTerms)
			extapi.AssertIsEqual(leftQuotientsTermsSum, rightInversesTermsSum)
			return nil
		}, extapi.Degree(), toCommit...)
	}

	return nil
}

func randLinearCoefficients(api frontend.API, nbRow int, commitment frontend.Variable) (rowCoeffs []frontend.Variable, challenge frontend.Variable) {
	if nbRow == 1 {
		// to avoid initializing the hasher.
		return []frontend.Variable{1}, commitment
	}
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	rowCoeffs = make([]frontend.Variable, nbRow)
	rowCoeffs[0] = 1
	for i := 1; i < nbRow; i++ {
		hasher.Reset()
		hasher.Write(i+1, commitment)
		rowCoeffs[i] = hasher.Sum()
	}
	return rowCoeffs, commitment
}

func randLinearCofficientsExt(extapi fieldextension.Field, nbRow int, commitment fieldextension.Element) (rowCoeffs []fieldextension.Element, challenge fieldextension.Element) {
	if nbRow == 1 {
		// to avoid initializing the hasher.
		return []fieldextension.Element{extapi.One()}, commitment
	}
	// we don't have a hash function over extensions yet. So we use 1, ch, ch^2, ...
	rowCoeffs = make([]fieldextension.Element, nbRow)
	rowCoeffs[0] = extapi.One()
	for i := 1; i < nbRow; i++ {
		rowCoeffs[i] = extapi.Mul(rowCoeffs[i-1], commitment)
	}
	return rowCoeffs, commitment
}

func randLinearCombination(api frontend.API, rowCoeffs []frontend.Variable, row []frontend.Variable) frontend.Variable {
	if len(rowCoeffs) != len(row) {
		panic("coefficient count mismatch")
	}
	var res frontend.Variable = 0
	for i := range rowCoeffs {
		res = api.Add(res, api.Mul(rowCoeffs[i], row[i]))
	}
	return res
}

func randLinearCombinationExt(extapi fieldextension.Field, rowCoeffs []fieldextension.Element, row []fieldextension.Element) fieldextension.Element {
	if len(rowCoeffs) != len(row) {
		panic("coefficient count mismatch")
	}
	res := extapi.Zero()
	for i := range rowCoeffs {
		term := extapi.Mul(rowCoeffs[i], row[i])
		res = extapi.Add(res, term)
	}
	return res
}

// batchDivBySubHint computes outputs[i] = inputs[1+i] / (inputs[0] - inputs[1+n+i])
// where n = len(outputs).
// inputs: [challenge, numerator_0, ..., numerator_{n-1}, denomOffset_0, ..., denomOffset_{n-1}]
// outputs: [quotient_0, ..., quotient_{n-1}]
func batchDivBySubHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	n := len(outputs)
	if len(inputs) != 1+2*n {
		return fmt.Errorf("expected %d inputs, got %d", 1+2*n, len(inputs))
	}
	challenge := inputs[0]
	diff := new(big.Int)
	for i := 0; i < n; i++ {
		numerator := inputs[1+i]
		tableVal := inputs[1+n+i]
		diff.Sub(challenge, tableVal)
		diff.Mod(diff, m)
		diffInv := new(big.Int).ModInverse(diff, m)
		if diffInv == nil {
			return fmt.Errorf("no modular inverse at index %d", i)
		}
		outputs[i].Mul(numerator, diffInv)
		outputs[i].Mod(outputs[i], m)
	}
	return nil
}

func countHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) <= 2 {
		return fmt.Errorf("at least two input required")
	}
	if !inputs[0].IsInt64() {
		return fmt.Errorf("first element must be length of table")
	}
	nbTable := int(inputs[0].Int64())
	if !inputs[1].IsInt64() {
		return fmt.Errorf("first element must be length of row")
	}
	nbRow := int(inputs[1].Int64())
	if len(inputs) < 2+nbTable {
		return fmt.Errorf("input doesn't fit table")
	}
	if len(outputs) != nbTable {
		return fmt.Errorf("output not table size")
	}
	if (len(inputs)-2-nbTable*nbRow)%nbRow != 0 {
		return fmt.Errorf("query count not full integer")
	}
	nbQueries := (len(inputs) - 2 - nbTable*nbRow) / nbRow
	if nbQueries <= 0 {
		return fmt.Errorf("at least one query required")
	}
	nbBytes := (m.BitLen() + 7) / 8
	buf := make([]byte, nbBytes*nbRow)
	histo := make(map[string]int64, nbTable) // string key as big ints not comparable
	for i := 0; i < nbTable; i++ {
		for j := 0; j < nbRow; j++ {
			inputs[2+nbRow*i+j].FillBytes(buf[j*nbBytes : (j+1)*nbBytes])
		}
		k := string(buf)
		if _, ok := histo[k]; ok {
			return fmt.Errorf("duplicate key")
		}
		histo[k] = 0
	}
	for i := 0; i < nbQueries; i++ {
		for j := 0; j < nbRow; j++ {
			inputs[2+nbRow*nbTable+nbRow*i+j].FillBytes(buf[j*nbBytes : (j+1)*nbBytes])
		}
		k := string(buf)
		v, ok := histo[k]
		if !ok {
			return fmt.Errorf("query element not in table")
		}
		v++
		histo[k] = v
	}
	for i := 0; i < nbTable; i++ {
		for j := 0; j < nbRow; j++ {
			inputs[2+nbRow*i+j].FillBytes(buf[j*nbBytes : (j+1)*nbBytes])
		}
		outputs[i].Set(big.NewInt(histo[string(buf)]))
	}
	return nil
}

// sumVariables sums the variables in vars using a tree to reduce levels (searchstring for grepping "add-using-tree").
func sumVariables(api frontend.API, vars []frontend.Variable) frontend.Variable {
	for len(vars) > 1 {
		for i := range len(vars) / 2 {
			vars[i] = api.Add(vars[2*i], vars[2*i+1])
		}
		if len(vars)%2 == 1 {
			vars[len(vars)/2] = vars[len(vars)-1]
		}
		vars = vars[:(len(vars)+1)/2]
	}
	if len(vars) == 0 {
		return 0
	}
	return vars[0]
}

// sumVariablesExt sums the variables in vars using a tree to reduce levels (searchstring for grepping "add-using-tree").
func sumVariablesExt(extapi fieldextension.Field, vars []fieldextension.Element) fieldextension.Element {
	for len(vars) > 1 {
		for i := range len(vars) / 2 {
			vars[i] = extapi.Add(vars[2*i], vars[2*i+1])
		}
		if len(vars)%2 == 1 {
			vars[len(vars)/2] = vars[len(vars)-1]
		}
		vars = vars[:(len(vars)+1)/2]
	}
	if len(vars) == 0 {
		return extapi.Zero()
	}
	return vars[0]
}
