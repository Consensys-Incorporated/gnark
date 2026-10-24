// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package gnark_test

import (
	"sort"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/test"
)

func TestIntegrationAPI(t *testing.T) {

	assert := test.NewAssert(t)

	keys := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i := range keys {

		name := keys[i]
		tData := circuits.Circuits[name]

		if testing.Short() && name != "add" && name != "mul" && name != "commit" {
			continue
		}

		assert.Run(func(assert *test.Assert) {

			opts := []test.TestingOption{
				test.WithSolverOpts(solver.WithHints(tData.HintFunctions...)),
			}
			if tData.Curves != nil {
				opts = append(opts, test.WithCurves(tData.Curves[0], tData.Curves[1:]...))
			}
			// add all valid assignments
			for i := range tData.ValidAssignments {
				opts = append(opts, test.WithValidAssignment(tData.ValidAssignments[i]))
			}
			// add all invalid assignments
			for i := range tData.InvalidAssignments {
				opts = append(opts, test.WithInvalidAssignment(tData.InvalidAssignments[i]))
			}

			assert.CheckCircuit(tData.Circuit, opts...)
		}, name)
	}

}
