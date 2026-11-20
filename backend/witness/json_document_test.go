// Copyright 2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package witness_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

func TestFromJSONConsumesEntireDocument(t *testing.T) {
	assignment := &circuit{X: 42, Y: 8000, E: 1}
	schema, err := frontend.NewSchema(ecc.BN254.ScalarField(), assignment)
	require.NoError(t, err)

	for _, tc := range []struct {
		name, suffix string
		wantError    bool
	}{
		{name: "single object"},
		{name: "trailing whitespace", suffix: " \t\r\n"},
		{name: "second object", suffix: ` {"X":7,"Y":8,"E":9}`, wantError: true},
		{name: "null", suffix: ` null`, wantError: true},
		{name: "array", suffix: ` []`, wantError: true},
		{name: "boolean", suffix: ` true`, wantError: true},
		{name: "invalid trailing bytes", suffix: ` garbage`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := frontend.NewWitness(&circuit{X: 7, Y: 8, E: 9}, ecc.BN254.ScalarField())
			require.NoError(t, err)
			before, err := w.MarshalBinary()
			require.NoError(t, err)

			err = w.FromJSON(schema, []byte(`{"X":42,"Y":8000,"E":1}`+tc.suffix))
			if tc.wantError {
				require.Error(t, err)
				after, err := w.MarshalBinary()
				require.NoError(t, err)
				require.Equal(t, before, after, "invalid JSON must not replace the witness")
				return
			}
			require.NoError(t, err)
			want, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			require.NoError(t, err)
			wantBytes, err := want.MarshalBinary()
			require.NoError(t, err)
			gotBytes, err := w.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, wantBytes, gotBytes)
		})
	}
}
