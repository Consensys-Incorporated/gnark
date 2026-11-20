// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package witness_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

type failingHeaderWriter struct {
	bytes.Buffer
	limit int
	err   error
}

func (w *failingHeaderWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.Len() {
		n, _ := w.Buffer.Write(p[:w.limit-w.Len()])
		return n, w.err
	}
	return w.Buffer.Write(p)
}

type headerErrorWriter struct {
	bytes.Buffer
	err error
}

func (w *headerErrorWriter) Write(p []byte) (int, error) {
	n, _ := w.Buffer.Write(p)
	return n, w.err
}

func TestWriteToCountsPartialHeaderWrites(t *testing.T) {
	witness, err := frontend.NewWitness(&circuit{X: 42, Y: 8000, E: 1}, ecc.BN254.ScalarField())
	require.NoError(t, err)
	encoded, err := witness.MarshalBinary()
	require.NoError(t, err)
	writeErr := errors.New("test writer stopped")

	for _, limit := range []int{0, 1, 3, 4, 5, 7} {
		t.Run(fmt.Sprintf("after_%d_bytes", limit), func(t *testing.T) {
			writer := &failingHeaderWriter{limit: limit, err: writeErr}
			n, err := witness.WriteTo(writer)
			require.ErrorIs(t, err, writeErr)
			require.Equal(t, int64(limit), n)
			require.True(t, bytes.Equal(encoded[:limit], writer.Bytes()))
		})
	}

	t.Run("short write without error", func(t *testing.T) {
		writer := &failingHeaderWriter{limit: 3}
		n, err := witness.WriteTo(writer)
		require.ErrorIs(t, err, io.ErrShortWrite)
		require.Equal(t, int64(3), n)
		require.Equal(t, encoded[:3], writer.Bytes())
	})

	t.Run("full header with error", func(t *testing.T) {
		writer := &headerErrorWriter{err: writeErr}
		n, err := witness.WriteTo(writer)
		require.ErrorIs(t, err, writeErr)
		require.Equal(t, int64(8), n)
		require.Equal(t, encoded[:8], writer.Bytes())
	})

	t.Run("complete write", func(t *testing.T) {
		var writer bytes.Buffer
		n, err := witness.WriteTo(&writer)
		require.NoError(t, err)
		require.Equal(t, int64(len(encoded)), n)
		require.Equal(t, encoded, writer.Bytes())
	})
}
