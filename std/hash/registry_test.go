package hash_test

import (
	"testing"

	"github.com/consensys/gnark/std/hash"
	"github.com/stretchr/testify/require"
)

func TestGetFieldHasherUnregistered(t *testing.T) {
	hasher, err := hash.GetFieldHasher("unregistered-hash", nil)
	require.Nil(t, hasher)
	require.ErrorContains(t, err, `hash function "unregistered-hash" not registered`)
}
