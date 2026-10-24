package gkrtesting

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/stretchr/testify/assert"
)

func TestLoadCircuit(t *testing.T) {
	cache := NewCache(gkrcore.PrimeField(ecc.BN254.ScalarField()))
	_, c := cache.GetCircuit("../test_vectors/circuits/two_identity_gates_composed_single_input.json")
	assert.Equal(t, 0, len(c[0].Inputs))
	assert.Equal(t, []int{0}, c[1].Inputs)
	assert.Equal(t, []int{1}, c[2].Inputs)
}
