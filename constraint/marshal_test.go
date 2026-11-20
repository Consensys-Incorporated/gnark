package constraint_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	csgrumpkin "github.com/consensys/gnark/constraint/grumpkin"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
)

type squareCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

// TestGrumpkinSerializationRoundTrip checks that a constraint system compiled
// over the Grumpkin scalar field can be read back. Grumpkin is not in
// gnark.Curves(), so the deserialization header check must not rely on it.
func TestGrumpkinSerializationRoundTrip(t *testing.T) {
	field := ecc.GRUMPKIN.ScalarField()
	for _, tc := range []struct {
		name       string
		newBuilder frontend.NewBuilder
		newCS      func() constraint.ConstraintSystem
	}{
		{"r1cs", r1cs.NewBuilder[constraint.U64], func() constraint.ConstraintSystem { return new(csgrumpkin.R1CS) }},
		{"scs", scs.NewBuilder[constraint.U64], func() constraint.ConstraintSystem { return new(csgrumpkin.SparseR1CS) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert := require.New(t)
			ccs, err := frontend.Compile(field, tc.newBuilder, &squareCircuit{})
			assert.NoError(err)

			var buf bytes.Buffer
			written, err := ccs.WriteTo(&buf)
			assert.NoError(err)

			reconstructed := tc.newCS()
			read, err := reconstructed.ReadFrom(&buf)
			assert.NoError(err)
			assert.Equal(written, read)
			assert.Equal(ccs.GetNbConstraints(), reconstructed.GetNbConstraints())

			valid, err := frontend.NewWitness(&squareCircuit{X: 3, Y: 9}, field)
			assert.NoError(err)
			assert.NoError(reconstructed.IsSolved(valid))
			invalid, err := frontend.NewWitness(&squareCircuit{X: 3, Y: 10}, field)
			assert.NoError(err)
			assert.Error(reconstructed.IsSolved(invalid))
		})
	}
}
