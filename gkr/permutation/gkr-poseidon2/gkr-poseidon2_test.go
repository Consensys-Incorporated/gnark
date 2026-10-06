package gkr_poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	gcHash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/gkr/gkrapi"
	gkrkoalabear "github.com/consensys/gnark/gkr/koalabear"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomHalves returns nbInstances random instances as the columns Assignment takes.
func randomHalves(width, nbInstances int) (left, right [][]koalabear.Element) {
	columns := func() [][]koalabear.Element {
		res := make([][]koalabear.Element, width/2)
		for i := range res {
			res[i] = make([]koalabear.Element, nbInstances)
			koalabear.Vector(res[i]).MustSetRandom()
		}
		return res
	}
	return columns(), columns()
}

// TestAffineGateFewTerms checks affine gates whose sum has fewer than two terms.
func TestAffineGateFewTerms(t *testing.T) {
	var one, two koalabear.Element
	one.SetOne()
	two.SetUint64(2)

	for _, tc := range []struct {
		name         string
		coefficients []koalabear.Element
	}{
		{"one term of coefficient 1", []koalabear.Element{one}},
		{"one term of another coefficient", []koalabear.Element{two}},
		{"zero coefficients are omitted", []koalabear.Element{{}, one}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := gkrapi.New()
			inputs := make([]gkr.Variable, len(tc.coefficients))
			for i := range inputs {
				inputs[i] = api.NewInput()
			}
			out := api.Gate(affineGate(nil, tc.coefficients), inputs...)
			api.Export(out)
			circuit, _, err := api.Compile(gkrapi.KoalaBearE6(), gkrapi.ConsolidateAll)
			require.NoError(t, err)

			assignment := make(gkrkoalabear.WireAssignment, len(circuit))
			var expected [2]koalabear.Element
			for i, input := range inputs {
				assignment[input] = make([]koalabear.Element, 2)
				koalabear.Vector(assignment[input]).MustSetRandom()
				for instanceI := range expected {
					var term koalabear.Element
					term.Mul(&tc.coefficients[i], &assignment[input][instanceI])
					expected[instanceI].Add(&expected[instanceI], &term)
				}
			}
			assignment.Complete(circuit)
			for instanceI := range expected {
				assert.True(t, expected[instanceI].Equal(&assignment[out][instanceI]), "instance %d", instanceI)
			}
		})
	}
}

// TestCompressor proves and verifies 2⁶ random instances with the default parameters, and checks
// the circuit's outputs against gnark-crypto's compression function.
func TestCompressor(t *testing.T) {
	const logNbInstances = 6

	params := poseidon2.GetDefaultParameters()
	compressor, err := NewCompressor(params)
	require.NoError(t, err)

	left, right := randomHalves(params.Width, 1<<logNbInstances)
	assignment := compressor.Assignment(left, right)

	proof, proverClaims, err := gkrkoalabear.Prove(compressor.Circuit, compressor.Schedule, assignment, gcHash.POSEIDON2_KOALABEAR.New())
	require.NoError(t, err)
	require.NoError(t, proverClaims.Check(assignment))

	// Prove has computed the outputs.
	permutation := poseidon2.NewDefaultPermutation()
	half := params.Width / 2
	for instanceI := range 1 << logNbInstances {
		var leftBytes, rightBytes []byte
		for i := range half {
			leftBytes = append(leftBytes, left[i][instanceI].Marshal()...)
			rightBytes = append(rightBytes, right[i][instanceI].Marshal()...)
		}
		expected, err := permutation.Compress(leftBytes, rightBytes)
		require.NoError(t, err)
		for i := range half {
			var out koalabear.Element
			require.NoError(t, out.SetBytesCanonical(expected[i*koalabear.Bytes:(i+1)*koalabear.Bytes]))
			assert.True(t, out.Equal(&assignment[compressor.Out[i]][instanceI]), "instance %d, output %d", instanceI, i)
		}
	}

	verifierClaims, err := gkrkoalabear.Verify(compressor.Circuit, compressor.Schedule, logNbInstances, proof, gcHash.POSEIDON2_KOALABEAR.New())
	require.NoError(t, err)
	require.NoError(t, verifierClaims.Check(assignment))

	// The size of the proof for the default parameters, 836 + 104n elements for 2ⁿ instances, pins
	// down the shape of the circuit and of its schedule.
	nbElements := 0
	for range proof.Flatten() {
		nbElements++
	}
	assert.Equal(t, 836+104*logNbInstances, nbElements)
}

func BenchmarkCompressor(b *testing.B) {
	const nbInstances = 1 << 16

	params := poseidon2.GetDefaultParameters()
	compressor, err := NewCompressor(params)
	require.NoError(b, err)

	left, right := randomHalves(params.Width, nbInstances)

	b.ResetTimer()
	for range b.N {
		_, _, err = gkrkoalabear.Prove(compressor.Circuit, compressor.Schedule, compressor.Assignment(left, right), gcHash.POSEIDON2_KOALABEAR.New())
		require.NoError(b, err)
	}
}
