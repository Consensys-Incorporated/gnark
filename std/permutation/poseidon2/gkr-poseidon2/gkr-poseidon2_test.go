package gkr_poseidon2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	_ "github.com/consensys/gnark/std/hash/all"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func gkrCompressionsCircuits(n int) (circuit, assignment testGkrCompressionCircuit) {
	ins := make([][2]frontend.Variable, n)
	for i := range n {
		ins[i] = [2]frontend.Variable{i * 2, i*2 + 1}
	}

	return testGkrCompressionCircuit{
			Ins: make([][2]frontend.Variable, len(ins)),
		}, testGkrCompressionCircuit{
			Ins: ins,
		}
}

func TestGkrCompression(t *testing.T) {
	circuit, assignment := gkrCompressionsCircuits(2)

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

type testGkrCompressionCircuit struct {
	Ins       [][2]frontend.Variable
	skipCheck bool
}

func (c *testGkrCompressionCircuit) Define(api frontend.API) error {

	gkr, err := NewCompressor(api)
	if err != nil {
		return err
	}
	pos2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	for i := range c.Ins {
		fromGkr := gkr.Compress(c.Ins[i][0], c.Ins[i][1])
		if !c.skipCheck {
			api.AssertIsEqual(pos2.Compress(c.Ins[i][0], c.Ins[i][1]), fromGkr)
		}
	}

	return nil
}

func TestGkrCompressionCompiles(t *testing.T) {
	// just measure the number of constraints
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &testGkrCompressionCircuit{
		Ins:       make([][2]frontend.Variable, 52000),
		skipCheck: true,
	})
	require.NoError(t, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

func BenchmarkGkrCompressions(b *testing.B) {
	circuit, assignment := gkrCompressionsCircuits(50000)

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(b, err)

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_, err = cs.Solve(witness)
		require.NoError(b, err)
	}
}

// directPoseidon2Circuit uses direct poseidon2 calls (no GKR)
type directPoseidon2Circuit struct {
	Ins [][2]frontend.Variable
}

func (c *directPoseidon2Circuit) Define(api frontend.API) error {
	pos2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	for i := range c.Ins {
		_ = pos2.Compress(c.Ins[i][0], c.Ins[i][1])
	}
	return nil
}

// gkrPoseidon2Circuit uses GKR-based poseidon2 compressions
type gkrPoseidon2Circuit struct {
	Ins [][2]frontend.Variable
}

func (c *gkrPoseidon2Circuit) Define(api frontend.API) error {
	gkr, err := NewCompressor(api)
	if err != nil {
		return err
	}
	for i := range c.Ins {
		_ = gkr.Compress(c.Ins[i][0], c.Ins[i][1])
	}
	return nil
}

type poseidon2MerkleTreeCircuit struct {
	Leaves []frontend.Variable
}

func (c *poseidon2MerkleTreeCircuit) Define(api frontend.API) error {
	if len(c.Leaves) == 0 {
		return errors.New("no hashing to do")
	}

	comp, err := NewCompressor(api)
	if err != nil {
		return err
	}

	layer := make([]frontend.Variable, len(c.Leaves)/2)
	for i := range layer {
		layer[i] = comp.Compress(c.Leaves[2*i], c.Leaves[2*i+1])
	}

	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, 0) // pad with zero
		}

		for i := range len(layer) / 2 {
			layer[i] = comp.Compress(layer[2*i], layer[2*i+1])
		}

		layer = layer[:len(layer)/2]
	}

	api.AssertIsDifferent(layer[0], 0)
	return nil
}

func BenchmarkGkrPoseidon2(b *testing.B) {
	const size = 1 << 15 // about 2 ^ 16 total hashes

	circuit := poseidon2MerkleTreeCircuit{
		Leaves: make([]frontend.Variable, size),
	}
	assignment := poseidon2MerkleTreeCircuit{
		Leaves: make([]frontend.Variable, size),
	}

	for i := range assignment.Leaves {
		assignment.Leaves[i] = i
	}

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(b, err)

	w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_, err = cs.Solve(w)
		require.NoError(b, err)
	}
}

// BenchmarkConstraintComparison compares constraint counts between direct poseidon2 and GKR-based poseidon2
// at various scales to identify the crossover point where GKR becomes beneficial.
func BenchmarkConstraintComparison(b *testing.B) {
	// Test various scales to find the crossover point
	scales := []int{1 << 6, 1 << 13, 1 << 14, 1 << 15, 1 << 16, 1 << 17, 1 << 18}

	for _, n := range scales {
		b.Run(fmt.Sprintf("Direct/n=%d", n), func(b *testing.B) {
			circuit := &directPoseidon2Circuit{
				Ins: make([][2]frontend.Variable, n),
			}
			cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
			require.NoError(b, err)
			b.ReportMetric(float64(cs.GetNbConstraints()), "constraints")
			b.ReportMetric(float64(cs.GetNbConstraints())/float64(n), "constraints/hash")
		})

		b.Run(fmt.Sprintf("GKR/n=%d", n), func(b *testing.B) {
			circuit := &gkrPoseidon2Circuit{
				Ins: make([][2]frontend.Variable, n),
			}
			cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
			require.NoError(b, err)
			b.ReportMetric(float64(cs.GetNbConstraints()), "constraints")
			b.ReportMetric(float64(cs.GetNbConstraints())/float64(n), "constraints/hash")
		})
	}
}
