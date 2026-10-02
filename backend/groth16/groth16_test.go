package groth16_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func TestCustomHashToField(t *testing.T) {
	assert := test.NewAssert(t)
	assignment := &commitmentCircuit{X: 1}
	for _, curve := range getCurves() {
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &commitmentCircuit{})
			assert.NoError(err)
			pk, vk, err := groth16.Setup(ccs)
			assert.NoError(err)
			witness, err := frontend.NewWitness(assignment, curve.ScalarField())
			assert.NoError(err)
			assert.Run(func(assert *test.Assert) {
				proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = groth16.Verify(proof, vk, pubWitness, backend.WithVerifierHashToFieldFunction(constantHash{}))
				assert.NoError(err)
			}, "custom success")
			assert.Run(func(assert *test.Assert) {
				proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = groth16.Verify(proof, vk, pubWitness)
				assert.Error(err)
			}, "prover_only")
			assert.Run(func(assert *test.Assert) {
				proof, err := groth16.Prove(ccs, pk, witness)
				assert.Error(err)
				_ = proof
			}, "verifier_only")
		}, curve.String())
	}
}

//--------------------//
//     benches		  //
//--------------------//

func BenchmarkSetup(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			r1cs, _ := referenceCircuit(curve)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _ = groth16.Setup(r1cs)
			}
		})
	}
}

func BenchmarkProver(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			r1cs, _solution := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			pk, err := groth16.DummySetup(r1cs)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = groth16.Prove(r1cs, pk, fullWitness)
			}
		})
	}
}

func BenchmarkVerifier(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			r1cs, _solution := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			publicWitness, err := fullWitness.Public()
			if err != nil {
				b.Fatal(err)
			}

			pk, vk, err := groth16.Setup(r1cs)
			if err != nil {
				b.Fatal(err)
			}
			proof, err := groth16.Prove(r1cs, pk, fullWitness)
			if err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = groth16.Verify(proof, vk, publicWitness)
			}
		})
	}
}

type refCircuit struct {
	nbConstraints int
	X             frontend.Variable
	Y             frontend.Variable `gnark:",public"`
}

func (circuit *refCircuit) Define(api frontend.API) error {
	for i := 0; i < circuit.nbConstraints; i++ {
		circuit.X = api.Mul(circuit.X, circuit.X)
	}
	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func referenceCircuit(curve ecc.ID) (constraint.ConstraintSystem, frontend.Circuit) {
	const nbConstraints = 40000
	circuit := refCircuit{
		nbConstraints: nbConstraints,
	}
	r1cs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	var good refCircuit
	good.X = 2

	// compute expected Y
	expectedY := new(big.Int).SetUint64(2)
	exp := big.NewInt(1)
	exp.Lsh(exp, nbConstraints)
	expectedY.Exp(expectedY, exp, curve.ScalarField())

	good.Y = expectedY

	return r1cs, &good
}

type commitmentCircuit struct {
	X frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {
	cmt, err := api.(frontend.Committer).Commit(c.X)
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	api.AssertIsEqual(cmt, "0xaabbcc")
	return nil
}

type constantHash struct{}

func (h constantHash) Write(p []byte) (n int, err error) { return len(p), nil }
func (h constantHash) Sum(b []byte) []byte               { return []byte{0xaa, 0xbb, 0xcc} }
func (h constantHash) Reset()                            {}
func (h constantHash) Size() int                         { return 3 }
func (h constantHash) BlockSize() int                    { return 32 }

func getCurves() []ecc.ID {
	if testing.Short() {
		return []ecc.ID{ecc.BN254}
	}
	return gnark.Curves()
}

func TestIndependentCommitments(t *testing.T) {
	assert := require.New(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &independentCommitmentsCircuit{})
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	witness, err := frontend.NewWitness(independentCommitmentsAssignment(), ecc.BN254.ScalarField())
	assert.NoError(err)
	pubWitness, err := witness.Public()
	assert.NoError(err)
	// the commitment hints may run concurrently, prove a few times to catch
	// any interference between them
	for i := 0; i < 20; i++ {
		proof, err := groth16.Prove(ccs, pk, witness)
		assert.NoError(err)
		assert.NoError(groth16.Verify(proof, vk, pubWitness), "proof %d", i)
	}
}

// independentCommitmentsCircuit has two commitments which don't depend on each
// other, with enough constraints around them so that the solver computes both
// commitment hints in the same level, in parallel.
type independentCommitmentsCircuit struct {
	X [400]frontend.Variable
	Y [400]frontend.Variable `gnark:",public"`
}

func (c *independentCommitmentsCircuit) Define(api frontend.API) error {
	for i := 0; i < len(c.X)/2; i++ {
		api.AssertIsEqual(api.Mul(c.X[i], c.X[i]), c.Y[i])
	}
	cmt1, err := api.(frontend.Committer).Commit(c.X[0], c.X[1])
	if err != nil {
		return err
	}
	for i := len(c.X) / 2; i < len(c.X); i++ {
		api.AssertIsEqual(api.Mul(c.X[i], c.X[i]), c.Y[i])
	}
	cmt2, err := api.(frontend.Committer).Commit(c.X[2], c.X[3])
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt1, cmt2)
	return nil
}

func independentCommitmentsAssignment() *independentCommitmentsCircuit {
	var a independentCommitmentsCircuit
	for i := range a.X {
		a.X[i] = i + 2
		a.Y[i] = (i + 2) * (i + 2)
	}
	return &a
}
