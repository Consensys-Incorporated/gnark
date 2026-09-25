package plonk_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

//--------------------//
//     benches		  //
//--------------------//

func TestProver(t *testing.T) {

	for _, curve := range getCurves() {
		t.Run(curve.String(), func(t *testing.T) {
			var b1, b2 bytes.Buffer
			assert := require.New(t)

			ccs, _solution, srs, srsLagrange := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			assert.NoError(err)

			publicWitness, err := fullWitness.Public()
			assert.NoError(err)

			pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
			assert.NoError(err)

			// write the PK to ensure it is not mutated
			_, err = pk.WriteTo(&b1)
			assert.NoError(err)

			proof, err := plonk.Prove(ccs, pk, fullWitness)
			assert.NoError(err)

			// check pk
			_, err = pk.WriteTo(&b2)
			assert.NoError(err)

			assert.True(bytes.Equal(b1.Bytes(), b2.Bytes()), "plonk prover mutated the proving key")

			err = plonk.Verify(proof, vk, publicWitness)
			assert.NoError(err)

			// testing with full witness should output a clear error.
			err = plonk.Verify(proof, vk, fullWitness)
			assert.Error(err)

			// check that error contains "witness length is invalid"
			assert.Contains(err.Error(), "witness length is invalid")

		})

	}
}

func TestCustomHashToField(t *testing.T) {
	assert := test.NewAssert(t)
	assignment := &commitmentCircuit{X: 1}
	for _, curve := range getCurves() {
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &commitmentCircuit{})
			assert.NoError(err)
			srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
			assert.NoError(err)

			pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
			assert.NoError(err)
			witness, err := frontend.NewWitness(assignment, curve.ScalarField())
			assert.NoError(err)
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness, backend.WithVerifierHashToFieldFunction(constantHash{}))
				assert.NoError(err)
			}, "prover_verifier")
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness)
				assert.Error(err)
			}, "prover_only")
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness)
				assert.Error(err)
				_ = proof
			}, "verifier_only")
		}, curve.String())
	}
}

func TestCustomChallengeHash(t *testing.T) {
	assert := test.NewAssert(t)
	assignment := &smallCircuit{X: 1}
	for _, curve := range getCurves() {
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &smallCircuit{})
			assert.NoError(err)
			srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
			assert.NoError(err)

			pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
			assert.NoError(err)
			witness, err := frontend.NewWitness(assignment, curve.ScalarField())
			assert.NoError(err)
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness, backend.WithProverChallengeHashFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness, backend.WithVerifierChallengeHashFunction(constantHash{}))
				assert.NoError(err)
			}, "prover_verifier")
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness, backend.WithProverChallengeHashFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness)
				assert.Error(err)
			}, "prover_only")
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness)
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness, backend.WithVerifierChallengeHashFunction(constantHash{}))
				assert.Error(err)
			}, "verifier_only")
		}, curve.String())
	}
}

func TestCustomKZGFoldingHash(t *testing.T) {
	assert := test.NewAssert(t)
	assignment := &smallCircuit{X: 1}
	for _, curve := range getCurves() {
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &smallCircuit{})
			assert.NoError(err)
			srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
			assert.NoError(err)

			pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
			assert.NoError(err)
			witness, err := frontend.NewWitness(assignment, curve.ScalarField())
			assert.NoError(err)
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness, backend.WithProverKZGFoldingHashFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness, backend.WithVerifierKZGFoldingHashFunction(constantHash{}))
				assert.NoError(err)
			}, "prover_verifier")
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness, backend.WithProverKZGFoldingHashFunction(constantHash{}))
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness)
				assert.Error(err)
			}, "prover_only")
			assert.Run(func(assert *test.Assert) {
				proof, err := plonk.Prove(ccs, pk, witness)
				assert.NoError(err)
				pubWitness, err := witness.Public()
				assert.NoError(err)
				err = plonk.Verify(proof, vk, pubWitness, backend.WithVerifierKZGFoldingHashFunction(constantHash{}))
				assert.Error(err)
			}, "verifier_only")
		}, curve.String())
	}
}

func BenchmarkSetup(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			ccs, _, srs, srsLagrange := referenceCircuit(curve)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _ = plonk.Setup(ccs, srs, srsLagrange)
			}
		})
	}
}

func BenchmarkProver(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			ccs, _solution, srs, srsLagrange := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			pk, _, err := benchSetup(ccs, srs, srsLagrange)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = benchProve(ccs, pk, fullWitness)
			}
		})
	}
}

func BenchmarkVerifier(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			ccs, _solution, srs, srsLagrange := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			publicWitness, err := fullWitness.Public()
			if err != nil {
				b.Fatal(err)
			}

			pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
			if err != nil {
				b.Fatal(err)
			}
			proof, err := plonk.Prove(ccs, pk, fullWitness)
			if err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = plonk.Verify(proof, vk, publicWitness)
			}
		})
	}
}

// BenchmarkLargeProver benchmarks the prover on a circuit slightly over 1<<21
// constraints, so the domain is 1<<22. The large padding region (~1.8M entries)
// exercises the partial-MSM + padding commitment optimization in commitToLRO.
func BenchmarkLargeProver(b *testing.B) {
	const nbConstraints = 1<<21 + 100_000 // ~2.2M → domain 1<<22, padding ~1.8M

	circuit := refCircuit{nbConstraints: nbConstraints}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("constraints: %d, domain: next power of 2 = %d", ccs.GetNbConstraints(), 1<<22)

	// X=1 → 1*1=1 at every gate, Y=1
	var good refCircuit
	good.X = 1
	good.Y = 1
	fullWitness, err := frontend.NewWitness(&good, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		b.Fatal(err)
	}

	// sanity check: prove + verify once
	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		b.Fatal(err)
	}
	pubWitness, err := fullWitness.Public()
	if err != nil {
		b.Fatal(err)
	}
	if err := plonk.Verify(proof, vk, pubWitness); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = plonk.Prove(ccs, pk, fullWitness)
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

func referenceCircuit(curve ecc.ID) (constraint.ConstraintSystem, frontend.Circuit, kzg.SRS, kzg.SRS) {
	const nbConstraints = (1 << 12) - 3
	circuit := refCircuit{
		nbConstraints: nbConstraints,
	}
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &circuit)
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
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	if err != nil {
		panic(err)
	}
	return ccs, &good, srs, srsLagrange
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

type smallCircuit struct {
	X frontend.Variable
}

func (c *smallCircuit) Define(api frontend.API) error {
	res := api.Mul(c.X, c.X)
	api.AssertIsEqual(c.X, res)
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
