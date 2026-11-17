package solidity_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"golang.org/x/crypto/sha3"
)

type noCommitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *noCommitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	return nil
}

type commitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *commitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("api does not support commitment")
	}
	cmt1, err := cmter.Commit(res)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt1, res)
	return nil
}

type twoCommitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *twoCommitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("api does not support commitment")
	}
	cmt1, err := cmter.Commit(res)
	if err != nil {
		return err
	}
	cmt2, err := cmter.Commit(cmt1)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt1, cmt2)
	return nil
}

// curveShortName returns a short filesystem-friendly name for the curve.
func curveShortName(id ecc.ID) string {
	switch id {
	case ecc.BN254:
		return "bn254"
	case ecc.BLS12_381:
		return "bls12381"
	default:
		panic("unsupported curve: " + id.String())
	}
}

func TestNoCommitment(t *testing.T) {
	// should succeed both with G16 and PLONK:
	assert := test.NewAssert(t)
	circuit := &noCommitCircuit{}
	assignment := &noCommitCircuit{A: 2, B: 3, Out: 6}
	defaultOpts := []test.TestingOption{
		test.WithCurves(ecc.BN254, ecc.BLS12_381),
		test.WithValidAssignment(assignment),
	}
	checkCircuit := func(assert *test.Assert, bid backend.ID) {
		opts := append(defaultOpts,
			test.WithBackends(bid),
		)

		assert.CheckCircuit(circuit, opts...)
	}
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.GROTH16)
	}, "Groth16")
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.PLONK)
	}, "PLONK")
}

func TestSingleCommitment(t *testing.T) {
	// should succeed both with G16 and PLONK:
	// - But for G16 only if the hash-to-field is set to a supported one.
	// - but for PLONK only if the hash-to-field is the default one. If not, then it should fail.
	assert := test.NewAssert(t)
	circuit := &commitCircuit{}
	assignment := &commitCircuit{A: 2, B: 3, Out: 6}
	defaultOpts := []test.TestingOption{
		test.WithCurves(ecc.BN254, ecc.BLS12_381),
		test.WithValidAssignment(assignment),
	}
	checkCircuit := func(assert *test.Assert, bid backend.ID, newHash func() hash.Hash) {
		opts := append(defaultOpts,
			test.WithBackends(bid),
			test.WithProverOpts(
				backend.WithProverHashToFieldFunction(newHash()),
			),
			test.WithVerifierOpts(
				backend.WithVerifierHashToFieldFunction(newHash()),
			),
			test.WithSolidityExportOptions(solidity.WithHashToFieldFunction(newHash())),
		)

		assert.CheckCircuit(circuit, opts...)
	}
	// G16 success with explicitly set options
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.GROTH16, sha256.New)
	}, "groth16", "sha256")
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.GROTH16, sha3.NewLegacyKeccak256)
	}, "groth16", "keccak256")
	// G16 success with using TargetSolidityVerifier
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.GROTH16),
			test.WithProverOpts(
				solidity.WithProverTargetSolidityVerifier(backend.GROTH16),
			),
			test.WithVerifierOpts(
				solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16),
			),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "groth16", "targetSolidityVerifier")
	// G16 success without any options because we set default options already in
	// assert.CheckCircuit if they are not set.
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.GROTH16),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "groth16", "no-options")

	// PLONK success with default options
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.PLONK),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "plonk", "default")
	// PLONK success with using TargetSolidityVerifier
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.PLONK),
			test.WithProverOpts(
				solidity.WithProverTargetSolidityVerifier(backend.PLONK),
			),
			test.WithVerifierOpts(
				solidity.WithVerifierTargetSolidityVerifier(backend.PLONK),
			),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "plonk", "targetSolidityVerifier")
}

func TestTwoCommitments(t *testing.T) {
	// should succeed with PLONK only.
	// - but for PLONK only if the hash-to-field is the default one. If not, then it should fail.
	assert := test.NewAssert(t)
	circuit := &twoCommitCircuit{}
	assignment := &twoCommitCircuit{A: 2, B: 3, Out: 6}
	assert.CheckCircuit(circuit, test.WithCurves(ecc.BN254, ecc.BLS12_381), test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK))
}

// TestExportSolidityCommitmentCount checks that the Groth16 solidity exporter
// refuses to emit a contract for verifying keys with more than one commitment.
//
// The generated contract only embeds CommitmentKeys[0] and only pairs
// commitments[0], while still folding all the commitments into the public input
// MSM. That makes it both unsound (commitments 1..n-1 are attacker-chosen free
// offsets) and incomplete (the prover produces a challenge-folded PoK across all
// keys). See https://github.com/Consensys/gnark/issues/1095.
func TestExportSolidityCommitmentCount(t *testing.T) {
	assert := test.NewAssert(t)

	setupVK := func(assert *test.Assert, id ecc.ID, circuit frontend.Circuit) groth16.VerifyingKey {
		ccs, err := frontend.Compile(id.ScalarField(), r1cs.NewBuilder, circuit)
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		return vk
	}

	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		curve := curve
		assert.Run(func(assert *test.Assert) {
			// zero commitments: must export fine
			assert.Run(func(assert *test.Assert) {
				vk := setupVK(assert, curve, &noCommitCircuit{})
				var b bytes.Buffer
				err := vk.ExportSolidity(&b)
				assert.NoError(err)
				assert.True(b.Len() > 0, "expected a contract to be written")
			}, "zero-commitments")
			// single commitment: must export fine
			assert.Run(func(assert *test.Assert) {
				vk := setupVK(assert, curve, &commitCircuit{})
				var b bytes.Buffer
				err := vk.ExportSolidity(&b, solidity.WithHashToFieldFunction(sha256.New()))
				assert.NoError(err)
				assert.True(b.Len() > 0, "expected a contract to be written")
			}, "single-commitment")
			// two commitments: must error, and must not write anything
			assert.Run(func(assert *test.Assert) {
				vk := setupVK(assert, curve, &twoCommitCircuit{})
				var b bytes.Buffer
				err := vk.ExportSolidity(&b, solidity.WithHashToFieldFunction(sha256.New()))
				assert.Error(err, "export with 2 commitments must fail")
				assert.Contains(err.Error(), "2 commitments", "error should report the commitment count")
				assert.Equal(0, b.Len(), "nothing must be written to the writer on error")
			}, "two-commitments")
		}, curveShortName(curve))
	}
}

// loadOrSetupGroth16VK loads an existing VK from vkPath, or if the file doesn't
// exist, compiles the circuit, runs setup, and writes the new VK to vkPath.
func loadOrSetupGroth16VK(assert *test.Assert, id ecc.ID, circuit frontend.Circuit, vkPath string) groth16.VerifyingKey {
	if _, err := os.Stat(vkPath); err == nil {
		vk := groth16.NewVerifyingKey(id)
		vkf, err := os.Open(vkPath)
		assert.NoError(err)
		defer vkf.Close()
		_, err = vk.ReadFrom(vkf)
		assert.NoError(err)
		return vk
	}
	ccs, err := frontend.Compile(id.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	_, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	vkf, err := os.Create(vkPath)
	assert.NoError(err)
	defer vkf.Close()
	_, err = vk.WriteTo(vkf)
	assert.NoError(err)
	return vk
}

func TestWriteContractsGroth16(t *testing.T) {
	t.Skip("temporary test to write out existing contracts")
	assert := test.NewAssert(t)
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		cn := curveShortName(curve)
		// groth16 no commitment
		vk := loadOrSetupGroth16VK(assert, curve, &noCommitCircuit{}, "testdata/blank_groth16_"+cn+"_nocommit.vk")
		solf, err := os.Create("testdata/blank_groth16_" + cn + "_nocommit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf)
		solf.Close()
		assert.NoError(err)
		// groth16 single commitment
		vk = loadOrSetupGroth16VK(assert, curve, &commitCircuit{}, "testdata/blank_groth16_"+cn+"_commit.vk")
		solf, err = os.Create("testdata/blank_groth16_" + cn + "_commit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf, solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()))
		solf.Close()
		assert.NoError(err)
	}
}

// loadOrSetupPlonkVK loads an existing VK from vkPath, or if the file doesn't
// exist, compiles the circuit, runs setup, and writes the new VK to vkPath.
func loadOrSetupPlonkVK(assert *test.Assert, id ecc.ID, circuit frontend.Circuit, vkPath string) plonk.VerifyingKey {
	if _, err := os.Stat(vkPath); err == nil {
		vk := plonk.NewVerifyingKey(id)
		vkf, err := os.Open(vkPath)
		assert.NoError(err)
		defer vkf.Close()
		_, err = vk.ReadFrom(vkf)
		assert.NoError(err)
		return vk
	}
	ccs, err := frontend.Compile(id.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)
	_, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)
	vkf, err := os.Create(vkPath)
	assert.NoError(err)
	defer vkf.Close()
	_, err = vk.WriteTo(vkf)
	assert.NoError(err)
	return vk
}

func TestWriteContractsPlonk(t *testing.T) {
	t.Skip("temporary test to write out existing contracts")
	assert := test.NewAssert(t)
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		cn := curveShortName(curve)
		// plonk no commitment
		vk := loadOrSetupPlonkVK(assert, curve, &noCommitCircuit{}, "testdata/blank_plonk_"+cn+"_nocommit.vk")
		solf, err := os.Create("testdata/blank_plonk_" + cn + "_nocommit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf)
		solf.Close()
		assert.NoError(err)
		// plonk single commitment
		vk = loadOrSetupPlonkVK(assert, curve, &commitCircuit{}, "testdata/blank_plonk_"+cn+"_commit.vk")
		solf, err = os.Create("testdata/blank_plonk_" + cn + "_commit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf)
		solf.Close()
		assert.NoError(err)
	}
}
