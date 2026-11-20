//go:build icicle

package plonk_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	accel_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// cacheCircuit is largeCircuit without the BSB22 commitment, so the raw
// solver cache stays enabled in the default (blinding-on) mode.
type cacheCircuit struct {
	A   frontend.Variable `gnark:",public"`
	Res frontend.Variable
}

func (c *cacheCircuit) Define(api frontend.API) error {
	x := c.A
	for i := 0; i < largeCircuitSize; i++ {
		x = api.Add(api.Mul(x, x), c.A)
	}
	api.AssertIsEqual(x, c.Res)
	return nil
}

// recurrenceResult computes the expected largeCircuit/cacheCircuit output.
func recurrenceResult(mod *big.Int) (a, x *big.Int) {
	a = big.NewInt(3)
	x = big.NewInt(3)
	for i := 0; i < largeCircuitSize; i++ {
		x.Mul(x, x)
		x.Add(x, a)
		x.Mod(x, mod)
	}
	return a, x
}

// TestRawSolverCacheRoundTrip proves a commitment-free circuit twice with
// GNARK_RAW_SOLVER_CACHE set: the first prove writes the cache, the second
// loads it, and both proofs verify.
func TestRawSolverCacheRoundTrip(t *testing.T) {
	assert := test.NewAssert(t)
	curveID := ecc.BN254

	cachePath := filepath.Join(t.TempDir(), "raw_solver.bin")
	t.Setenv("GNARK_RAW_SOLVER_CACHE", cachePath)

	ccs, err := frontend.Compile(curveID.ScalarField(), scs.NewBuilder, &cacheCircuit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)
	pk, vk, err := accel_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	a, x := recurrenceResult(curveID.ScalarField())
	w, err := frontend.NewWitness(&cacheCircuit{A: a, Res: x}, curveID.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	proof, err := accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	assert.NoError(accel_plonk.Verify(proof, vk, pw))
	_, err = os.Stat(cachePath)
	assert.NoError(err, "first prove must write the raw solver cache")

	proof, err = accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	assert.NoError(accel_plonk.Verify(proof, vk, pw))
}

// TestRawSolverCacheBSB22ReplayNoBlinding checks the path that stays allowed
// for BSB22 circuits: with GNARK_DISABLE_BLINDING set (zero-knowledge
// explicitly traded away), the cache and its commitment sidecars are written
// on the first prove and replayed on the second, and both proofs verify.
// The flag is read once in the package init, so this test can only run when
// the environment variable is set for the whole test process; it is skipped
// otherwise.
func TestRawSolverCacheBSB22ReplayNoBlinding(t *testing.T) {
	if _, ok := os.LookupEnv("GNARK_DISABLE_BLINDING"); !ok {
		t.Skip("requires GNARK_DISABLE_BLINDING (BSB22 cache replay is disabled in the default blinding-on mode)")
	}
	assert := test.NewAssert(t)
	curveID := ecc.BN254

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "raw_solver.bin")
	t.Setenv("GNARK_RAW_SOLVER_CACHE", cachePath)

	ccs, err := frontend.Compile(curveID.ScalarField(), scs.NewBuilder, &largeCircuit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)
	pk, vk, err := accel_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	a, x := recurrenceResult(curveID.ScalarField())
	w, err := frontend.NewWitness(&largeCircuit{A: a, Res: x}, curveID.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	proof, err := accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	assert.NoError(accel_plonk.Verify(proof, vk, pw))
	_, err = os.Stat(cachePath)
	assert.NoError(err, "first prove must write the raw solver cache")
	sidecars, err := filepath.Glob(filepath.Join(cacheDir, "bsb22_commit_*.bin"))
	assert.NoError(err)
	assert.True(len(sidecars) > 0, "first prove must write the BSB22 sidecar files")

	// second prove replays the cache (same pk, so the recomputed commitment
	// matches the cached wires) and must still produce a valid proof
	proof, err = accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	assert.NoError(accel_plonk.Verify(proof, vk, pw))
}

// TestRawSolverCacheSkippedForBSB22 checks that in the default (blinding-on)
// mode the raw solver cache is disabled for circuits with BSB22 commitments:
// replaying the cached commitment blinding across proofs would make the
// commitments linkable and leak the committed private wires. No cache file
// may be written, and two proofs of the same witness must carry distinct
// (freshly blinded) Bsb22Commitments.
func TestRawSolverCacheSkippedForBSB22(t *testing.T) {
	assert := test.NewAssert(t)
	curveID := ecc.BN254

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "raw_solver.bin")
	t.Setenv("GNARK_RAW_SOLVER_CACHE", cachePath)

	ccs, err := frontend.Compile(curveID.ScalarField(), scs.NewBuilder, &largeCircuit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)
	pk, vk, err := accel_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	a, x := recurrenceResult(curveID.ScalarField())
	w, err := frontend.NewWitness(&largeCircuit{A: a, Res: x}, curveID.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	proof1, err := accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	assert.NoError(accel_plonk.Verify(proof1, vk, pw))
	proof2, err := accel_plonk.Prove(ccs, pk, w)
	assert.NoError(err)
	assert.NoError(accel_plonk.Verify(proof2, vk, pw))

	_, err = os.Stat(cachePath)
	assert.True(os.IsNotExist(err), "raw solver cache must not be written for BSB22 circuits with blinding enabled")
	sidecars, err := filepath.Glob(filepath.Join(cacheDir, "bsb22_commit_*.bin"))
	assert.NoError(err)
	assert.Empty(sidecars, "BSB22 sidecar files must not be written with blinding enabled")

	p1 := proof1.(*plonk_bn254.Proof)
	p2 := proof2.(*plonk_bn254.Proof)
	assert.True(len(p1.Bsb22Commitments) > 0, "test circuit must carry a BSB22 commitment")
	for i := range p1.Bsb22Commitments {
		assert.False(p1.Bsb22Commitments[i].Equal(&p2.Bsb22Commitments[i]),
			"Bsb22Commitments must be freshly blinded on every prove")
	}
}
