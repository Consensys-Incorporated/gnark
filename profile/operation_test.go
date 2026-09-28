//go:build !windows

package profile_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
)

// EmulatedCircuit performs emulated arithmetic which uses deferred constraints
type EmulatedCircuit struct {
	A, B emulated.Element[emulated.Secp256k1Fp]
}

func (c *EmulatedCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// These operations use deferred constraint creation
	// Without operation profiling, profiling wouldn't show where Mul was called
	res := f.Mul(&c.A, &c.B)
	res = f.Mul(res, &c.A)
	f.AssertIsEqual(res, &c.B)

	return nil
}

func TestOperations(t *testing.T) {
	p := profile.Start(profile.WithNoOutput())
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &EmulatedCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()

	// Check that we recorded both constraint and operation samples
	nbConstraints := p.NbConstraints()
	nbOperations := p.NbOperations()

	if nbConstraints == 0 {
		t.Error("expected some constraints to be recorded")
	}

	if nbOperations == 0 {
		t.Error("expected some operations to be recorded")
	}

	// We did 2 Mul operations and 1 AssertIsEqual (which calls checkZero)
	// So we expect at least 3 operations
	// (there might be more due to internal operations like Reduce)
	if nbOperations < 3 {
		t.Errorf("expected at least 3 operations (2 Mul + 1 AssertIsEqual), got %d", nbOperations)
	}

	t.Logf("Constraints: %d, Operations: %d", nbConstraints, nbOperations)
	t.Logf("\n--- Constraints (sample_index=0) ---\n%s", p.Top())
	t.Logf("\n--- Operations (sample_index=1) ---\n%s", p.TopOperations())
}

func TestOperationsDirectAPI(t *testing.T) {
	// Test the RecordOperation API directly
	p := profile.Start(profile.WithNoOutput())

	// Record some operations manually (each records count=1)
	profile.RecordOperation("test.op1", 1)
	profile.RecordOperation("test.op2", 1)
	profile.RecordOperation("test.op2", 1) // record op2 twice

	// Also record regular constraints (simulate with RecordConstraint)
	profile.RecordConstraint()
	profile.RecordConstraint()

	p.Stop()

	nbConstraints := p.NbConstraints()
	nbOperations := p.NbOperations()

	if nbConstraints != 2 {
		t.Errorf("expected 2 constraints, got %d", nbConstraints)
	}

	if nbOperations != 3 {
		t.Errorf("expected 3 operations (1+2), got %d", nbOperations)
	}

	t.Logf("Direct API test - Constraints: %d, Operations: %d", nbConstraints, nbOperations)
}

func TestOperationsNoSession(t *testing.T) {
	// When no profiling session is active, RecordOperation should be a no-op
	// This tests that it doesn't panic and doesn't affect anything

	// No profile.Start() - just call RecordOperation
	profile.RecordOperation("test.noop", 1)
	profile.RecordConstraint()

	// Start a new session to verify nothing was recorded
	p := profile.Start(profile.WithNoOutput())
	p.Stop()

	// Should have 0 since we started the session after the calls
	if p.NbConstraints() != 0 {
		t.Errorf("expected 0 constraints when session started after recording")
	}
	if p.NbOperations() != 0 {
		t.Errorf("expected 0 operations when session started after recording")
	}
}

func TestOperationWeights(t *testing.T) {
	// Test that WithOperationWeights multiplies counts correctly
	weights := map[string]int{
		"expensive.op": 10,
		"medium.op":    5,
		// "cheap.op" is not in the map, should use count=1
	}
	p := profile.Start(profile.WithNoOutput(), profile.WithOperationWeights(weights))

	// Record operations
	profile.RecordOperation("expensive.op", 1) // should count as 10
	profile.RecordOperation("medium.op", 1)    // should count as 5
	profile.RecordOperation("medium.op", 1)    // should count as 5
	profile.RecordOperation("cheap.op", 1)     // should count as 1 (no weight)

	p.Stop()

	nbOperations := p.NbOperations()
	// Expected: 10 + 5 + 5 + 1 = 21
	if nbOperations != 21 {
		t.Errorf("expected 21 operations with weights (10+5+5+1), got %d", nbOperations)
	}

	t.Logf("WithOperationWeights test - Operations: %d (expected 21)", nbOperations)
}

func TestOperationWeightsMultipleSessions(t *testing.T) {
	// Test that different sessions can have different weights
	weights1 := map[string]int{"op": 10}
	weights2 := map[string]int{"op": 2}

	p1 := profile.Start(profile.WithNoOutput(), profile.WithOperationWeights(weights1))
	p2 := profile.Start(profile.WithNoOutput(), profile.WithOperationWeights(weights2))

	// Record an operation - each session should apply its own weight
	profile.RecordOperation("op", 1)

	p2.Stop()
	p1.Stop()

	if p1.NbOperations() != 10 {
		t.Errorf("session 1: expected 10 operations, got %d", p1.NbOperations())
	}
	if p2.NbOperations() != 2 {
		t.Errorf("session 2: expected 2 operations, got %d", p2.NbOperations())
	}

	t.Logf("Multiple sessions - p1: %d (expected 10), p2: %d (expected 2)",
		p1.NbOperations(), p2.NbOperations())
}

// ECMulCircuit wraps the ECMul precompile for profiling
type ECMulCircuit struct {
	P sw_emulated.AffinePoint[emulated.BN254Fp]
	U emulated.Element[emulated.BN254Fr]
}

func (c *ECMulCircuit) Define(api frontend.API) error {
	// This is a complex operation that involves many emulated field operations
	// and range checks - perfect for demonstrating operation profiling
	_ = evmprecompiles.ECMul(api, &c.P, &c.U)
	return nil
}

func TestOperationsECMul(t *testing.T) {
	// Test with a more complex circuit - ECMul precompile
	p := profile.Start(profile.WithNoOutput())
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &ECMulCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()

	nbConstraints := p.NbConstraints()
	nbOperations := p.NbOperations()

	t.Logf("ECMul Circuit - Constraints: %d, Operations: %d", nbConstraints, nbOperations)

	// ECMul involves many multiplications and range checks
	// We expect a significant number of operations
	if nbOperations < 100 {
		t.Errorf("expected at least 100 operations for ECMul, got %d", nbOperations)
	}

	// Print operations tree to show the breakdown
	t.Logf("\n--- Operations Breakdown ---\n%s", p.TopOperations())
}

// Example_operations demonstrates how to use operation profiling
// with emulated arithmetic.
func Example_operations() {
	// Start profiling - operations will be tracked at call sites
	p := profile.Start(profile.WithNoOutput())

	// Compile a circuit using emulated arithmetic
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &EmulatedCircuit{})

	p.Stop()

	// View actual constraints (default)
	// go tool pprof -sample_index=0 gnark.pprof

	// View operations (shows where Mul/AssertIsEqual were called)
	// go tool pprof -sample_index=1 gnark.pprof

	// Or programmatically:
	// p.Top() - shows constraint tree
	// p.TopOperations() - shows operation tree
}

func TestWithoutOperations(t *testing.T) {
	// Test that WithoutOperations excludes operation samples from the profile
	p := profile.Start(profile.WithNoOutput(), profile.WithoutOperations())

	// Record both constraint and operation samples
	profile.RecordConstraint()
	profile.RecordConstraint()
	profile.RecordOperation("test.op", 1)
	profile.RecordOperation("test.op", 1)

	p.Stop()

	// After Stop(), filtering is applied
	// NbConstraints should still work (returns 2)
	nbConstraints := p.NbConstraints()
	if nbConstraints != 2 {
		t.Errorf("expected 2 constraints, got %d", nbConstraints)
	}

	// Operations count should be 0 after filtering
	nbOperations := p.NbOperations()
	if nbOperations != 0 {
		t.Errorf("expected 0 operations with WithoutOperations, got %d", nbOperations)
	}

	t.Logf("WithoutOperations - Constraints: %d, Operations: %d", nbConstraints, nbOperations)
}

func TestWithoutConstraints(t *testing.T) {
	// Test that WithoutConstraints excludes constraint samples from the profile
	p := profile.Start(profile.WithNoOutput(), profile.WithoutConstraints())

	// Record both constraint and operation samples
	profile.RecordConstraint()
	profile.RecordConstraint()
	profile.RecordOperation("test.op", 1)
	profile.RecordOperation("test.op", 1)

	p.Stop()

	// NbConstraints returns 0 when WithoutConstraints is used
	nbConstraints := p.NbConstraints()
	if nbConstraints != 0 {
		t.Errorf("expected 0 constraints with WithoutConstraints, got %d", nbConstraints)
	}

	// NbOperations should still work correctly
	nbOperations := p.NbOperations()
	if nbOperations != 2 {
		t.Errorf("expected 2 operations, got %d", nbOperations)
	}

	// Top() should return empty string when constraints are excluded
	if p.Top() != "" {
		t.Errorf("expected empty Top() with WithoutConstraints")
	}

	// TopOperations() should still work
	if p.TopOperations() == "" {
		t.Errorf("expected non-empty TopOperations() with WithoutConstraints")
	}

	t.Logf("WithoutConstraints - Constraints: %d, Operations: %d", nbConstraints, nbOperations)
}

func TestWithoutBoth(t *testing.T) {
	// Test that using both WithoutConstraints and WithoutOperations panics
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when using both WithoutConstraints and WithoutOperations")
		}
	}()

	_ = profile.Start(profile.WithNoOutput(), profile.WithoutConstraints(), profile.WithoutOperations())
}

func TestTopSampleIndex(t *testing.T) {
	p := profile.Start(profile.WithNoOutput())

	profile.RecordConstraint()
	profile.RecordConstraint()
	profile.RecordOperation("test.op", 1)
	profile.RecordOperation("test.op", 1)
	profile.RecordOperation("test.op", 1)

	p.Stop()

	// Top reports constraints, TopOperations reports operations
	if top := p.Top(); !strings.Contains(top, "of 2 total") {
		t.Errorf("expected Top() to report 2 constraints, got:\n%s", top)
	}
	if top := p.TopOperations(); !strings.Contains(top, "of 3 total") {
		t.Errorf("expected TopOperations() to report 3 operations, got:\n%s", top)
	}
}
