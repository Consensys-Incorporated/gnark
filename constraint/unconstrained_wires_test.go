package constraint_test

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/bits"
)

func init() {
	solver.RegisterHint(identityHint)
}

func identityHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

type allConstrained struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable
}

func (c *allConstrained) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.Z), c.Y)
	return nil
}

type unconstrainedPublic struct {
	X      frontend.Variable `gnark:",public"`
	Y      frontend.Variable `gnark:",public"`
	Unused frontend.Variable `gnark:",public"`
}

func (c *unconstrainedPublic) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

type unconstrainedSecret struct {
	X      frontend.Variable `gnark:",public"`
	Y      frontend.Variable `gnark:",public"`
	Unused frontend.Variable
}

func (c *unconstrainedSecret) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

// hintInputOnly feeds an input to a hint and constrains the hint output. A hint
// is solved, not enforced, so Unused stays free.
type hintInputOnly struct {
	X      frontend.Variable `gnark:",public"`
	Y      frontend.Variable `gnark:",public"`
	Unused frontend.Variable `gnark:",public"`
}

func (c *hintInputOnly) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(identityHint, 1, c.Unused)
	if err != nil {
		return err
	}
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	api.AssertIsEqual(api.Mul(out[0], 0), 0)
	return nil
}

// decomposed reaches its input only through bits.ToBinary, which is a hint plus
// the constraints that tie the bits back to the wire.
type decomposed struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

func (c *decomposed) Define(api frontend.API) error {
	b := bits.ToBinary(api, c.X, bits.WithNbDigits(8))
	api.AssertIsEqual(b[0], c.Y)
	return nil
}

func TestCheckUnconstrainedWires(t *testing.T) {
	backends := []struct {
		name       string
		newBuilder frontend.NewBuilder
	}{
		{"r1cs", r1cs.NewBuilder[constraint.U64]},
		{"scs", scs.NewBuilder[constraint.U64]},
	}

	testCases := []struct {
		name    string
		circuit frontend.Circuit
		// wantUnconstrained is the input name the error must mention, or "" if
		// the circuit is expected to compile.
		wantUnconstrained string
	}{
		{"all constrained", &allConstrained{}, ""},
		{"unconstrained public", &unconstrainedPublic{}, "Unused"},
		{"unconstrained secret", &unconstrainedSecret{}, "Unused"},
		{"hint input is not a constraint", &hintInputOnly{}, "Unused"},
		{"constrained through a decomposition", &decomposed{}, ""},
	}

	for _, b := range backends {
		for _, tc := range testCases {
			t.Run(b.name+"/"+tc.name, func(t *testing.T) {
				_, err := frontend.Compile(ecc.BN254.ScalarField(), b.newBuilder, tc.circuit)

				if tc.wantUnconstrained == "" {
					if err != nil {
						t.Fatalf("expected the circuit to compile, got %v", err)
					}
					return
				}
				if err == nil {
					t.Fatal("expected an error naming the unconstrained input")
				}
				if !strings.Contains(err.Error(), "unconstrained input") {
					t.Fatalf("error does not report an unconstrained input: %v", err)
				}
				if !strings.Contains(err.Error(), tc.wantUnconstrained) {
					t.Fatalf("error does not name %q: %v", tc.wantUnconstrained, err)
				}

				// the same circuit compiles when the caller opts out
				if _, err := frontend.Compile(ecc.BN254.ScalarField(), b.newBuilder, tc.circuit,
					frontend.IgnoreUnconstrainedInputs()); err != nil {
					t.Fatalf("IgnoreUnconstrainedInputs should let it compile, got %v", err)
				}
			})
		}
	}
}
