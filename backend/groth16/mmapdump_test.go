package groth16_test

import (
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/backend/ioutils/mmap"
)

type mmapDumpPublicAPICircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *mmapDumpPublicAPICircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X, c.X), c.Y)
	return nil
}

func TestMmapDumpPublicAPIProve(t *testing.T) {
	if !mmap.Supported() {
		t.Skip("mmap is unsupported on this platform")
	}

	for _, curve := range getCurves() {
		t.Run(curve.String(), func(t *testing.T) {
			ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &mmapDumpPublicAPICircuit{})
			if err != nil {
				t.Fatal(err)
			}

			pk, vk, err := groth16.Setup(ccs)
			if err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(t.TempDir(), "proving_key.mmap")
			if err := groth16.WriteMmapDump(pk, path); err != nil {
				t.Fatal(err)
			}

			mappedPK, err := groth16.ReadMmapDump(curve, path, groth16.WithMmapDumpNoDomainPrecompute(1))
			if err != nil {
				t.Fatal(err)
			}
			defer mappedPK.Close()
			if mappedPK.CurveID() != curve {
				t.Fatalf("unexpected curve: got %s want %s", mappedPK.CurveID(), curve)
			}

			fullWitness, publicWitness := mmapDumpPublicAPIWitnesses(t, curve)
			proof, err := groth16.Prove(ccs, mappedPK, fullWitness)
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, publicWitness); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mmapDumpPublicAPIWitnesses(t *testing.T, curve ecc.ID) (witness.Witness, witness.Witness) {
	t.Helper()

	assignment := mmapDumpPublicAPICircuit{X: 3, Y: 27}
	fullWitness, err := frontend.NewWitness(&assignment, curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatal(err)
	}
	return fullWitness, publicWitness
}
