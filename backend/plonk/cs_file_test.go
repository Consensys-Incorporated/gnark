package plonk_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type csFileCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *csFileCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X, c.X), c.Y)
	return nil
}

func TestReadCSFromFile(t *testing.T) {
	for _, curve := range getCurves() {
		t.Run(curve.String(), func(t *testing.T) {
			ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &csFileCircuit{})
			if err != nil {
				t.Fatal(err)
			}

			var encoded bytes.Buffer
			if _, err := ccs.WriteTo(&encoded); err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(t.TempDir(), "scs.bin")
			if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}

			decoded, err := plonk.ReadCSFromFile(curve, path)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.GetNbConstraints() != ccs.GetNbConstraints() {
				t.Fatalf("unexpected constraint count: got %d want %d", decoded.GetNbConstraints(), ccs.GetNbConstraints())
			}

			var reencoded bytes.Buffer
			if _, err := decoded.WriteTo(&reencoded); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded.Bytes(), reencoded.Bytes()) {
				t.Fatal("constraint system changed after file round trip")
			}
		})
	}
}

func TestReadCSFromFileErrorReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.scs")
	decoded, err := plonk.ReadCSFromFile(ecc.BN254, path)
	if err == nil {
		t.Fatal("expected error")
	}
	if decoded != nil {
		t.Fatal("expected nil constraint system on error")
	}
}
