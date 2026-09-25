package groth16_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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
			ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &csFileCircuit{})
			if err != nil {
				t.Fatal(err)
			}

			var encoded bytes.Buffer
			if _, err := ccs.WriteTo(&encoded); err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(t.TempDir(), "r1cs.bin")
			if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}

			decoded, err := groth16.ReadCSFromFile(curve, path)
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
	path := filepath.Join(t.TempDir(), "missing.r1cs")
	decoded, err := groth16.ReadCSFromFile(ecc.BN254, path)
	if err == nil {
		t.Fatal("expected error")
	}
	if decoded != nil {
		t.Fatal("expected nil constraint system on error")
	}
}

const csFileBenchmarkCircuitSize = 2048

type csFileBenchmarkCircuit struct {
	X [csFileBenchmarkCircuitSize]frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *csFileBenchmarkCircuit) Define(api frontend.API) error {
	acc := frontend.Variable(1)
	for i := range c.X {
		acc = api.Mul(acc, api.Add(c.X[i], i+1))
	}
	api.AssertIsEqual(acc, c.Y)
	return nil
}

func BenchmarkReadCSFromFile(b *testing.B) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &csFileBenchmarkCircuit{})
	if err != nil {
		b.Fatal(err)
	}

	var encoded bytes.Buffer
	if _, err := ccs.WriteTo(&encoded); err != nil {
		b.Fatal(err)
	}
	encodedBytes := encoded.Bytes()

	path := filepath.Join(b.TempDir(), "r1cs.bin")
	if err := os.WriteFile(path, encodedBytes, 0600); err != nil {
		b.Fatal(err)
	}

	b.Run("ReadFrom", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decoded := groth16.NewCS(ecc.BN254)
			if _, err := decoded.ReadFrom(bytes.NewReader(encodedBytes)); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ReadCSFromFile", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := groth16.ReadCSFromFile(ecc.BN254, path); err != nil {
				b.Fatal(err)
			}
		}
	})
}
