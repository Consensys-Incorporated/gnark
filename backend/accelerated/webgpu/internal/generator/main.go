package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/consensys/bavard"
)

type templateData struct {
	CurveKey     string
	CurveDir     string
	GoPkg        string
	CurveImport  string
	FpImport     string
	FrImport     string
	FFTImport    string
	FpBytes      int
	ScalarBytes  int
	Limbs        int
	G1PointBytes int
	G2PointBytes int
	FpOpsSeed    int64
	FrOpsSeed    int64
	VectorSeed8  int64
	VectorSeed16 int64
	NTTSeed8     int64
	NTTSeed16    int64
}

//go:generate go run .
func main() {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("resolve generator path")
	}
	generatorDir := filepath.Dir(currentFile)
	testdataDir := filepath.Clean(filepath.Join(generatorDir, "../testdata/testgen"))
	templatesDir := filepath.Join(generatorDir, "templates")

	data := []templateData{
		{
			CurveKey: "bn254", CurveDir: "bn254", GoPkg: "bn254",
			CurveImport: "github.com/consensys/gnark-crypto/ecc/bn254",
			FpImport:    "github.com/consensys/gnark-crypto/ecc/bn254/fp",
			FrImport:    "github.com/consensys/gnark-crypto/ecc/bn254/fr",
			FFTImport:   "github.com/consensys/gnark-crypto/ecc/bn254/fr/fft",
			FpBytes:     32, ScalarBytes: 32, Limbs: 4, G1PointBytes: 96, G2PointBytes: 192,
			FpOpsSeed: 20260402, FrOpsSeed: 20260403, VectorSeed8: 2026040201, VectorSeed16: 2026040202, NTTSeed8: 2026040203, NTTSeed16: 2026040204,
		},
		{
			CurveKey: "bls12_377", CurveDir: "bls12-377", GoPkg: "bls12377",
			CurveImport: "github.com/consensys/gnark-crypto/ecc/bls12-377",
			FpImport:    "github.com/consensys/gnark-crypto/ecc/bls12-377/fp",
			FrImport:    "github.com/consensys/gnark-crypto/ecc/bls12-377/fr",
			FFTImport:   "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/fft",
			FpBytes:     48, ScalarBytes: 32, Limbs: 6, G1PointBytes: 144, G2PointBytes: 288,
			FpOpsSeed: 20260407, FrOpsSeed: 20260406, VectorSeed8: 2026040601, VectorSeed16: 2026040602, NTTSeed8: 2026040603, NTTSeed16: 2026040604,
		},
		{
			CurveKey: "bls12_381", CurveDir: "bls12-381", GoPkg: "bls12381",
			CurveImport: "github.com/consensys/gnark-crypto/ecc/bls12-381",
			FpImport:    "github.com/consensys/gnark-crypto/ecc/bls12-381/fp",
			FrImport:    "github.com/consensys/gnark-crypto/ecc/bls12-381/fr",
			FFTImport:   "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft",
			FpBytes:     48, ScalarBytes: 32, Limbs: 6, G1PointBytes: 144, G2PointBytes: 288,
			FpOpsSeed: 20260405, FrOpsSeed: 20260404, VectorSeed8: 2026040401, VectorSeed16: 2026040402, NTTSeed8: 2026040403, NTTSeed16: 2026040404,
		},
	}

	const copyrightHolder = "Consensys Software Inc."
	bgen := bavard.NewBatchGenerator(copyrightHolder, 2026, "gnark")

	rootEntries := []bavard.Entry{
		{File: filepath.Join(testdataDir, "types.go"), Templates: []string{"types.go.tmpl"}},
	}
	if err := bgen.Generate(struct{}{}, "testgen", templatesDir, rootEntries...); err != nil {
		panic(err)
	}
	runCmd("gofmt", "-w", testdataDir)
	runCmd("go", "tool", "goimports", "-w", testdataDir)

	for _, d := range data {
		entries := []bavard.Entry{
			{File: filepath.Join(testdataDir, d.CurveDir, "testdata.go"), Templates: []string{"testdata.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "field_vectors.go"), Templates: []string{"field_vectors.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "g1_bases.go"), Templates: []string{"g1_bases.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "g1_msm_vectors.go"), Templates: []string{"g1_msm_vectors.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "g1_ops_vectors.go"), Templates: []string{"g1_ops_vectors.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "g1_scalar_vectors.go"), Templates: []string{"g1_scalar_vectors.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "g2_msm_vectors.go"), Templates: []string{"g2_msm_vectors.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "g2_ops_vectors.go"), Templates: []string{"g2_ops_vectors.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "helpers.go"), Templates: []string{"helpers.go.tmpl"}},
			{File: filepath.Join(testdataDir, d.CurveDir, "ntt_vectors.go"), Templates: []string{"ntt_vectors.go.tmpl"}},
		}
		if err := bgen.Generate(d, d.GoPkg, templatesDir, entries...); err != nil {
			panic(err)
		}
		runCmd("gofmt", "-w", filepath.Join(testdataDir, d.CurveDir))
		runCmd("go", "tool", "goimports", "-w", filepath.Join(testdataDir, d.CurveDir))
	}

	if err := generateWGSL(filepath.Clean(filepath.Join(generatorDir, "../../shaders"))); err != nil {
		panic(err)
	}
	if err := generateGoAccelerators(bgen, filepath.Clean(filepath.Join(generatorDir, "../..")), templatesDir, data); err != nil {
		panic(err)
	}
}

func runCmd(name string, arg ...string) {
	fmt.Println(name, strings.Join(arg, " "))
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
