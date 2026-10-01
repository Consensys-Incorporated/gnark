package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/consensys/bavard"
)

type templateData struct {
	Curve    string
	CurveID  string
	RootPath string
	CurvePkg string

	G2ExtensionDegree int
}

//go:generate go run main.go
func main() {
	bn254 := templateData{
		Curve:             "BN254",
		CurveID:           "BN254",
		RootPath:          "../../groth16/bn254",
		CurvePkg:          "bn254",
		G2ExtensionDegree: 6,
	}
	bls12_377 := templateData{
		Curve:             "BLS12-377",
		CurveID:           "BLS12_377",
		RootPath:          "../../groth16/bls12-377",
		CurvePkg:          "bls12377",
		G2ExtensionDegree: 6,
	}
	bls12_381 := templateData{
		Curve:             "BLS12-381",
		CurveID:           "BLS12_381",
		RootPath:          "../../groth16/bls12-381",
		CurvePkg:          "bls12381",
		G2ExtensionDegree: 6,
	}
	bw6_761 := templateData{
		Curve:             "BW6-761",
		CurveID:           "BW6_761",
		RootPath:          "../../groth16/bw6-761",
		CurvePkg:          "bw6761",
		G2ExtensionDegree: 3,
	}
	data := []templateData{bn254, bls12_377, bls12_381, bw6_761}

	const copyrightHolder = "Consensys Software Inc."
	var bgen = bavard.NewBatchGenerator(copyrightHolder, 2025, "gnark")

	for _, d := range data {
		entries := []bavard.Entry{
			{File: filepath.Join(d.RootPath, "doc.go"), Templates: []string{"groth16.icicle.doc.go.tmpl"}},
			{File: filepath.Join(d.RootPath, "icicle.go"), Templates: []string{"groth16.icicle.go.tmpl"}},
			{File: filepath.Join(d.RootPath, "provingkey.go"), Templates: []string{"groth16.icicle.provingkey.go.tmpl"}},
		}
		if err := bgen.Generate(d, d.CurvePkg, "./templates/", entries...); err != nil {
			panic(err)
		}

		plonkRoot := strings.Replace(d.RootPath, "groth16", "plonk", 1)
		plonkEntries := []bavard.Entry{
			{File: filepath.Join(plonkRoot, "doc.go"), Templates: []string{"plonk.icicle.doc.go.tmpl"}},
			{File: filepath.Join(plonkRoot, "icicle.go"), Templates: []string{"plonk.icicle.go.tmpl"}},
			{File: filepath.Join(plonkRoot, "provingkey.go"), Templates: []string{"plonk.icicle.provingkey.go.tmpl"}},
		}
		if err := bgen.Generate(d, d.CurvePkg, "./templates/", plonkEntries...); err != nil {
			panic(err)
		}

		// solver-output cache helpers used by the accelerated backends; these
		// live in the per-curve constraint package to access unexported types.
		cacheEntry := bavard.Entry{
			File:      filepath.Join("../../../../../constraint", strings.ToLower(d.Curve), "solution_cache.go"),
			Templates: []string{"constraint.solution_cache.go.tmpl"},
		}
		if err := bgen.Generate(d, "cs", "./templates/", cacheEntry); err != nil {
			panic(err)
		}
	}

	runCmd("gofmt", "-w", "../../groth16", "../../plonk")
	for _, d := range data {
		runCmd("gofmt", "-w", filepath.Join("../../../../../constraint", strings.ToLower(d.Curve), "solution_cache.go"))
	}
	runGoImports()
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

func runGoImports() {
	fmt.Println("go tool goimports", "-w", "../../groth16", "../../plonk")
	cmd := exec.Command("go", "tool", "goimports", "-w", "../../groth16", "../../plonk")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}

}
