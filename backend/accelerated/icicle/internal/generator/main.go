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

	const copyrightHolder = "Consensys Incorporated"
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
	}

	runCmd("gofmt", "-w", "../../groth16")
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
	fmt.Println("go tool goimports", "-w", "../../groth16")
	cmd := exec.Command("go", "tool", "goimports", "-w", "../../groth16")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}

}
