package main

import (
	"path/filepath"

	"github.com/consensys/bavard"
)

// generateGoAccelerators writes the per-curve WebGPU accelerator packages for
// Groth16 and PLONK (backend/accelerated/webgpu/{groth16,plonk}/<curve>/) from
// the templates in templates/go/.
func generateGoAccelerators(bgen *bavard.BatchGenerator, webgpuDir, templatesDir string, data []templateData) error {
	for _, d := range data {
		entries := []bavard.Entry{
			{File: filepath.Join(webgpuDir, "groth16", d.CurveDir, "accelerator.go"), Templates: []string{"go/groth16_accelerator.go.tmpl"}, BuildTag: "js && wasm"},
			{File: filepath.Join(webgpuDir, "plonk", d.CurveDir, "accelerator.go"), Templates: []string{"go/plonk_accelerator.go.tmpl"}, BuildTag: "js && wasm"},
		}
		if err := bgen.Generate(d, d.GoPkg, templatesDir, entries...); err != nil {
			return err
		}
	}
	runCmd("gofmt", "-w", filepath.Join(webgpuDir, "groth16"), filepath.Join(webgpuDir, "plonk"))
	runCmd("go", "tool", "goimports", "-w", filepath.Join(webgpuDir, "groth16"), filepath.Join(webgpuDir, "plonk"))
	return nil
}
