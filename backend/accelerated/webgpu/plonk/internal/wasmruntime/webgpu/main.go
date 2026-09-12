//go:build js && wasm

// Command webgpu exposes the WebGPU-accelerated plonk prover to JavaScript.
package main

import (
	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/wasmruntime"
	webgpuplonk "github.com/consensys/gnark/backend/accelerated/webgpu/plonk"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

func main() {
	if err := wasmruntime.Install(wasmruntime.Config[gnarkplonk.ProvingKey, gnarkplonk.VerifyingKey, gnarkplonk.Proof]{
		GlobalName:   "gnarkPlonkRuntimeWebGPU",
		CSFactory:    gnarkplonk.NewCS,
		PKFactory:    gnarkplonk.NewProvingKey,
		VKFactory:    gnarkplonk.NewVerifyingKey,
		ProofFactory: gnarkplonk.NewProof,
		Prepare: func(ccs constraint.ConstraintSystem, pk gnarkplonk.ProvingKey) error {
			return webgpuplonk.Prepare(pk, ccs)
		},
		ReleasePK: webgpuplonk.Release,
		Prove:     gnarkplonk.Prove,
		Verify:    gnarkplonk.Verify,
	}); err != nil {
		panic(err)
	}
	select {}
}
