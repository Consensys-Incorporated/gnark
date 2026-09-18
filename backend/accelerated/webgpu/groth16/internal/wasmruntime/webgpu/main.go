//go:build js && wasm

// Command webgpu exposes the WebGPU-accelerated groth16 prover to JavaScript.
package main

import (
	webgpugroth16 "github.com/consensys/gnark/backend/accelerated/webgpu/groth16"
	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/wasmruntime"
	gnarkgroth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

func main() {
	if err := wasmruntime.Install(wasmruntime.Config[gnarkgroth16.ProvingKey, gnarkgroth16.VerifyingKey, gnarkgroth16.Proof]{
		GlobalName:   "gnarkGroth16RuntimeWebGPU",
		CSFactory:    gnarkgroth16.NewCS,
		PKFactory:    gnarkgroth16.NewProvingKey,
		VKFactory:    gnarkgroth16.NewVerifyingKey,
		ProofFactory: gnarkgroth16.NewProof,
		Prepare: func(_ constraint.ConstraintSystem, pk gnarkgroth16.ProvingKey) error {
			return webgpugroth16.Prepare(pk)
		},
		ReleasePK: webgpugroth16.Release,
		Prove:     gnarkgroth16.Prove,
		Verify:    gnarkgroth16.Verify,
	}); err != nil {
		panic(err)
	}
	select {}
}
