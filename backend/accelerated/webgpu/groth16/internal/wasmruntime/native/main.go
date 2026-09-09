//go:build js && wasm

// Command native exposes the CPU groth16 prover to JavaScript.
package main

import (
	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/wasmruntime"
	gnarkgroth16 "github.com/consensys/gnark/backend/groth16"
)

func main() {
	if err := wasmruntime.Install(wasmruntime.Config[gnarkgroth16.ProvingKey, gnarkgroth16.VerifyingKey, gnarkgroth16.Proof]{
		GlobalName:   "gnarkGroth16RuntimeNative",
		CSFactory:    gnarkgroth16.NewCS,
		PKFactory:    gnarkgroth16.NewProvingKey,
		VKFactory:    gnarkgroth16.NewVerifyingKey,
		ProofFactory: gnarkgroth16.NewProof,
		Prove:        gnarkgroth16.Prove,
		Verify:       gnarkgroth16.Verify,
	}); err != nil {
		panic(err)
	}
	select {}
}
