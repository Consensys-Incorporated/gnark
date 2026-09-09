//go:build js && wasm

// Command native exposes the CPU plonk prover to JavaScript.
package main

import (
	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/wasmruntime"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
)

func main() {
	if err := wasmruntime.Install(wasmruntime.Config[gnarkplonk.ProvingKey, gnarkplonk.VerifyingKey, gnarkplonk.Proof]{
		GlobalName:   "gnarkPlonkRuntimeNative",
		CSFactory:    gnarkplonk.NewCS,
		PKFactory:    gnarkplonk.NewProvingKey,
		VKFactory:    gnarkplonk.NewVerifyingKey,
		ProofFactory: gnarkplonk.NewProof,
		Prove:        gnarkplonk.Prove,
		Verify:       gnarkplonk.Verify,
	}); err != nil {
		panic(err)
	}
	select {}
}
