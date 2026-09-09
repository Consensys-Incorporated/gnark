//go:build js && wasm

// Package groth16 attaches the browser WebGPU runtime to gnark's Groth16
// prover for wasm targets.
//
// The prover itself is gnark's native one (backend/groth16): Prepare uploads
// the proving key bases to the GPU and installs an implementation of the
// prover's Accelerator interface on the key, after which groth16.Prove runs its
// multi-scalar multiplications and quotient computation on the GPU while
// witness solving and the final proof assembly stay in Go. The per-curve
// implementations in the bn254, bls12-377 and bls12-381 subpackages are
// generated from internal/generator/templates/go.
//
// The host application must install the TypeScript bridge
// (gnarkGroth16WebGPU on globalThis) before calling Prepare.
package groth16
