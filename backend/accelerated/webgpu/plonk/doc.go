//go:build js && wasm

// Package plonk attaches the browser WebGPU runtime to gnark's PLONK prover
// for wasm targets.
//
// The prover itself is gnark's native one (backend/plonk): Prepare uploads the
// SRS to the GPU and installs an implementation of the prover's Accelerator
// interface on the proving key, after which plonk.Prove runs its multi-scalar
// multiplications, the quotient numerator evaluation and the large inverse FFT
// on the GPU. The per-curve implementations in the bn254, bls12-377 and
// bls12-381 subpackages are generated from internal/generator/templates/go.
//
// The host application must install the TypeScript bridge (gnarkPlonkWebGPU on
// globalThis) before calling Prepare.
package plonk
