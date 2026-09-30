//go:build js && wasm

package groth16

import (
	"fmt"

	webgpu_bls12377 "github.com/consensys/gnark/backend/accelerated/webgpu/groth16/bls12-377"
	webgpu_bls12381 "github.com/consensys/gnark/backend/accelerated/webgpu/groth16/bls12-381"
	webgpu_bn254 "github.com/consensys/gnark/backend/accelerated/webgpu/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// Prepare uploads the bases of pk to the GPU and attaches a WebGPU accelerator
// to it, so that subsequent calls to groth16.Prove with pk run their MSMs and
// quotient computation on the GPU. It is idempotent and safe to call before the
// first proof to keep the one-time setup cost out of it.
func Prepare(pk groth16.ProvingKey) error {
	var err error
	switch pk := pk.(type) {
	case *groth16_bn254.ProvingKey:
		_, err = webgpu_bn254.Attach(pk)
	case *groth16_bls12377.ProvingKey:
		_, err = webgpu_bls12377.Attach(pk)
	case *groth16_bls12381.ProvingKey:
		_, err = webgpu_bls12381.Attach(pk)
	default:
		return fmt.Errorf("webgpu groth16: unsupported proving key %T", pk)
	}
	return err
}

// Release frees the GPU resources attached to pk by Prepare and restores the
// CPU prover.
func Release(pk groth16.ProvingKey) error {
	type releaser interface{ Release() error }
	var acc any
	switch pk := pk.(type) {
	case *groth16_bn254.ProvingKey:
		acc = pk.Accelerator()
	case *groth16_bls12377.ProvingKey:
		acc = pk.Accelerator()
	case *groth16_bls12381.ProvingKey:
		acc = pk.Accelerator()
	default:
		return fmt.Errorf("webgpu groth16: unsupported proving key %T", pk)
	}
	if r, ok := acc.(releaser); ok {
		return r.Release()
	}
	return nil
}
