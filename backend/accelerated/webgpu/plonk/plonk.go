//go:build js && wasm

package plonk

import (
	"fmt"

	webgpu_bls12377 "github.com/consensys/gnark/backend/accelerated/webgpu/plonk/bls12-377"
	webgpu_bls12381 "github.com/consensys/gnark/backend/accelerated/webgpu/plonk/bls12-381"
	webgpu_bn254 "github.com/consensys/gnark/backend/accelerated/webgpu/plonk/bn254"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	cs_bls12377 "github.com/consensys/gnark/constraint/bls12-377"
	cs_bls12381 "github.com/consensys/gnark/constraint/bls12-381"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// Prepare uploads the SRS of pk to the GPU and attaches a WebGPU accelerator to
// it, so that subsequent calls to plonk.Prove with pk run their MSMs, quotient
// numerator and large inverse FFT on the GPU. If ccs, the constraint system pk
// was set up for, is not nil, the circuit-dependent caches are built too, which
// keeps the one-time setup cost out of the first proof. Prepare is idempotent.
func Prepare(pk plonk.ProvingKey, ccs constraint.ConstraintSystem) error {
	switch pk := pk.(type) {
	case *plonk_bn254.ProvingKey:
		acc, err := webgpu_bn254.Attach(pk)
		if err != nil {
			return err
		}
		if spr, ok := ccs.(*cs_bn254.SparseR1CS); ok {
			return acc.Prewarm(spr)
		}
	case *plonk_bls12377.ProvingKey:
		acc, err := webgpu_bls12377.Attach(pk)
		if err != nil {
			return err
		}
		if spr, ok := ccs.(*cs_bls12377.SparseR1CS); ok {
			return acc.Prewarm(spr)
		}
	case *plonk_bls12381.ProvingKey:
		acc, err := webgpu_bls12381.Attach(pk)
		if err != nil {
			return err
		}
		if spr, ok := ccs.(*cs_bls12381.SparseR1CS); ok {
			return acc.Prewarm(spr)
		}
	default:
		return fmt.Errorf("webgpu plonk: unsupported proving key %T", pk)
	}
	if ccs != nil {
		return fmt.Errorf("webgpu plonk: constraint system %T does not match proving key %T", ccs, pk)
	}
	return nil
}

// Release frees the GPU resources attached to pk by Prepare and restores the
// CPU prover.
func Release(pk plonk.ProvingKey) error {
	type releaser interface{ Release() error }
	var acc any
	switch pk := pk.(type) {
	case *plonk_bn254.ProvingKey:
		acc = pk.Accelerator()
	case *plonk_bls12377.ProvingKey:
		acc = pk.Accelerator()
	case *plonk_bls12381.ProvingKey:
		acc = pk.Accelerator()
	default:
		return fmt.Errorf("webgpu plonk: unsupported proving key %T", pk)
	}
	if r, ok := acc.(releaser); ok {
		return r.Release()
	}
	return nil
}
