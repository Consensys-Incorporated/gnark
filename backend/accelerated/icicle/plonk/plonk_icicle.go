//go:build icicle

package plonk

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	plonk_bw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bls12377 "github.com/consensys/gnark/constraint/bls12-377"
	cs_bls12381 "github.com/consensys/gnark/constraint/bls12-381"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	cs_bw6761 "github.com/consensys/gnark/constraint/bw6-761"

	icicle_bls12377 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bls12-377"
	icicle_bls12381 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bls12-381"
	icicle_bn254 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bn254"
	icicle_bw6761 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bw6-761"
	"github.com/consensys/gnark/logger"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var onceWarmUpDevice sync.Once

func warmUpDevice() {
	onceWarmUpDevice.Do(func() {
		log := logger.Logger()
		err := icicle_runtime.LoadBackendFromEnvOrDefault()
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("ICICLE backend loading error: %s", err.AsString()))
		}

		// PLONK currently proves on CUDA device 0; warm it once to reduce
		// first-use latency spikes from allocator/runtime initialization.
		device := icicle_runtime.CreateDevice("CUDA", 0)
		warmDone := make(chan error, 1)
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			stream, streamErr := icicle_runtime.CreateStream()
			if streamErr != icicle_runtime.Success {
				warmDone <- fmt.Errorf("ICICLE create stream error: %s", streamErr.AsString())
				return
			}

			var runErr error
			defer func() {
				if syncErr := icicle_runtime.SynchronizeStream(stream); syncErr != icicle_runtime.Success && runErr == nil {
					runErr = fmt.Errorf("ICICLE device warmup synchronize error: %s", syncErr.AsString())
				}
				if destroyErr := icicle_runtime.DestroyStream(stream); destroyErr != icicle_runtime.Success && runErr == nil {
					runErr = fmt.Errorf("ICICLE destroy stream error: %s", destroyErr.AsString())
				}
				warmDone <- runErr
			}()

			if warmErr := icicle_runtime.WarmUpDevice(stream); warmErr != icicle_runtime.Success {
				runErr = fmt.Errorf("ICICLE device warmup error: %s", warmErr.AsString())
				return
			}
		})

		if warmErr := <-warmDone; warmErr != nil {
			panic(warmErr)
		}
		log.Debug().Str("device", "CUDA:0").Msg("ICICLE backend initialized and warmed for PLONK")
	})
}

// Prove runs the accelerated prover for supported curves.
func Prove(ccs constraint.ConstraintSystem, pk native_plonk.ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (native_plonk.Proof, error) {
	warmUpDevice()
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		// Accept both ICICLE-wrapped and native proving keys; wrap if needed.
		var iciclePK *icicle_bn254.ProvingKey
		switch t := pk.(type) {
		case *icicle_bn254.ProvingKey:
			iciclePK = t
		case *plonk_bn254.ProvingKey:
			// Wrap native proving key into ICICLE proving key; device buffers will be initialized lazily.
			iciclePK = &icicle_bn254.ProvingKey{ProvingKey: *t}
		default:
			return nil, fmt.Errorf("icicle plonk: unsupported proving key type %T for BN254", pk)
		}
		return icicle_bn254.Prove(tccs, iciclePK, fullWitness, opts...)
	case *cs_bls12377.SparseR1CS:
		// Accept both ICICLE-wrapped and native proving keys; wrap if needed.
		var iciclePK *icicle_bls12377.ProvingKey
		switch t := pk.(type) {
		case *icicle_bls12377.ProvingKey:
			iciclePK = t
		case *plonk_bls12377.ProvingKey:
			// Wrap native proving key into ICICLE proving key; device buffers will be initialized lazily.
			iciclePK = &icicle_bls12377.ProvingKey{ProvingKey: *t}
		default:
			return nil, fmt.Errorf("icicle plonk: unsupported proving key type %T for BLS12-377", pk)
		}
		return icicle_bls12377.Prove(tccs, iciclePK, fullWitness, opts...)
	case *cs_bls12381.SparseR1CS:
		// Accept both ICICLE-wrapped and native proving keys; wrap if needed.
		var iciclePK *icicle_bls12381.ProvingKey
		switch t := pk.(type) {
		case *icicle_bls12381.ProvingKey:
			iciclePK = t
		case *plonk_bls12381.ProvingKey:
			// Wrap native proving key into ICICLE proving key; device buffers will be initialized lazily.
			iciclePK = &icicle_bls12381.ProvingKey{ProvingKey: *t}
		default:
			return nil, fmt.Errorf("icicle plonk: unsupported proving key type %T for BLS12-381", pk)
		}
		return icicle_bls12381.Prove(tccs, iciclePK, fullWitness, opts...)
	case *cs_bw6761.SparseR1CS:
		// Accept both ICICLE-wrapped and native proving keys; wrap if needed.
		var iciclePK *icicle_bw6761.ProvingKey
		switch t := pk.(type) {
		case *icicle_bw6761.ProvingKey:
			iciclePK = t
		case *plonk_bw6761.ProvingKey:
			// Wrap native proving key into ICICLE proving key; device buffers will be initialized lazily.
			iciclePK = &icicle_bw6761.ProvingKey{ProvingKey: *t}
		default:
			return nil, fmt.Errorf("icicle plonk: unsupported proving key type %T for BW6-761", pk)
		}
		return icicle_bw6761.Prove(tccs, iciclePK, fullWitness, opts...)
	default:
		return nil, fmt.Errorf("icicle plonk: unsupported curve type")
	}
}

// Setup generates accelerated proving and verifying keys using the provided SRS.
func Setup(ccs constraint.ConstraintSystem, srs, srsLagrange kzg.SRS) (native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {
	warmUpDevice()
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		// Mirror groth16: wrap native Setup into an ICICLE friendly ProvingKey
		var pk icicle_bn254.ProvingKey
		vk := new(plonk_bn254.VerifyingKey)
		_nativePk, _vk, err := plonk_bn254.Setup(tccs, *srs.(*kzg_bn254.SRS), *srsLagrange.(*kzg_bn254.SRS))
		if err != nil {
			return nil, nil, err
		}
		pk.ProvingKey = *_nativePk
		*vk = *_vk
		return &pk, vk, nil
	case *cs_bls12377.SparseR1CS:
		// Mirror groth16: wrap native Setup into an ICICLE friendly ProvingKey
		var pk icicle_bls12377.ProvingKey
		vk := new(plonk_bls12377.VerifyingKey)
		_nativePk, _vk, err := plonk_bls12377.Setup(tccs, *srs.(*kzg_bls12377.SRS), *srsLagrange.(*kzg_bls12377.SRS))
		if err != nil {
			return nil, nil, err
		}
		pk.ProvingKey = *_nativePk
		*vk = *_vk
		return &pk, vk, nil
	case *cs_bls12381.SparseR1CS:
		// Mirror groth16: wrap native Setup into an ICICLE friendly ProvingKey
		var pk icicle_bls12381.ProvingKey
		vk := new(plonk_bls12381.VerifyingKey)
		_nativePk, _vk, err := plonk_bls12381.Setup(tccs, *srs.(*kzg_bls12381.SRS), *srsLagrange.(*kzg_bls12381.SRS))
		if err != nil {
			return nil, nil, err
		}
		pk.ProvingKey = *_nativePk
		*vk = *_vk
		return &pk, vk, nil
	case *cs_bw6761.SparseR1CS:
		// Mirror groth16: wrap native Setup into an ICICLE friendly ProvingKey
		var pk icicle_bw6761.ProvingKey
		vk := new(plonk_bw6761.VerifyingKey)
		_nativePk, _vk, err := plonk_bw6761.Setup(tccs, *srs.(*kzg_bw6761.SRS), *srsLagrange.(*kzg_bw6761.SRS))
		if err != nil {
			return nil, nil, err
		}
		pk.ProvingKey = *_nativePk
		*vk = *_vk
		return &pk, vk, nil
	default:
		return nil, nil, fmt.Errorf("icicle plonk: unsupported curve type")
	}
}

// NewProvingKey creates an empty proving key for deserialization for supported curves.
func NewProvingKey(curveID ecc.ID) native_plonk.ProvingKey {
	switch curveID {
	case ecc.BN254:
		return &icicle_bn254.ProvingKey{}
	case ecc.BLS12_377:
		return &icicle_bls12377.ProvingKey{}
	case ecc.BLS12_381:
		return &icicle_bls12381.ProvingKey{}
	case ecc.BW6_761:
		return &icicle_bw6761.ProvingKey{}
	default:
		panic("icicle plonk: unsupported curve")
	}
}
