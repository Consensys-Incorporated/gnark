package plonk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/recursion"
)

// GetNativeProverOptions returns PLONK prover options for the native prover to
// initialize the configuration suitable for in-circuit verification.
func GetNativeProverOptions(outer, field *big.Int) backend.ProverOption {
	return func(pc *backend.ProverConfig) error {
		fsProverHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get prover fs hash: %w", err)
		}
		kzgProverHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get prover kzg hash: %w", err)
		}
		htfProverHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get hash to field: %w", err)
		}
		fsOpt := backend.WithProverChallengeHashFunction(fsProverHasher)
		if err = fsOpt(pc); err != nil {
			return fmt.Errorf("apply prover fs hash option: %w", err)
		}
		kzgOpt := backend.WithProverKZGFoldingHashFunction(kzgProverHasher)
		if err = kzgOpt(pc); err != nil {
			return fmt.Errorf("apply prover kzg folding hash option: %w", err)
		}
		htfOpt := backend.WithProverHashToFieldFunction(htfProverHasher)
		if err = htfOpt(pc); err != nil {
			return fmt.Errorf("apply prover htf option: %w", err)
		}
		return nil

	}
}

// GetNativeVerifierOptions returns PLONK verifier options to initialize the
// configuration to be compatible with in-circuit verification.
func GetNativeVerifierOptions(outer, field *big.Int) backend.VerifierOption {
	return func(vc *backend.VerifierConfig) error {
		fsVerifierHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get verifier fs hash: %w", err)
		}
		kzgVerifierHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get verifier kzg hash: %w", err)
		}
		htfVerifierHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get verifier hash to field: %w", err)
		}
		fsOpt := backend.WithVerifierChallengeHashFunction(fsVerifierHasher)
		if err = fsOpt(vc); err != nil {
			return fmt.Errorf("apply verifier fs hash option: %w", err)
		}
		kzgOpt := backend.WithVerifierKZGFoldingHashFunction(kzgVerifierHasher)
		if err = kzgOpt(vc); err != nil {
			return fmt.Errorf("apply verifier kzg folding hash option: %w", err)
		}
		htfOpt := backend.WithVerifierHashToFieldFunction(htfVerifierHasher)
		if err = htfOpt(vc); err != nil {
			return fmt.Errorf("apply verifier htf hash option: %w", err)
		}
		return nil
	}
}

type verifierCfg struct {
	// noSubgroupCheck disables the G1 membership checks on the prover-supplied
	// proof points. It defaults to false: the checks are on unless a caller
	// explicitly opts out with [WithNoSubgroupCheck].
	noSubgroupCheck bool
}

func newCfg(opts ...VerifierOption) (*verifierCfg, error) {
	cfg := new(verifierCfg)
	for i := range opts {
		if err := opts[i](cfg); err != nil {
			return nil, fmt.Errorf("option %d: %w", i, err)
		}
	}
	return cfg, nil
}

// VerifierOption allows to modify the behaviour of the PLONK verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithCompleteArithmetic forces the usage of complete formulas for point
// addition and multi-scalar multiplication.
//
// Deprecated: Scalar multiplication is now complete by default. This option is
// a no-op and will be removed in a future version.
func WithCompleteArithmetic() VerifierOption {
	return func(cfg *verifierCfg) error {
		return nil
	}
}

// WithNoSubgroupCheck returns a VerifierOption that skips the G1 membership
// checks on the prover-supplied proof points (LRO, H and the BSB22
// commitments).
//
// SECURITY: only use this when the caller has already asserted that every proof
// point is on the curve and in the prime-order subgroup G1. The native verifier
// checks all of them, so skipping them makes the in-circuit verifier accept
// proofs the native one rejects.
func WithNoSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.noSubgroupCheck = true
		return nil
	}
}
