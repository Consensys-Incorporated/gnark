package groth16

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/recursion"
)

type verifierCfg struct {
	algopt []algopts.AlgebraOption
	pedopt []pedersen.VerifierOption
	// noSubgroupCheck disables the membership checks on the prover-supplied
	// proof points. It defaults to false: the checks are on unless a caller
	// explicitly opts out with [WithNoSubgroupCheck].
	noSubgroupCheck bool
}

// VerifierOption allows to modify the behaviour of Groth16 verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithCompleteArithmetic returns a VerifierOption that forces complete arithmetic.
//
// Deprecated: Scalar multiplication is now complete by default. This option is
// a no-op and will be removed in a future version.
func WithCompleteArithmetic() VerifierOption {
	return func(cfg *verifierCfg) error {
		return nil
	}
}

// WithSubgroupCheck returns a VerifierOption that forces subgroup checks.
//
// Deprecated: the proof points are now validated by default. This option is a
// no-op and will be removed in a future version.
func WithSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		return nil
	}
}

// WithNoSubgroupCheck returns a VerifierOption that skips the membership checks
// on the prover-supplied proof points (Ar, Krs, Bs and the Pedersen commitment
// and its knowledge proof).
//
// SECURITY: only use this when the caller has already asserted that every proof
// point is on its curve and in the correct prime-order subgroup. Without that,
// the verification is unsound: the in-circuit Miller loop treats y == 0 as the
// point at infinity, so an arbitrary (x, 0) is a free identity element, and a
// point outside the prime-order subgroup pairs to the same value as its
// in-subgroup part.
func WithNoSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.pedopt = append(cfg.pedopt, pedersen.WithNoSubgroupCheck())
		cfg.noSubgroupCheck = true
		return nil
	}
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

// GetNativeProverOptions returns Groth16 prover options for the native prover
// to initialize the configuration suitable for in-circuit verification.
func GetNativeProverOptions(outer, field *big.Int) backend.ProverOption {
	return func(pc *backend.ProverConfig) error {
		htfProverHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get hash to field: %w", err)
		}
		htfOpt := backend.WithProverHashToFieldFunction(htfProverHasher)
		if err = htfOpt(pc); err != nil {
			return fmt.Errorf("apply prover htf option: %w", err)
		}
		return nil

	}
}

// GetNativeVerifierOptions returns Groth16 verifier options to initialize the
// configuration to be compatible with in-circuit verification.
func GetNativeVerifierOptions(outer, field *big.Int) backend.VerifierOption {
	return func(vc *backend.VerifierConfig) error {
		htfVerifierHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get hash to field: %w", err)
		}
		htfOpt := backend.WithVerifierHashToFieldFunction(htfVerifierHasher)
		if err = htfOpt(vc); err != nil {
			return fmt.Errorf("apply verifier htf option: %w", err)
		}
		return nil
	}
}
