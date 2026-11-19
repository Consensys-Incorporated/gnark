package pedersen

import "fmt"

type verifierCfg struct {
	// noSubgroupCheck disables the G1 membership checks on the commitment and
	// the knowledge proof. It defaults to false: the checks are on unless a
	// caller explicitly opts out with [WithNoSubgroupCheck].
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

// VerifierOption allows to modify the behaviour of Pedersen verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithSubgroupCheck returns a VerifierOption that forces subgroup check.
//
// Deprecated: the commitment and knowledge proof are now validated by default.
// This option is a no-op and will be removed in a future version.
func WithSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		return nil
	}
}

// WithNoSubgroupCheck returns a VerifierOption that skips the G1 membership
// checks on the commitment and the knowledge proof.
//
// SECURITY: only use this when the caller has already asserted that both points
// are on the curve and in the prime-order subgroup G1. Without that, the
// verification is unsound: the in-circuit Miller loop treats y == 0 as the point
// at infinity, so an arbitrary (x, 0) contributes a factor of 1 to the pairing
// and satisfies the pairing check for free.
func WithNoSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.noSubgroupCheck = true
		return nil
	}
}
