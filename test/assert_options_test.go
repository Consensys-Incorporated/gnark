package test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
)

func optionsTestHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
	out[0].Set(in[0])
	return nil
}

func TestProverOptsKeepSolverOpts(t *testing.T) {
	for name, opts := range map[string][]TestingOption{
		"solver_then_prover": {
			WithSolverOpts(solver.WithHints(optionsTestHint)),
			WithProverOpts(backend.WithProverHashToFieldFunction(sha256.New())),
		},
		"prover_then_solver": {
			WithProverOpts(backend.WithProverHashToFieldFunction(sha256.New())),
			WithSolverOpts(solver.WithHints(optionsTestHint)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			var opt testingConfig
			for _, o := range opts {
				if err := o(&opt); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := backend.NewProverConfig(opt.proverOpts...)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.SolverOpts) != 1 {
				t.Fatalf("expected the solver options in the prover config, got %d", len(cfg.SolverOpts))
			}
			if cfg.HashToFieldFn == nil {
				t.Fatal("expected the prover hash to field function to be set")
			}
		})
	}
}
