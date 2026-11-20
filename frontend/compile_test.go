package frontend_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
)

type compileOptionsCircuit struct {
	X frontend.Variable
}

func (c *compileOptionsCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), 9)
	return nil
}

func TestCompileOptions(t *testing.T) {
	for _, option := range []struct {
		name string
		new  func(int) frontend.CompileOption
		get  func(frontend.CompileConfig) int
	}{
		{
			name: "capacity",
			new:  frontend.WithCapacity,
			get:  func(cfg frontend.CompileConfig) int { return cfg.Capacity },
		},
		{
			name: "compression threshold",
			new:  frontend.WithCompressThreshold,
			get:  func(cfg frontend.CompileConfig) int { return cfg.CompressThreshold },
		},
	} {
		t.Run(option.name, func(t *testing.T) {
			for _, value := range []int{math.MinInt, -1, 0, 1, 300} {
				t.Run(fmt.Sprint(value), func(t *testing.T) {
					t.Run("config", func(t *testing.T) {
						initial := frontend.CompileConfig{Capacity: 16, CompressThreshold: 300}
						cfg := initial
						err := option.new(value)(&cfg)
						if value < 0 {
							require.ErrorContains(t, err, "must be non-negative")
							require.Equal(t, initial, cfg)
						} else {
							require.NoError(t, err)
							require.Equal(t, value, option.get(cfg))
						}
					})

					for _, builder := range []struct {
						name string
						new  frontend.NewBuilder
					}{
						{name: "r1cs", new: r1cs.NewBuilder[constraint.U64]},
						{name: "scs", new: scs.NewBuilder[constraint.U64]},
					} {
						t.Run(builder.name, func(t *testing.T) {
							// Exercise the real builders: invalid options must return before allocation.
							var ccs constraint.ConstraintSystem
							var err error
							require.NotPanics(t, func() {
								ccs, err = frontend.Compile(ecc.BN254.ScalarField(), builder.new,
									&compileOptionsCircuit{}, option.new(value))
							})
							if value < 0 {
								require.ErrorContains(t, err, "apply option:")
								require.ErrorContains(t, err, "must be non-negative")
								require.Nil(t, ccs)
								return
							}
							require.NoError(t, err)
							witness, err := frontend.NewWitness(&compileOptionsCircuit{X: 3}, ecc.BN254.ScalarField())
							require.NoError(t, err)
							_, err = ccs.Solve(witness)
							require.NoError(t, err)
						})
					}
				})
			}
		})
	}
}
