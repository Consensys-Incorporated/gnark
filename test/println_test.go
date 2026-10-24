package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/rs/zerolog"
)

type printlnPercentCircuit struct {
	X frontend.Variable
}

func (c *printlnPercentCircuit) Define(api frontend.API) error {
	api.Println("progress 100%", c.X)
	api.AssertIsEqual(c.X, 7)
	return nil
}

// TestPrintlnLiteralPercent checks that a literal '%' in a printed string is
// not interpreted as a formatting verb when the solver resolves the log.
func TestPrintlnLiteralPercent(t *testing.T) {
	field := ecc.BN254.ScalarField()
	builders := map[string]frontend.NewBuilder{
		"r1cs": r1cs.NewBuilder[constraint.U64],
		"scs":  scs.NewBuilder[constraint.U64],
	}
	for name, nb := range builders {
		t.Run(name, func(t *testing.T) {
			ccs, err := frontend.Compile(field, nb, &printlnPercentCircuit{})
			if err != nil {
				t.Fatal(err)
			}
			w, err := frontend.NewWitness(&printlnPercentCircuit{X: 7}, field)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			logger := zerolog.New(&buf).Level(zerolog.DebugLevel)
			if _, err := ccs.Solve(w, solver.WithLogger(logger)); err != nil {
				t.Fatal(err)
			}
			if out := buf.String(); !strings.Contains(out, "progress 100% 7") {
				t.Fatalf("unexpected log output: %s", strings.TrimSpace(out))
			}
		})
	}
}
