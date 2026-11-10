package sw_grumpkin

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// chordEqual computes P+P2 (P2 = P, a separate witness) with AddAssign (op = 0), 2P+P with DoubleAndAdd
// (op = 1) or with DoubleAndAddSelect (op = 2), and asserts the result differs
// from the true multiple Want.
type chordEqual struct {
	P, P2, Want G1Affine
	op          int
}

func (c *chordEqual) Define(api frontend.API) error {
	var r G1Affine
	switch c.op {
	case 0:
		r = c.P
		r.AddAssign(api, c.P2)
	case 1:
		r.DoubleAndAdd(api, &c.P, &c.P2)
	case 2:
		r.DoubleAndAddSelect(api, 1, &c.P, &c.P2)
	}
	eq := api.And(api.IsZero(api.Sub(r.X, c.Want.X)), api.IsZero(api.Sub(r.Y, c.Want.Y)))
	api.AssertIsEqual(eq, 0)
	return nil
}

// TestChordEqualInputs is a regression test for AddAssign, DoubleAndAdd and
// DoubleAndAddSelect using an unchecked division for the chord slope: on equal
// inputs the slope constraint is λ·0 = 0, the R1CS solver picks λ = 0, and the
// circuit is satisfied with a wrong result. They must be unsatisfiable instead.
func TestChordEqualInputs(t *testing.T) {
	_, g := grumpkin.Generators()
	for op, k := range []int64{2, 3, 3} {
		var want grumpkin.G1Affine
		want.ScalarMultiplication(&g, big.NewInt(k))
		w := chordEqual{op: op}
		w.P.Assign(&g)
		w.P2.Assign(&g)
		w.Want.Assign(&want)
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &chordEqual{op: op})
		if err != nil {
			t.Fatal(err)
		}
		fw, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(fw); err == nil {
			t.Errorf("op %d on equal inputs returned a point != [%d]P", op, k)
		}
	}
}

type doubleInf struct{ P G1Affine }

func (c *doubleInf) Define(api frontend.API) error {
	var r G1Affine
	r.Double(api, c.P)
	return nil
}

// TestDoubleInfinity is a regression test for Double using an unchecked
// division for the tangent slope: on the (0,0) infinity encoding the slope
// constraint is λ·0 = 0, so the result (λ², −λ³) was prover-chosen. It must be
// unsatisfiable instead.
func TestDoubleInfinity(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &doubleInf{})
	if err != nil {
		t.Fatal(err)
	}
	fw, err := frontend.NewWitness(&doubleInf{P: G1Affine{X: 0, Y: 0}}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(fw); err == nil {
		t.Error("Double((0,0)) is satisfiable")
	}
}
