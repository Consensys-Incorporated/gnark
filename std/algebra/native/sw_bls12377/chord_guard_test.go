package sw_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// chordEqualG1 computes P+P with AddAssign (op = 0) or 2P+P with DoubleAndAdd
// (op = 1) and asserts the result differs from the true multiple Want.
type chordEqualG1 struct {
	P, P2, Want G1Affine
	op          int
}

func (c *chordEqualG1) Define(api frontend.API) error {
	var r G1Affine
	switch c.op {
	case 0:
		r = c.P
		r.AddAssign(api, c.P2)
	case 1:
		r.DoubleAndAdd(api, &c.P, &c.P2)
	}
	eq := api.And(api.IsZero(api.Sub(r.X, c.Want.X)), api.IsZero(api.Sub(r.Y, c.Want.Y)))
	api.AssertIsEqual(eq, 0)
	return nil
}

type chordEqualG2 struct {
	P, P2, Want g2AffP
	op          int
}

func (c *chordEqualG2) Define(api frontend.API) error {
	var r g2AffP
	switch c.op {
	case 0:
		r = c.P
		r.AddAssign(api, c.P2)
	case 1:
		r.DoubleAndAdd(api, &c.P, &c.P2)
	}
	eq := api.And(
		api.And(api.IsZero(api.Sub(r.X.A0, c.Want.X.A0)), api.IsZero(api.Sub(r.X.A1, c.Want.X.A1))),
		api.And(api.IsZero(api.Sub(r.Y.A0, c.Want.Y.A0)), api.IsZero(api.Sub(r.Y.A1, c.Want.Y.A1))),
	)
	api.AssertIsEqual(eq, 0)
	return nil
}

func solveR1CS(t *testing.T, circuit, w frontend.Circuit) error {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := frontend.NewWitness(w, ecc.BW6_761.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return ccs.IsSolved(fw)
}

// TestChordEqualInputs is a regression test for AddAssign and DoubleAndAdd
// using an unchecked division for the chord slope: on equal inputs the slope
// constraint is λ·0 = 0, the R1CS solver picks λ = 0, and the circuit is
// satisfied with a wrong result. They must be unsatisfiable instead.
func TestChordEqualInputs(t *testing.T) {
	_, _, g1, g2 := bls12377.Generators()
	for op, k := range []int64{2, 3} {
		var w1 bls12377.G1Affine
		w1.ScalarMultiplication(&g1, big.NewInt(k))
		var c1 chordEqualG1
		c1.op = op
		wit1 := chordEqualG1{op: op}
		wit1.P.Assign(&g1)
		wit1.P2.Assign(&g1)
		wit1.Want.Assign(&w1)
		if err := solveR1CS(t, &c1, &wit1); err == nil {
			t.Errorf("G1 op %d on equal inputs returned a point != [%d]P", op, k)
		}

		var w2 bls12377.G2Affine
		w2.ScalarMultiplication(&g2, big.NewInt(k))
		c2 := chordEqualG2{op: op}
		wit2 := chordEqualG2{op: op}
		wit2.P.Assign(&g2)
		wit2.P2.Assign(&g2)
		wit2.Want.Assign(&w2)
		if err := solveR1CS(t, &c2, &wit2); err == nil {
			t.Errorf("G2 op %d on equal inputs returned a point != [%d]P", op, k)
		}
	}
}

type doubleG1 struct{ P G1Affine }

func (c *doubleG1) Define(api frontend.API) error {
	var r G1Affine
	r.Double(api, c.P)
	return nil
}

type doubleG2 struct{ P g2AffP }

func (c *doubleG2) Define(api frontend.API) error {
	var r g2AffP
	r.Double(api, c.P)
	return nil
}

// TestDoubleInfinity is a regression test for Double using an unchecked
// division for the tangent slope: on the (0,0) infinity encoding the slope
// constraint is λ·0 = 0, so the result (λ², −λ³) was prover-chosen. It must be
// unsatisfiable instead.
func TestDoubleInfinity(t *testing.T) {
	w1 := doubleG1{P: G1Affine{X: 0, Y: 0}}
	if err := solveR1CS(t, &doubleG1{}, &w1); err == nil {
		t.Error("G1 Double((0,0)) is satisfiable")
	}
	var w2 doubleG2
	w2.P.X.A0, w2.P.X.A1, w2.P.Y.A0, w2.P.Y.A1 = 0, 0, 0, 0
	if err := solveR1CS(t, &doubleG2{}, &w2); err == nil {
		t.Error("G2 Double((0,0)) is satisfiable")
	}
}
