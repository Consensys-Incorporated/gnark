package sw_grumpkin

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type scalarMulNotEqualCircuit struct {
	Q, Honest G1Affine
	S         frontend.Variable
}

func (c *scalarMulNotEqualCircuit) Define(api frontend.API) error {
	var res G1Affine
	res.ScalarMul(api, c.Q, c.S)
	eq := api.And(api.IsZero(api.Sub(res.X, c.Honest.X)), api.IsZero(api.Sub(res.Y, c.Honest.Y)))
	api.AssertIsEqual(eq, 0)
	return nil
}

// TestScalarMulGLVGeneratorOffsetCollision pins that the default grumpkin
// ScalarMul cannot be steered into an equal-point chord. Its main loop uses the
// incomplete DoubleAndAdd and protects it only with an offset by the generator
// G, which lies in the group: for Q = [q]G every accumulator is [a·q + g]G and
// every table entry [b·q]G, so q ≡ g/(b − a) makes the last loop step compute
// DoubleAndAdd(U, U) — for any scalar and the honest decomposition. With the
// former unchecked chord division that step had the constraint λ·0 = 0 (λ
// free); the chord division is now checked, so the circuit must be
// unsatisfiable. (See also TestChordEqualInputs.)
func TestScalarMulGLVGeneratorOffsetCollision(t *testing.T) {
	cc := getInnerCurveConfig(ecc.BN254.ScalarField())
	r := cc.fr                           // grumpkin group order
	mu := new(big.Int).Sub(r, cc.lambda) // phi1Neg acts as [−λ]
	s := new(big.Int).SetBytes([]byte("grumpkin glv offset collision"))
	s.Mod(s, ecc.BN254.ScalarField())

	// honest decomposition, as in decomposeScalar: s = s1 − λ·s2
	sp := ecc.SplitScalar(s, cc.glvBasis)
	s1 := new(big.Int).Set(&sp[0])
	s2 := new(big.Int).Neg(&sp[1])
	if s1.Sign() < 0 || s2.Sign() < 0 || s1.BitLen() > 127 || s2.BitLen() > 127 {
		t.Skip("decomposition outside the gadget's range for this scalar")
	}
	const nbits = 127
	mod := func(x *big.Int) *big.Int { return x.Mod(x, r) }
	// Acc = Q + phi1Neg(Q) + G, tracked as [a]Q + [g]G
	a := mod(new(big.Int).Add(big.NewInt(1), mu))
	g := big.NewInt(1)
	digit := func(x *big.Int, i int) int64 { return 2*int64(x.Bit(i)) - 1 }
	var q *big.Int
	for i := nbits - 1; i > 0; i-- {
		b := mod(new(big.Int).Add(big.NewInt(digit(s1, i)), new(big.Int).Mul(big.NewInt(digit(s2, i)), mu)))
		if i == 1 {
			// Acc == B  <=>  a·q + g ≡ b·q
			den := mod(new(big.Int).Sub(b, a))
			q = new(big.Int).ModInverse(den, r)
			q.Mul(q, g)
			mod(q)
			break
		}
		// Acc = [2]Acc + B
		a = mod(new(big.Int).Add(new(big.Int).Lsh(a, 1), b))
		g = mod(new(big.Int).Lsh(g, 1))
	}

	_, gen := grumpkin.Generators()
	var Q, honest grumpkin.G1Affine
	Q.ScalarMultiplication(&gen, q)
	honest.ScalarMultiplication(&Q, s)
	var w scalarMulNotEqualCircuit
	w.Q.Assign(&Q)
	w.Honest.Assign(&honest)
	w.S = s
	// The test engine refuses 0/0 in DivUnchecked, but the compiled
	// constraint system accepts it (the quotient is unconstrained), so check
	// both: the slope constraint λ·0 = 0 is what a prover gets to exploit.
	if err := test.IsSolved(&scalarMulNotEqualCircuit{}, &w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ScalarMul(Q, s) returned a point != [s]Q (test engine)")
	}
	check := func(ccs constraint.ConstraintSystem, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		fw, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(fw); err == nil {
			t.Fatalf("ScalarMul(Q, s) returned a point != [s]Q (%T)", ccs)
		}
	}
	check(frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &scalarMulNotEqualCircuit{}))
	check(frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &scalarMulNotEqualCircuit{}))
}
