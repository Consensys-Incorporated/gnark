package sw_bn254

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func randomG1G2Affines() (bn254.G1Affine, bn254.G2Affine) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type MillerLoopCircuit struct {
	In1G1, In2G1 G1Affine
	In1G2, In2G2 G2Affine
	Res          GTEl
}

func (c *MillerLoopCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.MillerLoop([]*G1Affine{&c.In1G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMillerLoopTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines()
	p2, q2 := randomG1G2Affines()
	lines1 := bn254.PrecomputeLines(q1)
	lines2 := bn254.PrecomputeLines(q2)
	res, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{p1, p2},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines1, lines2},
	)
	assert.NoError(err)
	witness := MillerLoopCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
		Res:   NewGTEl(res),
	}
	err = test.IsSolved(&MillerLoopCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MillerLoopSingleCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
}

func (c *MillerLoopSingleCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	mlres, err := pairing.MillerLoop([]*G1Affine{&c.InG1}, []*G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("miller loop: %w", err)
	}
	pairing.AssertIsEqual(mlres, &c.Res)
	return nil
}

func TestMillerLoopSingleTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		p, q := randomG1G2Affines()
		lines := bn254.PrecomputeLines(q)
		res, err := bn254.MillerLoopFixedQ([]bn254.G1Affine{p}, [][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines})
		assert.NoError(err)
		witness := MillerLoopSingleCircuit{
			InG1: NewG1Affine(p),
			InG2: NewG2Affine(q),
			Res:  NewGTEl(res),
		}
		err = test.IsSolved(&MillerLoopSingleCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=valid")
	assert.Run(func(assert *test.Assert) {
		_, q := randomG1G2Affines()
		var p bn254.G1Affine
		p.SetInfinity()
		lines := bn254.PrecomputeLines(q)
		res, err := bn254.MillerLoopFixedQ([]bn254.G1Affine{p}, [][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines})
		assert.NoError(err)
		witness := MillerLoopSingleCircuit{
			InG1: NewG1Affine(p),
			InG2: NewG2Affine(q),
			Res:  NewGTEl(res),
		}
		err = test.IsSolved(&MillerLoopSingleCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=g1-zero")
	assert.Run(func(assert *test.Assert) {
		p, _ := randomG1G2Affines()
		var q bn254.G2Affine
		q.SetInfinity()
		lines := bn254.PrecomputeLines(q)
		res, err := bn254.MillerLoopFixedQ([]bn254.G1Affine{p}, [][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines})
		assert.NoError(err)
		witness := MillerLoopSingleCircuit{
			InG1: NewG1Affine(p),
			InG2: NewG2Affine(q),
			Res:  NewGTEl(res),
		}
		err = test.IsSolved(&MillerLoopSingleCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=g2-zero")
	assert.Run(func(assert *test.Assert) {
		var p bn254.G1Affine
		var q bn254.G2Affine
		p.SetInfinity()
		q.SetInfinity()
		lines := bn254.PrecomputeLines(q)
		res, err := bn254.MillerLoopFixedQ([]bn254.G1Affine{p}, [][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines})
		assert.NoError(err)
		witness := MillerLoopSingleCircuit{
			InG1: NewG1Affine(p),
			InG2: NewG2Affine(q),
			Res:  NewGTEl(res),
		}
		err = test.IsSolved(&MillerLoopSingleCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=g1-g2-zero")
}

func TestMillerLoopRejectsOffTwistG2(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p, q := bn254.Generators()

	// Scaling (x, y) by (s^2, s^3) maps Q to an isomorphic curve with
	// coefficient s^6*b; for s^6 != 1, the result is off the original twist.
	var s, s2, s3 bn254.E2
	s.A0.SetUint64(2)
	s.A1.SetZero()
	s2.Square(&s)
	s3.Mul(&s2, &s)
	q.X.Mul(&q.X, &s2)
	q.Y.Mul(&q.Y, &s3)
	assert.False(q.IsOnCurve())

	lines := bn254.PrecomputeLines(q)
	res, err := bn254.MillerLoopFixedQ([]bn254.G1Affine{p}, [][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines})
	assert.NoError(err)
	witness := MillerLoopSingleCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&MillerLoopSingleCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "expected off-twist G2 input to be rejected")
}

type FinalExponentiation struct {
	InGt GTEl
	Res  GTEl
}

func (c *FinalExponentiation) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	expected := pairing.FinalExponentiation(&c.InGt)
	pairing.AssertIsEqual(expected, &c.Res)
	return nil
}

func TestFinalExponentiationTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var gt bn254.GT
	gt.SetRandom()
	res := bn254.FinalExponentiation(&gt)
	witness := FinalExponentiation{
		InGt: NewGTEl(gt),
		Res:  NewGTEl(res),
	}
	err := test.IsSolved(&FinalExponentiation{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FinalExponentiationIsOne struct {
	InGt GTEl
}

func (c *FinalExponentiationIsOne) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertFinalExponentiationIsOne(&c.InGt)
	return nil
}

func TestFinalExponentiationIsOneTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
	ml, err := bn254.MillerLoop(
		[]bn254.G1Affine{p1, p2},
		[]bn254.G2Affine{q1, q2},
	)
	assert.NoError(err)
	witness := FinalExponentiationIsOne{
		InGt: NewGTEl(ml),
	}
	err = test.IsSolved(&FinalExponentiationIsOne{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type PairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.Pair([]*G1Affine{&c.InG1}, []*G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestPairFixedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2AffineFixed(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{InG2: NewG2AffineFixedPlaceholder()}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiPairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
	n    int
}

func (c *MultiPairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	P, Q := []*G1Affine{}, []*G2Affine{}
	for i := 0; i < c.n; i++ {
		P = append(P, &c.InG1)
		Q = append(Q, &c.InG2)
	}
	res, err := pairing.Pair(P, Q)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiPairTestSolve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines()
	p := make([]bn254.G1Affine, 4)
	q := make([]bn254.G2Affine, 4)
	for i := 0; i < 4; i++ {
		p[i] = p1
		q[i] = q1
	}

	for i := 2; i < 4; i++ {
		res, err := bn254.Pair(p[:i], q[:i])
		assert.NoError(err)
		witness := MultiPairCircuit{
			InG1: NewG1Affine(p1),
			InG2: NewG2Affine(q1),
			Res:  NewGTEl(res),
		}
		err = test.IsSolved(&MultiPairCircuit{n: i}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type PairingCheckCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
}

func (c *PairingCheckCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	err = pairing.PairingCheck([]*G1Affine{&c.In1G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func TestPairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
	witness := PairingCheckCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	err := test.IsSolved(&PairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ThreePairingCheckCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In3G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
	In3G2 G2Affine
}

func (c *ThreePairingCheckCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	err = pairing.PairingCheck(
		[]*G1Affine{&c.In1G1, &c.In2G1, &c.In3G1},
		[]*G2Affine{&c.In1G2, &c.In2G2, &c.In3G2},
	)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func TestThreePairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(2a, 2b) * e(-2a, b) * e(a, -2b) == 1

	p, q := randomG1G2Affines()
	var p1, p2, p3 bn254.G1Affine
	var q1, q2, q3 bn254.G2Affine
	p1.Double(&p)
	q1.Double(&q)
	p2.Neg(&p1)
	q2.Set(&q)
	p3.Set(&p)
	q3.Neg(&q1)

	witness := ThreePairingCheckCircuit{
		In1G1: NewG1Affine(p1), // 2p
		In1G2: NewG2Affine(q1), // 2q
		In2G1: NewG1Affine(p2), // -2p
		In2G2: NewG2Affine(q2), // q
		In3G1: NewG1Affine(p3), // p
		In3G2: NewG2Affine(q3), // -2q
	}
	err := test.IsSolved(&ThreePairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type GroupMembershipCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
}

func (c *GroupMembershipCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	return nil
}

func TestGroupMembershipSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	witness := GroupMembershipCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
	}
	err := test.IsSolved(&GroupMembershipCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsOnTwistCircuit struct {
	Q        G2Affine
	Expected frontend.Variable
}

func (c *IsOnTwistCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.IsOnTwist(&c.Q)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestIsOnTwistSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// test for a point not on the twist
	var Q bn254.G2Affine
	_, err := Q.X.A0.SetString("0x119606e6d3ea97cea4eff54433f5c7dbc026b8d0670ddfbe6441e31225028d31")
	assert.NoError(err)
	_, err = Q.X.A1.SetString("0x1d3df5be6084324da6333a6ad1367091ca9fbceb70179ec484543a58b8cb5d63")
	assert.NoError(err)
	_, err = Q.Y.A0.SetString("0x1b9a36ea373fe2c5b713557042ce6deb2907d34e12be595f9bbe84c144de86ef")
	assert.NoError(err)
	_, err = Q.Y.A1.SetString("0x49fe60975e8c78b7b31a6ed16a338ac8b28cf6a065cfd2ca47e9402882518ba0")
	assert.NoError(err)
	assert.False(Q.IsOnCurve())
	witness := IsOnTwistCircuit{
		Q:        NewG2Affine(Q),
		Expected: 0,
	}
	err = test.IsSolved(&IsOnTwistCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test for a point on the twist
	_, Q = randomG1G2Affines()
	assert.True(Q.IsOnCurve())
	witness = IsOnTwistCircuit{
		Q:        NewG2Affine(Q),
		Expected: 1,
	}
	err = test.IsSolved(&IsOnTwistCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsOnG2Circuit struct {
	Q        G2Affine
	Expected frontend.Variable
}

func (c *IsOnG2Circuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.IsOnG2(&c.Q)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestIsOnG2Solve(t *testing.T) {
	assert := test.NewAssert(t)
	// test for a point not on the curve
	var Q bn254.G2Affine
	_, err := Q.X.A0.SetString("0x119606e6d3ea97cea4eff54433f5c7dbc026b8d0670ddfbe6441e31225028d31")
	assert.NoError(err)
	_, err = Q.X.A1.SetString("0x1d3df5be6084324da6333a6ad1367091ca9fbceb70179ec484543a58b8cb5d63")
	assert.NoError(err)
	_, err = Q.Y.A0.SetString("0x1b9a36ea373fe2c5b713557042ce6deb2907d34e12be595f9bbe84c144de86ef")
	assert.NoError(err)
	_, err = Q.Y.A1.SetString("0x49fe60975e8c78b7b31a6ed16a338ac8b28cf6a065cfd2ca47e9402882518ba0")
	assert.NoError(err)
	assert.False(Q.IsOnCurve())
	witness := IsOnG2Circuit{
		Q:        NewG2Affine(Q),
		Expected: 0,
	}
	err = test.IsSolved(&IsOnG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test for a point on curve not in G2
	_, err = Q.X.A0.SetString("0x07192b9fd0e2a32e3e1caa8e59462b757326d48f641924e6a1d00d66478913eb")
	assert.NoError(err)
	_, err = Q.X.A1.SetString("0x15ce93f1b1c4946dd6cfbb3d287d9c9a1cdedb264bda7aada0844416d8a47a63")
	assert.NoError(err)
	_, err = Q.Y.A0.SetString("0x0fa65a9b48ba018361ed081e3b9e958451de5d9e8ae0bd251833ebb4b2fafc96")
	assert.NoError(err)
	_, err = Q.Y.A1.SetString("0x06e1f5e20f68f6dfa8a91a3bea048df66d9eaf56cc7f11215401f7e05027e0c6")
	assert.NoError(err)
	assert.True(Q.IsOnCurve())
	assert.False(Q.IsInSubGroup())
	witness = IsOnG2Circuit{
		Q:        NewG2Affine(Q),
		Expected: 0,
	}
	err = test.IsSolved(&IsOnG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test for a point in G2
	_, Q = randomG1G2Affines()
	assert.True(Q.IsOnCurve())
	assert.True(Q.IsInSubGroup())
	witness = IsOnG2Circuit{
		Q:        NewG2Affine(Q),
		Expected: 1,
	}
	err = test.IsSolved(&IsOnG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsMillerLoopAndFinalExpCircuit struct {
	Prev     GTEl
	P        G1Affine
	Q        G2Affine
	Expected frontend.Variable
}

func (c *IsMillerLoopAndFinalExpCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.IsMillerLoopAndFinalExpOne(&c.P, &c.Q, &c.Prev)
	api.AssertIsEqual(res, c.Expected)
	return nil

}

func TestIsMillerLoopAndFinalExpCircuitTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()

	var np bn254.G1Affine
	np.Neg(&p)

	ok, err := bn254.PairingCheck([]bn254.G1Affine{p, np}, []bn254.G2Affine{q, q})
	assert.NoError(err)
	assert.True(ok)

	lines := bn254.PrecomputeLines(q)
	// need to use ML with precomputed lines. Otherwise, the result will be different
	mlres, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{p},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{lines},
	)
	assert.NoError(err)

	witness := IsMillerLoopAndFinalExpCircuit{
		Prev:     NewGTEl(mlres),
		P:        NewG1Affine(np),
		Q:        NewG2Affine(q),
		Expected: 1,
	}
	err = test.IsSolved(&IsMillerLoopAndFinalExpCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	var randPrev bn254.GT
	randPrev.SetRandom()

	witness = IsMillerLoopAndFinalExpCircuit{
		Prev:     NewGTEl(randPrev),
		P:        NewG1Affine(np),
		Q:        NewG2Affine(q),
		Expected: 0,
	}
	err = test.IsSolved(&IsMillerLoopAndFinalExpCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MuxesCircuits struct {
	InG2       []G2Affine
	InGt       []GTEl
	SelG2      frontend.Variable
	SelGt      frontend.Variable
	ExpectedG2 G2Affine
	ExpectedGt GTEl
}

func (c *MuxesCircuits) Define(api frontend.API) error {
	g2api, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2: %w", err)
	}
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	var inG2 []*G2Affine
	for i := range c.InG2 {
		inG2 = append(inG2, &c.InG2[i])
	}
	var inGt []*GTEl
	for i := range c.InGt {
		inGt = append(inGt, &c.InGt[i])
	}
	g2 := pairing.MuxG2(c.SelG2, inG2...)
	gt := pairing.MuxGt(c.SelGt, inGt...)
	if len(c.InG2) == 0 {
		if g2 != nil {
			return fmt.Errorf("mux G2: expected nil, got %v", g2)
		}
	} else {
		g2api.AssertIsEqual(g2, &c.ExpectedG2)
	}
	if len(c.InGt) == 0 {
		if gt != nil {
			return fmt.Errorf("mux Gt: expected nil, got %v", gt)
		}
	} else {
		pairing.AssertIsEqual(gt, &c.ExpectedGt)
	}
	return nil
}

func TestPairingMuxes(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	for _, nbPairs := range []int{0, 1, 2, 3, 4, 5} {
		assert.Run(func(assert *test.Assert) {
			g2s := make([]bn254.G2Affine, nbPairs)
			gts := make([]bn254.GT, nbPairs)
			var p bn254.G1Affine
			witG2s := make([]G2Affine, nbPairs)
			witGts := make([]GTEl, nbPairs)
			for i := range nbPairs {
				p, g2s[i] = randomG1G2Affines()
				gts[i], err = bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{g2s[i]})
				assert.NoError(err)
				witG2s[i] = NewG2Affine(g2s[i])
				witGts[i] = NewGTEl(gts[i])
			}
			circuit := MuxesCircuits{InG2: make([]G2Affine, nbPairs), InGt: make([]GTEl, nbPairs)}
			var witness MuxesCircuits
			if nbPairs > 0 {
				selG2, err := rand.Int(rand.Reader, big.NewInt(int64(nbPairs)))
				assert.NoError(err)
				selGt, err := rand.Int(rand.Reader, big.NewInt(int64(nbPairs)))
				assert.NoError(err)
				expectedG2 := witG2s[selG2.Int64()]
				expectedGt := witGts[selGt.Int64()]
				witness = MuxesCircuits{
					InG2:       witG2s,
					InGt:       witGts,
					SelG2:      selG2,
					SelGt:      selGt,
					ExpectedG2: expectedG2,
					ExpectedGt: expectedGt,
				}
			} else {
				witness = MuxesCircuits{
					InG2:  witG2s,
					InGt:  witGts,
					SelG2: big.NewInt(0),
					SelGt: big.NewInt(0),
				}
			}
			err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
			assert.NoError(err)
		}, fmt.Sprintf("nbPairs=%d", nbPairs))
	}
}

// bench
func BenchmarkPairing(b *testing.B) {
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
	witness := PairingCheckCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	var ccs constraint.ConstraintSystem
	b.Run("compile scs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &PairingCheckCircuit{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	var buf bytes.Buffer
	_, err = ccs.WriteTo(&buf)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("scs size: %d (bytes), nb constraints %d, nbInstructions: %d", buf.Len(), ccs.GetNbConstraints(), ccs.GetNbInstructions())
	b.Run("solve scs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("compile r1cs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PairingCheckCircuit{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	buf.Reset()
	_, err = ccs.WriteTo(&buf)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("r1cs size: %d (bytes), nb constraints %d, nbInstructions: %d", buf.Len(), ccs.GetNbConstraints(), ccs.GetNbInstructions())

	b.Run("solve r1cs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// zeroHintOutputs is a malicious hint replacement returning the all-zero
// witness. It is used to exercise the residue-witness invertibility anchor.
func zeroHintOutputs(_ *big.Int, _, outputs []*big.Int) error {
	for i := range outputs {
		outputs[i].SetInt64(0)
	}
	return nil
}

// TestFinalExponentiationIsOneRejectsZeroWitness is a regression test for the
// zero-residue-witness soundness bug: the check
// x·cubicNonResiduePower == residueWitness^λ is homogeneous in the hint
// outputs, so the all-zero finalExpHint output degenerates it to 0 == 0 for
// any x. The invertibility anchor (residueWitness·residueWitness⁻¹ == 1) must
// reject it. Uses the same valid inputs as TestFinalExponentiationIsOneTestSolve.
func TestFinalExponentiationIsOneRejectsZeroWitness(t *testing.T) {
	assert := test.NewAssert(t)
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
	ml, err := bn254.MillerLoop(
		[]bn254.G1Affine{p1, p2},
		[]bn254.G2Affine{q1, q2},
	)
	assert.NoError(err)
	witness := FinalExponentiationIsOne{
		InGt: NewGTEl(ml),
	}
	err = test.IsSolved(&FinalExponentiationIsOne{}, &witness, ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(finalExpHint), zeroHintOutputs))
	assert.Error(err, "all-zero residue witness must be rejected by the invertibility anchor")
}
