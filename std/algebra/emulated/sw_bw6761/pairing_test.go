package sw_bw6761

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func randomG1G2Affines() (bw6761.G1Affine, bw6761.G2Affine) {
	_, _, G1AffGen, G2AffGen := bw6761.Generators()
	mod := bw6761.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bw6761.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bw6761.G2Affine
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
		return fmt.Errorf("Miller loop: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMillerLoopTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines()
	p2, q2 := randomG1G2Affines()
	res, err := bw6761.MillerLoopDirect(
		[]bw6761.G1Affine{p1, p2},
		[]bw6761.G2Affine{q1, q2},
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

type FinalExponentiationIsOneCircuit struct {
	In1G1, In2G1 G1Affine
	In1G2, In2G2 G2Affine
}

func (c *FinalExponentiationIsOneCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.MillerLoop([]*G1Affine{&c.In1G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("miller loop: %w", err)
	}
	pairing.AssertFinalExponentiationIsOne(res)
	return nil
}

func TestFinalExponentiationIsOneTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(p1, q1) * e(-p1, q1) = 1, so the Miller loop output has trivial final
	// exponentiation. This is a completeness check for AssertFinalExponentiationIsOne.
	p1, q1 := randomG1G2Affines()
	var p2 bw6761.G1Affine
	p2.Neg(&p1)
	q2 := q1
	witness := FinalExponentiationIsOneCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	err := test.IsSolved(&FinalExponentiationIsOneCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestFinalExponentiationIsOneSoundness(t *testing.T) {
	assert := test.NewAssert(t)
	// e(p1, q1) * e(p2, q2) for independent random pairs has non-trivial final
	// exponentiation (=/= 1), so no valid witness exists and the circuit must be
	// unsatisfiable. This is a soundness check for AssertFinalExponentiationIsOne.
	p1, q1 := randomG1G2Affines()
	p2, q2 := randomG1G2Affines()
	witness := FinalExponentiationIsOneCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	err := test.IsSolved(&FinalExponentiationIsOneCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.Error(err)
}

type FinalExponentiationCircuit struct {
	InGt GTEl
	Res  GTEl
}

func (c *FinalExponentiationCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.FinalExponentiation(&c.InGt)
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestFinalExponentiationTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var gt bw6761.GT
	gt.SetRandom()
	res := bw6761.FinalExponentiation(&gt)
	witness := FinalExponentiationCircuit{
		InGt: NewGTEl(gt),
		Res:  NewGTEl(res),
	}
	err := test.IsSolved(&FinalExponentiationCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// TestFinalExponentiationRejectsZeroInput is a regression for the easy-part 0/0:
// before the fix DivUnchecked(conj(0), 0) accepted a witness GT of 0 (only
// enforcing q·0 == 0 and leaving the quotient free). The easy part now uses
// Inverse, whose anchor result·result⁻¹ == 1 is unsatisfiable at result == 0, so
// FinalExponentiation(0) is rejected. (With honest hints result=0 solves to
// output 0 before the fix, i.e. it was accepted.)
func TestFinalExponentiationRejectsZeroInput(t *testing.T) {
	assert := test.NewAssert(t)
	var zero bw6761.GT // = 0
	witness := FinalExponentiationCircuit{InGt: NewGTEl(zero), Res: NewGTEl(zero)}
	err := test.IsSolved(&FinalExponentiationCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.Error(err, "FinalExponentiation(0) must be rejected: Inverse(0) anchor is unsatisfiable")
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
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
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
	res, err := bw6761.Pair([]bw6761.G1Affine{p}, []bw6761.G2Affine{q})
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
	res, err := bw6761.Pair([]bw6761.G1Affine{p}, []bw6761.G2Affine{q})
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
	p := make([]bw6761.G1Affine, 3)
	q := make([]bw6761.G2Affine, 3)
	for i := 0; i < 3; i++ {
		p[i] = p1
		q[i] = q1
	}

	for i := 2; i < 3; i++ {
		res, err := bw6761.Pair(p[:i], q[:i])
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
	var p2 bw6761.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bw6761.G2Affine
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
	var p1, p2, p3 bw6761.G1Affine
	var q1, q2, q3 bw6761.G2Affine
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
			g2s := make([]bw6761.G2Affine, nbPairs)
			gts := make([]bw6761.GT, nbPairs)
			var p bw6761.G1Affine
			witG2s := make([]G2Affine, nbPairs)
			witGts := make([]GTEl, nbPairs)
			for i := range nbPairs {
				p, g2s[i] = randomG1G2Affines()
				gts[i], err = bw6761.Pair([]bw6761.G1Affine{p}, []bw6761.G2Affine{g2s[i]})
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
	var p2 bw6761.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bw6761.G2Affine
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
