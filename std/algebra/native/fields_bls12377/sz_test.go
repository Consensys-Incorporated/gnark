package fields_bls12377

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/multicommit"
)

// ---------------------------------------------------------------------------
// Regression tests for the stale-commitment soundness bug in the shared
// Schwartz-Zippel checker (sz.go).
//
// The checker builds the list of committed variables eagerly in resolve(), but
// the callback handed to multicommit.WithCommitment re-reads the live
// ch.checks slice. A user multicommit callback that is registered *after* the
// first E12/E6 multiplication is invoked *before* the SZ callback, so any
// multiplication performed inside it appends a check which is verified at a
// challenge that does not commit to its own a, b, c, q.
// ---------------------------------------------------------------------------

// nbCommittedVariables returns the number of variables fed into the single
// Bsb22 commitment of a compiled SCS constraint system.
func nbCommittedVariables(t *testing.T, ccs constraint.ConstraintSystem) int {
	t.Helper()
	cmts, ok := ccs.GetCommitments().(constraint.PlonkCommitments)
	if !ok {
		t.Fatalf("expected PlonkCommitments, got %T", ccs.GetCommitments())
	}
	if len(cmts) != 1 {
		t.Fatalf("expected exactly one commitment, got %d", len(cmts))
	}
	return len(cmts[0].Committed)
}

// --- shared circuit shapes -------------------------------------------------

// szTwoMulE12Circuit performs two E12 multiplications. When InCallback is set
// the second one happens inside a user multicommit.WithCommitment callback
// that is registered after the first multiplication.
type szTwoMulE12Circuit struct {
	A, B, C    E12
	D, E, F    E12
	InCallback bool
}

func (c *szTwoMulE12Circuit) Define(api frontend.API) error {
	var r E12
	r.Mul(api, c.A, c.B)
	r.AssertIsEqual(api, c.C)

	second := func(api frontend.API) {
		var s E12
		s.Mul(api, c.D, c.E)
		s.AssertIsEqual(api, c.F)
	}

	if c.InCallback {
		multicommit.WithCommitment(api, func(api frontend.API, _ frontend.Variable) error {
			second(api)
			return nil
		})
	} else {
		second(api)
	}
	return nil
}

// szTwoMulE6Circuit is the E6 analogue of szTwoMulE12Circuit.
type szTwoMulE6Circuit struct {
	A, B, C    E6
	D, E, F    E6
	InCallback bool
}

func (c *szTwoMulE6Circuit) Define(api frontend.API) error {
	var r E6
	r.Mul(api, c.A, c.B)
	r.AssertIsEqual(api, c.C)

	second := func(api frontend.API) {
		var s E6
		s.Mul(api, c.D, c.E)
		s.AssertIsEqual(api, c.F)
	}

	if c.InCallback {
		multicommit.WithCommitment(api, func(api frontend.API, _ frontend.Variable) error {
			second(api)
			return nil
		})
	} else {
		second(api)
	}
	return nil
}

// szTwoMulBy034Circuit exercises the sparse pairing multiplication, which goes
// through the same shared checker (this is the "pairing inside a user
// commitment callback" case).
type szTwoMulBy034Circuit struct {
	A          E12
	C3, C4     E2
	G          E12
	H3, H4     E2
	InCallback bool
}

func (c *szTwoMulBy034Circuit) Define(api frontend.API) error {
	r := c.A
	r.MulBy034(api, c.C3, c.C4)

	second := func(api frontend.API) {
		s := c.G
		s.MulBy034(api, c.H3, c.H4)
	}

	if c.InCallback {
		multicommit.WithCommitment(api, func(api frontend.API, _ frontend.Variable) error {
			second(api)
			return nil
		})
	} else {
		second(api)
	}
	return nil
}

// --- test 1: the wire-count regression (no malicious prover modelling) ------

// TestSZCheckerCommitsToEveryMultiplication asserts that moving one
// multiplication into a user multicommit callback does not change the number
// of variables the SZ checker commits to. On the buggy code the callback
// variant contributes zero committed variables.
func TestSZCheckerCommitsToEveryMultiplication(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	for _, tc := range []struct {
		name          string
		inDefine      frontend.Circuit
		inCallback    frontend.Circuit
		perMulCommits int
	}{
		{"E12.Mul", &szTwoMulE12Circuit{}, &szTwoMulE12Circuit{InCallback: true}, 47},
		{"E6.Mul", &szTwoMulE6Circuit{}, &szTwoMulE6Circuit{InCallback: true}, 23},
		{"E12.MulBy034", &szTwoMulBy034Circuit{}, &szTwoMulBy034Circuit{InCallback: true}, 39},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ccsDefine, err := frontend.Compile(field, scs.NewBuilder, tc.inDefine)
			if err != nil {
				t.Fatalf("compile (both in Define): %v", err)
			}
			nDefine := nbCommittedVariables(t, ccsDefine)

			ccsCallback, err := compileMayPanic(field, tc.inCallback)
			if err != nil {
				// Failing closed at compile time is an acceptable outcome: the
				// late multiplication is never verified against a stale
				// challenge.
				t.Logf("compile (second mul in callback) failed closed: %v", err)
				return
			}
			nCallback := nbCommittedVariables(t, ccsCallback)

			t.Logf("committed variables: both-in-Define=%d, second-in-callback=%d", nDefine, nCallback)
			if nCallback != nDefine {
				t.Fatalf("multiplication inside a commitment callback contributes %d committed variables instead of %d: "+
					"its inputs are not bound by the Schwartz-Zippel challenge",
					nCallback-(nDefine-tc.perMulCommits), tc.perMulCommits)
			}
		})
	}
}

// compileMayPanic compiles a circuit, converting a panic into an error. The
// fail-closed path may surface either way depending on where the guard fires.
func compileMayPanic(field *big.Int, circuit frontend.Circuit) (ccs constraint.ConstraintSystem, err error) {
	defer func() {
		if r := recover(); r != nil {
			ccs = nil
			err = &panicError{r}
		}
	}()
	return frontend.Compile(field, scs.NewBuilder, circuit)
}

type panicError struct{ v any }

func (e *panicError) Error() string { return "panic: " + toString(e.v) }

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "unknown panic value"
}

// --- test 2: the actual forgery -------------------------------------------

// forgeE12MulWhenLinear replaces the output of mulE12SZHint by zeros whenever
// the first operand is the degree-1 polynomial a(X) = X - challenge and the
// second operand is 1. That makes the prover claim a*b = 0 with a zero
// quotient, which satisfies the Schwartz-Zippel identity at the single point
// X = challenge and nowhere else. Honest multiplications are left untouched.
func forgeE12MulWhenLinear(challenge *big.Int) solver.Hint {
	return func(field *big.Int, inputs, outputs []*big.Int) error {
		isForged := len(inputs) == 24 &&
			inputs[0].Cmp(challenge) == 0 && inputs[6].Cmp(big.NewInt(1)) == 0 &&
			inputs[12].Cmp(big.NewInt(1)) == 0
		if isForged {
			for i := 1; i < 12 && isForged; i++ {
				if i != 6 && inputs[i].Sign() != 0 {
					isForged = false
				}
			}
			for i := 13; i < 24 && isForged; i++ {
				if inputs[i].Sign() != 0 {
					isForged = false
				}
			}
		}
		if isForged {
			return zeroHintOutput(field, inputs, outputs)
		}
		return mulE12SZHint(field, inputs, outputs)
	}
}

// TestSZCheckerRejectsChecksAddedInCommitmentCallback is the soundness
// regression test. An E12 multiplication performed inside a user
// multicommit.WithCommitment callback must never be verified at a challenge
// that the prover could predict and that does not commit to its operands.
func TestSZCheckerRejectsChecksAddedInCommitmentCallback(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	ccs, err := compileMayPanic(field, &szTwoMulE12Circuit{InCallback: true})
	if err != nil {
		t.Logf("compilation fails closed, as required: %v", err)
		return
	}

	// With the Bsb22 commitment hint overridden to return the number of its
	// inputs, the root commitment is a value the prover knows ahead of time.
	// The SZ callback is the second multicommit callback, so it receives
	// root^2.
	nbCommitted := nbCommittedVariables(t, ccs)
	root := big.NewInt(int64(nbCommitted) + 1) // +1 for the depth input of the commitment hint
	challenge := new(big.Int).Mul(root, root)
	challenge.Mod(challenge, bls12377.ID.BaseField())
	t.Logf("committed variables=%d, predicted SZ challenge=%s", nbCommitted, challenge)

	// honest first multiplication
	a, b := randomE12(), randomE12()
	var c bls12377.E12
	c.Mul(&a, &b)

	// forged second multiplication: d(X) = X - challenge, e = 1, f = 0
	var d, e, f bls12377.E12
	d.C0.B0.A0.SetBigInt(new(big.Int).Mod(new(big.Int).Neg(challenge), bls12377.ID.BaseField()))
	d.C1.B0.A0.SetOne()
	e.SetOne()

	witness := &szTwoMulE12Circuit{InCallback: true}
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)
	witness.D.Assign(&d)
	witness.E.Assign(&e)
	witness.F.Assign(&f)
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatal(err)
	}

	negChallenge := new(big.Int).Mod(new(big.Int).Neg(challenge), bls12377.ID.BaseField())
	err = ccs.IsSolved(w,
		solver.OverrideHint(solver.GetHintID(mulE12SZHint), forgeE12MulWhenLinear(negChallenge)),
		solver.OverrideHint(solver.GetHintID(cs.Bsb22CommitmentComputePlaceholder), commitmentInputCountHint),
	)
	if err == nil {
		t.Fatal("SOUNDNESS: a multiplication performed inside a user commitment callback " +
			"was accepted with a forged result; its operands are not bound by the challenge")
	}
	t.Logf("forged proof rejected: %v", err)
}

// --- test 3: the reverse ordering -----------------------------------------

// szCommitFirstCircuit registers a user commitment callback before any field
// extension multiplication happens, so the SZ checker is created from inside
// the multicommit callback.
type szCommitFirstCircuit struct {
	A, B, C E12
	// MulInDefine additionally performs an E12 multiplication in Define, after
	// the call to WithCommitment. This changes the order in which the deferred
	// functions are registered and is the shape that PR #1845 turns from
	// fail-closed into a silent soundness break.
	MulInDefine bool
}

func (c *szCommitFirstCircuit) Define(api frontend.API) error {
	multicommit.WithCommitment(api, func(api frontend.API, _ frontend.Variable) error {
		var r E12
		r.Mul(api, c.A, c.B)
		r.AssertIsEqual(api, c.C)
		return nil
	}, api.Add(c.A.C0.B0.A0, c.B.C0.B0.A0))
	if c.MulInDefine {
		var s E12
		s.Mul(api, c.A, c.A)
		api.AssertIsDifferent(s.C0.B0.A0, 0)
	}
	return nil
}

// TestSZCheckerWithCommitmentBeforeFirstMul checks the reverse ordering. It
// must either compile into a sound circuit or fail loudly - never silently
// accept a multiplication verified at a stale challenge.
func TestSZCheckerWithCommitmentBeforeFirstMul(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	for _, mulInDefine := range []bool{false, true} {
		name := "callbackMulOnly"
		want := 47
		if mulInDefine {
			name = "callbackMulPlusDefineMul"
			want = 94
		}
		t.Run(name, func(t *testing.T) {
			ccs, err := compileMayPanic(field, &szCommitFirstCircuit{MulInDefine: mulInDefine})
			if err != nil {
				if !strings.Contains(err.Error(), "recursively") && !strings.Contains(err.Error(), "closed") {
					t.Fatalf("unexpected failure mode: %v", err)
				}
				t.Logf("fails closed, as required: %v", err)
				return
			}

			// If it does compile, every multiplication must be committed to.
			n := nbCommittedVariables(t, ccs)
			t.Logf("compiled; committed variables=%d", n)
			if n < want {
				t.Fatalf("SOUNDNESS: the multiplications contribute %d committed variables, want at least %d: "+
					"an operand of the multiplication inside the commitment callback is not bound by the challenge", n, want)
			}

			// and a wrong result must be rejected
			a, b := randomE12(), randomE12()
			var cWrong bls12377.E12
			cWrong.SetRandom()
			witness := &szCommitFirstCircuit{MulInDefine: mulInDefine}
			witness.A.Assign(&a)
			witness.B.Assign(&b)
			witness.C.Assign(&cWrong)
			w, _ := frontend.NewWitness(witness, field)
			if err := ccs.IsSolved(w); err == nil {
				t.Fatal("SOUNDNESS: wrong product accepted")
			}
		})
	}
}
