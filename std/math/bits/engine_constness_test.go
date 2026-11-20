package bits_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

// Regression cover for issue #650. The test engine used to answer ConstantValue
// from a single engine-wide flag rather than from the value, so it could not model
// a circuit mixing witness inputs and constants.
//
// The consequence was stronger than losing context: for the same circuit the test
// engine and the compiler took different branches, so a check that fires during
// compilation was unreachable from a test-engine test. Both tests below fail on
// master and pass once constness is a property of the value.
//
// Results are reported through pointer fields, which survive the circuit copy that
// IsSolved performs. Writing to a plain bool field does not come back.

type constnessProbe struct {
	Witness      frontend.Variable `gnark:",public"`
	witnessConst *bool
	literalConst *bool
}

func (c *constnessProbe) Define(api frontend.API) error {
	_, w := api.Compiler().ConstantValue(c.Witness)
	_, l := api.Compiler().ConstantValue(frontend.Variable(3))
	if c.witnessConst != nil {
		*c.witnessConst = w
	}
	if c.literalConst != nil {
		*c.literalConst = l
	}
	return nil
}

// TestConstnessIsUniformAcrossTheEngine shows the flag is global, not per value.
// Two configurations exist and neither can express a mixed circuit: the default
// reports everything non-constant, including a literal, and the option reports
// everything constant, including a genuine witness.
func TestConstnessIsUniformAcrossTheEngine(t *testing.T) {
	var defW, defL, allW, allL bool

	if err := test.IsSolved(
		&constnessProbe{witnessConst: &defW, literalConst: &defL},
		&constnessProbe{Witness: 1}, ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatal(err)
	}

	if err := test.IsSolved(
		&constnessProbe{witnessConst: &allW, literalConst: &allL},
		&constnessProbe{Witness: 1}, ecc.BN254.ScalarField(),
		test.SetAllVariablesAsConstants(),
	); err != nil {
		t.Fatal(err)
	}

	t.Logf("default engine:                 witness=%v literal=%v", defW, defL)
	t.Logf("SetAllVariablesAsConstants:     witness=%v literal=%v", allW, allL)

	// A mixed circuit must report mixed. On master both values come back the same,
	// because the answer is read from an engine-wide flag rather than the value.
	if defW {
		t.Error("a witness should not read as constant under the default engine")
	}
	if !defL {
		t.Error("a Go literal should read as constant; on master it does not, which is the defect")
	}
	if defW == defL {
		t.Error("default engine could not distinguish a witness from a literal")
	}

	// The legacy option keeps its documented meaning: everything reads as constant.
	if !allW || !allL {
		t.Errorf("SetAllVariablesAsConstants should force both to constant, got witness=%v literal=%v", allW, allL)
	}
}

// wideDigit feeds FromBinary a literal 2, which is more than one bit.
type wideDigit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *wideDigit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.X)
	_ = bits.FromBinary(api, []frontend.Variable{frontend.Variable(2), frontend.Variable(0)})
	return nil
}

// TestCompilerAndEngineTakeDifferentBranches is the finding.
//
// fromBinary has two branches. The all-constant branch folds the digits and rejects
// any digit wider than one bit. The general branch instead calls AssertIsBoolean on
// each digit. The two therefore fail with different messages, which makes the branch
// taken observable.
//
// Compiling reaches the constant branch. The test engine reaches the general one,
// for the identical circuit, because ConstantValue reports false for every value.
func TestCompilerAndEngineTakeDifferentBranches(t *testing.T) {
	var compileErr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				compileErr = "panic: " + toString(r)
			}
		}()
		if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &wideDigit{}); err != nil {
			compileErr = err.Error()
		}
	}()

	var engineErr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				engineErr = "panic: " + toString(r)
			}
		}()
		if err := test.IsSolved(&wideDigit{}, &wideDigit{X: 1}, ecc.BN254.ScalarField()); err != nil {
			engineErr = err.Error()
		}
	}()

	t.Logf("compiler:    %s", orNone(compileErr))
	t.Logf("test engine: %s", orNone(engineErr))

	constantBranch := strings.Contains(compileErr, "more than 1 bit")
	if !constantBranch {
		t.Fatalf("expected the compiler to reach the constant-folding branch, got: %s", orNone(compileErr))
	}

	// The test engine must reach the same branch as the compiler. On master it does
	// not: it reports [assertIsBoolean] 2 from the general branch instead.
	if !strings.Contains(engineErr, "more than 1 bit") {
		t.Errorf("test engine took a different branch from the compiler, got: %s", orNone(engineErr))
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "non-string panic"
}

func orNone(s string) string {
	if s == "" {
		return "(no error)"
	}
	return s
}

// derivedProbe records constness of values DERIVED from a witness rather than of
// the witness itself.
type derivedProbe struct {
	Witness frontend.Variable `gnark:",public"`
	sum     *bool
	bit     *bool
	lit     *bool
}

func (c *derivedProbe) Define(api frontend.API) error {
	_, s := api.Compiler().ConstantValue(api.Add(c.Witness, 1))
	_, l := api.Compiler().ConstantValue(api.Add(frontend.Variable(1), frontend.Variable(2)))
	_, b := api.Compiler().ConstantValue(api.ToBinary(c.Witness, 8)[0])
	*c.sum, *c.lit, *c.bit = s, l, b
	return nil
}

// TestConstnessPropagates covers the direction that is easy to get wrong.
//
// Constness has to travel with the value through every operation that produces one.
// Two failures are possible and only one of them is safe:
//
//	under-claiming  a constant reads as non-constant, the engine takes the general
//	                branch, which is what master already does
//	over-claiming   a value derived from a witness reads as constant, the engine
//	                folds something the compiler cannot, and a test passes on a
//	                circuit that will not compile
//
// The ToBinary case is the trap. Its bits used to be plain Go uints, and a uint
// reaches the engine through the same path as a written literal, so every bit of a
// witness would have read as constant.
func TestConstnessPropagates(t *testing.T) {
	var sum, bit, lit bool
	if err := test.IsSolved(
		&derivedProbe{sum: &sum, bit: &bit, lit: &lit},
		&derivedProbe{Witness: 7}, ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatal(err)
	}

	if sum {
		t.Error("witness + 1 must not read as constant")
	}
	if bit {
		t.Error("a bit of ToBinary(witness) must not read as constant")
	}
	if !lit {
		t.Error("1 + 2 must read as constant")
	}
}

// mulProbe records the constness of a product where one operand is a witness whose
// solved value lands on the two cases Mul has an allocation shortcut for.
type mulProbe struct {
	Witness frontend.Variable `gnark:",public"`
	byWit   *bool
	byConst *bool
}

func (c *mulProbe) Define(api frontend.API) error {
	_, w := api.Compiler().ConstantValue(api.Mul(frontend.Variable(7), c.Witness))
	_, k := api.Compiler().ConstantValue(api.Mul(frontend.Variable(7), frontend.Variable(1)))
	*c.byWit, *c.byConst = w, k
	return nil
}

// TestMulShortcutDoesNotOverClaim covers the allocation shortcut in Mul, which returns
// before taint and so used to decide constness from the runtime value of its second
// operand. A witness that solves to 0 came back as the Go literal 0 and read as
// constant; a witness that solves to 1 came back as i1 and inherited i1's constness.
// Neither builder can fold a product of two variables, so both were over-claims.
func TestMulShortcutDoesNotOverClaim(t *testing.T) {
	for _, solved := range []int{0, 1} {
		t.Run(fmt.Sprintf("witness=%d", solved), func(t *testing.T) {
			var byWit, byConst bool
			if err := test.IsSolved(
				&mulProbe{byWit: &byWit, byConst: &byConst},
				&mulProbe{Witness: solved}, ecc.BN254.ScalarField(),
			); err != nil {
				t.Fatal(err)
			}
			if byWit {
				t.Errorf("7 * witness read as constant when the witness solves to %d", solved)
			}
			if !byConst {
				t.Error("7 * 1 must still read as constant")
			}
		})
	}
}
