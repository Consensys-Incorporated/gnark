package multicommit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/std/internal/fieldextension"
	"github.com/consensys/gnark/test"
)

type noRecursionCircuit struct {
	X frontend.Variable
}

func (c *noRecursionCircuit) Define(api frontend.API) error {
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error { return nil }, commitment)
		return nil
	}, c.X)
	return nil
}

func TestNoRecursion(t *testing.T) {
	circuit := noRecursionCircuit{}
	assert := test.NewAssert(t)
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.Error(err)
}

type multipleCommitmentCircuit struct {
	X frontend.Variable
}

func (c *multipleCommitmentCircuit) Define(api frontend.API) error {
	var stored frontend.Variable
	// first callback receives first unique commitment derived from the root commitment
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		api.AssertIsDifferent(c.X, commitment)
		stored = commitment
		return nil
	}, c.X)
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		api.AssertIsDifferent(stored, commitment)
		return nil
	}, c.X)
	return nil
}

func TestMultipleCommitments(t *testing.T) {
	circuit := multipleCommitmentCircuit{}
	assignment := multipleCommitmentCircuit{X: 10}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254))
}

type wideCommitment struct {
	X              frontend.Variable
	withCommitment bool
	// degree is the wide commitment width and the extension degree to draw it
	// from. Zero means 4, the default for koalabear. mamabear only defines a
	// degree-3 extension, so it has to ask for 3.
	degree int
}

func (c *wideCommitment) extDegree() int {
	if c.degree == 0 {
		return 4
	}
	return c.degree
}

func (c *wideCommitment) Define(api frontend.API) error {
	if c.withCommitment {
		WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
			api.AssertIsDifferent(commitment, 0)
			return nil
		}, c.X)
	}
	WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
		fe, err := fieldextension.NewExtension(api, fieldextension.WithDegree(c.extDegree()))
		if err != nil {
			return err
		}
		res := fe.Mul(commitment, commitment)
		for i := range res {
			api.AssertIsDifferent(res[i], 0)
		}
		return nil
	}, c.extDegree(), c.X)
	return nil
}

func TestWideCommitment(t *testing.T) {
	f := koalabear.Modulus()
	assert := test.NewAssert(t)
	// should error as we call WithCommitment
	err := test.IsSolved(&wideCommitment{withCommitment: true}, &wideCommitment{X: 10}, f)
	assert.Error(err)
	// should pass as we don't call WithCommitment
	err = test.IsSolved(&wideCommitment{withCommitment: false}, &wideCommitment{X: 10}, f)
	assert.NoError(err)

	// should fail as we don't have WithWideCommitment for r1cs and scs
	_, err = frontend.Compile(f, r1cs.NewBuilder, &wideCommitment{withCommitment: false})
	assert.Error(err)
	_, err = frontend.Compile(f, scs.NewBuilder, &wideCommitment{withCommitment: false})
	assert.Error(err)

	// should pass as we provide with builder with WideCommitment support
	_, err = frontend.CompileU32(f, widecommitter.From[constraint.U32](r1cs.NewBuilder), &wideCommitment{withCommitment: false})
	assert.NoError(err)
	_, err = frontend.CompileU32(f, widecommitter.From[constraint.U32](scs.NewBuilder), &wideCommitment{withCommitment: false})
	assert.NoError(err)

	// shouldn't pass if we have mixed WithCommitment and WithWideCommitment
	_, err = frontend.CompileU32(f, widecommitter.From[constraint.U32](scs.NewBuilder), &wideCommitment{withCommitment: true})
	assert.Error(err)
	_, err = frontend.CompileU32(f, widecommitter.From[constraint.U32](r1cs.NewBuilder), &wideCommitment{withCommitment: true})
	assert.Error(err)
}

// TestWideCommitmentMamabear is the U64 counterpart of TestWideCommitment.
// mamabear is a small field whose constraint system uses the U64 element, so it
// goes through frontend.Compile rather than CompileU32 and exercises the U64
// instantiation of the widecommitter wrapper.
func TestWideCommitmentMamabear(t *testing.T) {
	f := mamabear.Modulus()
	// mamabear's extension is degree 3 (3*49 = 147 bits, more than koalabear's
	// degree 4 at 124), so the wide commitment is drawn from that.
	const deg = 3
	assert := test.NewAssert(t)

	// should error as we call WithCommitment
	err := test.IsSolved(&wideCommitment{withCommitment: true, degree: deg}, &wideCommitment{X: 10}, f)
	assert.Error(err)
	// should pass as we don't call WithCommitment
	err = test.IsSolved(&wideCommitment{withCommitment: false, degree: deg}, &wideCommitment{X: 10}, f)
	assert.NoError(err)

	// should fail as the plain builders have no WideCommitment support
	_, err = frontend.Compile(f, r1cs.NewBuilder, &wideCommitment{withCommitment: false, degree: deg})
	assert.Error(err)
	_, err = frontend.Compile(f, scs.NewBuilder, &wideCommitment{withCommitment: false, degree: deg})
	assert.Error(err)

	// should pass as we provide a builder with WideCommitment support
	_, err = frontend.Compile(f, widecommitter.From[constraint.U64](r1cs.NewBuilder), &wideCommitment{withCommitment: false, degree: deg})
	assert.NoError(err)
	_, err = frontend.Compile(f, widecommitter.From[constraint.U64](scs.NewBuilder), &wideCommitment{withCommitment: false, degree: deg})
	assert.NoError(err)

	// shouldn't pass if we have mixed WithCommitment and WithWideCommitment
	_, err = frontend.Compile(f, widecommitter.From[constraint.U64](scs.NewBuilder), &wideCommitment{withCommitment: true, degree: deg})
	assert.Error(err)
	_, err = frontend.Compile(f, widecommitter.From[constraint.U64](r1cs.NewBuilder), &wideCommitment{withCommitment: true, degree: deg})
	assert.Error(err)
}
