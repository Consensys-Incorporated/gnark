package multicommit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
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
}

func (c *wideCommitment) Define(api frontend.API) error {
	if c.withCommitment {
		WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
			api.AssertIsDifferent(commitment, 0)
			return nil
		}, c.X)
	}
	WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
		fe, err := fieldextension.NewExtension(api, fieldextension.WithDegree(4))
		if err != nil {
			return err
		}
		res := fe.Mul(commitment, commitment)
		for i := range res {
			api.AssertIsDifferent(res[i], 0)
		}
		return nil
	}, 4, c.X)
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
	_, err = frontend.CompileU32(f, widecommitter.From(r1cs.NewBuilder), &wideCommitment{withCommitment: false})
	assert.NoError(err)
	_, err = frontend.CompileU32(f, widecommitter.From(scs.NewBuilder), &wideCommitment{withCommitment: false})
	assert.NoError(err)

	// shouldn't pass if we have mixed WithCommitment and WithWideCommitment
	_, err = frontend.CompileU32(f, widecommitter.From(scs.NewBuilder), &wideCommitment{withCommitment: true})
	assert.Error(err)
	_, err = frontend.CompileU32(f, widecommitter.From(r1cs.NewBuilder), &wideCommitment{withCommitment: true})
	assert.Error(err)
}
