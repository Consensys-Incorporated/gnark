package polynomial_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
)

type evalPolyCircuit struct {
	P          []frontend.Variable `gnark:",public"`
	At         frontend.Variable   `gnark:",secret"`
	Evaluation frontend.Variable   `gnark:",secret"`
}

func (c *evalPolyCircuit) Define(api frontend.API) error {
	p := polynomial.Polynomial(c.P)
	evaluation := p.Eval(api, c.At)
	api.AssertIsEqual(evaluation, c.Evaluation)
	return nil
}

func testEvalPoly(t *testing.T, p []int64, at int64, evaluation int64) {
	assert := test.NewAssert(t)

	witness := evalPolyCircuit{
		P:          polynomial.Polynomial(int64SliceToVariableSlice(p)),
		At:         at,
		Evaluation: evaluation,
	}

	assert.CheckCircuit(&evalPolyCircuit{P: make(polynomial.Polynomial, len(p))}, test.WithValidAssignment(&witness))
}

func TestEvalPoly(t *testing.T) {
	testEvalPoly(t, []int64{1, 2, 3, 4}, 5, 586)
}

type evalMultiLinCircuit struct {
	M          []frontend.Variable `gnark:",public"`
	At         []frontend.Variable `gnark:",secret"`
	Evaluation frontend.Variable   `gnark:",secret"`
}

func (c *evalMultiLinCircuit) Define(api frontend.API) error {
	m := polynomial.MultiLin(c.M)
	evaluation := m.Evaluate(api, c.At)
	api.AssertIsEqual(evaluation, c.Evaluation)
	return nil
}

func TestEvalMultiLin(t *testing.T) {
	assert := test.NewAssert(t)

	// M = 2 X₀ + X₁ + 1
	witness := evalMultiLinCircuit{
		M:          polynomial.MultiLin{1, 2, 3, 4},
		At:         []frontend.Variable{5, 6},
		Evaluation: 17,
	}

	assert.CheckCircuit(&evalMultiLinCircuit{M: make(polynomial.MultiLin, 4), At: make([]frontend.Variable, 2)}, test.WithValidAssignment(&witness))
}

type evalEqCircuit struct {
	X  []frontend.Variable `gnark:",public"`
	Y  []frontend.Variable `gnark:",secret"`
	Eq frontend.Variable   `gnark:"secret"`
}

func (c *evalEqCircuit) Define(api frontend.API) error {
	evaluation := polynomial.EvalEq(api, c.X, c.Y)
	api.AssertIsEqual(evaluation, c.Eq)
	return nil
}

func TestEvalEq(t *testing.T) {
	assert := test.NewAssert(t)

	witness := evalEqCircuit{
		X:  []frontend.Variable{1, 2, 3, 4},
		Y:  []frontend.Variable{5, 6, 7, 8},
		Eq: 148665,
	}

	assert.CheckCircuit(&evalEqCircuit{X: make([]frontend.Variable, 4), Y: make([]frontend.Variable, 4)}, test.WithValidAssignment(&witness))
}

type interpolateLDECircuit struct {
	At                    frontend.Variable   `gnark:",secret"`
	Values                []frontend.Variable `gnark:",public"`
	ExpectedInterpolation frontend.Variable   `gnark:",secret"`
}

func (c *interpolateLDECircuit) Define(api frontend.API) error {
	evaluation := polynomial.InterpolateLDE(api, c.At, c.Values)
	api.AssertIsEqual(evaluation, c.ExpectedInterpolation)
	return nil
}

func testInterpolateLDE(t *testing.T, at int64, values []int64, expectedInterpolation int64) {

	test.NewAssert(t).CheckCircuit(
		&interpolateLDECircuit{Values: make([]frontend.Variable, len(values))},

		test.WithValidAssignment(&interpolateLDECircuit{At: at, Values: int64SliceToVariableSlice(values), ExpectedInterpolation: expectedInterpolation}),
	)
}

func TestInterpolateLDEManyValues(t *testing.T) {
	// 21! does not fit in an int64, the interpolant through equal values is constant
	values := make([]int64, 22)
	for i := range values {
		values[i] = 5
	}
	testInterpolateLDE(t, 100, values, 5)
}

func TestInterpolateLDESingleValue(t *testing.T) {
	testInterpolateLDE(t, 5, []int64{7}, 7)
}

func TestInterpolateLDEOnRange(t *testing.T) {
	// The polynomial is 2 X⁴ - X³ - 9 X² + 9 X - 6
	testInterpolateLDE(
		t,
		5,
		[]int64{-6, -5, 0, 75, 334},
		939,
	)
}

func TestInterpolateLDEOnRangeWithinRange(t *testing.T) {
	// The polynomial is 2 X⁴ - X³ - 9 X² + 9 X - 6
	testInterpolateLDE(
		t,
		1,
		[]int64{-6, -5, 0, 75, 334},
		-5,
	)
}

func TestInterpolateLinearExtension(t *testing.T) {
	// The polynomial is 4X + 3
	testInterpolateLDE(
		t,
		2,
		[]int64{3, 7},
		11,
	)
}

func TestInterpolateQuadraticExtension(t *testing.T) {
	// The polynomial is 1 + 2X + 3X²
	testInterpolateLDE(
		t,
		3,
		[]int64{1, 6, 17},
		34,
	)

	testInterpolateLDE(
		t,
		-1,
		[]int64{1, 6, 17},
		2,
	)
}

func int64SliceToVariableSlice(slice []int64) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(slice))
	for _, v := range slice {
		res = append(res, v)
	}
	return res
}

func ExampleMultiLin_Evaluate() {
	const logSize = 20
	const size = 1 << logSize
	m := polynomial.MultiLin(make([]frontend.Variable, size))
	e := polynomial.MultiLin(make([]frontend.Variable, logSize))

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &evalMultiLinCircuit{M: m, At: e, Evaluation: 0})
	if err != nil {
		panic(err)
	}
	fmt.Println("r1cs size:", cs.GetNbConstraints())

	cs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &evalMultiLinCircuit{M: m, At: e, Evaluation: 0})
	if err != nil {
		panic(err)
	}
	fmt.Println("scs size:", cs.GetNbConstraints())

	// Output: r1cs size: 1048627
	//scs size: 2097226
}
