package scs_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

type divUncheckedCase uint8

const (
	divUncheckedVarVar divUncheckedCase = iota
	divUncheckedVarConst
	divUncheckedConstVar
	divUncheckedConstConst
)

type circuitDupAdd struct {
	A, B frontend.Variable
	R    frontend.Variable
}

func (c *circuitDupAdd) Define(api frontend.API) error {

	f := api.Add(c.A, c.B)   // 1 constraint
	f = api.Add(c.A, c.B, f) // 1 constraint
	f = api.Add(c.A, c.B, f) // 1 constraint

	d := api.Add(api.Mul(c.A, 3), api.Mul(3, c.B)) // 3a + 3b --> 3 (a + b) shouldn't add a constraint.
	e := api.Mul(api.Add(c.A, c.B), 3)             // no constraints

	api.AssertIsEqual(f, e)   // 1 constraint
	api.AssertIsEqual(d, f)   // 1 constraint
	api.AssertIsEqual(c.R, e) // 1 constraint

	return nil
}

func TestDuplicateAdd(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitDupAdd{})
	assert.NoError(err)

	assert.Equal(6, ccs.GetNbConstraints(), "comparing expected number of constraints")

	w, err := frontend.NewWitness(&circuitDupAdd{
		A: 13,
		B: 42,
		R: 165,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)

	_, err = ccs.Solve(w)
	assert.NoError(err, "solving failed")
}

type circuitDupMul struct {
	A, B   frontend.Variable
	R1, R2 frontend.Variable
}

func (c *circuitDupMul) Define(api frontend.API) error {

	f := api.Mul(c.A, c.B)   // 1 constraint
	f = api.Mul(c.A, c.B, f) // 1 constraint
	f = api.Mul(c.A, c.B, f) // 1 constraint
	// f == (a*b)**3

	d := api.Mul(api.Mul(c.A, 2), api.Mul(3, c.B)) // no constraints
	e := api.Mul(api.Mul(c.A, c.B), 1)             // no constraints
	e = api.Mul(e, e)                              // e**2 (no constraints)
	e = api.Mul(e, api.Mul(c.A, c.B), 1)           // e**3 (no constraints)

	api.AssertIsEqual(f, e)    // 1 constraint
	api.AssertIsEqual(d, c.R1) // 1 constraint
	api.AssertIsEqual(c.R2, e) // 1 constraint

	return nil
}

func TestDuplicateMul(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitDupMul{})
	assert.NoError(err)

	assert.Equal(6, ccs.GetNbConstraints(), "comparing expected number of constraints")

	w, err := frontend.NewWitness(&circuitDupMul{
		A:  13,
		B:  42,
		R1: (13 * 2) * (42 * 3),
		R2: (13 * 42) * (13 * 42) * (13 * 42),
	}, ecc.BN254.ScalarField())
	assert.NoError(err)

	_, err = ccs.Solve(w)
	assert.NoError(err, "solving failed")
}

type IssueDiv0Circuit struct {
	A1, B1 frontend.Variable
	A2, B2 frontend.Variable
	A3, B3 frontend.Variable
	A4, B4 frontend.Variable

	Res1, Res2, Res3, Res4, Res5, Res6, Res7, Res8 frontend.Variable
}

func (c *IssueDiv0Circuit) Define(api frontend.API) error {
	// case 1
	t1 := api.Add(api.Mul(0, c.A1), api.Mul(4, c.B1), 0)
	t2 := api.Add(api.Mul(0, c.A1), api.Mul(5, c.B1), 0)

	// case 2
	t3 := api.Add(api.Mul(4, c.A2), api.Mul(0, c.B2), 0)
	t4 := api.Add(api.Mul(5, c.A2), api.Mul(0, c.B2), 0)

	// case 3
	t5 := api.Add(api.Mul(0, c.A3), api.Mul(0, c.B3), 0)
	t6 := api.Add(api.Mul(0, c.A3), api.Mul(5, c.B3), 0)

	// case 4
	t7 := api.Add(api.Mul(0, c.A4), api.Mul(0, c.B4), 0)
	t8 := api.Add(api.Mul(5, c.A4), api.Mul(0, c.B4), 0)

	// test solver
	api.AssertIsEqual(t1, c.Res1)
	api.AssertIsEqual(t2, c.Res2)
	api.AssertIsEqual(t3, c.Res3)
	api.AssertIsEqual(t4, c.Res4)
	api.AssertIsEqual(t5, c.Res5)
	api.AssertIsEqual(t6, c.Res6)
	api.AssertIsEqual(t7, c.Res7)
	api.AssertIsEqual(t8, c.Res8)
	return nil
}

func TestExistDiv0(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &IssueDiv0Circuit{})
	assert.NoError(err)
	w, err := frontend.NewWitness(&IssueDiv0Circuit{
		A1: 11, B1: 21,
		A2: 11, B2: 21,
		A3: 11, B3: 21,
		A4: 11, B4: 21,
		Res1: 84, Res2: 105,
		Res3: 44, Res4: 55,
		Res5: 0, Res6: 105,
		Res7: 0, Res8: 55,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	_, err = ccs.Solve(w)
	assert.NoError(err)
}

type IssueDiv0Circuit2 struct {
	A1, B1 frontend.Variable

	Res1, Res2 frontend.Variable
}

func (c *IssueDiv0Circuit2) Define(api frontend.API) error {
	// case 1
	b1 := api.Mul(0, c.A1)
	b2 := api.Mul(4, c.B1)
	t1 := api.Mul(b1, b2)

	b3 := api.Mul(2, c.A1)
	b4 := api.Mul(5, c.B1)
	t2 := api.Mul(b3, b4)

	// test solver
	api.AssertIsEqual(t1, c.Res1)
	api.AssertIsEqual(t2, c.Res2)
	return nil
}

func TestExistDiv02(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &IssueDiv0Circuit2{})
	assert.NoError(err)
	w, err := frontend.NewWitness(&IssueDiv0Circuit2{
		A1: 11, B1: 21,
		Res1: 0, Res2: 2310,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	_, err = ccs.Solve(w)
	assert.NoError(err)
}

type TestZeroMulNoConstraintCircuit struct {
	A, B frontend.Variable
}

func (c *TestZeroMulNoConstraintCircuit) Define(api frontend.API) error {
	// case 1
	t1 := api.Mul(0, c.A)
	t2 := api.Mul(t1, c.B)

	t3 := api.Sub(c.A, c.A)
	t4 := api.Mul(3, t3)

	// test solver
	api.AssertIsEqual(t2, 0)
	api.AssertIsEqual(t4, 0)
	return nil
}

func TestZeroMulNoConstraint(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &TestZeroMulNoConstraintCircuit{})
	assert.NoError(err)
	if ccs.GetNbConstraints() != 0 {
		t.Fatal("expected 0 constraints")
	}
}

type mulAccFastTrackCircuit struct {
	A, B frontend.Variable
	Res  frontend.Variable
}

func (c *mulAccFastTrackCircuit) Define(api frontend.API) error {
	r := api.MulAcc(api.Mul(c.A, 1), c.B, c.A)
	api.AssertIsEqual(r, c.Res)
	return nil
}

func TestMulAccFastTrack(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &mulAccFastTrackCircuit{})
	assert.NoError(err)
	assert.Equal(2, ccs.GetNbConstraints())
	w, err := frontend.NewWitness(&mulAccFastTrackCircuit{
		A: 11, B: 21,
		Res: 242,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	solution, err := ccs.Solve(w)
	assert.NoError(err)
	_ = solution
}

type subSameNoConstraintCircuit struct {
	A frontend.Variable
}

func (c *subSameNoConstraintCircuit) Define(api frontend.API) error {
	r := api.Sub(c.A, c.A)
	api.AssertIsEqual(r, 0)
	return nil
}

func TestSubSameNoConstraint(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &subSameNoConstraintCircuit{})
	assert.NoError(err)
	if ccs.GetNbConstraints() != 0 {
		t.Fatal("expected 0 constraints")
	}
}

type divUncheckedZeroCircuit struct {
	Case divUncheckedCase `gnark:"-"`
	A    frontend.Variable
	B    frontend.Variable
}

func (c *divUncheckedZeroCircuit) Define(api frontend.API) error {
	var res frontend.Variable
	switch c.Case {
	case divUncheckedVarVar:
		res = api.DivUnchecked(c.A, c.B)
	case divUncheckedVarConst:
		res = api.DivUnchecked(c.A, 0)
	case divUncheckedConstVar:
		res = api.DivUnchecked(0, c.B)
	case divUncheckedConstConst:
		res = api.DivUnchecked(0, 0)
	default:
		panic("unknown case")
	}
	api.AssertIsEqual(res, 0)
	return nil
}

func TestDivUncheckedZeroSolveFails(t *testing.T) {
	tests := []struct {
		name      string
		mode      divUncheckedCase
		solveFail bool
	}{
		{name: "var_var", mode: divUncheckedVarVar, solveFail: true},
		{name: "var_const", mode: divUncheckedVarConst, solveFail: false},
		{name: "const_var", mode: divUncheckedConstVar, solveFail: true},
		{name: "const_const", mode: divUncheckedConstConst, solveFail: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := &divUncheckedZeroCircuit{Case: tc.mode}
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
			if !tc.solveFail {
				if err == nil {
					t.Fatal("expected compile-time error")
				}
				return
			}
			assert.NoError(err)
			w, err := frontend.NewWitness(&divUncheckedZeroCircuit{
				Case: tc.mode,
				A:    0,
				B:    0,
			}, ecc.BN254.ScalarField())
			assert.NoError(err)
			_, err = ccs.Solve(w)
			assert.Error(err)
			if !errors.Is(err, constraint.ErrDivideByZero) {
				t.Fatalf("expected ErrDivideByZero, got %v", err)
			}
		})
	}
}

type regressionOr struct {
	A          frontend.Variable
	constOr    int
	constCheck int
}

func (c *regressionOr) Define(api frontend.API) error {
	y := api.Or(c.A, c.constOr)
	api.AssertIsEqual(y, c.constCheck)
	return nil
}

func TestRegressionOr(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range []struct{ in, o, c int }{
		{1, 1, 1}, {0, 1, 1},
		{1, 0, 1}, {0, 0, 0},
	} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &regressionOr{constOr: tc.o, constCheck: tc.c})
		assert.NoError(err)
		w, err := frontend.NewWitness(&regressionOr{
			A: tc.in,
		}, ecc.BN254.ScalarField())
		if err != nil {
			t.Error("compile", err)
		}
		_, err = ccs.Solve(w)
		if err != nil {
			t.Error("solve", err)
		}
	}
}

type regressionXorZero struct {
	A frontend.Variable
}

func (c *regressionXorZero) Define(api frontend.API) error {
	api.AssertIsBoolean(c.A)
	y := api.Xor(c.A, 0)
	_ = y
	return nil
}

func TestRegressionXorZeroNoConstraint(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &regressionXorZero{})
	assert.NoError(err)
	assert.Equal(1, ccs.GetNbConstraints(), "expected only the boolean assertion")
}

type regressionLookup2ConstantSelector struct {
	B                    frontend.Variable
	I0, I1, I2, I3, Want frontend.Variable
	Mode                 int `gnark:"-"`
}

func (c *regressionLookup2ConstantSelector) Define(api frontend.API) error {
	api.AssertIsBoolean(c.B)
	var y frontend.Variable
	switch c.Mode {
	case 0:
		y = api.Lookup2(0, c.B, c.I0, c.I1, c.I2, c.I3)
	case 1:
		y = api.Lookup2(1, c.B, c.I0, c.I1, c.I2, c.I3)
	case 2:
		y = api.Lookup2(c.B, 0, c.I0, c.I1, c.I2, c.I3)
	case 3:
		y = api.Lookup2(c.B, 1, c.I0, c.I1, c.I2, c.I3)
	default:
		panic("invalid mode")
	}
	api.AssertIsEqual(y, c.Want)
	return nil
}

func TestRegressionLookup2ConstantSelector(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range []struct {
		mode, bit, want int
	}{
		{0, 0, 10}, {0, 1, 30},
		{1, 0, 20}, {1, 1, 40},
		{2, 0, 10}, {2, 1, 20},
		{3, 0, 30}, {3, 1, 40},
	} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &regressionLookup2ConstantSelector{Mode: tc.mode})
		assert.NoError(err)
		w, err := frontend.NewWitness(&regressionLookup2ConstantSelector{
			B:    tc.bit,
			I0:   10,
			I1:   20,
			I2:   30,
			I3:   40,
			Want: tc.want,
		}, ecc.BN254.ScalarField())
		assert.NoError(err)
		_, err = ccs.Solve(w)
		assert.NoError(err)
	}
}

type deduplicateCommitmentsCircuit struct {
	repetitions int
	A           frontend.Variable
}

func (c *deduplicateCommitmentsCircuit) Define(api frontend.API) error {
	toCommit := make([]frontend.Variable, c.repetitions)
	x := api.Mul(c.A, c.A)
	for i := 0; i < c.repetitions; i++ {
		toCommit[i] = x
	}
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("expected Committer interface")
	}
	res, err := cmter.Commit(toCommit...)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(res, 0)
	return nil
}

func TestDeduplicateCommitments(t *testing.T) {
	assert := test.NewAssert(t)
	ccsCmts1, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &deduplicateCommitmentsCircuit{repetitions: 1})
	assert.NoError(err)
	ccsCmts5, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &deduplicateCommitmentsCircuit{repetitions: 5})
	assert.NoError(err)

	assert.Equal(ccsCmts1.GetNbConstraints(), ccsCmts5.GetNbConstraints(), "expected same number of constraints")
}

type zeroCoeffCommitmentCircuit struct {
	A frontend.Variable
}

func (c *zeroCoeffCommitmentCircuit) Define(api frontend.API) error {
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("expected Committer interface")
	}
	_, err := cmter.Commit(api.Div(0, c.A), c.A)
	return err
}

func TestCommitSkipsZeroCoeffTerms(t *testing.T) {
	assert := test.NewAssert(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &zeroCoeffCommitmentCircuit{})
	assert.NoError(err)

	w, err := frontend.NewWitness(&zeroCoeffCommitmentCircuit{A: 3}, ecc.BN254.ScalarField())
	assert.NoError(err)

	_, err = ccs.Solve(w)
	assert.NoError(err)
}
