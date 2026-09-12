// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package r1cs

import (
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
)

type divUncheckedCase uint8

const (
	divUncheckedVarVar divUncheckedCase = iota
	divUncheckedVarConst
	divUncheckedConstVar
	divUncheckedConstConst
)

func testQuickSortParametric[E constraint.Element](t *testing.T) {
	toSort := make(expr.LinearExpression[E], 12)
	rand := 3
	for i := 0; i < 12; i++ {
		toSort[i].VID = rand
		rand += 3
		rand = rand % 13
	}

	sort.Sort(toSort)

	for i := 0; i < 10; i++ {
		cur := toSort[i].WireID()
		next := toSort[i+1].WireID()
		if cur >= next {
			t.Fatal("err sorting linear expression")
		}
	}
}

func TestQuickSort(t *testing.T) {
	testQuickSortParametric[constraint.U64](t)
	testQuickSortParametric[constraint.U32](t)
}

func TestReduce(t *testing.T) {

	cs := newBuilder[constraint.U64](ecc.BN254.ScalarField(), frontend.CompileConfig{})
	x := cs.newInternalVariable()
	y := cs.newInternalVariable()
	z := cs.newInternalVariable()

	a := cs.Mul(x, 3)
	b := cs.Mul(x, 5)
	c := cs.Mul(y, 10)
	d := cs.Mul(y, 11)
	e := cs.Mul(z, 2)
	f := cs.Mul(z, 2)

	toTest := (cs.Add(a, b, c, d, e, f)).(expr.LinearExpression[constraint.U64])

	// check sizes
	if len(toTest) != 3 {
		t.Fatal("Error reduce, duplicate variables not collapsed")
	}

}

func TestCompress(t *testing.T) {
	cs := newBuilder[constraint.U64](ecc.BN254.ScalarField(), frontend.CompileConfig{CompressThreshold: 3})
	vars := make([]frontend.Variable, 4)
	for i := range vars {
		v := cs.newInternalVariable()
		vars[i] = cs.Mul(v, 1<<i)
	}

	// if add two variables, then should not compress
	v1 := cs.Add(vars[0], vars[1])
	if vli1 := v1.(expr.LinearExpression[constraint.U64]); len(vli1) != 2 {
		t.Fatalf("expected linear expression length 2, got %d", len(vli1))
	}
	// if add three vars, then should compress
	v2 := cs.Add(vars[0], vars[1], vars[2])
	if vli2 := v2.(expr.LinearExpression[constraint.U64]); len(vli2) != 1 {
		t.Fatalf("expected linear expression length 1, got %d", len(vli2))
	}
}

func BenchmarkReduce(b *testing.B) {
	cs := newBuilder[constraint.U64](ecc.BN254.ScalarField(), frontend.CompileConfig{})
	// 4 interesting cases;
	// Add many small linear expressions
	// Add few large linear expressions
	// Add many large linear expressions
	// Doubling of large linear expressions
	rand := rand.New(rand.NewSource(time.Now().Unix())) //#nosec G404 weak rng is fine here
	const nbTerms = 100000
	terms := make([]frontend.Variable, nbTerms)
	for i := 0; i < len(terms); i++ {
		terms[i] = cs.newInternalVariable()
	}

	rL := make([]frontend.Variable, 1000)
	for i := 0; i < len(rL); i++ {
		rL[i] = cs.Mul(terms[i%50], rand.Uint64()) //#nosec G404 -- This is a false positive
	}

	mL := make([]frontend.Variable, 1000)
	b.ResetTimer()
	b.Run("reduce redundancy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mL[i%len(mL)] = cs.Add(rand.Uint64(), rL[0], rL[1:]...) //#nosec G404 -- This is a false positive
		}
	})

	b.ResetTimer()
	b.Run("many small", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cs.Add(mL[0], mL[1], mL[2:]...)
		}
	})

	c := cs.Add(terms[0], terms[1], terms[2:]...)

	b.ResetTimer()
	b.Run("doubling large", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cs.Add(c, c)
		}
	})
}

type EmptyCircuit struct {
	X  frontend.Variable
	cb func(frontend.API) error
}

func (c *EmptyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 0)
	api.Compiler().Defer(c.cb)
	return nil
}

func TestPreCompileHook(t *testing.T) {
	var called bool
	c := &EmptyCircuit{
		cb: func(a frontend.API) error { called = true; return nil },
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("callback not called")
	}
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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, &subSameNoConstraintCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if ccs.GetNbConstraints() != 0 {
		t.Fatal("expected 0 constraints")
	}
}

type lookup2ConstantSelectorCircuit struct {
	B                    frontend.Variable
	I0, I1, I2, I3, Want frontend.Variable
	Mode                 int `gnark:"-"`
}

func (c *lookup2ConstantSelectorCircuit) Define(api frontend.API) error {
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

func TestLookup2ConstantSelector(t *testing.T) {
	for _, tc := range []struct {
		mode, bit, want int
	}{
		{0, 0, 10}, {0, 1, 30},
		{1, 0, 20}, {1, 1, 40},
		{2, 0, 10}, {2, 1, 20},
		{3, 0, 30}, {3, 1, 40},
	} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, &lookup2ConstantSelectorCircuit{Mode: tc.mode})
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(&lookup2ConstantSelectorCircuit{
			B:    tc.bit,
			I0:   10,
			I1:   20,
			I2:   30,
			I3:   40,
			Want: tc.want,
		}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ccs.Solve(w); err != nil {
			t.Fatal(err)
		}
	}
}

type overwriteZeroConstCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

func (c *overwriteZeroConstCircuit) Define(api frontend.API) error {
	constVar := api.Mul(0, c.X)               // this create a zero constant
	constVar = api.MulAcc(constVar, c.X, c.Y) // due to bug the zero constant is overwritten
	_ = constVar
	constVar2 := api.Mul(0, c.Y) // this create another zero constant
	api.AssertIsEqual(constVar2, 0)

	return nil
}

func TestOverrideZeroConstant(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, &overwriteZeroConstCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	wit, err := frontend.NewWitness(&overwriteZeroConstCircuit{
		X: 5,
		Y: 10,
	}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	_, err = ccs.Solve(wit)
	if err != nil {
		t.Fatal(err)
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

func TestDivUncheckedZeroSolve(t *testing.T) {
	tests := []struct {
		name      string
		mode      divUncheckedCase
		solvePass bool
	}{
		{name: "var_var", mode: divUncheckedVarVar, solvePass: true},
		{name: "var_const", mode: divUncheckedVarConst, solvePass: false},
		{name: "const_var", mode: divUncheckedConstVar, solvePass: true},
		{name: "const_const", mode: divUncheckedConstConst, solvePass: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			circuit := &divUncheckedZeroCircuit{Case: tc.mode}
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, circuit)
			if !tc.solvePass {
				if err == nil {
					t.Fatal("expected compile-time error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wit, err := frontend.NewWitness(&divUncheckedZeroCircuit{
				Case: tc.mode,
				A:    0,
				B:    0,
			}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ccs.Solve(wit); err != nil {
				t.Fatalf("expected r1cs solver to accept DivUnchecked(0, 0), got %v", err)
			}
		})
	}
}

func TestDivUncheckedNonZeroNumeratorZeroDenominatorFails(t *testing.T) {
	circuit := &divUncheckedZeroCircuit{Case: divUncheckedVarVar}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	wit, err := frontend.NewWitness(&divUncheckedZeroCircuit{
		Case: divUncheckedVarVar,
		A:    1,
		B:    0,
	}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ccs.Solve(wit); err == nil {
		t.Fatal("expected r1cs solver to fail")
	}
}
