package gkrcore

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func field() *big.Int { return ecc.BN254.ScalarField() }

// test gate functions

func mul3(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Mul(api.Mul(in[0], in[1]), in[2])
}

func add3(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Add(api.Add(in[0], in[1]), in[2])
}

func addMul(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Mul(api.Add(in[0], in[1]), in[2])
}

func addMul2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Add(in[0], api.Mul(in[1], in[2]))
}

func sqrAdd2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Add(api.Mul(in[0], in[0]), in[1], in[1])
}

func mulAdd(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Add(api.Mul(in[0], in[1]), in[1])
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name      string
		f         gkr.GateFunction
		nbIn      int
		constants []int64 // expected constant values (duplicates should be deduplicated)
	}{
		{
			"x+5",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], big.NewInt(5))
			},
			1,
			[]int64{5},
		},
		{
			"(x+3)*7",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(api.Add(in[0], big.NewInt(3)), big.NewInt(7))
			},
			1,
			[]int64{3, 7},
		},
		{
			"(x+5)+(y+5)", // tests deduplication
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				sum1 := api.Add(in[0], big.NewInt(5))
				sum2 := api.Add(in[1], big.NewInt(5))
				return api.Add(sum1, sum2)
			},
			2,
			[]int64{5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := CompileGateFunction(tt.f, tt.nbIn, field())
			require.NoError(t, err)

			assert.Equal(t, len(tt.constants), len(compiled.Evaluate.Constants))

			gotValues := make(map[int64]bool)
			for _, c := range compiled.Evaluate.Constants {
				gotValues[c.Int64()] = true
			}
			for _, want := range tt.constants {
				assert.True(t, gotValues[want], "expected constant %d", want)
			}
		})
	}
}

func TestCompileGateFunction(t *testing.T) {
	tests := []struct {
		name        string
		f           gkr.GateFunction
		nbIn        int
		degree      int
		solvableVar int // -1 means none, otherwise first additive var
	}{
		{"identity", Identity, 1, 1, 0},
		{"x+y", Add2, 2, 1, 0},
		{"x-y", Sub2, 2, 1, 0},
		{"x*y", Mul2, 2, 2, -1},
		{"x*y*z", mul3, 3, 3, -1},
		{"x+y+z", add3, 3, 1, 0},
		{"(x+y)*z", addMul, 3, 2, -1},
		{"x+y*z", addMul2, 3, 2, 0},
		{"x²+2y", sqrAdd2, 2, 2, 1},
		{"x*y+y", mulAdd, 2, 2, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := CompileGateFunction(tt.f, tt.nbIn, field())
			require.NoError(t, err)
			assert.Equal(t, tt.nbIn, compiled.NbIn)
			assert.Equal(t, tt.degree, compiled.Degree)
			assert.Equal(t, tt.solvableVar, compiled.SolvableVar)
		})
	}
}

func testFitPoly(t *testing.T, name string, f gkr.GateFunction, nbIn, degree, maxDegree int) {
	t.Run(name, func(t *testing.T) {
		tester := gateTester{mod: field()}
		g, err := CompileGateFunction(f, nbIn, field())
		require.NoError(t, err)
		tester.setGate(g.Evaluate, nbIn)
		require.Equal(t, degree, len(tester.fitPoly(maxDegree))-1)
	})
}

func TestFitPoly(t *testing.T) {
	testFitPoly(t, "identity", Identity, 1, 1, 3)
	testFitPoly(t, "add", Add2, 2, 1, 2)
	testFitPoly(t, "sub", Sub2, 2, 1, 4)
	testFitPoly(t, "mul", Mul2, 2, 2, 2)
	testFitPoly(t, "mul3", mul3, 3, 3, 4)
	testFitPoly(t, "add3", add3, 3, 1, 4)
	testFitPoly(t, "addMul", addMul, 3, 2, 4)
}

func testIsAdditive(t *testing.T, name string, f gkr.GateFunction, isAdditive ...bool) {
	t.Run(name, func(t *testing.T) {
		tester := gateTester{mod: field()}
		g, err := CompileGateFunction(f, len(isAdditive), field())
		require.NoError(t, err)
		tester.setGate(g.Evaluate, len(isAdditive))
		for i := range isAdditive {
			assert.Equal(t, isAdditive[i], tester.isAdditive(i))
		}
	})
}

func TestIsAdditive(t *testing.T) {
	testIsAdditive(t, "x+y", Add2, true, true)
	testIsAdditive(t, "x-y", Sub2, true, true)
	testIsAdditive(t, "x*y", Mul2, false, false)
	testIsAdditive(t, "x+y*z", addMul2, true, false, false)
	testIsAdditive(t, "x²+2y", sqrAdd2, false, true)
	testIsAdditive(t, "x*y+y", mulAdd, false, false)
}
