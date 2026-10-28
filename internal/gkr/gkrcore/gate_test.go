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

func bn254() Field { return gkr.PrimeField(ecc.BN254.ScalarField()) }

// testFields runs under bn254() and under the KoalaBear E6 description, to check that both
// agree on every gate's metadata.
func testFields() []Field {
	return []Field{bn254(), gkr.KoalaBearE6()}
}

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
			compiled, err := CompileGateFunction(tt.f, tt.nbIn, bn254())
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

// TestConstantsFirst checks the bytecode of gates with constant operands. In the expected
// instructions, constants take the indices [0, len(constants)), then the inputs follow.
func TestConstantsFirst(t *testing.T) {
	tests := []struct {
		name         string
		f            gkr.GateFunction
		nbIn         int
		constants    []int64
		instructions []GateInstruction
	}{
		{
			"x+(2+3): constants only fold",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.Add(2, 3))
			},
			1, []int64{5},
			[]GateInstruction{{OpAdd, []uint16{0, 1}}},
		},
		{
			"x+2+y+3: constants merge and come first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], 2, in[1], 3)
			},
			2, []int64{5},
			[]GateInstruction{{OpAdd, []uint16{0, 2, 1}}},
		},
		{
			"x*2*y*3: constants merge and come first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], 2, in[1], 3)
			},
			2, []int64{6},
			[]GateInstruction{{OpMul, []uint16{0, 2, 1}}},
		},
		{
			"x*7: constant comes first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], 7)
			},
			1, []int64{7},
			[]GateInstruction{{OpMul, []uint16{0, 1}}},
		},
		{
			"x*((2*3)-1): folding nests",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], api.Sub(api.Mul(2, 3), 1))
			},
			1, []int64{5},
			[]GateInstruction{{OpMul, []uint16{0, 1}}},
		},
		{
			"x+(2-5): folding is exact over the integers",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.Sub(2, 5))
			},
			1, []int64{-3},
			[]GateInstruction{{OpAdd, []uint16{0, 1}}},
		},
		{
			"10-x-3-y-2: a constant minuend absorbs the constant subtrahends",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Sub(10, in[0], 3, in[1], 2)
			},
			2, []int64{5},
			[]GateInstruction{{OpSub, []uint16{0, 1, 2}}},
		},
		{
			"x-3-y-2: constant subtrahends merge into one, placed last",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Sub(in[0], 3, in[1], 2)
			},
			2, []int64{5},
			[]GateInstruction{{OpSub, []uint16{1, 2, 0}}},
		},
		{
			"x-y-4: a single constant subtrahend stays",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Sub(in[0], in[1], 4)
			},
			2, []int64{4},
			[]GateInstruction{{OpSub, []uint16{1, 2, 0}}},
		},
		{
			"x+y*z: multiplicands first, addend last",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], in[1], in[2])
			},
			3, nil,
			[]GateInstruction{{OpMulAcc, []uint16{1, 2, 0}}},
		},
		{
			"x+3*y: a constant multiplicand stays first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], 3, in[1])
			},
			2, []int64{3},
			[]GateInstruction{{OpMulAcc, []uint16{0, 2, 1}}},
		},
		{
			"x+y*3: a constant multiplicand moves first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], in[1], 3)
			},
			2, []int64{3},
			[]GateInstruction{{OpMulAcc, []uint16{0, 2, 1}}},
		},
		{
			"5+x*y: a constant addend stays last",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(5, in[0], in[1])
			},
			2, []int64{5},
			[]GateInstruction{{OpMulAcc, []uint16{1, 2, 0}}},
		},
		{
			"(x+y+z)^17: inputs keep their order",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], in[1], in[2])
			},
			3, nil,
			[]GateInstruction{{OpSumExp17, []uint16{0, 1, 2}}},
		},
		{
			"(x+3+y)^17: a constant moves first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], 3, in[1])
			},
			2, []int64{3},
			[]GateInstruction{{OpSumExp17, []uint16{0, 1, 2}}},
		},
		{
			"(x+y+3)^17: a constant swaps with the first input",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], in[1], 3)
			},
			2, []int64{3},
			[]GateInstruction{{OpSumExp17, []uint16{0, 2, 1}}},
		},
		{
			"(x+4+3)^17: constants stay unmerged",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], 4, 3)
			},
			1, []int64{4, 3},
			[]GateInstruction{{OpSumExp17, []uint16{0, 2, 1}}},
		},
		{
			"x+y with a constant used only after the output: the constant gets no index",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				out := api.Add(in[0], in[1])
				api.Mul(in[0], 9)
				return out
			},
			2, nil,
			[]GateInstruction{{OpAdd, []uint16{0, 1}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := CompileGateFunction(tt.f, tt.nbIn, bn254())
			require.NoError(t, err)

			var constants []int64
			for _, c := range compiled.Evaluate.Constants {
				constants = append(constants, c.Int64())
			}
			assert.Equal(t, tt.constants, constants)
			assert.Equal(t, tt.instructions, compiled.Evaluate.Instructions)
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
			compiled, err := CompileGateFunction(tt.f, tt.nbIn, bn254())
			require.NoError(t, err)
			assert.Equal(t, tt.nbIn, compiled.NbIn)
			assert.Equal(t, tt.degree, compiled.Degree)
			assert.Equal(t, tt.solvableVar, compiled.SolvableVar)
		})
	}
}

func testFitPoly(t *testing.T, name string, f gkr.GateFunction, nbIn, degree, maxDegree int) {
	t.Run(name, func(t *testing.T) {
		g, err := CompileGateFunction(f, nbIn, bn254())
		require.NoError(t, err)
		for _, fd := range testFields() {
			tester := gateTester{field: fd}
			tester.setGate(g.Evaluate, nbIn)
			require.Equal(t, degree, len(tester.fitPoly(maxDegree))-1)
		}
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
		g, err := CompileGateFunction(f, len(isAdditive), bn254())
		require.NoError(t, err)
		for _, fd := range testFields() {
			tester := gateTester{field: fd}
			tester.setGate(g.Evaluate, len(isAdditive))
			for i := range isAdditive {
				assert.Equal(t, isAdditive[i], tester.isAdditive(i))
			}
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

// TestExtensionDefiningRelation checks mul's reduction against KoalaBear's E6 tower generator's
// defining relation, X⁶ = 2X³ + 2 (from its minimal polynomial X⁶ - 2X³ - 2).
func TestExtensionDefiningRelation(t *testing.T) {
	tester := gateTester{field: gkr.KoalaBearE6()}

	x := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	x6 := tester.pow(x, big.NewInt(6))
	x3 := tester.pow(x, big.NewInt(3))
	want := tester.add(tester.mul(tester.embed(big.NewInt(2)), x3), tester.embed(big.NewInt(2)))
	require.True(t, tester.equal(x6, want))
}
