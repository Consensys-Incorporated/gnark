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

// testFields runs under bn254() and under the KoalaBear E6 and MamaBear E3 descriptions, to check
// that all agree on every gate's metadata.
func testFields() []Field {
	return []Field{bn254(), gkr.KoalaBearE6(), gkr.MamaBearE3()}
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

// TestBytecode checks the bytecode of compiled gates: the constants, and the instructions with their
// registers. In the expected instructions, the registers take the indices [0, NbRegisters), then the
// constants follow.
func TestBytecode(t *testing.T) {
	tests := []struct {
		name         string
		f            gkr.GateFunction
		nbIn         int
		constants    []int64
		instructions []gkr.GateInstruction
		nbRegisters  int
	}{
		{
			"x+(2+3): constants only fold",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.Add(2, 3))
			},
			1, []int64{5},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x+2+y+3: constants merge and come first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], 2, in[1], 3)
			},
			2, []int64{5},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{3, 0, 1}, Dst: 2}},
			3,
		},
		{
			"x*2*y*3: constants merge and come first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], 2, in[1], 3)
			},
			2, []int64{6},
			[]gkr.GateInstruction{{Op: gkr.OpMul, Inputs: []uint16{3, 0, 1}, Dst: 2}},
			3,
		},
		{
			"x*7: constant comes first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], 7)
			},
			1, []int64{7},
			[]gkr.GateInstruction{{Op: gkr.OpMul, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x*((2*3)-1): folding nests",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], api.Sub(api.Mul(2, 3), 1))
			},
			1, []int64{5},
			[]gkr.GateInstruction{{Op: gkr.OpMul, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x+(2-5): folding is exact modulo the field",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.Sub(2, 5))
			},
			1, []int64{-3},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"10-x-3-y-2: a constant minuend absorbs the constant subtrahends",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Sub(10, in[0], 3, in[1], 2)
			},
			2, []int64{5},
			[]gkr.GateInstruction{{Op: gkr.OpSub, Inputs: []uint16{3, 0, 1}, Dst: 2}},
			3,
		},
		{
			"x-3-y-2: constant subtrahends merge into one, placed second",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Sub(in[0], 3, in[1], 2)
			},
			2, []int64{5},
			[]gkr.GateInstruction{{Op: gkr.OpSub, Inputs: []uint16{0, 3, 1}, Dst: 2}},
			3,
		},
		{
			"x-y-4: a single constant subtrahend moves second",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Sub(in[0], in[1], 4)
			},
			2, []int64{4},
			[]gkr.GateInstruction{{Op: gkr.OpSub, Inputs: []uint16{0, 3, 1}, Dst: 2}},
			3,
		},
		{
			"x+y*z: multiplicands first, addend last",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], in[1], in[2])
			},
			3, nil,
			[]gkr.GateInstruction{{Op: gkr.OpMulAcc, Inputs: []uint16{1, 2, 0}, Dst: 3}},
			4,
		},
		{
			"x+3*y: a constant multiplicand stays first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], 3, in[1])
			},
			2, []int64{3},
			[]gkr.GateInstruction{{Op: gkr.OpMulAcc, Inputs: []uint16{3, 1, 0}, Dst: 2}},
			3,
		},
		{
			"x+y*3: a constant multiplicand moves first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], in[1], 3)
			},
			2, []int64{3},
			[]gkr.GateInstruction{{Op: gkr.OpMulAcc, Inputs: []uint16{3, 1, 0}, Dst: 2}},
			3,
		},
		{
			"5+x*y: a constant addend stays last",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(5, in[0], in[1])
			},
			2, []int64{5},
			[]gkr.GateInstruction{{Op: gkr.OpMulAcc, Inputs: []uint16{0, 1, 3}, Dst: 2}},
			3,
		},
		{
			"(x+y+z)^17: inputs keep their order",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], in[1], in[2])
			},
			3, nil,
			[]gkr.GateInstruction{{Op: gkr.OpSumExp17, Inputs: []uint16{0, 1, 2}, Dst: 3}},
			4,
		},
		{
			"(x+3+y)^17: a constant moves first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], 3, in[1])
			},
			2, []int64{3},
			[]gkr.GateInstruction{{Op: gkr.OpSumExp17, Inputs: []uint16{3, 0, 1}, Dst: 2}},
			3,
		},
		{
			"(x+y+3)^17: a constant swaps with the first input",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], in[1], 3)
			},
			2, []int64{3},
			[]gkr.GateInstruction{{Op: gkr.OpSumExp17, Inputs: []uint16{3, 1, 0}, Dst: 2}},
			3,
		},
		{
			"(x+4+3)^17: constants stay unmerged",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.SumExp17(in[0], 4, 3)
			},
			1, []int64{4, 3},
			[]gkr.GateInstruction{{Op: gkr.OpSumExp17, Inputs: []uint16{2, 0, 3}, Dst: 1}},
			2,
		},
		{
			"x+y with a constant used only after the output: the constant gets no index",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				out := api.Add(in[0], in[1])
				api.Mul(in[0], 9)
				return out
			},
			2, nil,
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{0, 1}, Dst: 2}},
			3,
		},
		{
			"((x+y)*z)+w: every operand is last read by its instruction, so one register is reused",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(api.Mul(api.Add(in[0], in[1]), in[2]), in[3])
			},
			4, nil,
			[]gkr.GateInstruction{
				{Op: gkr.OpAdd, Inputs: []uint16{0, 1}, Dst: 4},
				{Op: gkr.OpMul, Inputs: []uint16{4, 2}, Dst: 4},
				{Op: gkr.OpAdd, Inputs: []uint16{4, 3}, Dst: 4},
			},
			5,
		},
		{
			"(x*y)+(x+y): the first operand is read again, so the product takes a new register",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(api.Mul(in[0], in[1]), api.Add(in[0], in[1]))
			},
			2, nil,
			[]gkr.GateInstruction{
				{Op: gkr.OpMul, Inputs: []uint16{0, 1}, Dst: 2},
				{Op: gkr.OpAdd, Inputs: []uint16{0, 1}, Dst: 3},
				{Op: gkr.OpAdd, Inputs: []uint16{2, 3}, Dst: 2},
			},
			4,
		},
		{
			"x·y + x + x·y: the sum does not take the register of the product, read again at position 2",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				p := api.Mul(in[0], in[1])
				return api.Add(p, in[0], p)
			},
			2, nil,
			[]gkr.GateInstruction{
				{Op: gkr.OpMul, Inputs: []uint16{0, 1}, Dst: 2},
				{Op: gkr.OpAdd, Inputs: []uint16{2, 0, 2}, Dst: 3},
			},
			4,
		},
		{
			"x*(x+y): the product takes the register of the sum, an instruction result read last",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Mul(in[0], api.Add(in[0], in[1]))
			},
			2, nil,
			[]gkr.GateInstruction{
				{Op: gkr.OpAdd, Inputs: []uint16{0, 1}, Dst: 2},
				{Op: gkr.OpMul, Inputs: []uint16{0, 2}, Dst: 2},
			},
			3,
		},
		{
			"x*y is computed and discarded, x+y is returned: the product is removed",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				api.Mul(in[0], in[1])
				return api.Add(in[0], in[1])
			},
			2, nil,
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{0, 1}, Dst: 2}},
			3,
		},
		{
			"x+2·3: a multiply-accumulate of two constants records an addition, constant first",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.MulAcc(in[0], 2, 3)
			},
			1, []int64{6},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x+(-5): the negation of a constant is a constant",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.Neg(5))
			},
			1, []int64{-5},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x+(1+2·3): a multiply-accumulate of constants is a constant",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.MulAcc(1, 2, 3))
			},
			1, []int64{7},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x+(1+2+3)^17: a sum raised to the power 17 of constants is a constant",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.SumExp17(1, 2, 3))
			},
			1, []int64{16926659444736},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"x+(p-1)¹⁷: folding is modulo the field",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(in[0], api.SumExp17(new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)), 0, 0))
			},
			1, []int64{-1},
			[]gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{2, 0}, Dst: 1}},
			2,
		},
		{
			"(y*z)+(y+z): the register of an input that is never read is not reused",
			func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				return api.Add(api.Mul(in[1], in[2]), api.Add(in[1], in[2]))
			},
			3, nil,
			[]gkr.GateInstruction{
				{Op: gkr.OpMul, Inputs: []uint16{1, 2}, Dst: 3},
				{Op: gkr.OpAdd, Inputs: []uint16{1, 2}, Dst: 4},
				{Op: gkr.OpAdd, Inputs: []uint16{3, 4}, Dst: 3},
			},
			5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := CompileGateFunction(tt.f, tt.nbIn, bn254())
			require.NoError(t, err)

			// the constants are residues modulo the field's, p-3 for -3
			var expected, constants []string
			for _, c := range tt.constants {
				expected = append(expected, new(big.Int).Mod(big.NewInt(c), ecc.BN254.ScalarField()).String())
			}
			for _, c := range compiled.Evaluate.Constants {
				constants = append(constants, c.String())
			}
			assert.Equal(t, expected, constants)
			assert.Equal(t, tt.instructions, compiled.Evaluate.Instructions)
			assert.Equal(t, tt.nbRegisters, compiled.Evaluate.NbRegisters())
			assert.NoError(t, compiled.Evaluate.CheckEvaluatorAssumptions())
		})
	}
}

// TestCheckEvaluatorAssumptionsRejectsInputWrite checks that a hand-built bytecode with an instruction
// that writes the register of an input is rejected, naming the instruction.
func TestCheckEvaluatorAssumptionsRejectsInputWrite(t *testing.T) {
	bytecode := gkr.GateBytecode{
		Instructions: []gkr.GateInstruction{
			{Op: gkr.OpAdd, Inputs: []uint16{0, 1}, Dst: 2},
			{Op: gkr.OpMul, Inputs: []uint16{2, 1}, Dst: 1},
		},
		NbIn: 2,
	}
	assert.EqualError(t, bytecode.CheckEvaluatorAssumptions(), "instruction 1 (mul): writes the register of input 1")
}

// TestCheckEvaluatorAssumptionsRejectsLateConstant checks that a hand-built bytecode with a
// constant in position 2 of an Add is rejected, naming the instruction.
func TestCheckEvaluatorAssumptionsRejectsLateConstant(t *testing.T) {
	bytecode := gkr.GateBytecode{
		Instructions: []gkr.GateInstruction{{Op: gkr.OpAdd, Inputs: []uint16{0, 1, 3}, Dst: 2}},
		Constants:    []*big.Int{big.NewInt(5)},
		NbIn:         2,
	}
	assert.EqualError(t, bytecode.CheckEvaluatorAssumptions(), "instruction 0 (add): constant operand at position 2")
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
			assert.Equal(t, tt.nbIn, compiled.Evaluate.NbIn)
			assert.Equal(t, tt.degree, compiled.Degree)
			assert.Equal(t, tt.solvableVar, compiled.SolvableVar)
		})
	}
}

func testFitPoly(t *testing.T, name string, f gkr.GateFunction, nbIn, degree, maxDegree int) {
	t.Run(name, func(t *testing.T) {
		for _, fd := range testFields() {
			tester := gateTester{FieldAPI: FieldAPI{Field: fd}, f: f, nbIn: nbIn}
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
		for _, fd := range testFields() {
			tester := gateTester{FieldAPI: FieldAPI{Field: fd}, f: f, nbIn: len(isAdditive)}
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

// TestExtensionDefiningRelation checks mul's reduction against the defining relation of each
// extension's tower generator: KoalaBear's E6, X⁶ = 2X³ + 2 (from its minimal polynomial
// X⁶ - 2X³ - 2), and MamaBear's E3, X³ = X + 1 (from X³ - X - 1).
func TestExtensionDefiningRelation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field Field
		power []int64 // the coefficients of Xⁿ, n the degree, in increasing degree
	}{
		{"KoalaBear E6", gkr.KoalaBearE6(), []int64{2, 0, 0, 2, 0, 0}},
		{"MamaBear E3", gkr.MamaBearE3(), []int64{1, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tester := FieldAPI{Field: tc.field}
			n := tc.field.Degree()

			x := make([]*big.Int, n)
			want := make([]*big.Int, n)
			for i := range x {
				x[i] = big.NewInt(0)
				want[i] = big.NewInt(tc.power[i])
			}
			x[1].SetInt64(1)

			require.True(t, tester.equal(tester.pow(x, big.NewInt(int64(n))), want))
		})
	}
}
