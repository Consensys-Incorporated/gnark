package polynomial

import (
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

type Polynomial []frontend.Variable
type MultiLin []frontend.Variable

var minFoldScaledLogSize = 16

// Evaluate assumes len(m) = 1 << len(at)
// it doesn't modify m
func (m MultiLin) Evaluate(api frontend.API, at []frontend.Variable) frontend.Variable {
	_m := m.Clone()

	/*minFoldScaledLogSize := 16
	if api is r1cs {
		minFoldScaledLogSize = math.MaxInt64  // no scaling for r1cs
	}*/

	scaleCorrectionFactor := frontend.Variable(1)
	// at each iteration fold by at[i]
	for len(_m) > 1 {
		if len(_m) >= minFoldScaledLogSize {
			scaleCorrectionFactor = api.Mul(scaleCorrectionFactor, _m.foldScaled(api, at[0]))
		} else {
			_m.fold(api, at[0])
		}
		_m = _m[:len(_m)/2]
		at = at[1:]
	}

	if len(at) != 0 {
		panic("incompatible evaluation vector size")
	}

	return api.Mul(_m[0], scaleCorrectionFactor)
}

// fold fixes the value of m's first variable to at, thus halving m's required bookkeeping table size
// WARNING: The user should halve m themselves after the call
func (m MultiLin) fold(api frontend.API, at frontend.Variable) {
	zero := m[:len(m)/2]
	one := m[len(m)/2:]
	for j := range zero {
		diff := api.Sub(one[j], zero[j])
		zero[j] = api.MulAcc(zero[j], diff, at)
	}
}

// foldScaled(m, at) = fold(m, at) / (1 - at)
// it returns 1 - at, for convenience
func (m MultiLin) foldScaled(api frontend.API, at frontend.Variable) (denom frontend.Variable) {
	denom = api.Sub(1, at)
	coeff := api.Div(at, denom)
	zero := m[:len(m)/2]
	one := m[len(m)/2:]
	for j := range zero {
		zero[j] = api.MulAcc(zero[j], one[j], coeff)
	}
	return
}

func (m MultiLin) NumVars() int {
	return bits.TrailingZeros(uint(len(m)))
}

func (m MultiLin) Clone() MultiLin {
	clone := make(MultiLin, len(m))
	copy(clone, m)
	return clone
}

func (p Polynomial) Eval(api frontend.API, at frontend.Variable) (pAt frontend.Variable) {
	pAt = 0

	for i := len(p) - 1; i >= 0; i-- {
		pAt = api.Add(pAt, p[i])
		if i != 0 {
			pAt = api.Mul(pAt, at)
		}
	}

	return
}

// negFactorial returns (-n)(-n+1)...(-2)(-1) for n ≥ 1, and 1 for n = 0.
// This is not asymptotically efficient, but works for small values.
func negFactorial(n int) *big.Int {
	result := big.NewInt(1)
	for k := 1; k <= n; k++ {
		result.Mul(result, big.NewInt(int64(-k)))
	}
	return result
}

// computeDeltaAtNaive brute forces the computation of the δᵢ(at)
func computeDeltaAtNaive(api frontend.API, at frontend.Variable, valuesLen int) []frontend.Variable {
	deltaAt := make([]frontend.Variable, valuesLen)
	factInv := api.Inverse(negFactorial(valuesLen - 1))

	for i := range deltaAt {
		deltaAt[i] = factInv
		for j := 0; j < valuesLen; j++ {
			if i != j {
				deltaAt[i] = api.Mul(deltaAt[i], api.Sub(at, j))
			}
		}

		if i+1 < len(deltaAt) {
			factAdjustment := api.DivUnchecked(i+1-valuesLen, i+1)
			factInv = api.Mul(factAdjustment, factInv)
		}
	}
	return deltaAt
}

// InterpolateLDE fits a polynomial f of degree len(values)-1 such that f(i) = values[i] whenever defined. Returns f(at)
func InterpolateLDE(api frontend.API, at frontend.Variable, values []frontend.Variable) frontend.Variable {
	deltaAt := computeDeltaAtNaive(api, at, len(values))

	res := frontend.Variable(0)

	for i, c := range values {
		res = api.Add(res,
			api.Mul(c, deltaAt[i]),
		)
	}

	return res
}

// EvalEq returns Πⁿ₁ Eq(xᵢ, yᵢ) = Πⁿ₁ xᵢyᵢ + (1-xᵢ)(1-yᵢ) = Πⁿ₁ (1 + 2xᵢyᵢ - xᵢ - yᵢ). Is assumes len(x) = len(y) =: n
func EvalEq(api frontend.API, x, y []frontend.Variable) (eq frontend.Variable) {

	eq = 1
	for i := range x {
		next := api.Mul(x[i], y[i])
		next = api.Add(next, next)
		next = api.Add(next, 1)
		next = api.Sub(next, x[i])
		next = api.Sub(next, y[i])

		eq = api.Mul(eq, next)
	}
	return
}
