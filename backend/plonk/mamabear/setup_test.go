package plonk

import (
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark-crypto/field/mamabear/fft"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"

	cs "github.com/consensys/gnark/constraint/mamabear"
)

type testCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",secret"`
	Z frontend.Variable `gnark:",public"`
}

func (c *testCircuit) Define(api frontend.API) error {
	// a few constraints sharing wires, so the permutation has non-trivial cycles
	xy := api.Mul(c.X, c.Y)
	s := api.Add(xy, c.X)
	api.AssertIsEqual(s, c.Z)
	api.AssertIsDifferent(c.Y, 0)
	return nil
}

// compileTrace compiles the test circuit over mamabear and builds its trace.
func compileTrace(t *testing.T) (*cs.SparseR1CS, *fft.Domain, *Trace) {
	t.Helper()
	ccs, err := frontend.Compile(mamabear.Modulus(), scs.NewBuilder, &testCircuit{})
	require.NoError(t, err)

	spr, ok := ccs.(*cs.SparseR1CS)
	require.True(t, ok, "expected a mamabear SparseR1CS, got %T", ccs)

	nbConstraints := spr.GetNbConstraints()
	nbPublic := len(spr.Public)
	sizeSystem := nbConstraints + nbPublic
	size := uint64(1) << bits.Len(uint(sizeSystem-1))

	domain := fft.NewDomain(size)
	return spr, domain, NewTrace(spr, domain)
}

func TestNewTraceShape(t *testing.T) {
	spr, domain, trace := compileTrace(t)
	size := int(domain.Cardinality)

	for name, p := range map[string][]mamabear.Element{
		"Ql": trace.Ql.Coefficients(),
		"Qr": trace.Qr.Coefficients(),
		"Qm": trace.Qm.Coefficients(),
		"Qo": trace.Qo.Coefficients(),
		"Qk": trace.Qk.Coefficients(),
		"S1": trace.S1.Coefficients(),
		"S2": trace.S2.Coefficients(),
		"S3": trace.S3.Coefficients(),
	} {
		require.Len(t, p, size, "%s has the wrong length", name)
	}
	require.Len(t, trace.S, 3*size, "permutation support has the wrong length")

	// The first len(Public) rows are the public input placeholders:
	// -1*w_i + qk_i = 0, with every other selector zero.
	var minusOne mamabear.Element
	minusOne.SetOne().Neg(&minusOne)
	ql, qr, qm, qo, qk := trace.Ql.Coefficients(), trace.Qr.Coefficients(),
		trace.Qm.Coefficients(), trace.Qo.Coefficients(), trace.Qk.Coefficients()
	for i := range spr.Public {
		require.Equal(t, minusOne, ql[i], "Ql[%d]", i)
		require.True(t, qr[i].IsZero(), "Qr[%d]", i)
		require.True(t, qm[i].IsZero(), "Qm[%d]", i)
		require.True(t, qo[i].IsZero(), "Qo[%d]", i)
		require.True(t, qk[i].IsZero(), "Qk[%d]", i)
	}
}

// TestBuildPermutationIsAPermutation is the property that actually matters: S
// must be a bijection on [0, 3*size), otherwise the copy constraints do not
// encode a valid wiring.
func TestBuildPermutationIsAPermutation(t *testing.T) {
	_, domain, trace := compileTrace(t)
	n := 3 * int(domain.Cardinality)

	require.Len(t, trace.S, n)
	seen := make([]bool, n)
	moved := 0
	for i, v := range trace.S {
		require.GreaterOrEqual(t, v, int64(0), "S[%d] is unset", i)
		require.Less(t, v, int64(n), "S[%d] out of range", i)
		require.False(t, seen[v], "S is not injective: %d hit twice", v)
		seen[v] = true
		if int64(i) != v {
			moved++
		}
	}
	// Guard against the check above going vacuous: the test circuit shares wires
	// between constraints, so the permutation must have non-trivial cycles. The
	// identity is a bijection too and would tell us nothing.
	require.NotZero(t, moved, "S is the identity, the bijection check is vacuous")
}

// TestPermutationPolynomialsMatchSupport checks S1, S2, S3 really are the
// permutation evaluated on <g> || u<g> || u^2<g>, split in three.
func TestPermutationPolynomialsMatchSupport(t *testing.T) {
	_, domain, trace := compileTrace(t)
	n := int(domain.Cardinality)

	support := getSupportPermutation(domain)
	require.Len(t, support, 3*n)

	s := [3][]mamabear.Element{
		trace.S1.Coefficients(), trace.S2.Coefficients(), trace.S3.Coefficients(),
	}
	for part := range 3 {
		for i := range n {
			require.Equal(t, support[trace.S[part*n+i]], s[part][i],
				"S%d[%d] does not match the permutation support", part+1, i)
		}
	}
}

// TestGetSupportPermutation checks the support is <g> || u<g> || u^2<g>.
func TestGetSupportPermutation(t *testing.T) {
	domain := fft.NewDomain(8)
	res := getSupportPermutation(domain)
	n := int(domain.Cardinality)
	require.Len(t, res, 3*n)

	var acc, u2 mamabear.Element
	acc.SetOne()
	u2.Square(&domain.FrMultiplicativeGen)
	for i := range n {
		require.Equal(t, acc, res[i], "coset 0 at %d", i)

		var shifted mamabear.Element
		shifted.Mul(&acc, &domain.FrMultiplicativeGen)
		require.Equal(t, shifted, res[n+i], "coset 1 at %d", i)

		shifted.Mul(&acc, &u2)
		require.Equal(t, shifted, res[2*n+i], "coset 2 at %d", i)

		acc.Mul(&acc, &domain.Generator)
	}
	// <g> has order exactly the domain cardinality
	require.True(t, acc.IsOne(), "generator does not have order %d", n)
}
