package rational

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVectorOperations checks the vector methods against the operations on the elements.
func TestVectorOperations(t *testing.T) {
	const n = 5
	a, b := make(Vector, n), make(Vector, n)
	a.MustSetRandom()
	b.MustSetRandom()
	var c Element
	c.MustSetRandom()

	for _, tc := range []struct {
		name   string
		vector func(res *Vector)
		entry  func(res, a, b *Element)
	}{
		{"Add", func(res *Vector) { res.Add(a, b) }, func(res, a, b *Element) { res.Add(a, b) }},
		{"Sub", func(res *Vector) { res.Sub(a, b) }, func(res, a, b *Element) { res.Sub(a, b) }},
		{"Mul", func(res *Vector) { res.Mul(a, b) }, func(res, a, b *Element) { res.Mul(a, b) }},
		{"Neg", func(res *Vector) { res.Neg(a) }, func(res, a, _ *Element) { res.Neg(a) }},
		{"ScalarMul", func(res *Vector) { res.ScalarMul(a, &c) }, func(res, a, _ *Element) { res.Mul(a, &c) }},
		{"ScalarAdd", func(res *Vector) { res.ScalarAdd(a, &c) }, func(res, a, _ *Element) { res.Add(a, &c) }},
		{"ScalarSub", func(res *Vector) { res.ScalarSub(a, &c) }, func(res, a, _ *Element) { res.Sub(a, &c) }},
		{"ScalarSubFrom", func(res *Vector) { res.ScalarSubFrom(&c, a) }, func(res, a, _ *Element) { res.Sub(&c, a) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := make(Vector, n)
			tc.vector(&res)
			for i := range res {
				var want Element
				tc.entry(&want, &a[i], &b[i])
				require.True(t, want.Equal(&res[i]), "entry %d", i)
			}
		})
	}

	t.Run("InnerProduct", func(t *testing.T) {
		var want, term Element
		for i := range a {
			term.Mul(&a[i], &b[i])
			want.Add(&want, &term)
		}
		got := a.InnerProduct(b)
		require.True(t, want.Equal(&got))
	})
}
