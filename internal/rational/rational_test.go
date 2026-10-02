package rational

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetInterface(t *testing.T) {
	cases := []struct {
		name  string
		value interface{}
		want  string // Text(10) of the expected value
	}{
		{"int64", int64(-3), "-3"},
		{"int", 5, "5"},
		{"integer float64", 4.0, "4"},
		{"decimal string", "7", "7"},
		{"fraction string, unreduced", "6/4", "3/2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var z Element
			_, err := z.SetInterface(c.value)
			assert.NoError(t, err)
			assert.Equal(t, c.want, z.Text(10))
		})
	}

	t.Run("non-integer float64 rejected", func(t *testing.T) {
		var z Element
		_, err := z.SetInterface(4.5)
		assert.Error(t, err)
	})

	t.Run("unparseable string rejected", func(t *testing.T) {
		var z Element
		_, err := z.SetInterface("not a number")
		assert.Error(t, err)
	})
}

// Inverse diverges from big.Rat.Inv, which panics on 0.
func TestInverseZero(t *testing.T) {
	var zero, inv Element
	inv.Inverse(&zero)
	assert.True(t, inv.IsZero())
}

func TestBytesRoundTrip(t *testing.T) {
	cases := []interface{}{0, 1, -1, "3/5", "-7/11"}
	for _, v := range cases {
		var x, y Element
		_, err := x.SetInterface(v)
		assert.NoError(t, err)
		y.SetBytes(x.Marshal())
		assert.True(t, x.Equal(&y), "round trip mismatch for %v: %s != %s", v, x.String(), y.String())
	}
}

// SetBytes diverges from big.Rat.SetFrac, which panics on a zero denominator.
func TestSetBytesZeroDenominator(t *testing.T) {
	var z Element
	z.SetBytes(make([]byte, Bytes))
	assert.True(t, z.IsZero())
}

// TestOperandConstancy checks that mutating a copy through an aliased receiver (res := p;
// res.Add(&res, &p0)) never writes into p's storage.
func TestOperandConstancy(t *testing.T) {
	var p0, p, pPure Element
	p0.SetInt64(1)
	p.SetInt64(-3)
	pPure.SetInt64(-3)

	res := p
	res.Add(&res, &p0)
	assert.True(t, p.Equal(&pPure))
}
