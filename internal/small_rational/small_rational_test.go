package small_rational

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCmp(t *testing.T) {
	// 9 distinct values, (i-4)/2 for i = 0..8: -2, -1.5, -1, -0.5, 0, 0.5, 1, 1.5, 2, alternating
	// between two SetInterface input forms: a plain integer and an explicit "n/2" fraction string.
	cases := make([]SmallRational, 9)
	for i := int64(0); i < 9; i++ {
		var err error
		if i%2 == 0 {
			_, err = cases[i].SetInterface((i - 4) / 2)
		} else {
			_, err = cases[i].SetInterface(fmt.Sprintf("%d/2", i-4))
		}
		assert.NoError(t, err)
	}

	for i := range cases {
		for j := range cases {
			var expectedCmp int
			cmp := cases[i].Cmp(&cases[j])
			if i < j {
				expectedCmp = -1
			} else if i == j {
				expectedCmp = 0
			} else {
				expectedCmp = 1
			}
			assert.Equal(t, expectedCmp, cmp, "comparing index %d, index %d", i, j)
		}
	}

	const zeroIndex = 4 // (4-4)/2 = 0
	var zero SmallRational
	for i := range cases {
		var expectedCmp int
		cmp := cases[i].Cmp(&zero)
		cmpNeg := zero.Cmp(&cases[i])
		if i < zeroIndex {
			expectedCmp = -1
		} else if i == zeroIndex {
			expectedCmp = 0
		} else {
			expectedCmp = 1
		}

		assert.Equal(t, expectedCmp, cmp, "comparing index %d, 0", i)
		assert.Equal(t, -expectedCmp, cmpNeg, "comparing 0, index %d", i)
	}
}

func TestDouble(t *testing.T) {
	values := []interface{}{1, 2, 3, 4, 5, "2/3", "3/2", "6/4"}
	valsDoubled := []interface{}{2, 4, 6, 8, 10, "8/6", 3, 3}

	for i := range values {
		var v, vDoubled, vDoubledExpected SmallRational
		_, err := v.SetInterface(values[i])
		assert.NoError(t, err)
		_, err = vDoubledExpected.SetInterface(valsDoubled[i])
		assert.NoError(t, err)
		vDoubled.Double(&v)
		assert.True(t, vDoubled.Equal(&vDoubledExpected),
			"mismatch at %d: expected 2×%s = %s, saw %s", i, v.String(), vDoubledExpected.String(), vDoubled.String())

	}
}

func TestOperandConstancy(t *testing.T) {
	var p0, p, pPure SmallRational
	p0.SetInt64(1)
	p.SetInt64(-3)
	pPure.SetInt64(-3)

	res := p
	res.Add(&res, &p0)
	assert.True(t, p.Equal(&pPure))
}

func TestSquare(t *testing.T) {
	var two, four, x SmallRational
	two.SetInt64(2)
	four.SetInt64(4)

	x.Square(&two)

	assert.True(t, x.Equal(&four), "expected 4, saw %s", x.Text(10))
}

func TestSetBytes(t *testing.T) {
	var c SmallRational
	c.SetBytes([]byte("firstChallenge.0"))

}
