package fieldextension

import (
	"testing"

	fr "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type kbE2AddTestCircuit struct {
	A, B, C e2
}

func (c *kbE2AddTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.Add(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2Add(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	a.MustSetRandom()
	b.MustSetRandom()
	c.Add(&a, &b)

	assert.CheckCircuit(
		&kbE2AddTestCircuit{},
		test.WithValidAssignment(&kbE2AddTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: e2{A0: b.A0, A1: b.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbE2SubTestCircuit struct {
	A, B, C e2
}

func (c *kbE2SubTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.Sub(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2Sub(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	a.MustSetRandom()
	b.MustSetRandom()
	c.Sub(&a, &b)

	assert.CheckCircuit(
		&kbE2SubTestCircuit{},
		test.WithValidAssignment(&kbE2SubTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: e2{A0: b.A0, A1: b.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbE2MulTestCircuit struct {
	A, B, C e2
}

func (c *kbE2MulTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.Mul(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2Mul(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	a.MustSetRandom()
	b.MustSetRandom()
	c.Mul(&a, &b)

	assert.CheckCircuit(
		&kbE2MulTestCircuit{},
		test.WithValidAssignment(&kbE2MulTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: e2{A0: b.A0, A1: b.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbE2MulByElementTestCircuit struct {
	A e2
	B frontend.Variable
	C e2
}

func (c *kbE2MulByElementTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.MulByElement(c.A, c.B)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2MulByElement(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E2
	var b fr.Element
	a.MustSetRandom()
	b.MustSetRandom()
	c.MulByElement(&a, &b)

	assert.CheckCircuit(
		&kbE2MulByElementTestCircuit{},
		test.WithValidAssignment(&kbE2MulByElementTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			B: b,
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbE2MulByNonResidueTestCircuit struct {
	A, C e2
}

func (c *kbE2MulByNonResidueTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	res := ext2.MulByNonResidue(c.A)
	api.AssertIsEqual(res.A0, c.C.A0)
	api.AssertIsEqual(res.A1, c.C.A1)

	return nil
}

func TestKoalabearExt2MulByNonResidue(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E2
	a.MustSetRandom()
	c.MulByQuadraticNonResidue(&a)

	assert.CheckCircuit(
		&kbE2MulByNonResidueTestCircuit{},
		test.WithValidAssignment(&kbE2MulByNonResidueTestCircuit{
			A: e2{A0: a.A0, A1: a.A1},
			C: e2{A0: c.A0, A1: c.A1},
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbE2InverseTestCircuit struct {
	A, AInv e2
}

func (c *kbE2InverseTestCircuit) Define(api frontend.API) error {
	ext2 := newKoalabearExt2(api)

	invA := ext2.Inverse(c.A)
	api.AssertIsEqual(invA.A0, c.AInv.A0)
	api.AssertIsEqual(invA.A1, c.AInv.A1)
	return nil
}

func TestKoalabearExt2Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	var a, aInv extensions.E2
	a.MustSetRandom()
	if a.IsZero() {
		a.SetOne()
	}
	aInv.Inverse(&a)

	assert.CheckCircuit(
		&kbE2InverseTestCircuit{},
		test.WithValidAssignment(&kbE2InverseTestCircuit{
			A:    e2{A0: a.A0, A1: a.A1},
			AInv: e2{A0: aInv.A0, A1: aInv.A1},
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbExt4AddTestCircuit struct {
	A, B, C Element
}

func (c *kbExt4AddTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	addRes := ext4.Add(c.A, c.B)
	ext4.AssertIsEqual(addRes, c.C)

	return nil
}

func TestKoalabearExt4Add(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.MustSetRandom()
	b.MustSetRandom()
	c.Add(&a, &b)

	assert.CheckCircuit(
		&kbExt4AddTestCircuit{},
		test.WithValidAssignment(&kbExt4AddTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbExt4SubTestCircuit struct {
	A, B, C Element
}

func (c *kbExt4SubTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	subRes := ext4.Sub(c.A, c.B)
	ext4.AssertIsEqual(subRes, c.C)

	return nil
}

func TestKoalabearExt4Sub(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.MustSetRandom()
	b.MustSetRandom()
	c.Sub(&a, &b)

	assert.CheckCircuit(
		&kbExt4SubTestCircuit{},
		test.WithValidAssignment(&kbExt4SubTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbExt4MulByElementTestCircuit struct {
	A Element
	B frontend.Variable
	C Element
}

func (c *kbExt4MulByElementTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	mulRes := ext4.MulByElement(c.A, c.B)
	ext4.AssertIsEqual(mulRes, c.C)

	return nil
}

func TestKoalabearExt4MulByElement(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E4
	var b fr.Element
	a.MustSetRandom()
	b.MustSetRandom()
	c.MulByElement(&a, &b)

	assert.CheckCircuit(
		&kbExt4MulByElementTestCircuit{},
		test.WithValidAssignment(&kbExt4MulByElementTestCircuit{A: ValueOf(a), B: b, C: ValueOf(c)}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbMulTestCircuit struct {
	A, B, C Element
}

func (c *kbMulTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	mulRes := ext4.Mul(c.A, c.B)
	ext4.AssertIsEqual(mulRes, c.C)

	return nil
}

func TestKoalabearExt4Mul(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var a, b, c extensions.E4
		a.MustSetRandom()
		b.MustSetRandom()
		c.Mul(&a, &b)

		assert.CheckCircuit(
			&kbMulTestCircuit{},
			test.WithValidAssignment(&kbMulTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "random")
	assert.Run(func(assert *test.Assert) {
		var a, b, c extensions.E4
		a.SetOne()
		b.SetOne()
		c.Mul(&a, &b)

		assert.CheckCircuit(
			&kbMulTestCircuit{},
			test.WithValidAssignment(&kbMulTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "one")
	assert.Run(func(assert *test.Assert) {
		var a, b, c extensions.E4
		a.SetZero()
		b.SetZero()
		c.Mul(&a, &b)

		assert.CheckCircuit(
			&kbMulTestCircuit{},
			test.WithValidAssignment(&kbMulTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "zero")
	assert.Run(func(assert *test.Assert) {
		var a, b, c extensions.E4
		a.B0.A0.SetInt64(-1)
		a.B0.A1.SetInt64(-1)
		a.B1.A0.SetInt64(-1)
		a.B1.A1.SetInt64(-1)

		b.B0.A0.SetInt64(-1)
		b.B0.A1.SetInt64(-1)
		b.B1.A0.SetInt64(-1)
		b.B1.A1.SetInt64(-1)

		c.Mul(&a, &b)

		assert.CheckCircuit(
			&kbMulTestCircuit{},
			test.WithValidAssignment(&kbMulTestCircuit{A: ValueOf(a), B: ValueOf(b), C: ValueOf(c)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "-1")
}

type kbInverseTestCircuit struct {
	A, AInv Element
}

func (c *kbInverseTestCircuit) Define(api frontend.API) error {
	ext4 := newKoalabearExt4(api)

	invA := ext4.Inverse(c.A)
	ext4.AssertIsEqual(invA, c.AInv)
	return nil
}
func TestKoalabearExt4Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var a, aInv extensions.E4
		a.MustSetRandom()
		if a.IsZero() {
			a.SetOne()
		}
		aInv.Inverse(&a)

		assert.CheckCircuit(
			&kbInverseTestCircuit{},
			test.WithValidAssignment(&kbInverseTestCircuit{A: ValueOf(a), AInv: ValueOf(aInv)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "random")
	assert.Run(func(assert *test.Assert) {
		var a, aInv extensions.E4
		a.SetOne()
		aInv.Inverse(&a)

		assert.CheckCircuit(
			&kbInverseTestCircuit{},
			test.WithValidAssignment(&kbInverseTestCircuit{A: ValueOf(a), AInv: ValueOf(aInv)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "one")
	assert.Run(func(assert *test.Assert) {
		var a, aInv extensions.E4
		a.SetZero()
		aInv.SetZero()

		// should fail
		assert.CheckCircuit(
			&kbInverseTestCircuit{},
			test.WithInvalidAssignment(&kbInverseTestCircuit{A: ValueOf(a), AInv: ValueOf(aInv)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "zero")
	assert.Run(func(assert *test.Assert) {
		var a, aInv extensions.E4
		a.B0.A0.SetInt64(-1)
		a.B0.A1.SetInt64(-1)
		a.B1.A0.SetInt64(-1)
		a.B1.A1.SetInt64(-1)
		aInv.Inverse(&a)

		assert.CheckCircuit(
			&kbInverseTestCircuit{},
			test.WithValidAssignment(&kbInverseTestCircuit{A: ValueOf(a), AInv: ValueOf(aInv)}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "-1")

}

type kbFlattenConsistencyCircut struct {
	A e4

	B Element
}

func (c *kbFlattenConsistencyCircut) Define(api frontend.API) error {
	flattenA := flattenE4(c.A)
	for i := 0; i < 4; i++ {
		api.AssertIsEqual(flattenA[i], c.B[i])
	}

	// case 0
	unflattenBc0 := unflattenE4(c.B[:0])
	roundtripc0 := flattenE4(unflattenBc0)
	for i := range roundtripc0 {
		api.AssertIsEqual(roundtripc0[i], 0)
	}
	// case 1
	unflattenBc1 := unflattenE4(c.B[:1])
	roundtripc1 := flattenE4(unflattenBc1)
	api.AssertIsEqual(roundtripc1[0], c.B[0])
	for i := 1; i < 4; i++ {
		api.AssertIsEqual(roundtripc1[i], 0)
	}
	// case 2
	unflattenBc2 := unflattenE4(c.B[:2])
	roundtripc2 := flattenE4(unflattenBc2)
	for i := range 2 {
		api.AssertIsEqual(roundtripc2[i], c.B[i])
	}
	for i := 2; i < 4; i++ {
		api.AssertIsEqual(roundtripc2[i], 0)
	}
	// case 3
	unflattenBc3 := unflattenE4(c.B[:3])
	roundtripc3 := flattenE4(unflattenBc3)
	for i := range 3 {
		api.AssertIsEqual(roundtripc3[i], c.B[i])
	}
	for i := 3; i < 4; i++ {
		api.AssertIsEqual(roundtripc3[i], 0)
	}
	// case 4
	unflattenBc4 := unflattenE4(c.B[:4])
	roundtripc4 := flattenE4(unflattenBc4)
	for i := 0; i < 4; i++ {
		api.AssertIsEqual(roundtripc4[i], c.B[i])
	}

	return nil
}

func TestKoalabearExt4FlattenUnflattenConsistency(t *testing.T) {
	assert := test.NewAssert(t)
	var a extensions.E4
	a.MustSetRandom()

	assert.CheckCircuit(
		&kbFlattenConsistencyCircut{},
		test.WithValidAssignment(&kbFlattenConsistencyCircut{
			A: e4{
				B0: e2{
					A0: a.B0.A0,
					A1: a.B0.A1,
				},
				B1: e2{
					A0: a.B1.A0,
					A1: a.B1.A1,
				},
			},
			B: ValueOf(a),
		}),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

type kbValueOfTestCircuit struct {
	A        Element
	Expected e4
}

func (c *kbValueOfTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.A[0], c.Expected.B0.A0)
	api.AssertIsEqual(c.A[1], c.Expected.B0.A1)
	api.AssertIsEqual(c.A[2], c.Expected.B1.A0)
	api.AssertIsEqual(c.A[3], c.Expected.B1.A1)
	return nil
}

func TestValueOf(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		var a fr.Element
		assert.Run(func(assert *test.Assert) {
			a.MustSetRandom()

			assert.CheckCircuit(
				&kbValueOfTestCircuit{},
				test.WithValidAssignment(&kbValueOfTestCircuit{
					A:        ValueOf(a),
					Expected: e4{B0: e2{A0: a, A1: 0}, B1: e2{A0: 0, A1: 0}},
				}),
				test.WithoutCurveChecks(),
				test.WithSmallfieldCheck())
		}, "random")
		assert.Run(func(assert *test.Assert) {
			a.SetZero()

			assert.CheckCircuit(
				&kbValueOfTestCircuit{},
				test.WithValidAssignment(&kbValueOfTestCircuit{
					A:        ValueOf(a),
					Expected: e4{B0: e2{A0: a, A1: 0}, B1: e2{A0: 0, A1: 0}},
				}),
				test.WithoutCurveChecks(),
				test.WithSmallfieldCheck())
		}, "zero")
		assert.Run(func(assert *test.Assert) {
			a.SetOne()

			assert.CheckCircuit(
				&kbValueOfTestCircuit{},
				test.WithValidAssignment(&kbValueOfTestCircuit{
					A:        ValueOf(a),
					Expected: e4{B0: e2{A0: a, A1: 0}, B1: e2{A0: 0, A1: 0}},
				}),
				test.WithoutCurveChecks(),
				test.WithSmallfieldCheck())
		}, "one")
		assert.Run(func(assert *test.Assert) {
			a.SetInt64(-1)

			assert.CheckCircuit(
				&kbValueOfTestCircuit{},
				test.WithValidAssignment(&kbValueOfTestCircuit{
					A:        ValueOf(a),
					Expected: e4{B0: e2{A0: a, A1: 0}, B1: e2{A0: 0, A1: 0}},
				}),
				test.WithoutCurveChecks(),
				test.WithSmallfieldCheck())
		}, "-1")
	}, "koalabear.Element")

	assert.Run(func(assert *test.Assert) {
		var a extensions.E4
		a.MustSetRandom()

		assert.CheckCircuit(
			&kbValueOfTestCircuit{},
			test.WithValidAssignment(&kbValueOfTestCircuit{
				A: ValueOf(a),
				Expected: e4{
					B0: e2{
						A0: a.B0.A0,
						A1: a.B0.A1,
					},
					B1: e2{
						A0: a.B1.A0,
						A1: a.B1.A1,
					},
				},
			}),
			test.WithoutCurveChecks(),
			test.WithSmallfieldCheck())
	}, "extensions.E4")
}
