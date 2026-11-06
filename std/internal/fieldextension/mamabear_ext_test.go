package fieldextension

import (
	"testing"

	"errors"

	fr "github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark-crypto/field/mamabear/extensions"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/test"
)

// checkMamabear runs the circuit over mamabear only: the extension is defined
// by t^3 - t - 1 over that field and is meaningless elsewhere.
func checkMamabear(assert *test.Assert, circuit, assignment frontend.Circuit) {
	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(assignment),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck(fr.Modulus()))
}

var errDegree = errors.New("unexpected extension degree")

func asE3(a extensions.E3) e3 {
	return e3{A0: a.A0, A1: a.A1, A2: a.A2}
}

type mbE3AddTestCircuit struct {
	A, B, C e3
}

func (c *mbE3AddTestCircuit) Define(api frontend.API) error {
	ext3 := newMamabearExt3(api)
	ext3.AssertIsEqual(ext3.Add(flattenE3(c.A), flattenE3(c.B)), flattenE3(c.C))
	return nil
}

func TestMamabearExt3Add(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E3
	a.MustSetRandom()
	b.MustSetRandom()
	c.Add(&a, &b)
	checkMamabear(assert, &mbE3AddTestCircuit{},
		&mbE3AddTestCircuit{A: asE3(a), B: asE3(b), C: asE3(c)})
}

type mbE3SubTestCircuit struct {
	A, B, C e3
}

func (c *mbE3SubTestCircuit) Define(api frontend.API) error {
	ext3 := newMamabearExt3(api)
	ext3.AssertIsEqual(ext3.Sub(flattenE3(c.A), flattenE3(c.B)), flattenE3(c.C))
	return nil
}

func TestMamabearExt3Sub(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E3
	a.MustSetRandom()
	b.MustSetRandom()
	c.Sub(&a, &b)
	checkMamabear(assert, &mbE3SubTestCircuit{},
		&mbE3SubTestCircuit{A: asE3(a), B: asE3(b), C: asE3(c)})
}

type mbE3MulTestCircuit struct {
	A, B, C e3
}

func (c *mbE3MulTestCircuit) Define(api frontend.API) error {
	ext3 := newMamabearExt3(api)
	ext3.AssertIsEqual(ext3.Mul(flattenE3(c.A), flattenE3(c.B)), flattenE3(c.C))
	return nil
}

// TestMamabearExt3Mul is the one that pins the reduction: t^3 = t+1 folds the
// two top coefficients back into c0, c1 and c2, so a wrong modulus shows up
// here and nowhere else.
func TestMamabearExt3Mul(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E3
	a.MustSetRandom()
	b.MustSetRandom()
	c.Mul(&a, &b)
	checkMamabear(assert, &mbE3MulTestCircuit{},
		&mbE3MulTestCircuit{A: asE3(a), B: asE3(b), C: asE3(c)})
}

// TestMamabearExt3MulBasis multiplies t^2 by t, which is exactly where the
// defining polynomial bites: the result must be t+1, not t^3.
func TestMamabearExt3MulBasis(t *testing.T) {
	assert := test.NewAssert(t)
	var tt, t2, c extensions.E3
	tt.A1.SetOne()  // t
	t2.A2.SetOne()  // t^2
	c.Mul(&t2, &tt) // t^3 = t + 1
	var one, zero fr.Element
	one.SetOne()
	if c.A0 != one || c.A1 != one || c.A2 != zero {
		t.Fatalf("t^3 should be t+1, got %s", c.String())
	}
	checkMamabear(assert, &mbE3MulTestCircuit{},
		&mbE3MulTestCircuit{A: asE3(t2), B: asE3(tt), C: asE3(c)})
}

type mbE3MulByElementTestCircuit struct {
	A e3
	B frontend.Variable
	C e3
}

func (c *mbE3MulByElementTestCircuit) Define(api frontend.API) error {
	ext3 := newMamabearExt3(api)
	ext3.AssertIsEqual(ext3.MulByElement(flattenE3(c.A), c.B), flattenE3(c.C))
	return nil
}

func TestMamabearExt3MulByElement(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E3
	var b fr.Element
	a.MustSetRandom()
	b.MustSetRandom()
	c.MulByElement(&a, &b)
	checkMamabear(assert, &mbE3MulByElementTestCircuit{},
		&mbE3MulByElementTestCircuit{A: asE3(a), B: b, C: asE3(c)})
}

type mbE3InverseTestCircuit struct {
	A, C e3
}

func (c *mbE3InverseTestCircuit) Define(api frontend.API) error {
	ext3 := newMamabearExt3(api)
	ext3.AssertIsEqual(ext3.Inverse(flattenE3(c.A)), flattenE3(c.C))
	return nil
}

func TestMamabearExt3Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E3
	a.MustSetRandom()
	c.Inverse(&a)
	checkMamabear(assert, &mbE3InverseTestCircuit{},
		&mbE3InverseTestCircuit{A: asE3(a), C: asE3(c)})
}

type mbE3InverseRoundTripCircuit struct {
	A e3
}

// Define checks a * a^-1 == 1 fully in circuit, so the hint output is
// constrained rather than trusted.
func (c *mbE3InverseRoundTripCircuit) Define(api frontend.API) error {
	ext3 := newMamabearExt3(api)
	a := flattenE3(c.A)
	ext3.AssertIsEqual(ext3.Mul(a, ext3.Inverse(a)), ext3.AsExtensionVariable(1))
	return nil
}

func TestMamabearExt3InverseRoundTrip(t *testing.T) {
	assert := test.NewAssert(t)
	var a extensions.E3
	a.MustSetRandom()
	checkMamabear(assert, &mbE3InverseRoundTripCircuit{}, &mbE3InverseRoundTripCircuit{A: asE3(a)})
}

// TestMamabearExt3ViaNewExtension checks that NewExtension dispatches to the
// dedicated degree-3 implementation over mamabear, rather than falling through
// to the generic path which would mis-reduce a non-binomial modulus.
type mbE3ViaNewExtensionCircuit struct {
	A, B, C e3
}

func (c *mbE3ViaNewExtensionCircuit) Define(api frontend.API) error {
	ext, err := NewExtension(api)
	if err != nil {
		return err
	}
	if ext.Degree() != 3 {
		return errDegree
	}
	ext.AssertIsEqual(ext.Mul(flattenE3(c.A), flattenE3(c.B)), flattenE3(c.C))
	return nil
}

func TestMamabearExt3ViaNewExtension(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E3
	a.MustSetRandom()
	b.MustSetRandom()
	c.Mul(&a, &b)
	checkMamabear(assert, &mbE3ViaNewExtensionCircuit{},
		&mbE3ViaNewExtensionCircuit{A: asE3(a), B: asE3(b), C: asE3(c)})
}
