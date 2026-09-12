package maptocurve_increment

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// testMessages exercises:
//   - small constants (0, 1, 42, 123456789),
//   - the largest "safe" message: 2^(bitlen(q)-8) − 1 (exactly bitlen(q)−8 bits),
//   - a message with the top 8 bits set (violates the msg < q/256
//     precondition; the circuit still solves — non-uniqueness is documented).
func testMessages[F emulated.FieldParams]() []*big.Int {
	var t F
	q := t.Modulus()
	bitlen := q.BitLen()

	maxSafe := new(big.Int).Lsh(big.NewInt(1), uint(bitlen-8))
	maxSafe.Sub(maxSafe, big.NewInt(1))

	overflow := new(big.Int).Sub(q, big.NewInt(1))
	overflow.Rsh(overflow, 8) // (q-1)/256
	overflow.Lsh(overflow, 4) // a value with non-zero bits in the top window

	return []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(42),
		big.NewInt(123456789),
		maxSafe,
		overflow,
	}
}

// --- supported-field gating ---

// TestSupportedCurve pins the compile-time guard in NewMapper: only the curves
// the hints can solve (BN254, secp256k1, P-256) are accepted — any other base
// field must be rejected at circuit-definition time rather than at proving time
// — and the hardcoded 2-adicity must match the hints (s = 1 for all three).
func TestSupportedCurve(t *testing.T) {
	supported := func(name string, s int, ok bool) {
		t.Helper()
		if !ok {
			t.Errorf("%s should be supported", name)
		}
		if s != 1 {
			t.Errorf("%s: 2-adicity = %d, want 1", name, s)
		}
	}
	bn, ok := supportedCurve[emulated.BN254Fp]()
	supported("BN254", bn, ok)
	k1, ok := supportedCurve[emulated.Secp256k1Fp]()
	supported("secp256k1", k1, ok)
	r1, ok := supportedCurve[emulated.P256Fp]()
	supported("P-256", r1, ok)

	if _, ok := supportedCurve[emulated.P384Fp](); ok {
		t.Error("P-384 should not be supported")
	}
	if _, ok := supportedCurve[emulated.BLS12381Fp](); ok {
		t.Error("BLS12-381 should not be supported")
	}
}

// leafHint is the signature of the per-curve search routines (xIncrementBN254,
// yIncrementSecp256k1, …): given msg it fills emulated outputs emOut (K,
// x[,y,z]).
type leafHint = func(msg *big.Int, emOut []*big.Int) error

// expectedFn returns the honest map-to-curve point (x, y) for msg over the
// modulus q, as produced by the reference (out-of-circuit) search.
type expectedFn = func(t *testing.T, msg, q *big.Int) (x, y *big.Int)

// xExpected builds the expected point for an x-increment leaf. The leaf returns
// x, y directly (emOut[1], emOut[2]).
func xExpected(leaf leafHint) expectedFn {
	return func(t *testing.T, msg, _ *big.Int) (*big.Int, *big.Int) {
		t.Helper()
		emOut := []*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
		if err := leaf(msg, emOut); err != nil {
			t.Fatalf("reference x-increment search: %v", err)
		}
		return emOut[1], emOut[2]
	}
}

// yExpected builds the expected point for a y-increment leaf. The leaf returns
// only x (emOut[1]); the y-coordinate is reconstructed as Y = msg·T + K mod q,
// exactly as the in-circuit gadget does.
func yExpected(leaf leafHint) expectedFn {
	return func(t *testing.T, msg, q *big.Int) (*big.Int, *big.Int) {
		t.Helper()
		emOut := []*big.Int{new(big.Int), new(big.Int)}
		if err := leaf(msg, emOut); err != nil {
			t.Fatalf("reference y-increment search: %v", err)
		}
		y := new(big.Int).Mul(msg, big.NewInt(T))
		y.Add(y, emOut[0])
		y.Mod(y, q)
		return emOut[1], y
	}
}

// --- X-Increment tests ---

type xIncrementCircuit[B, S emulated.FieldParams] struct {
	M    emulated.Element[B]
	X, Y emulated.Element[B] // expected honest map-to-curve point
}

func (c *xIncrementCircuit[B, S]) Define(api frontend.API) error {
	crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
	if err != nil {
		return err
	}
	m, err := NewMapper(api, crv)
	if err != nil {
		return err
	}
	p, err := m.XIncrement(&c.M)
	if err != nil {
		return err
	}
	crv.AssertIsOnCurve(p)
	// correctness: the computed point must match the honest reference point.
	crv.AssertIsEqual(p, &sw_emulated.AffinePoint[B]{X: c.X, Y: c.Y})
	return nil
}

func testXIncrement[B, S emulated.FieldParams](t *testing.T, expected expectedFn) {
	t.Helper()
	assert := test.NewAssert(t)
	var fp B
	q := fp.Modulus()
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages[B]() {
		x, y := expected(t, msg, q)
		opts = append(opts, test.WithValidAssignment(&xIncrementCircuit[B, S]{
			M: emulated.ValueOf[B](msg),
			X: emulated.ValueOf[B](x),
			Y: emulated.ValueOf[B](y),
		}))
	}
	assert.CheckCircuit(&xIncrementCircuit[B, S]{}, opts...)
}

func TestXIncrementEmulatedBN254(t *testing.T) {
	testXIncrement[emulated.BN254Fp, emulated.BN254Fr](t, xExpected(xIncrementBN254))
}
func TestXIncrementEmulatedSecp256k1(t *testing.T) {
	testXIncrement[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t, xExpected(xIncrementSecp256k1))
}
func TestXIncrementEmulatedP256(t *testing.T) {
	testXIncrement[emulated.P256Fp, emulated.P256Fr](t, xExpected(xIncrementSecp256r1))
}

// --- Y-Increment tests ---

type yIncrementCircuit[B, S emulated.FieldParams] struct {
	M    emulated.Element[B]
	X, Y emulated.Element[B] // expected honest map-to-curve point
}

func (c *yIncrementCircuit[B, S]) Define(api frontend.API) error {
	crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
	if err != nil {
		return err
	}
	m, err := NewMapper(api, crv)
	if err != nil {
		return err
	}
	p, err := m.YIncrement(&c.M)
	if err != nil {
		return err
	}
	crv.AssertIsOnCurve(p)
	crv.AssertIsEqual(p, &sw_emulated.AffinePoint[B]{X: c.X, Y: c.Y})
	return nil
}

func testYIncrement[B, S emulated.FieldParams](t *testing.T, expected expectedFn) {
	t.Helper()
	assert := test.NewAssert(t)
	var fp B
	q := fp.Modulus()
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages[B]() {
		x, y := expected(t, msg, q)
		opts = append(opts, test.WithValidAssignment(&yIncrementCircuit[B, S]{
			M: emulated.ValueOf[B](msg),
			X: emulated.ValueOf[B](x),
			Y: emulated.ValueOf[B](y),
		}))
	}
	assert.CheckCircuit(&yIncrementCircuit[B, S]{}, opts...)
}

func TestYIncrementEmulatedBN254(t *testing.T) {
	testYIncrement[emulated.BN254Fp, emulated.BN254Fr](t, yExpected(yIncrementBN254))
}
func TestYIncrementEmulatedSecp256k1(t *testing.T) {
	testYIncrement[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t, yExpected(yIncrementSecp256k1))
}
func TestYIncrementEmulatedP256(t *testing.T) {
	testYIncrement[emulated.P256Fp, emulated.P256Fr](t, yExpected(yIncrementSecp256r1))
}

// --- Increment dispatcher tests ---

type incrementCircuit[B, S emulated.FieldParams] struct {
	M    emulated.Element[B]
	X, Y emulated.Element[B] // expected honest map-to-curve point
}

func (c *incrementCircuit[B, S]) Define(api frontend.API) error {
	crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
	if err != nil {
		return err
	}
	m, err := NewMapper(api, crv)
	if err != nil {
		return err
	}
	p, err := m.Increment(&c.M)
	if err != nil {
		return err
	}
	crv.AssertIsOnCurve(p)
	crv.AssertIsEqual(p, &sw_emulated.AffinePoint[B]{X: c.X, Y: c.Y})
	return nil
}

func testIncrement[B, S emulated.FieldParams](t *testing.T, expected expectedFn) {
	t.Helper()
	assert := test.NewAssert(t)
	var fp B
	q := fp.Modulus()
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages[B]() {
		x, y := expected(t, msg, q)
		opts = append(opts, test.WithValidAssignment(&incrementCircuit[B, S]{
			M: emulated.ValueOf[B](msg),
			X: emulated.ValueOf[B](x),
			Y: emulated.ValueOf[B](y),
		}))
	}
	assert.CheckCircuit(&incrementCircuit[B, S]{}, opts...)
}

// Increment dispatches to YIncrement for the j=0 curves (BN254, secp256k1) and
// to XIncrement for P-256 (a ≠ 0, low 2-adicity); the expected oracle mirrors
// that choice.
func TestIncrementEmulatedBN254(t *testing.T) {
	testIncrement[emulated.BN254Fp, emulated.BN254Fr](t, yExpected(yIncrementBN254))
}
func TestIncrementEmulatedSecp256k1(t *testing.T) {
	testIncrement[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t, yExpected(yIncrementSecp256k1))
}
func TestIncrementEmulatedP256(t *testing.T) {
	testIncrement[emulated.P256Fp, emulated.P256Fr](t, xExpected(xIncrementSecp256r1))
}
