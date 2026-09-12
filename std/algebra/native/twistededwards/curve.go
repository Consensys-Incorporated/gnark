package twistededwards

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
)

// curve curve is the default twisted edwards companion curve (defined on api.Curve().Fr)
type curve struct {
	api    frontend.API
	id     twistededwards.ID
	params *CurveParams
	endo   *EndoParams // non-nil iff the curve has a GLV endomorphism (Bandersnatch)
}

func (c *curve) Params() *CurveParams {
	return c.params
}

func (c *curve) API() frontend.API {
	return c.api
}

func (c *curve) Add(p1, p2 Point) Point {
	var p Point
	p.add(c.api, &p1, &p2, c.params)
	return p
}

func (c *curve) Double(p1 Point) Point {
	var p Point
	p.double(c.api, &p1, c.params)
	return p
}
func (c *curve) Neg(p1 Point) Point {
	var p Point
	p.neg(c.api, &p1)
	return p
}
func (c *curve) AssertIsOnCurve(p1 Point) {
	p1.assertIsOnCurve(c.api, c.params)
}
func (c *curve) ScalarMul(p1 Point, scalar frontend.Variable) Point {
	var p Point
	p.scalarMul(c.api, &p1, scalar, c.params)
	return p
}

// DoubleBaseScalarMul computes s1*p1 + s2*p2.
//
// By default it is complete for all scalar inputs, including zero, and for
// identity points. When [algopts.WithIncompleteArithmetic] is set it dispatches
// to the faster lattice-based MSM path (see DoubleBaseScalarMulNonZero) and
// inherits that path's preconditions.
func (c *curve) DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable, opts ...algopts.AlgebraOption) Point {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	if cfg.IncompleteArithmetic {
		return c.DoubleBaseScalarMulNonZero(p1, p2, s1, s2)
	}
	var p Point
	p.doubleBaseScalarMul(c.api, &p1, &p2, s1, s2, c.params)
	return p
}

// DoubleBaseScalarMulNonZero computes s1*p1 + s2*p2 using the most efficient
// lattice-based MSM variant available for the curve:
//   - GLV-equipped curves (Bandersnatch): 6-MSM with r^(1/3)-bounded sub-scalars.
//   - non-GLV curves (Jubjub, BabyJubjub, edBLS12-377, edBW6-761): 3-MSM with
//     r^(2/3)-bounded sub-scalars and LogUp lookups.
//
// Preconditions (the result is undefined otherwise):
//   - p1, p2 must lie in the prime-order subgroup (not merely on the curve).
//     The hinted result is bound back into the subgroup, so torsion inputs make
//     the circuit unsatisfiable rather than unsound.
//   - the scalars s1, s2 must be nonzero and p1, p2 must not be the TE identity
//     (0, 1).
//   - for the GLV path the result s1*p1 + s2*p2 must itself be non-identity
//     (e.g. p2 = -p1 with s1 = s2 is excluded), since the endomorphism φ is
//     evaluated with unchecked divisions that are undefined at the identity.
//
// Use DoubleBaseScalarMul (without WithIncompleteArithmetic) for complete
// edge-case handling.
func (c *curve) DoubleBaseScalarMulNonZero(p1, p2 Point, s1, s2 frontend.Variable) Point {
	var p Point
	if c.endo != nil {
		p.doubleBaseScalarMul6MSMLogUp(c.api, &p1, &p2, s1, s2, c.params, c.endo)
	} else {
		p.doubleBaseScalarMul3MSMLogUp(c.api, &p1, &p2, s1, s2, c.params)
	}
	return p
}
