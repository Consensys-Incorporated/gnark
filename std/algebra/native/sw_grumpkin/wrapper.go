package sw_grumpkin

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	fr_grumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/selector"
)

// Curve allows G1 operations in Grumpkin.
type Curve struct {
	api frontend.API
	fr  *emulated.Field[ScalarField]
}

// NewCurve initializes a new [Curve] instance.
func NewCurve(api frontend.API) (*Curve, error) {
	// this is a 2-chain curve, so the base field of Grumpkin is the scalar
	// field of BN254. Error early to avoid any misuse.
	if api.Compiler().Field().Cmp(fr_bn254.Modulus()) != 0 {
		return nil, errors.New("expected BN254 scalar field for Grumpkin curve operations")
	}
	f, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, errors.New("scalar field")
	}
	return &Curve{
		api: api,
		fr:  f,
	}, nil
}

// MarshalScalar returns the scalar s in binary, little endian representation.
func (c *Curve) MarshalScalar(s Scalar, opts ...algopts.AlgebraOption) []frontend.Variable {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	nbBits := 8 * ((ScalarField{}.Modulus().BitLen() + 7) / 8)
	var ss *emulated.Element[ScalarField]
	if cfg.ToBitsCanonical {
		ss = c.fr.ReduceStrict(&s)
	} else {
		ss = c.fr.Reduce(&s)
	}
	x := c.fr.ToBits(ss)[:nbBits]
	slices.Reverse(x)
	return x
}

// MarshalG1 returns [P.X || P.Y] in binary. Both P.X and P.Y are
// in little endian.
func (c *Curve) MarshalG1(P G1Affine, opts ...algopts.AlgebraOption) []frontend.Variable {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	nbBits := 8 * ((ecc.GRUMPKIN.BaseField().BitLen() + 7) / 8)
	bOpts := []bits.BaseConversionOption{bits.WithNbDigits(nbBits)}
	if !cfg.ToBitsCanonical {
		bOpts = append(bOpts, bits.OmitModulusCheck())
	}
	res := make([]frontend.Variable, 2*nbBits)
	x := bits.ToBinary(c.api, P.X, bOpts...)
	y := bits.ToBinary(c.api, P.Y, bOpts...)
	for i := 0; i < nbBits; i++ {
		res[i] = x[nbBits-1-i]
		res[i+nbBits] = y[nbBits-1-i]
	}
	// We don't tag the point at infinity here as there is only 2 bits available for the mask.
	return res
}

// Add points P and Q and return the result. Does not modify the inputs.
func (c *Curve) Add(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddAssign(c.api, *Q)
	return res
}

// AddUnified adds any two points and returns the sum. It does not modify the input
// points.
func (c *Curve) AddUnified(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddUnified(c.api, *Q)
	return res
}

// AssertIsEqual asserts the equality of P and Q.
func (c *Curve) AssertIsEqual(P, Q *G1Affine) {
	P.AssertIsEqual(c.api, *Q)
}

// Neg negates P and returns the result. Does not modify P.
func (c *Curve) Neg(P *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.Neg(c.api, *P)
	return res
}

// jointScalarMul computes s1*P+s2*P2 and returns the result. It doesn't modify the
// inputs.
func (c *Curve) jointScalarMul(P1, P2 *G1Affine, s1, s2 *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{}
	varScalar1 := c.packScalarToVar(s1)
	varScalar2 := c.packScalarToVar(s2)
	res.jointScalarMul(c.api, *P1, *P2, varScalar1, varScalar2, opts...)
	return res
}

// ScalarMul computes scalar*P and returns the result. It doesn't modify the
// inputs.
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
func (c *Curve) ScalarMul(P *G1Affine, s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	varScalar := c.packScalarToVar(s)
	res.ScalarMul(c.api, *P, varScalar, opts...)
	return res
}

// ScalarMulBase computes scalar*G where G is the standard base point of the
// curve. It doesn't modify the scalar.
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
func (c *Curve) ScalarMulBase(s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := new(G1Affine)
	varScalar := c.packScalarToVar(s)
	res.ScalarMulBase(c.api, varScalar, opts...)
	return res
}

// MultiScalarMul computes ∑scalars_i * P_i and returns it. It doesn't modify
// the inputs. It returns an error if there is a mismatch in the lengths of the
// inputs.
//
// By default, uses complete arithmetic.
//
// In incomplete mode, the non-folding path inherits the exceptional set of the
// underlying joint-scalar helper and may additionally fail on sparse partial-
// sum merge collisions. The folding path inherits the exceptional set of
// scalarBitsMul and may additionally fail on sparse prefix-sum collisions.
// Accordingly, the incomplete exceptional set is implementation-dependent and
// not fully characterized at the API level.
func (c *Curve) MultiScalarMul(P []*G1Affine, scalars []*Scalar, opts ...algopts.AlgebraOption) (*G1Affine, error) {
	if len(P) == 0 {
		return &G1Affine{
			X: 0,
			Y: 0,
		}, nil
	}
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	addFn := c.Add
	if !cfg.IncompleteArithmetic {
		addFn = c.AddUnified
	}
	if !cfg.FoldMulti {
		if len(P) != len(scalars) {
			return nil, errors.New("mismatching points and scalars slice lengths")
		}
		// points and scalars must be non-zero
		n := len(P)
		var res *G1Affine
		if n%2 == 1 {
			res = c.ScalarMul(P[n-1], scalars[n-1], opts...)
		} else {
			res = c.jointScalarMul(P[n-2], P[n-1], scalars[n-2], scalars[n-1], opts...)
		}
		for i := 1; i < n-1; i += 2 {
			q := c.jointScalarMul(P[i-1], P[i], scalars[i-1], scalars[i], opts...)
			res = addFn(res, q)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(scalars) == 0 {
			return nil, errors.New("need scalar for folding")
		}
		// with a single point the result is P[0] (gamma^0 * P[0])
		if len(P) == 1 {
			return P[0], nil
		}
		gamma := c.packScalarToVar(scalars[0])
		// decompose gamma in the endomorphism eigenvalue basis and bit-decompose the sub-scalars
		gamma1, gamma2 := callDecomposeScalar(c.api, gamma)
		nbits := 127
		gamma1Bits := c.api.ToBinary(gamma1, nbits)
		gamma2Bits := c.api.ToBinary(gamma2, nbits)

		// points and scalars must be non-zero
		var res G1Affine
		res.scalarBitsMul(c.api, *P[len(P)-1], gamma1Bits, gamma2Bits, opts...)
		for i := len(P) - 2; i > 0; i-- {
			res = *addFn(P[i], &res)
			res.scalarBitsMul(c.api, res, gamma1Bits, gamma2Bits, opts...)
		}
		res = *addFn(P[0], &res)
		return &res, nil
	}
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (c *Curve) Select(b frontend.Variable, p1, p2 *G1Affine) *G1Affine {
	return &G1Affine{
		X: c.api.Select(b, p1.X, p2.X),
		Y: c.api.Select(b, p1.Y, p2.Y),
	}
}

// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
// Returns:
//   - p1 if b0=0 and b1=0,
//   - p2 if b0=1 and b1=0,
//   - p3 if b0=0 and b1=1,
//   - p4 if b0=1 and b1=1.
func (c *Curve) Lookup2(b1, b2 frontend.Variable, p1, p2, p3, p4 *G1Affine) *G1Affine {
	return &G1Affine{
		X: c.api.Lookup2(b1, b2, p1.X, p2.X, p3.X, p4.X),
		Y: c.api.Lookup2(b1, b2, p1.Y, p2.Y, p3.Y, p4.Y),
	}
}

// Mux performs a lookup from the inputs and returns inputs[sel]. It is most
// efficient for power of two lengths of the inputs, but works for any number of
// inputs.
func (c *Curve) Mux(sel frontend.Variable, inputs ...*G1Affine) *G1Affine {
	xs := make([]frontend.Variable, len(inputs))
	ys := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		xs[i] = inputs[i].X
		ys[i] = inputs[i].Y
	}
	return &G1Affine{
		X: selector.Mux(c.api, sel, xs...),
		Y: selector.Mux(c.api, sel, ys...),
	}
}

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v grumpkin.G1Affine) G1Affine {
	return G1Affine{
		X: (fr_bn254.Element)(v.X),
		Y: (fr_bn254.Element)(v.Y),
	}
}

// Scalar is a scalar in the groups. As the implementation is defined on a
// 2-chain, then this type is an alias to [frontend.Variable].
type Scalar = emulated.Element[ScalarField]

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_grumpkin.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// packScalarToVar packs the limbs of emulated scalar to a frontend.Variable.
//
// The method is for compatibility for existing scalar multiplication
// implementation which assumes as an input frontend.Variable.
func (c *Curve) packScalarToVar(s *Scalar) frontend.Variable {
	_, nbBits := emulated.GetEffectiveFieldParams[ScalarField](c.api.Compiler().Field())
	reduced := c.fr.Reduce(s)
	var res frontend.Variable = 0
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = c.api.Add(res, c.api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res
}

// ScalarField defines the [emulated.FieldParams] implementation on a one limb of the scalar field.
type ScalarField = emparams.GrumpkinFr
