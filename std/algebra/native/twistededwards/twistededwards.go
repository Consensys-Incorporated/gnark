// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	edbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	edbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	edbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
)

// Curve methods implemented by a twisted edwards curve inside a circuit
type Curve interface {
	Params() *CurveParams
	// Add computes p1+p2 for inputs that lie on the curve.
	Add(p1, p2 Point) Point
	// Double computes 2*p1 for an input point that lies on the curve.
	Double(p1 Point) Point
	// Neg computes -p1 for an input point that lies on the curve.
	Neg(p1 Point) Point
	// AssertIsOnCurve constrains p1 to satisfy the twisted Edwards curve equation.
	AssertIsOnCurve(p1 Point)
	// ScalarMul computes [scalar]p1. p1 must lie in the prime-order subgroup; for
	// such points it is complete for all scalar inputs, including zero.
	ScalarMul(p1 Point, scalar frontend.Variable) Point
	// DoubleBaseScalarMul computes [s1]p1+[s2]p2 for points that lie on the curve.
	// It is complete by default; passing algopts.WithIncompleteArithmetic
	// dispatches to the faster lattice MSM path (see DoubleBaseScalarMulNonZero).
	DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable, opts ...algopts.AlgebraOption) Point
	// DoubleBaseScalarMulNonZero computes [s1]p1+[s2]p2 with the optimized
	// lattice MSM path. It requires p1, p2 to lie in the prime-order subgroup and
	// to be non-identity, and s1, s2 to be nonzero; for the GLV path the result
	// must also be non-identity.
	DoubleBaseScalarMulNonZero(p1, p2 Point, s1, s2 frontend.Variable) Point
	API() frontend.API
}

// Point represent a pair of X, Y coordinates inside a circuit
type Point struct {
	X, Y frontend.Variable
}

// CurveParams twisted edwards curve parameters ax^2 + y^2 = 1 + d*x^2*y^2
// Matches gnark-crypto curve specific params
type CurveParams struct {
	A, D, Cofactor, Order *big.Int
	Base                  [2]*big.Int // base point coordinates
}

// EndoParams holds the GLV endomorphism parameters for curves that have one
// (Bandersnatch). The endomorphism Φ(x, y) = ((Endo[0]·(1−y²)/(x·y) + …) acts as
// scalar multiplication by Lambda on the prime-order subgroup. This is used
// only by the `doubleBaseScalarMul6MSMLogUp` MSM(6, n/3) variant.
type EndoParams struct {
	Endo   [2]*big.Int
	Lambda *big.Int
}

// NewEdCurve returns a new Edwards curve
func NewEdCurve(api frontend.API, id twistededwards.ID) (Curve, error) {
	snarkField, err := GetSnarkField(id)
	if err != nil {
		return nil, err
	}
	if api.Compiler().Field().Cmp(snarkField) != 0 {
		return nil, errors.New("invalid curve pair; snark field doesn't match twisted edwards field")
	}
	params, err := GetCurveParams(id)
	if err != nil {
		return nil, err
	}

	var endo *EndoParams
	if id == twistededwards.BLS12_381_BANDERSNATCH {
		endo = &EndoParams{
			Endo:   [2]*big.Int{new(big.Int), new(big.Int)},
			Lambda: new(big.Int),
		}
		endo.Endo[0].SetString("37446463827641770816307242315180085052603635617490163568005256780843403514036", 10)
		endo.Endo[1].SetString("49199877423542878313146170939139662862850515542392585932876811575731455068989", 10)
		endo.Lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
	}

	return &curve{api: api, params: params, endo: endo, id: id}, nil
}

func GetCurveParams(id twistededwards.ID) (*CurveParams, error) {
	var params *CurveParams
	switch id {
	case twistededwards.BN254:
		params = newEdBN254()
	case twistededwards.BLS12_377:
		params = newEdBLS12_377()
	case twistededwards.BLS12_381:
		params = newEdBLS12_381()
	case twistededwards.BLS12_381_BANDERSNATCH:
		params = newEdBLS12_381_BANDERSNATCH()
	case twistededwards.BW6_761:
		params = newEdBW6_761()
	default:
		return nil, errors.New("unknown twisted edwards curve id")
	}
	return params, nil
}

// GetSnarkField returns the matching snark curve for a twisted edwards curve
func GetSnarkField(id twistededwards.ID) (*big.Int, error) {
	switch id {
	case twistededwards.BN254:
		return ecc.BN254.ScalarField(), nil
	case twistededwards.BLS12_377:
		return ecc.BLS12_377.ScalarField(), nil
	case twistededwards.BLS12_381, twistededwards.BLS12_381_BANDERSNATCH:
		return ecc.BLS12_381.ScalarField(), nil
	case twistededwards.BW6_761:
		return ecc.BW6_761.ScalarField(), nil
	default:
		return nil, errors.New("unknown twisted edwards curve id")
	}
}

// -------------------------------------------------------------------------------------------------
// constructors

func newCurveParams() *CurveParams {
	return &CurveParams{
		A:        new(big.Int),
		D:        new(big.Int),
		Cofactor: new(big.Int),
		Order:    new(big.Int),
		Base:     [2]*big.Int{new(big.Int), new(big.Int)},
	}
}

func newEdBN254() *CurveParams {

	edcurve := edbn254.GetEdwardsCurve()
	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS12_381() *CurveParams {

	edcurve := edbls12381.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS12_381_BANDERSNATCH() *CurveParams {

	edcurve := edbls12381_bandersnatch.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS12_377() *CurveParams {

	edcurve := edbls12377.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBW6_761() *CurveParams {

	edcurve := edbw6761.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}
