// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import (
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	tbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	tbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	tbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/stretchr/testify/require"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/test"
)

var curves = []twistededwards.ID{twistededwards.BN254, twistededwards.BLS12_377, twistededwards.BLS12_381, twistededwards.BLS12_381_BANDERSNATCH, twistededwards.BW6_761}

type mustBeOnCurve struct {
	curveID twistededwards.ID
	P       Point
}

func (circuit *mustBeOnCurve) Define(api frontend.API) error {

	// get edwards curve curve
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	curve.AssertIsOnCurve(circuit.P)

	return nil
}

func TestIsOnCurve(t *testing.T) {

	assert := test.NewAssert(t)

	for _, curve := range curves {
		var circuit, validWitness, invalidWitness mustBeOnCurve
		circuit.curveID = curve

		// get matching snark curve
		snarkField, err := GetSnarkField(curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)

		// get curve params
		params, err := GetCurveParams(curve)
		assert.NoError(err)

		// create witness
		validWitness.P.X = params.Base[0]
		validWitness.P.Y = params.Base[1]

		invalidWitness.P = offCurvePoint()

		// check circuits.
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithCurves(snarkCurve))

	}

}

func assertPointEqual(api frontend.API, actual, expected Point) {
	api.AssertIsEqual(actual.X, expected.X)
	api.AssertIsEqual(actual.Y, expected.Y)
}

type addCircuit struct {
	curveID twistededwards.ID
	P1, P2  Point
	Result  Point
}

func (circuit *addCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Add(circuit.P1, circuit.P2), circuit.Result)
	return nil
}

type addFixedCircuit struct {
	curveID    twistededwards.ID
	P          Point
	Result     Point
	fixedPoint Point `gnark:"-"`
}

func (circuit *addFixedCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Add(circuit.fixedPoint, circuit.P), circuit.Result)
	return nil
}

type doubleCircuit struct {
	curveID twistededwards.ID
	P       Point
	Result  Point
}

func (circuit *doubleCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Double(circuit.P), circuit.Result)
	return nil
}

type negCircuit struct {
	curveID twistededwards.ID
	P       Point
	Result  Point
}

func (circuit *negCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Neg(circuit.P), circuit.Result)
	return nil
}

type scalarMulCircuit struct {
	curveID twistededwards.ID
	P       Point
	Scalar  frontend.Variable
	Result  Point
}

func (circuit *scalarMulCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.ScalarMul(circuit.P, circuit.Scalar), circuit.Result)
	return nil
}

type fixedScalarMulCircuit struct {
	curveID    twistededwards.ID
	Scalar     frontend.Variable
	Result     Point
	fixedPoint Point `gnark:"-"`
}

func (circuit *fixedScalarMulCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.ScalarMul(circuit.fixedPoint, circuit.Scalar), circuit.Result)
	return nil
}

type doubleBaseScalarMulCircuit struct {
	curveID twistededwards.ID
	P1, P2  Point
	S1, S2  frontend.Variable
	Result  Point
}

func (circuit *doubleBaseScalarMulCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.DoubleBaseScalarMul(circuit.P1, circuit.P2, circuit.S1, circuit.S2), circuit.Result)
	return nil
}

type doubleBaseScalarMulNonZeroCircuit struct {
	curveID twistededwards.ID
	P1, P2  Point
	S1, S2  frontend.Variable
	Result  Point
}

func (circuit *doubleBaseScalarMulNonZeroCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.DoubleBaseScalarMulNonZero(circuit.P1, circuit.P2, circuit.S1, circuit.S2), circuit.Result)
	return nil
}

func TestAdd(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &addCircuit{curveID: curveID}
		witness := &addCircuit{P1: data.P1, P2: data.P2, Result: data.AddResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestAddFixed(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &addFixedCircuit{curveID: curveID, fixedPoint: data.P2}
		witness := &addFixedCircuit{P: data.P1, Result: data.AddResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestDouble(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &doubleCircuit{curveID: curveID}
		witness := &doubleCircuit{P: data.P1, Result: data.DoubleResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestNeg(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &negCircuit{curveID: curveID}
		witness := &negCircuit{P: data.P2, Result: data.NegResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestScalarMul(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &scalarMulCircuit{curveID: curveID}
		witness := &scalarMulCircuit{P: data.P2, Scalar: data.S2, Result: data.ScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestFixedScalarMul(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &fixedScalarMulCircuit{curveID: curveID, fixedPoint: data.P2}
		witness := &fixedScalarMulCircuit{Scalar: data.S2, Result: data.ScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestDoubleBaseScalarMul(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &doubleBaseScalarMulCircuit{curveID: curveID}
		witness := &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: data.S1, S2: data.S2, Result: data.DoubleScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestDoubleBaseScalarMulNonZero(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &doubleBaseScalarMulNonZeroCircuit{curveID: curveID}
		witness := &doubleBaseScalarMulNonZeroCircuit{P1: data.P1, P2: data.P2, S1: data.S1, S2: data.S2, Result: data.DoubleScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestAddEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}

		pPlusIdentity := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(0))
		identityPlusP := testDataForScalars(params, curveID, big.NewInt(0), big.NewInt(1))
		pPlusP := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(1))
		pPlusNegP := testDataForScalars(params, curveID, big.NewInt(1), negScalar(params.Order, big.NewInt(1)))

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: pPlusIdentity.P1, P2: pPlusIdentity.P2, Result: pPlusIdentity.AddResult})
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: identityPlusP.P1, P2: identityPlusP.P2, Result: identityPlusP.AddResult})
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: pPlusP.P1, P2: pPlusP.P2, Result: pPlusP.AddResult})
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: pPlusNegP.P1, P2: pPlusNegP.P2, Result: pPlusNegP.AddResult})
		})
	}
}

func TestAddFixedEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}

		pPlusIdentity := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(0))
		pPlusNegP := testDataForScalars(params, curveID, big.NewInt(1), negScalar(params.Order, big.NewInt(1)))

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &addFixedCircuit{curveID: curveID, fixedPoint: pPlusIdentity.P2}, &addFixedCircuit{P: pPlusIdentity.P1, Result: pPlusIdentity.AddResult})
			assertSolvedForCurve(t, curveID, &addFixedCircuit{curveID: curveID, fixedPoint: pPlusNegP.P2}, &addFixedCircuit{P: pPlusNegP.P1, Result: pPlusNegP.AddResult})
		})
	}
}

func TestDoubleEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &doubleCircuit{curveID: curveID}, &doubleCircuit{P: identityPoint(), Result: identityPoint()})
		})
	}
}

func TestNegEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &negCircuit{curveID: curveID}, &negCircuit{P: identityPoint(), Result: identityPoint()})
		})
	}
}

func TestScalarMulEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(2))

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &scalarMulCircuit{curveID: curveID}, &scalarMulCircuit{P: data.P1, Scalar: 0, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, &scalarMulCircuit{curveID: curveID}, &scalarMulCircuit{P: identityPoint(), Scalar: 2, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, &scalarMulCircuit{curveID: curveID}, &scalarMulCircuit{P: data.P1, Scalar: 1, Result: data.P1})
		})
	}
}

func TestFixedScalarMulEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &fixedScalarMulCircuit{curveID: curveID, fixedPoint: identityPoint()}, &fixedScalarMulCircuit{Scalar: 2, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, &fixedScalarMulCircuit{curveID: curveID, fixedPoint: Point{X: params.Base[0], Y: params.Base[1]}}, &fixedScalarMulCircuit{Scalar: 0, Result: identityPoint()})
		})
	}
}

// TestDoubleBaseScalarMulEdgeCases covers the complete public method, including
// zero scalars and identity points. The optimized NonZero variant is tested
// separately.
func TestDoubleBaseScalarMulEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(2))
		base := Point{X: params.Base[0], Y: params.Base[1]}

		t.Run(curveLabel(curveID), func(t *testing.T) {
			circuit := &doubleBaseScalarMulCircuit{curveID: curveID}
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: 0, S2: 0, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: 1, S2: 0, Result: data.P1})
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: 0, S2: 1, Result: data.P2})
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: identityPoint(), P2: base, S1: 1, S2: 2, Result: data.P2})
		})
	}
}

type curveTestData struct {
	P1                    Point
	P2                    Point
	AddResult             Point
	DoubleResult          Point
	ScalarMulResult       Point
	DoubleScalarMulResult Point
	NegResult             Point
	S1                    *big.Int
	S2                    *big.Int
}

func checkCircuitForCurve(t *testing.T, curveID twistededwards.ID, circuit, validWitness, invalidWitness frontend.Circuit) {
	t.Helper()

	assert := test.NewAssert(t)
	snarkField, err := GetSnarkField(curveID)
	assert.NoError(err)

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(validWitness),
		test.WithInvalidAssignment(invalidWitness),
		test.WithCurves(utils.FieldToCurve(snarkField)),
	)
}

func assertSolvedForCurve(t *testing.T, curveID twistededwards.ID, circuit, witness frontend.Circuit) {
	t.Helper()

	snarkField, err := GetSnarkField(curveID)
	if err != nil {
		t.Fatalf("%s: get snark field: %v", curveLabel(curveID), err)
	}
	if err := test.IsSolved(circuit, witness, snarkField); err != nil {
		t.Fatalf("%s: %v", curveLabel(curveID), err)
	}
}

func randomTestData(params *CurveParams, curveID twistededwards.ID) curveTestData {
	return testDataForScalars(params, curveID, nonZeroRandomScalar(params), nonZeroRandomScalar(params))
}

func testDataForScalars(params *CurveParams, curveID twistededwards.ID, scalar1, scalar2 *big.Int) curveTestData {
	switch curveID {
	case twistededwards.BN254:
		var p1, p2, r, d, rs1, rs12, n tbn254.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
	case twistededwards.BLS12_381:
		var p1, p2, r, d, rs1, rs12, n tbls12381.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
	case twistededwards.BLS12_381_BANDERSNATCH:
		var p1, p2, r, d, rs1, rs12, n tbls12381_bandersnatch.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
	case twistededwards.BLS12_377:
		var p1, p2, r, d, rs1, rs12, n tbls12377.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
	case twistededwards.BW6_761:
		var p1, p2, r, d, rs1, rs12, n tbw6761.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
	default:
		panic("not implemented")
	}
}

func identityPoint() Point {
	return Point{X: 0, Y: 1}
}

func offCurvePoint() Point {
	return Point{X: 0, Y: 0}
}

func nonZeroRandomScalar(params *CurveParams) *big.Int {
	for {
		scalar := params.randomScalar()
		if scalar.Sign() != 0 {
			return scalar
		}
	}
}

func negScalar(order, scalar *big.Int) *big.Int {
	neg := new(big.Int).Neg(scalar)
	neg.Mod(neg, order)
	return neg
}

func curveLabel(id twistededwards.ID) string {
	switch id {
	case twistededwards.BN254:
		return "bn254"
	case twistededwards.BLS12_377:
		return "bls12-377"
	case twistededwards.BLS12_381:
		return "bls12-381"
	case twistededwards.BLS12_381_BANDERSNATCH:
		return "bandersnatch"
	case twistededwards.BW6_761:
		return "bw6-761"
	default:
		return "unknown"
	}
}

// randomScalar returns a scalar <= p.Order
func (p *CurveParams) randomScalar() *big.Int {
	r, _ := rand.Int(rand.Reader, p.Order)
	return r
}

type scalarMulFakeGLVRegressionCircuit struct {
	Scalar frontend.Variable `gnark:",public"`
}

func (c *scalarMulFakeGLVRegressionCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	base := Point{X: curve.Params().Base[0], Y: curve.Params().Base[1]}
	_ = curve.ScalarMul(base, c.Scalar)
	return nil
}

func zeroRationalReconstructHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 3 {
		return errors.New("expecting three outputs")
	}
	for i := range outputs {
		outputs[i].SetUint64(0)
	}
	return nil
}

// This is a regression for a soundness issue in scalarMulFakeGLV. A malicious
// rationalReconstruct hint can return the trivial decomposition s1=s2=0,
// which makes the internal accumulator check vacuous and lets any scalar-mul
// hint output pass.
func TestScalarMulFakeGLVRegressionTrivialDecomposition(t *testing.T) {
	assert := require.New(t)

	witness := scalarMulFakeGLVRegressionCircuit{Scalar: big.NewInt(1)}

	err := test.IsSolved(&scalarMulFakeGLVRegressionCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(
		&scalarMulFakeGLVRegressionCircuit{},
		&witness,
		ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(rationalReconstruct), zeroRationalReconstructHint),
	)
	assert.Error(err)
}

// torsionForgedScalarMulHint returns [s]P + (0,-1) instead of [s]P, along with
// the honest subgroup preimage of the resulting (out-of-subgroup) point.
func torsionForgedScalarMulHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 5 {
		return errors.New("expecting five inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	var P, tors, S tbn254.PointAffine
	P.X.SetBigInt(inputs[0])
	P.Y.SetBigInt(inputs[1])
	P.ScalarMultiplication(&P, inputs[2])
	tors.X.SetZero()
	tors.Y.SetOne()
	tors.Y.Neg(&tors.Y)
	P.Add(&P, &tors)
	m := new(big.Int).ModInverse(inputs[4], inputs[3])
	S.ScalarMultiplication(&P, m)
	P.X.BigInt(outputs[0])
	P.Y.BigInt(outputs[1])
	S.X.BigInt(outputs[2])
	S.Y.BigInt(outputs[3])
	return nil
}

// TestScalarMulFakeGLVRejectsTorsionResult is a regression test for the
// cofactor-torsion soundness issue in scalarMulFakeGLV: a prover returning
// [s]P + (0,-1) would pass the [s1]P + [s2]q = O check whenever s2 is even. The
// [cofactor]S subgroup binding on the hinted result q rejects it. We pick a
// scalar whose decomposition denominator s2 is even so the rejection can only
// come from the subgroup binding, not the accumulator check.
func TestScalarMulFakeGLVRejectsTorsionResult(t *testing.T) {
	assert := require.New(t)
	params, err := GetCurveParams(twistededwards.BN254)
	assert.NoError(err)
	r := params.Order

	var s *big.Int
	step := new(big.Int).Div(r, big.NewInt(9973))
	cand := new(big.Int).Rsh(r, 1)
	for i := 0; i < 4000 && s == nil; i++ {
		cand.Add(cand, step)
		cand.Mod(cand, r)
		if cand.Sign() == 0 {
			continue
		}
		out := []*big.Int{new(big.Int), new(big.Int), new(big.Int)}
		assert.NoError(rationalReconstruct(ecc.BN254.ScalarField(), []*big.Int{cand, r}, out))
		if out[1].Sign() != 0 && out[1].Bit(0) == 0 { // |s2| even and nonzero
			s = new(big.Int).Set(cand)
		}
	}
	assert.NotNil(s, "no even-s2 scalar found")

	var base, q, tors, qForged tbn254.PointAffine
	base.X.SetBigInt(params.Base[0])
	base.Y.SetBigInt(params.Base[1])
	q.ScalarMultiplication(&base, s)
	tors.X.SetZero()
	tors.Y.SetOne()
	tors.Y.Neg(&tors.Y)
	qForged.Add(&q, &tors)

	baseX, baseY := new(big.Int), new(big.Int)
	base.X.BigInt(baseX)
	base.Y.BigInt(baseY)
	fX, fY := new(big.Int), new(big.Int)
	qForged.X.BigInt(fX)
	qForged.Y.BigInt(fY)

	witness := scalarMulCircuit{
		P:      Point{X: baseX, Y: baseY},
		Scalar: s,
		Result: Point{X: fX, Y: fY},
	}
	err = test.IsSolved(
		&scalarMulCircuit{curveID: twistededwards.BN254},
		&witness,
		ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(scalarMulHint), torsionForgedScalarMulHint),
	)
	assert.Error(err)
}

// bn254DoubleBaseInputs builds the doubleBaseScalarMulHint inputs matching the
// circuit's witness produced by testDataForScalars: the points are P1=[s1]base
// and P2=[s2]base and the scalars are s1, s2 (8 inputs, incl. order & cofactor).
func bn254DoubleBaseInputs(params *CurveParams, s1, s2 *big.Int) []*big.Int {
	var base, p1, p2 tbn254.PointAffine
	base.X.SetBigInt(params.Base[0])
	base.Y.SetBigInt(params.Base[1])
	p1.ScalarMultiplication(&base, s1)
	p2.ScalarMultiplication(&base, s2)
	p1X, p1Y := new(big.Int), new(big.Int)
	p2X, p2Y := new(big.Int), new(big.Int)
	p1.X.BigInt(p1X)
	p1.Y.BigInt(p1Y)
	p2.X.BigInt(p2X)
	p2.Y.BigInt(p2Y)
	return []*big.Int{
		p1X, p1Y, new(big.Int).Set(s1),
		p2X, p2Y, new(big.Int).Set(s2),
		new(big.Int).Set(params.Order),
		new(big.Int).Set(params.Cofactor),
	}
}

// resultFromHint runs a doubleBaseScalarMulHint variant and returns R = Q1+Q2.
func resultFromHint(hint solver.Hint, inputs []*big.Int) (Point, error) {
	outputs := make([]*big.Int, 6)
	for i := range outputs {
		outputs[i] = new(big.Int)
	}
	if err := hint(ecc.BN254.ScalarField(), inputs, outputs); err != nil {
		return Point{}, err
	}
	var q1, q2, r tbn254.PointAffine
	q1.X.SetBigInt(outputs[0])
	q1.Y.SetBigInt(outputs[1])
	q2.X.SetBigInt(outputs[2])
	q2.Y.SetBigInt(outputs[3])
	r.Add(&q1, &q2)
	rX, rY := new(big.Int), new(big.Int)
	r.X.BigInt(rX)
	r.Y.BigInt(rY)
	return Point{X: rX, Y: rY}, nil
}

// forgedBN254DoubleBaseScalarMulHint offsets Q1 by a prime-subgroup element
// (P1). The forged R stays in the subgroup, so the [cofactor]S subgroup check
// passes but the scaled MSM relation [z]R = [x1]P1+[x2]P2 rejects it.
func forgedBN254DoubleBaseScalarMulHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 8 {
		return errors.New("expecting eight inputs")
	}
	if len(outputs) != 6 {
		return errors.New("expecting six outputs")
	}
	var p1, p2, q1, q2, r, s tbn254.PointAffine
	p1.X.SetBigInt(inputs[0])
	p1.Y.SetBigInt(inputs[1])
	p2.X.SetBigInt(inputs[3])
	p2.Y.SetBigInt(inputs[4])
	q1.ScalarMultiplication(&p1, inputs[2])
	q2.ScalarMultiplication(&p2, inputs[5])

	// offset by the prime-subgroup element P1
	q1.Add(&q1, &p1)

	// honest subgroup preimage of the (still in-subgroup) forged R
	r.Add(&q1, &q2)
	m := new(big.Int).ModInverse(inputs[7], inputs[6])
	s.ScalarMultiplication(&r, m)

	q1.X.BigInt(outputs[0])
	q1.Y.BigInt(outputs[1])
	q2.X.BigInt(outputs[2])
	q2.Y.BigInt(outputs[3])
	s.X.BigInt(outputs[4])
	s.Y.BigInt(outputs[5])
	return nil
}

// torsionForgedBN254DoubleBaseScalarMulHint offsets Q1 by the 2-torsion point
// (0,-1) and returns the honest preimage of the resulting subgroup point R. The
// forged R = R_true+(0,-1) is NOT in the subgroup, so [cofactor]S = R_true != R
// and the subgroup check rejects it. This is Ivo's cofactor-torsion attack.
func torsionForgedBN254DoubleBaseScalarMulHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 8 {
		return errors.New("expecting eight inputs")
	}
	if len(outputs) != 6 {
		return errors.New("expecting six outputs")
	}
	var p1, p2, q1, q2, tors, r, s tbn254.PointAffine
	p1.X.SetBigInt(inputs[0])
	p1.Y.SetBigInt(inputs[1])
	p2.X.SetBigInt(inputs[3])
	p2.Y.SetBigInt(inputs[4])
	q1.ScalarMultiplication(&p1, inputs[2])
	q2.ScalarMultiplication(&p2, inputs[5])

	tors.X.SetZero()
	tors.Y.SetOne()
	tors.Y.Neg(&tors.Y)
	q1.Add(&q1, &tors)

	// best-effort preimage: [cofactor]S recovers only the subgroup part
	r.Add(&q1, &q2)
	m := new(big.Int).ModInverse(inputs[7], inputs[6])
	s.ScalarMultiplication(&r, m)

	q1.X.BigInt(outputs[0])
	q1.Y.BigInt(outputs[1])
	q2.X.BigInt(outputs[2])
	q2.Y.BigInt(outputs[3])
	s.X.BigInt(outputs[4])
	s.Y.BigInt(outputs[5])
	return nil
}

func TestDoubleBaseScalarMulNonZeroRejectsForgedPartialHints(t *testing.T) {
	assert := require.New(t)
	params, err := GetCurveParams(twistededwards.BN254)
	assert.NoError(err)

	data := testDataForScalars(params, twistededwards.BN254, big.NewInt(5), big.NewInt(7))
	inputs := bn254DoubleBaseInputs(params, data.S1, data.S2)
	forged, err := resultFromHint(forgedBN254DoubleBaseScalarMulHint, inputs)
	assert.NoError(err)

	witness := doubleBaseScalarMulNonZeroCircuit{
		P1:     data.P1,
		P2:     data.P2,
		S1:     data.S1,
		S2:     data.S2,
		Result: forged,
	}
	err = test.IsSolved(
		&doubleBaseScalarMulNonZeroCircuit{curveID: twistededwards.BN254},
		&witness,
		ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(doubleBaseScalarMulHint), forgedBN254DoubleBaseScalarMulHint),
	)
	assert.Error(err)
}

// TestDoubleBaseScalarMulNonZeroRejectsTorsionResult is a regression test for
// the cofactor-torsion soundness issue: a malicious prover returns
// R_true + (0,-1) with an (honest, possibly even) denominator z. The scaled MSM
// relation [z]R = [x1]P1+[x2]P2 alone would accept it when z is even, but the
// [cofactor]S subgroup binding rejects it.
func TestDoubleBaseScalarMulNonZeroRejectsTorsionResult(t *testing.T) {
	assert := require.New(t)
	params, err := GetCurveParams(twistededwards.BN254)
	assert.NoError(err)

	// Pick scalars whose honest shared denominator z is EVEN. Then the scaled
	// MSM relation [z]R = [x1]P1+[x2]P2 accepts R_true+(0,-1) on its own (since
	// [z](0,-1)=O), so the rejection must come from the [cofactor]S subgroup
	// binding, not the MSM check.
	r := params.Order
	rc := lattice.NewReconstructor(r)
	step := new(big.Int).Div(r, big.NewInt(9973))
	a := new(big.Int).Rsh(r, 1)
	b := new(big.Int).Add(a, step)
	var s1, s2 *big.Int
	for i := 0; i < 4000 && s1 == nil; i++ {
		a.Add(a, step)
		a.Mod(a, r)
		b.Add(b, step)
		b.Mod(b, r)
		if a.Sign() == 0 || b.Sign() == 0 {
			continue
		}
		if z := rc.MultiRationalReconstruct(a, b)[2]; z.Sign() != 0 && z.Bit(0) == 0 {
			s1, s2 = new(big.Int).Set(a), new(big.Int).Set(b)
		}
	}
	assert.NotNil(s1, "no even-denominator decomposition found")

	data := testDataForScalars(params, twistededwards.BN254, s1, s2)
	inputs := bn254DoubleBaseInputs(params, data.S1, data.S2)
	forged, err := resultFromHint(torsionForgedBN254DoubleBaseScalarMulHint, inputs)
	assert.NoError(err)

	witness := doubleBaseScalarMulNonZeroCircuit{
		P1:     data.P1,
		P2:     data.P2,
		S1:     data.S1,
		S2:     data.S2,
		Result: forged,
	}
	err = test.IsSolved(
		&doubleBaseScalarMulNonZeroCircuit{curveID: twistededwards.BN254},
		&witness,
		ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(doubleBaseScalarMulHint), torsionForgedBN254DoubleBaseScalarMulHint),
	)
	assert.Error(err)
}

// torsionForgedBandersnatchDoubleBaseScalarMulHint is the Bandersnatch (GLV,
// 6-MSM path) analogue: it offsets Q1 by the 2-torsion point (0,-1). The
// subgroup binding runs before the endomorphism is applied, so the torsion R is
// rejected there.
func torsionForgedBandersnatchDoubleBaseScalarMulHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 8 {
		return errors.New("expecting eight inputs")
	}
	if len(outputs) != 6 {
		return errors.New("expecting six outputs")
	}
	var p1, p2, q1, q2, tors, r, s tbls12381_bandersnatch.PointAffine
	p1.X.SetBigInt(inputs[0])
	p1.Y.SetBigInt(inputs[1])
	p2.X.SetBigInt(inputs[3])
	p2.Y.SetBigInt(inputs[4])
	q1.ScalarMultiplication(&p1, inputs[2])
	q2.ScalarMultiplication(&p2, inputs[5])

	tors.X.SetZero()
	tors.Y.SetOne()
	tors.Y.Neg(&tors.Y)
	q1.Add(&q1, &tors)

	r.Add(&q1, &q2)
	m := new(big.Int).ModInverse(inputs[7], inputs[6])
	s.ScalarMultiplication(&r, m)

	q1.X.BigInt(outputs[0])
	q1.Y.BigInt(outputs[1])
	q2.X.BigInt(outputs[2])
	q2.Y.BigInt(outputs[3])
	s.X.BigInt(outputs[4])
	s.Y.BigInt(outputs[5])
	return nil
}

func TestDoubleBaseScalarMulNonZeroRejectsTorsionResultGLV(t *testing.T) {
	assert := require.New(t)
	params, err := GetCurveParams(twistededwards.BLS12_381_BANDERSNATCH)
	assert.NoError(err)

	data := testDataForScalars(params, twistededwards.BLS12_381_BANDERSNATCH, big.NewInt(5), big.NewInt(7))

	var base, p1, p2 tbls12381_bandersnatch.PointAffine
	base.X.SetBigInt(params.Base[0])
	base.Y.SetBigInt(params.Base[1])
	p1.ScalarMultiplication(&base, data.S1)
	p2.ScalarMultiplication(&base, data.S2)
	p1X, p1Y, p2X, p2Y := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	p1.X.BigInt(p1X)
	p1.Y.BigInt(p1Y)
	p2.X.BigInt(p2X)
	p2.Y.BigInt(p2Y)
	inputs := []*big.Int{
		p1X, p1Y, new(big.Int).Set(data.S1),
		p2X, p2Y, new(big.Int).Set(data.S2),
		new(big.Int).Set(params.Order),
		new(big.Int).Set(params.Cofactor),
	}
	outputs := make([]*big.Int, 6)
	for i := range outputs {
		outputs[i] = new(big.Int)
	}
	assert.NoError(torsionForgedBandersnatchDoubleBaseScalarMulHint(nil, inputs, outputs))
	var q1, q2, r tbls12381_bandersnatch.PointAffine
	q1.X.SetBigInt(outputs[0])
	q1.Y.SetBigInt(outputs[1])
	q2.X.SetBigInt(outputs[2])
	q2.Y.SetBigInt(outputs[3])
	r.Add(&q1, &q2)
	rX, rY := new(big.Int), new(big.Int)
	r.X.BigInt(rX)
	r.Y.BigInt(rY)

	witness := doubleBaseScalarMulNonZeroCircuit{
		P1:     Point{X: p1X, Y: p1Y},
		P2:     Point{X: p2X, Y: p2Y},
		S1:     data.S1,
		S2:     data.S2,
		Result: Point{X: rX, Y: rY},
	}
	err = test.IsSolved(
		&doubleBaseScalarMulNonZeroCircuit{curveID: twistededwards.BLS12_381_BANDERSNATCH},
		&witness,
		ecc.BLS12_381.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(doubleBaseScalarMulHint), torsionForgedBandersnatchDoubleBaseScalarMulHint),
	)
	assert.Error(err)
}

// --- On-curve binding of the hinted subgroup preimage ------------------------
//
// assertInSubgroup proves R is in the prime-order subgroup by checking
// [cofactor]S == R for a hinted preimage S. That group-theoretic argument is
// only valid if S is itself a curve point: S comes from a hint, and the
// (DivUnchecked-based) doubling formulas are defined for arbitrary field pairs,
// so without an on-curve constraint an off-curve S is just an unconstrained
// field pair driven through the doubling map. The test below pins the on-curve
// constraint that closes this gap (Ivo's review comment on PR #1765).

// assertInSubgroupCircuit exercises assertInSubgroup directly with a
// witness-supplied result R and preimage S.
type assertInSubgroupCircuit struct {
	curveID twistededwards.ID
	R, S    Point
}

func (circuit *assertInSubgroupCircuit) Define(api frontend.API) error {
	params, err := GetCurveParams(circuit.curveID)
	if err != nil {
		return err
	}
	assertInSubgroup(api, &circuit.R, &circuit.S, params)
	return nil
}

// bn254CircuitDouble applies the in-circuit twisted Edwards doubling (Point.double)
// over the coordinate field for arbitrary (possibly off-curve) inputs. It returns
// ok=false if a denominator vanishes.
func bn254CircuitDouble(x, y, a fr.Element) (X, Y fr.Element, ok bool) {
	var xx, yy, axx, d1, d2, n1, n2, inv, two fr.Element
	two.SetUint64(2)
	xx.Mul(&x, &x)
	yy.Mul(&y, &y)
	axx.Mul(&xx, &a)
	d1.Add(&yy, &axx) // y² + a·x²
	d2.Sub(&two, &d1) // 2 - (y² + a·x²)
	if d1.IsZero() || d2.IsZero() {
		return X, Y, false
	}
	n1.Mul(&x, &y)
	n1.Double(&n1) // 2·x·y
	inv.Inverse(&d1)
	X.Mul(&n1, &inv)
	n2.Sub(&yy, &axx) // y² - a·x²
	inv.Inverse(&d2)
	Y.Mul(&n2, &inv)
	return X, Y, true
}

// bn254CofactorMul applies bn254CircuitDouble log2(cofactor) times, matching the
// [cofactor]S computation inside assertInSubgroup.
func bn254CofactorMul(x, y, a fr.Element, cofactor uint64) (fr.Element, fr.Element, bool) {
	for c := cofactor; c > 1; c /= 2 {
		var ok bool
		x, y, ok = bn254CircuitDouble(x, y, a)
		if !ok {
			return x, y, false
		}
	}
	return x, y, true
}

func bn254OnCurve(x, y, a, d fr.Element) bool {
	var xx, yy, axx, lhs, dxx, dxxyy, rhs, one fr.Element
	one.SetOne()
	xx.Mul(&x, &x)
	yy.Mul(&y, &y)
	axx.Mul(&xx, &a)
	lhs.Add(&axx, &yy)
	dxx.Mul(&xx, &d)
	dxxyy.Mul(&dxx, &yy)
	rhs.Add(&dxxyy, &one)
	return lhs.Equal(&rhs)
}

func fePoint(x, y fr.Element) Point {
	return Point{X: x.BigInt(new(big.Int)), Y: y.BigInt(new(big.Int))}
}

// TestAssertInSubgroupBindsOnCurvePreimage is a regression test for the on-curve
// binding of the hinted preimage. It builds R := [cofactor]S with the *exact*
// in-circuit doubling formulas, so the [cofactor]S == R equality always holds by
// construction. The rejection of the off-curve case therefore comes solely from
// the S.assertIsOnCurve constraint added to assertInSubgroup: without that
// constraint an off-curve S with a matching R would be accepted.
func TestAssertInSubgroupBindsOnCurvePreimage(t *testing.T) {
	assert := require.New(t)
	params, err := GetCurveParams(twistededwards.BN254)
	assert.NoError(err)
	cofactor := params.Cofactor.Uint64()
	a := new(fr.Element).SetBigInt(params.A)
	d := new(fr.Element).SetBigInt(params.D)

	// Valid case: an honest on-curve preimage S with R = [cofactor]S.
	var base tbn254.PointAffine
	base.X.SetBigInt(params.Base[0])
	base.Y.SetBigInt(params.Base[1])
	rx, ry, ok := bn254CofactorMul(base.X, base.Y, *a, cofactor)
	assert.True(ok, "on-curve doubling chain must be defined")
	assert.True(bn254OnCurve(base.X, base.Y, *a, *d))
	validWitness := assertInSubgroupCircuit{R: fePoint(rx, ry), S: fePoint(base.X, base.Y)}
	assert.NoError(test.IsSolved(&assertInSubgroupCircuit{curveID: twistededwards.BN254}, &validWitness, ecc.BN254.ScalarField()))

	// Malicious case: an off-curve preimage S with R := [cofactor]S computed by
	// the same doubling formulas, so [cofactor]S == R holds. Only the on-curve
	// constraint can reject this.
	var sx, sy, ox, oy fr.Element
	foundOffCurve := false
	for i := uint64(2); i < 1000 && !foundOffCurve; i++ {
		for j := uint64(1); j < 8; j++ {
			sx.SetUint64(i)
			sy.SetUint64(i + j)
			if bn254OnCurve(sx, sy, *a, *d) {
				continue
			}
			var okChain bool
			ox, oy, okChain = bn254CofactorMul(sx, sy, *a, cofactor)
			if !okChain {
				continue
			}
			foundOffCurve = true
			break
		}
	}
	assert.True(foundOffCurve, "expected to find an off-curve preimage with a defined doubling chain")
	assert.False(bn254OnCurve(sx, sy, *a, *d), "preimage S must be off-curve for this regression")

	forgedWitness := assertInSubgroupCircuit{R: fePoint(ox, oy), S: fePoint(sx, sy)}
	err = test.IsSolved(&assertInSubgroupCircuit{curveID: twistededwards.BN254}, &forgedWitness, ecc.BN254.ScalarField())
	assert.Error(err, "off-curve preimage must be rejected by the on-curve constraint")
}
