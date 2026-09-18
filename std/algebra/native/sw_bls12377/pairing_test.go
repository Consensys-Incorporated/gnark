// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/test"
)

type finalExp struct {
	ML fields_bls12377.E12
	R  GT
}

func (circuit *finalExp) Define(api frontend.API) error {

	finalExpRes := FinalExponentiation(api, circuit.ML)
	finalExpRes.AssertIsEqual(api, circuit.R)

	return nil
}

func TestFinalExp(t *testing.T) {

	// pairing test data
	_, _, milRes, pairingRes := pairingData()

	// create cs
	witness := finalExp{
		ML: NewGTEl(milRes),
		R:  NewGTEl(pairingRes),
	}

	assert := test.NewAssert(t)
	assert.CheckCircuit(&finalExp{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type pairingBLS377 struct {
	P   G1Affine
	Q   G2Affine
	Res GT
}

func (circuit *pairingBLS377) Define(api frontend.API) error {
	pr := NewPairing(api)
	pr.AssertIsOnG1(&circuit.P)
	pr.AssertIsOnG2(&circuit.Q)
	pairingRes, _ := Pair(api, []G1Affine{circuit.P}, []G2Affine{circuit.Q})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestPairingBLS377(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := pairingData()

	// assign values to witness
	witness := pairingBLS377{
		P:   NewG1Affine(P),
		Q:   NewG2Affine(Q),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingBLS377{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type triplePairingBLS377 struct {
	P1, P2, P3 G1Affine
	Q1, Q2, Q3 G2Affine
	Res        GT
}

func (circuit *triplePairingBLS377) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P1, circuit.P2, circuit.P3}, []G2Affine{circuit.Q1, circuit.Q2, circuit.Q3})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestTriplePairingBLS377(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := triplePairingData()

	witness := triplePairingBLS377{
		P1:  NewG1Affine(P[0]),
		P2:  NewG1Affine(P[1]),
		P3:  NewG1Affine(P[2]),
		Q1:  NewG2Affine(Q[0]),
		Q2:  NewG2Affine(Q[1]),
		Q3:  NewG2Affine(Q[2]),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&triplePairingBLS377{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761), test.NoProverChecks())

}

type pairingFixedBLS377 struct {
	P   G1Affine
	Q   G2Affine
	Res GT
}

func (circuit *pairingFixedBLS377) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P}, []G2Affine{circuit.Q})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestPairingFixedBLS377(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := pairingData()

	witness := pairingBLS377{
		P:   NewG1Affine(P),
		Q:   NewG2AffineFixed(Q),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingFixedBLS377{Q: NewG2AffineFixedPlaceholder()}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type doublePairingFixedBLS377 struct {
	P0  G1Affine
	P1  G1Affine
	Q0  G2Affine
	Q1  G2Affine
	Res GT
}

func (circuit *doublePairingFixedBLS377) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P0, circuit.P1}, []G2Affine{circuit.Q0, circuit.Q1})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestDoublePairingFixedBLS377(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := doublePairingFixedQData()

	witness := doublePairingFixedBLS377{
		P0:  NewG1Affine(P[0]),
		P1:  NewG1Affine(P[1]),
		Q0:  NewG2AffineFixed(Q[0]),
		Q1:  NewG2AffineFixed(Q[1]),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&doublePairingFixedBLS377{Q0: NewG2AffineFixedPlaceholder(), Q1: NewG2AffineFixedPlaceholder()}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type pairingCheckBLS377 struct {
	P1, P2 G1Affine
	Q1, Q2 G2Affine
}

func (circuit *pairingCheckBLS377) Define(api frontend.API) error {

	err := PairingCheck(api, []G1Affine{circuit.P1, circuit.P2}, []G2Affine{circuit.Q1, circuit.Q2})

	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}

	return nil
}

func TestPairingCheckBLS377(t *testing.T) {

	// pairing test data
	P, Q := pairingCheckData()
	witness := pairingCheckBLS377{
		P1: NewG1Affine(P[0]),
		P2: NewG1Affine(P[1]),
		Q1: NewG2Affine(Q[0]),
		Q2: NewG2Affine(Q[1]),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingCheckBLS377{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761), test.NoProverChecks())

}

type groupMembership struct {
	P G1Affine
	Q G2Affine
}

func (circuit *groupMembership) Define(api frontend.API) error {
	pr := NewPairing(api)
	pr.AssertIsOnG1(&circuit.P)
	pr.AssertIsOnG2(&circuit.Q)

	return nil
}

type threePairingCheckBLS377 struct {
	P1, P2, P3 G1Affine
	Q1, Q2, Q3 G2Affine
}

func (circuit *threePairingCheckBLS377) Define(api frontend.API) error {

	err := PairingCheck(api, []G1Affine{circuit.P1, circuit.P2, circuit.P3}, []G2Affine{circuit.Q1, circuit.Q2, circuit.Q3})

	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}

	return nil
}

func TestThreePairingCheckBLS377(t *testing.T) {

	// pairing test data
	P, Q := threePairingCheckData()
	witness := threePairingCheckBLS377{
		P1: NewG1Affine(P[0]),
		P2: NewG1Affine(P[1]),
		P3: NewG1Affine(P[2]),
		Q1: NewG2Affine(Q[0]),
		Q2: NewG2Affine(Q[1]),
		Q3: NewG2Affine(Q[2]),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&threePairingCheckBLS377{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761), test.NoProverChecks())

}

func TestGroupMembership(t *testing.T) {

	// pairing test data
	P, Q, _, _ := pairingData()

	// assign values to witness
	witness := groupMembership{
		P: NewG1Affine(P),
		Q: NewG2Affine(Q),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&groupMembership{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

// utils
func pairingData() (P bls12377.G1Affine, Q bls12377.G2Affine, milRes, pairingRes bls12377.GT) {
	_, _, P, Q = bls12377.Generators()
	milRes, _ = bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
	pairingRes = bls12377.FinalExponentiation(&milRes)
	return
}

func pairingCheckData() (P [2]bls12377.G1Affine, Q [2]bls12377.G2Affine) {
	// e(a,2b) * e(-2a,b) == 1
	_, _, P[0], Q[0] = bls12377.Generators()
	P[1].Double(&P[0]).Neg(&P[1])
	Q[1].Set(&Q[0])
	Q[0].Double(&Q[0])

	return
}

func threePairingCheckData() (P [3]bls12377.G1Affine, Q [3]bls12377.G2Affine) {
	// e(2a, 2b) * e(-2a, b) * e(a, -2b) == 1

	_, _, p, q := bls12377.Generators()

	P[0].Double(&p)
	Q[0].Double(&q)
	P[1].Neg(&P[0])
	Q[1].Set(&q)
	P[2].Set(&p)
	Q[2].Neg(&Q[0])

	return
}

func triplePairingData() (P [3]bls12377.G1Affine, Q [3]bls12377.G2Affine, pairingRes bls12377.GT) {
	_, _, P[0], Q[0] = bls12377.Generators()
	var u, v fr.Element
	var _u, _v big.Int
	for i := 1; i < 3; i++ {
		_, _ = u.SetRandom()
		_, _ = v.SetRandom()
		u.BigInt(&_u)
		v.BigInt(&_v)
		P[i].ScalarMultiplication(&P[0], &_u)
		Q[i].ScalarMultiplication(&Q[0], &_v)
	}
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P[0], P[1], P[2]}, []bls12377.G2Affine{Q[0], Q[1], Q[2]})
	pairingRes = bls12377.FinalExponentiation(&milRes)

	return
}

func doublePairingFixedQData() (P [2]bls12377.G1Affine, Q [2]bls12377.G2Affine, milRes, pairingRes bls12377.GT) {
	_, _, P[0], Q[0] = bls12377.Generators()
	var u, v fr.Element
	var _u, _v big.Int
	_, _ = u.SetRandom()
	_, _ = v.SetRandom()
	u.BigInt(&_u)
	v.BigInt(&_v)
	P[1].ScalarMultiplication(&P[0], &_u)
	Q[1].ScalarMultiplication(&Q[0], &_v)
	milRes, _ = bls12377.MillerLoop([]bls12377.G1Affine{P[0], P[1]}, []bls12377.G2Affine{Q[0], Q[1]})
	pairingRes = bls12377.FinalExponentiation(&milRes)
	return
}
