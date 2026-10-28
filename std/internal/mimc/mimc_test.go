// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package mimc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type mimcCircuit struct {
	ExpectedResult frontend.Variable `gnark:"data,public"`
	Data           [10]frontend.Variable
}

func (circuit *mimcCircuit) Define(api frontend.API) error {
	mimc, err := NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.Data[:]...)
	result := mimc.Sum()
	api.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

func TestMimcAll(t *testing.T) {
	assert := test.NewAssert(t)

	curves := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
	}

	for curve, hashFunc := range curves {

		// minimal cs res = hash(data)
		var circuit, validWitness, invalidWitness mimcCircuit

		modulus := curve.ScalarField()
		var data [10]big.Int
		data[0].Sub(modulus, big.NewInt(1))
		for i := 1; i < 10; i++ {
			data[i].Add(&data[i-1], &data[i-1]).Mod(&data[i], modulus)
		}

		// running MiMC (Go)
		goMimc := hashFunc.New()
		for i := 0; i < 10; i++ {
			goMimc.Write(data[i].Bytes())
		}
		expectedh := goMimc.Sum(nil)

		// assert correctness against correct witness
		for i := 0; i < 10; i++ {
			validWitness.Data[i] = data[i].String()
		}
		validWitness.ExpectedResult = expectedh

		// assert failure against wrong witness
		for i := 0; i < 10; i++ {
			invalidWitness.Data[i] = data[i].Sub(&data[i], big.NewInt(1)).String()
		}
		invalidWitness.ExpectedResult = expectedh

		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithCurves(curve))
	}

}

// stateStoreTestCircuit checks that SetState works as expected. The circuit, however
// does not check the correctness of the hashes returned by the MiMC function
// as there is another test already testing this property.
type stateStoreTestCircuit struct {
	X frontend.Variable
}

func (s *stateStoreTestCircuit) Define(api frontend.API) error {

	hsh1, err1 := NewMiMC(api)
	hsh2, err2 := NewMiMC(api)

	if err1 != nil || err2 != nil {
		return fmt.Errorf("could not instantiate the MIMC hasher: %w", errors.Join(err1, err2))
	}

	// This pre-shuffle the hasher state so that the test does not start from
	// a zero state.
	hsh1.Write(s.X)

	state := hsh1.State()
	hsh2.SetState(state)

	hsh1.Write(s.X)
	hsh2.Write(s.X)

	var (
		dig1      = hsh1.Sum()
		dig2      = hsh2.Sum()
		newState1 = hsh1.State()
		newState2 = hsh2.State()
	)

	api.AssertIsEqual(dig1, dig2)

	for i := range newState1 {
		api.AssertIsEqual(newState1[i], newState2[i])
	}

	return nil
}

func TestStateStoreMiMC(t *testing.T) {

	assert := test.NewAssert(t)

	curves := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
	}

	for curve := range curves {

		// minimal cs res = hash(data)
		var (
			circuit    = &stateStoreTestCircuit{}
			assignment = &stateStoreTestCircuit{X: 2}
		)

		assert.CheckCircuit(circuit,
			test.WithValidAssignment(assignment),
			test.WithCurves(curve))
	}
}

type recoveredStateTestCircuit struct {
	State    []frontend.Variable
	Input    frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *recoveredStateTestCircuit) Define(api frontend.API) error {
	h, err := NewMiMC(api)
	if err != nil {
		return fmt.Errorf("initialize hash: %w", err)
	}
	if err = h.SetState(c.State); err != nil {
		return fmt.Errorf("set state: %w", err)
	}
	h.Write(c.Input)
	res := h.Sum()
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestHasherFromState(t *testing.T) {
	assert := test.NewAssert(t)

	hashes := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
	}

	for cc, hh := range hashes {
		hasher := hh.New()
		ss, ok := hasher.(hash.StateStorer)
		assert.True(ok)
		_, err := ss.Write([]byte("hello world"))
		assert.NoError(err)
		state := ss.State()
		nbBytes := cc.ScalarField().BitLen() / 8
		buf := make([]byte, nbBytes)
		_, err = rand.Read(buf)
		assert.NoError(err)
		ss.Write(buf)
		expected := ss.Sum(nil)
		bstate := new(big.Int).SetBytes(state)
		binput := new(big.Int).SetBytes(buf)
		assert.CheckCircuit(
			&recoveredStateTestCircuit{State: make([]frontend.Variable, 1)},
			test.WithValidAssignment(&recoveredStateTestCircuit{State: []frontend.Variable{bstate}, Input: binput, Expected: expected}),
			test.WithCurves(cc))
	}
}
