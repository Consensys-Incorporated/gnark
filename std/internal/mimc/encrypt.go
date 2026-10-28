// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package mimc

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"

	"github.com/consensys/gnark/frontend"
)

var encryptFuncs map[ecc.ID]func(MiMC, frontend.Variable) frontend.Variable
var newMimc map[ecc.ID]func(frontend.API) MiMC

func init() {
	encryptFuncs = make(map[ecc.ID]func(MiMC, frontend.Variable) frontend.Variable)
	encryptFuncs[ecc.BN254] = encryptPow5
	encryptFuncs[ecc.BLS12_381] = encryptPow5
	encryptFuncs[ecc.BLS12_377] = encryptPow17
	encryptFuncs[ecc.BW6_761] = encryptPow5

	newMimc = make(map[ecc.ID]func(frontend.API) MiMC)
	newMimc[ecc.BN254] = newMimcBN254
	newMimc[ecc.BLS12_381] = newMimcBLS381
	newMimc[ecc.BLS12_377] = newMimcBLS377
	newMimc[ecc.BW6_761] = newMimcBW761
}

// -------------------------------------------------------------------------------------------------
// constructors

func newMimcBLS377(api frontend.API) MiMC {
	res := MiMC{}
	res.params = bls12377.GetConstants()
	res.id = ecc.BLS12_377
	res.h = 0
	res.api = api
	return res
}

func newMimcBLS381(api frontend.API) MiMC {
	res := MiMC{}
	res.params = bls12381.GetConstants()
	res.id = ecc.BLS12_381
	res.h = 0
	res.api = api
	return res
}

func newMimcBN254(api frontend.API) MiMC {
	res := MiMC{}
	res.params = bn254.GetConstants()
	res.id = ecc.BN254
	res.h = 0
	res.api = api
	return res
}

func newMimcBW761(api frontend.API) MiMC {
	res := MiMC{}
	res.params = bw6761.GetConstants()
	res.id = ecc.BW6_761
	res.h = 0
	res.api = api
	return res
}

// -------------------------------------------------------------------------------------------------
// encryption functions

func pow5(api frontend.API, x frontend.Variable) frontend.Variable {
	r := api.Mul(x, x)
	r = api.Mul(r, r)
	return api.Mul(r, x)
}

func pow7(api frontend.API, x frontend.Variable) frontend.Variable {
	t := api.Mul(x, x)
	r := api.Mul(t, t)
	r = api.Mul(r, t)
	return api.Mul(r, x)
}

func pow17(api frontend.API, x frontend.Variable) frontend.Variable {
	r := api.Mul(x, x)
	r = api.Mul(r, r)
	r = api.Mul(r, r)
	r = api.Mul(r, r)
	return api.Mul(r, x)
}

// encryptPow5 of a mimc run expressed as r1cs
// m is the message, k the key
func encryptPow5(h MiMC, m frontend.Variable) frontend.Variable {
	x := m
	for i := 0; i < len(h.params); i++ {
		x = pow5(h.api, h.api.Add(x, h.h, h.params[i]))
	}
	return h.api.Add(x, h.h)
}

// encryptPow7 of a mimc run expressed as r1cs
// m is the message, k the key
func encryptPow7(h MiMC, m frontend.Variable) frontend.Variable {
	x := m
	for i := 0; i < len(h.params); i++ {
		x = pow7(h.api, h.api.Add(x, h.h, h.params[i]))
	}
	return h.api.Add(x, h.h)
}

// encryptPow17 of a mimc run expressed as r1cs
// m is the message, k the key
func encryptPow17(h MiMC, m frontend.Variable) frontend.Variable {
	x := m
	for i := 0; i < len(h.params); i++ {
		// res = (res+key+c)**17
		x = pow17(h.api, h.api.Add(x, h.h, h.params[i]))
	}
	return h.api.Add(x, h.h)

}
