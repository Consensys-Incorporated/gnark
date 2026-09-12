// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import "math/big"

// Emulated field parameters for twisted Edwards curve orders.
// These are used for overflow-safe scalar decomposition verification.

// edBN254Order is the BabyJubjub curve order (251 bits).
type edBN254Order struct{}

func (edBN254Order) NbLimbs() uint     { return 4 }
func (edBN254Order) BitsPerLimb() uint { return 64 }
func (edBN254Order) IsPrime() bool     { return true }
func (edBN254Order) Modulus() *big.Int {
	r, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	return r
}

// edBLS12381Order is the Jubjub curve order (252 bits).
type edBLS12381Order struct{}

func (edBLS12381Order) NbLimbs() uint     { return 4 }
func (edBLS12381Order) BitsPerLimb() uint { return 64 }
func (edBLS12381Order) IsPrime() bool     { return true }
func (edBLS12381Order) Modulus() *big.Int {
	r, _ := new(big.Int).SetString("6554484396890773809930967563523245729705921265872317281365359162392183254199", 10)
	return r
}

// edBandersnatchOrder is the Bandersnatch curve order (253 bits).
type edBandersnatchOrder struct{}

func (edBandersnatchOrder) NbLimbs() uint     { return 4 }
func (edBandersnatchOrder) BitsPerLimb() uint { return 64 }
func (edBandersnatchOrder) IsPrime() bool     { return true }
func (edBandersnatchOrder) Modulus() *big.Int {
	r, _ := new(big.Int).SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
	return r
}

// edBLS12377Order is the BLS12-377 twisted Edwards curve order (251 bits).
type edBLS12377Order struct{}

func (edBLS12377Order) NbLimbs() uint     { return 4 }
func (edBLS12377Order) BitsPerLimb() uint { return 64 }
func (edBLS12377Order) IsPrime() bool     { return true }
func (edBLS12377Order) Modulus() *big.Int {
	r, _ := new(big.Int).SetString("2111115437357092606062206234695386632838870926408408195193685246394721360383", 10)
	return r
}

// edBW6761Order is the BW6-761 twisted Edwards curve order (374 bits).
type edBW6761Order struct{}

func (edBW6761Order) NbLimbs() uint     { return 6 }
func (edBW6761Order) BitsPerLimb() uint { return 64 }
func (edBW6761Order) IsPrime() bool     { return true }
func (edBW6761Order) Modulus() *big.Int {
	r, _ := new(big.Int).SetString("32333053251621136751331591711861691692049189094364332567435817881934511297123972799646723302813083835942624121493", 10)
	return r
}
