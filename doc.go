// Package gnark provides fast Zero Knowledge Proofs (ZKP) systems and a high level APIs to design ZKP circuits.
//
// gnark supports the following ZKP schemes:
//   - Groth16
//   - PLONK
//
// gnark supports the following curves:
//   - BN254
//   - BLS12_377
//   - BLS12_381
//   - BW6_761
//
// User documentation
// https://docs.gnark.consensys.net
package gnark

import (
	"github.com/blang/semver/v4"
	"github.com/consensys/gnark-crypto/ecc"
)

var Version = semver.MustParse("0.16.3")

// Curves return the curves supported by gnark
func Curves() []ecc.ID {
	return []ecc.ID{
		ecc.BN254,
		ecc.BLS12_377,
		ecc.BLS12_381,
		ecc.BW6_761,
	}
}
