// Package plonk provides wrappers for PLONK with ICICLE acceleration.
package plonk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Verify wraps native plonk.Verify for convenience.
func Verify(proof native_plonk.Proof, vk native_plonk.VerifyingKey, publicWitness witness.Witness, opts ...backend.VerifierOption) error {
	return native_plonk.Verify(proof, vk, publicWitness, opts...)
}

// NewVerifyingKey returns a new empty VerifyingKey compatible with native plonk.NewVerifyingKey.
func NewVerifyingKey(curveID ecc.ID) native_plonk.VerifyingKey {
	return native_plonk.NewVerifyingKey(curveID)
}

// NewProof returns a new empty Proof compatible with native plonk.NewProof.
func NewProof(curveID ecc.ID) native_plonk.Proof {
	return native_plonk.NewProof(curveID)
}

// NewCS returns a new typed CS compatible with native plonk.NewCS.
func NewCS(curveID ecc.ID) constraint.ConstraintSystem {
	return native_plonk.NewCS(curveID)
}
