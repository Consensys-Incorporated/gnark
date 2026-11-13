//go:build !icicle

package plonk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Prove falls back to the native CPU PLONK prover when compiled without the
// 'icicle' build tag.
func Prove(ccs constraint.ConstraintSystem, pk native_plonk.ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (native_plonk.Proof, error) {
	return native_plonk.Prove(ccs, pk, fullWitness, opts...)
}

// Setup falls back to the native CPU PLONK setup when compiled without the
// 'icicle' build tag.
func Setup(ccs constraint.ConstraintSystem, srs, srsLagrange kzg.SRS) (native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {
	return native_plonk.Setup(ccs, srs, srsLagrange)
}

// NewProvingKey falls back to the native PLONK proving key when compiled
// without the 'icicle' build tag.
func NewProvingKey(curveID ecc.ID) native_plonk.ProvingKey {
	return native_plonk.NewProvingKey(curveID)
}
