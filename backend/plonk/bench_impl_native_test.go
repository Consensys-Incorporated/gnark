//go:build !icicle

package plonk_test

import (
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func benchSetup(ccs constraint.ConstraintSystem, srs, srsLagrange kzg.SRS) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	return plonk.Setup(ccs, srs, srsLagrange)
}

func benchProve(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, w witness.Witness) (plonk.Proof, error) {
	return plonk.Prove(ccs, pk, w)
}
