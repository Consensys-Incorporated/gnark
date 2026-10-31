//go:build icicle

package plonk_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	accel_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

type circuit struct {
	A, B frontend.Variable `gnark:",public"`
	Res  frontend.Variable
}

func (c *circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Res)
	return nil
}

func TestMarshalBN254(t *testing.T) {
	assert := test.NewAssert(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bn254.SparseR1CS)

	// Build an SRS suitable for this circuit
	srs, srsLagrange, err := unsafekzg.NewSRS(tCcs)
	assert.NoError(err)

	// Native setup
	nativePK, nativeVK, err := native_plonk.Setup(tCcs, srs, srsLagrange)
	assert.NoError(err)

	// Marshal native -> icicle bn254.ProvingKey
	iciPK := accel_plonk.NewProvingKey(ecc.BN254)
	buf := new(bytes.Buffer)
	_, err = nativePK.WriteTo(buf)
	assert.NoError(err)
	_, err = iciPK.ReadFrom(buf)
	assert.NoError(err)

	// Roundtrip back into native
	buf.Reset()
	_, err = iciPK.WriteTo(buf)
	assert.NoError(err)
	var nativePK2 plonk_bn254.ProvingKey
	_, err = nativePK2.ReadFrom(buf)
	assert.NoError(err)

	// Prove both ways
	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	proofNative, err := native_plonk.Prove(tCcs, &nativePK2, w)
	assert.NoError(err)
	proofIcicle, err := accel_plonk.Prove(tCcs, iciPK, w)
	assert.NoError(err)

	err = accel_plonk.Verify(proofNative, nativeVK, pw)
	assert.NoError(err)
	err = accel_plonk.Verify(proofIcicle, nativeVK, pw)
	assert.NoError(err)
}

func TestSetupBN254(t *testing.T) {
	assert := test.NewAssert(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit{})
	assert.NoError(err)
	tCcs := ccs.(*cs_bn254.SparseR1CS)

	// Build an SRS suitable for this circuit
	srs, srsLagrange, err := unsafekzg.NewSRS(tCcs)
	assert.NoError(err)

	// Accelerated setup
	iciPK, iciVK, err := accel_plonk.Setup(tCcs, srs, srsLagrange)
	assert.NoError(err)

	// Prove/verify using accelerated Prove
	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	proofIcicle, err := accel_plonk.Prove(tCcs, iciPK, w)
	assert.NoError(err)
	err = accel_plonk.Verify(proofIcicle, iciVK, pw)
	assert.NoError(err)
}
