package keccakf_test

import (
	"testing"

	"github.com/consensys/gnark/std/math/uints"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/permutation/keccakf"
	"github.com/consensys/gnark/test"
)

type keccakfCircuit struct {
	In       [25]uints.U64
	Expected [25]uints.U64 `gnark:",public"`
}

func (c *keccakfCircuit) Define(api frontend.API) error {
	var res [25]uints.U64
	for i := range res {
		res[i] = c.In[i]
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		res = keccakf.Permute(uapi, res)
	}
	for i := range res {
		uapi.AssertEq(res[i], c.Expected[i])
	}
	return nil
}

type keccakfCountCircuit struct {
	In       [25]uints.U64
	Expected [25]uints.U64 `gnark:",public"`
}

func (c *keccakfCountCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	res := keccakf.Permute(uapi, c.In)
	for i := range res {
		uapi.AssertEq(res[i], c.Expected[i])
	}
	return nil
}

func TestKeccakfCount(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keccakfCountCircuit{})
	assert.NoError(err)
	t.Log("KeccakF-1600 r1cs constraints =", ccs.GetNbConstraints(), "instructions =", ccs.GetNbInstructions())
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &keccakfCountCircuit{})
	assert.NoError(err)
	t.Log("KeccakF-1600 scs constraints =", ccs.GetNbConstraints(), "instructions =", ccs.GetNbInstructions())
}

func TestKeccakf(t *testing.T) {
	var nativeIn [25]uint64
	var res [25]uint64
	for i := range nativeIn {
		nativeIn[i] = 2
		res[i] = 2
	}
	for i := 0; i < 2; i++ {
		res = keccakF1600(res)
	}
	witness := keccakfCircuit{}
	for i := range nativeIn {
		witness.In[i] = uints.NewU64(nativeIn[i])
		witness.Expected[i] = uints.NewU64(res[i])
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&keccakfCircuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16, backend.PLONK),
		test.NoProverChecks(),
		test.NoFuzzing())
}
