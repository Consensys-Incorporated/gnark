package groth16

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16backend_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// tests without commitment

type InnerCircuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInner(assert *test.Assert, field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuit{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func TestBN254InBN254(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BN254.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBLS12InBW6(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

func TestBW6InBN254(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// assignment tests

type WitnessCircut struct {
	A emulated.Element[emparams.Secp256k1Fr] `gnark:",public"`
}

func (c *WitnessCircut) Define(frontend.API) error { return nil }

func TestValueOfWitness(t *testing.T) {
	assignment := WitnessCircut{
		A: emulated.ValueOf[emparams.Secp256k1Fr]("1234"),
	}
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bn254.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bls12377.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		w, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
		assert.NoError(err)
		ww, err := ValueOfWitness[sw_bls12381.ScalarField](w)
		assert.NoError(err)
		_ = ww
	}, "bls12381")
}

func TestValueOfProof(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bn254.Generators()
		proof := groth16backend_bn254.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bls12377.Generators()
		proof := groth16backend_bls12377.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		_, _, G1, G2 := bls12381.Generators()
		proof := groth16backend_bls12381.Proof{
			Ar:  G1,
			Krs: G1,
			Bs:  G2,
		}
		assignment, err := ValueOfProof[sw_bls12381.G1Affine, sw_bls12381.G2Affine](&proof)
		assert.NoError(err)
		_ = assignment
	}, "bls12381")
}

func TestValueOfVerifyingKey(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		// WitnessCircut declares an input and has an empty Define.
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &WitnessCircut{}, frontend.IgnoreUnconstrainedInputs())
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
		_ = vvk
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		// WitnessCircut declares an input and has an empty Define.
		ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &WitnessCircut{}, frontend.IgnoreUnconstrainedInputs())
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
		assert.NoError(err)
		_ = vvk
	}, "bls12377")
	assert.Run(func(assert *test.Assert) {
		// WitnessCircut declares an input and has an empty Define.
		ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &WitnessCircut{}, frontend.IgnoreUnconstrainedInputs())
		assert.NoError(err)
		_, vk, err := groth16.Setup(ccs)
		assert.NoError(err)
		vvk, err := ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](vk)
		assert.NoError(err)
		_ = vvk
	}, "bls12381")
}

// constant inner verification key with precomputation

type OuterCircuitConstant[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	vk           VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness Witness[FR]
}

func (c *OuterCircuitConstant[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.vk, c.Proof, c.InnerWitness)
}

func TestBW6InBN254Constant(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuitConstant[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		vk:           circuitVk,
	}
	outerAssignment := &OuterCircuitConstant[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// tests with commitment

type InnerCircuitCommitment struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommitment) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)

	// commitment both to internal and public
	commitment, err := api.(frontend.Committer).Commit(res, c.N)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)

	return nil
}

func getInnerCommitment(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitCommitment{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitCommitment{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, GetNativeProverOptions(outer, field))
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}
func TestBN254InBN254Commitment(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerWitness, innerProof := getInnerCommitment(assert, ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
	assert.Equal(len(innerCcs.GetCommitments().CommitmentIndexes()), 1)

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBLS12InBW6Commitment(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerWitness, innerProof := getInnerCommitment(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())
	assert.Equal(len(innerCcs.GetCommitments().CommitmentIndexes()), 1)

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Proof:        PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

func TestBW6InBN254Commitment(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerWitness, innerProof := getInnerCommitment(assert, ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())
	assert.Equal(len(innerCcs.GetCommitments().CommitmentIndexes()), 1)

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		Proof:        PlaceholderProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs),
		InnerWitness: PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type innerParametricCircuit struct {
	nbConstraints int
	SecretInput   frontend.Variable `gnark:",secret"`
	PublicInputs  frontend.Variable `gnark:",public"`
}

func (c *innerParametricCircuit) Define(api frontend.API) error {
	res := api.Mul(c.SecretInput, c.SecretInput)
	for i := 2; i < c.nbConstraints-1; i++ {
		res = api.Mul(res, c.SecretInput)
	}
	api.AssertIsEqual(c.PublicInputs, res)
	commitment, err := api.(frontend.Committer).Commit(res, c.PublicInputs)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, 0)
	return nil
}

// getInnerParametric method returns a dummy circuit with the number of constraints
// of the main one provided as argument, it also generates a proof for this
// circuit and verifies it. It returns the circuit, the verifying key, the
// public witness and the proof.
func getInnerParametric(assert *test.Assert, nbConstraints int, field, outer *big.Int) (
	constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof,
) {
	dummyCcs, err := frontend.Compile(field, r1cs.NewBuilder, &innerParametricCircuit{
		nbConstraints: nbConstraints,
	})
	assert.NoError(err)
	dummyPK, dummyVK, err := groth16.Setup(dummyCcs)
	assert.NoError(err)

	// dummy proof
	x, err := rand.Int(rand.Reader, field)
	assert.NoError(err)
	res := big.NewInt(1)
	for i := 0; i < nbConstraints-1; i++ {
		res.Mul(res, x)
	}
	dummyAssignment := &innerParametricCircuit{
		SecretInput:  x,
		PublicInputs: res,
	}
	dummyWitness, err := frontend.NewWitness(dummyAssignment, field)
	assert.NoError(err)
	dummyProof, err := groth16.Prove(dummyCcs, dummyPK, dummyWitness, GetNativeProverOptions(outer, field))
	assert.NoError(err)
	dummyPubWitness, err := dummyWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(dummyProof, dummyVK, dummyPubWitness, GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return dummyCcs, dummyVK, dummyPubWitness, dummyProof
}

type OuterCircuitMulti[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	// selectors include a 1 for inner and 0 for dummy verification keys
	// it allows to switch between the two vks to use the right one for each
	// proof and witness
	Selectors []frontend.Variable
	Proofs    []Proof[G1El, G2El]
	// vks includes the dummy vk in the first place and the inner vk in the
	// second place
	vks            []VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitnesses []Witness[FR]                    `gnark:",public"`
}

func (c *OuterCircuitMulti[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// init the verifier
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	// switch between vkeys based on each selector
	for i, selector := range c.Selectors {
		vk, err := verifier.SwitchVerificationKey(selector, c.vks)
		if err != nil {
			return fmt.Errorf("switch vk: %w", err)
		}
		if err := verifier.AssertProof(vk, c.Proofs[i], c.InnerWitnesses[i]); err != nil {
			return err
		}
	}
	return nil
}

func TestBLS12InBW6Multi(t *testing.T) {
	innertField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()
	nbCircuit := 5
	nbProofs := 5
	assert := test.NewAssert(t)
	var err error

	ccss := make([]constraint.ConstraintSystem, nbCircuit)
	vks := make([]groth16.VerifyingKey, nbCircuit)
	witnesses := make([]witness.Witness, nbCircuit)
	proofs := make([]groth16.Proof, nbCircuit)
	for i := 0; i < nbCircuit; i++ {
		// the different circuits can have different sizes. However, the number of public inputs and commitments must match
		ccss[i], vks[i], witnesses[i], proofs[i] = getInnerParametric(assert, 100*(i+1), innertField, outerField)
	}
	circuitVks := make([]VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT], nbCircuit)
	for i, vk := range vks {
		circuitVks[i], err = ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
		assert.NoError(err)
	}
	circuitProofs := make([]Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine], nbProofs)
	circuitWitnesses := make([]Witness[sw_bls12377.ScalarField], nbProofs)
	innerSelectors := make([]int, nbProofs)
	circuitSelectors := make([]frontend.Variable, nbProofs)
	for i := 0; i < nbProofs; i++ {
		selector, err := rand.Int(rand.Reader, big.NewInt(int64(nbCircuit)))
		assert.NoError(err)
		innerSelectors[i] = int(selector.Int64())
		circuitSelectors[i] = frontend.Variable(innerSelectors[i])
		circuitProofs[i], err = ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proofs[innerSelectors[i]])
		assert.NoError(err)
		circuitWitnesses[i], err = ValueOfWitness[sw_bls12377.ScalarField](witnesses[innerSelectors[i]])
		assert.NoError(err)
	}
	outerCircuit := &OuterCircuitMulti[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Selectors:      make([]frontend.Variable, nbProofs),
		Proofs:         make([]Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine], nbProofs),
		InnerWitnesses: make([]Witness[sw_bls12377.ScalarField], nbProofs),
		vks:            circuitVks, // the inner verification keys are hardcoded in the aggregation circuit
	}
	for i := 0; i < nbProofs; i++ {
		outerCircuit.Proofs[i] = PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccss[0])
		outerCircuit.InnerWitnesses[i] = PlaceholderWitness[sw_bls12377.ScalarField](ccss[0])
	}
	outerAssignment := &OuterCircuitMulti[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Selectors:      circuitSelectors,
		InnerWitnesses: circuitWitnesses,
		Proofs:         circuitProofs,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

type OuterCircuitIsValid[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness Witness[FR]
	Res          frontend.Variable `gnark:",public"`
}

func (c *OuterCircuitIsValid[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	res, err := verifier.IsValidProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	if err != nil {
		return fmt.Errorf("proof check: %w", err)
	}
	api.AssertIsEqual(res, c.Res)
	return nil
}

func TestBLS12InBW6InvalidProof(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerWitness, innerProof := getInnerCommitment(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())
	assert.Equal(len(innerCcs.GetCommitments().CommitmentIndexes()), 1)

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuitIsValid[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		Proof:        PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}

	assert.Run(func(assert *test.Assert) {
		outerAssignment := &OuterCircuitIsValid[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			InnerWitness: circuitWitness,
			Proof:        circuitProof,
			VerifyingKey: circuitVk,
			Res:          1,
		}
		err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
		assert.NoError(err)
	}, "valid")

	assert.Run(func(assert *test.Assert) {
		invalidCircuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
		assert.NoError(err)
		var randg1 bls12377.G1Affine
		var randg1s fr_bls12377.Element
		randg1s.SetRandom()
		randg1.ScalarMultiplicationBase(randg1s.BigInt(new(big.Int)))
		invalidCircuitVk.G1.K[0] = sw_bls12377.NewG1Affine(randg1)

		outerAssignment := &OuterCircuitIsValid[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			InnerWitness: circuitWitness,
			Proof:        circuitProof,
			VerifyingKey: invalidCircuitVk,
			Res:          0,
		}
		err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
		assert.NoError(err)
	}, "invalid=vk")

	assert.Run(func(assert *test.Assert) {
		invalidCircuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
		assert.NoError(err)
		var randg1 bls12377.G1Affine
		var randg1s fr_bls12377.Element
		randg1s.SetRandom()
		randg1.ScalarMultiplicationBase(randg1s.BigInt(new(big.Int)))
		invalidCircuitProof.Ar = sw_bls12377.NewG1Affine(randg1)

		outerAssignment := &OuterCircuitIsValid[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			InnerWitness: circuitWitness,
			Proof:        invalidCircuitProof,
			VerifyingKey: circuitVk,
			Res:          0,
		}
		err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
		assert.NoError(err)
	}, "invalid=proof")

	assert.Run(func(assert *test.Assert) {
		invalidCircuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
		assert.NoError(err)
		invalidCircuitWitness.Public[0] = emulated.ValueOf[sw_bls12377.ScalarField](123)

		outerAssignment := &OuterCircuitIsValid[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			InnerWitness: invalidCircuitWitness,
			Proof:        circuitProof,
			VerifyingKey: circuitVk,
			Res:          0,
		}
		err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
		assert.NoError(err)
	}, "invalid=witness")
}
