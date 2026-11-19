package plonk_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Example of verifying recursively BLS12-377 PLONK proof in BW6-761 PLONK circuit using field emulation
func Example_native() {
	// compute the proof which we want to verify recursively
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(
		ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(),
	)

	// initialize the witness elements
	circuitVk, err := plonk.ValueOfVerifyingKeyFixed[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the PLONK proof
	err = native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
}
