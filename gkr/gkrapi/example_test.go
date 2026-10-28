package gkrapi_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	gkrbn254 "github.com/consensys/gnark/gkr/bn254"
	"github.com/consensys/gnark/gkr/gkrapi"
)

// Example builds a single-multiplication-gate circuit natively through the API, compiles it for
// BN254, proves two instances of it with gkr/bn254, flattens and deserializes the proof, verifies
// it, and checks the claims against the assignment.
func Example() {
	api := gkrapi.New()
	x := api.NewInput()
	y := api.NewInput()
	z := api.Mul(x, y)
	api.Export(z)

	circuit, schedule, err := api.Compile(gkrapi.PrimeField(ecc.BN254.ScalarField()), gkrapi.ConsolidateAll)
	assertNoError(err)

	assignment := make(gkrbn254.WireAssignment, len(circuit))
	assignment[x] = []fr.Element{fr.NewElement(2), fr.NewElement(3)}
	assignment[y] = []fr.Element{fr.NewElement(5), fr.NewElement(7)}
	// assignment[z] is left nil: Prove computes it.

	// Prove and Verify must be given hashers seeded identically with a commitment to the circuit,
	// the schedule, the number of instances and the inputs and outputs. The example omits it.
	proof, proverClaims, err := gkrbn254.Prove(circuit, schedule, assignment, mimc.NewFieldHasher())
	assertNoError(err)
	assertNoError(proverClaims.Check(assignment))

	var flattened []fr.Element
	for _, element := range proof.Flatten() {
		flattened = append(flattened, *element)
	}
	deserialized, err := gkrbn254.DeserializeProof(circuit, schedule, flattened)
	assertNoError(err)

	verifierClaims, err := gkrbn254.Verify(circuit, schedule, 1, deserialized, mimc.NewFieldHasher())
	assertNoError(err)
	assertNoError(verifierClaims.Check(assignment)) // every returned claim must be checked

	fmt.Println("proof verified")
	// Output: proof verified
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
