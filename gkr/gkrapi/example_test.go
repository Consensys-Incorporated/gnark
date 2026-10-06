package gkrapi_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc" // registers the MiMC hash used below
	gcHash "github.com/consensys/gnark-crypto/hash"
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

	proof, proverClaims, err := gkrbn254.Prove(circuit, schedule, assignment, gcHash.MIMC_BN254.New())
	assertNoError(err)
	assertNoError(proverClaims.Check(assignment))

	var flattened []fr.Element
	for _, element := range proof.Flatten() {
		flattened = append(flattened, *element)
	}
	deserialized, err := gkrbn254.DeserializeProof(circuit, schedule, flattened)
	assertNoError(err)

	verifierClaims, err := gkrbn254.Verify(circuit, schedule, 1, deserialized, gcHash.MIMC_BN254.New())
	assertNoError(err)
	assertNoError(verifierClaims.Check(assignment))

	fmt.Println("proof verified")
	// Output: proof verified
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
