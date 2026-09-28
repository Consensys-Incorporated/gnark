package gkrapi_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc" // registers the MiMC hash used below
	gcHash "github.com/consensys/gnark-crypto/hash"
	bn254 "github.com/consensys/gnark/gkr/bn254"
	"github.com/consensys/gnark/gkr/gkrapi"
)

// Example builds a single-multiplication-gate circuit natively through the API, compiles it for
// BN254, proves and verifies two instances of it with gkr/bn254, and checks the claims against
// the assignment.
func Example() {
	api := gkrapi.New()
	x := api.NewInput()
	y := api.NewInput()
	z := api.Mul(x, y)
	api.Export(z)

	circuit, schedule, err := api.Compile(ecc.BN254.ScalarField(), gkrapi.ConsolidateAll)
	assertNoError(err)

	assignment := make(bn254.WireAssignment, len(circuit))
	assignment[x] = []fr.Element{fr.NewElement(2), fr.NewElement(3)}
	assignment[y] = []fr.Element{fr.NewElement(5), fr.NewElement(7)}
	// assignment[z] is left nil: Prove computes it.

	proof, proverClaims, err := bn254.Prove(circuit, schedule, assignment, gcHash.MIMC_BN254.New())
	assertNoError(err)
	assertNoError(proverClaims.Check(assignment))

	verifierClaims, err := bn254.Verify(circuit, schedule, 1, proof, gcHash.MIMC_BN254.New())
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
