package evmprecompiles

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ecaddCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	X1       sw_emulated.AffinePoint[emulated.BN254Fp]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *ecaddCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := ECAdd(api, &c.X0, &c.X1)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECAdd() (circ, wit frontend.Circuit) {
	_, _, G, _ := bn254.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bn254.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bn254.G1Affine
	expected.Add(&P, &Q)
	circuit := ecaddCircuit{}
	witness := ecaddCircuit{
		X0: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](P.X),
			Y: emulated.ValueOf[emulated.BN254Fp](P.Y),
		},
		X1: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](Q.X),
			Y: emulated.ValueOf[emulated.BN254Fp](Q.Y),
		},
		Expected: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](expected.X),
			Y: emulated.ValueOf[emulated.BN254Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func TestECAddCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd()
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECAddCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd()
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
}

type ecmulCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	U        emulated.Element[emulated.BN254Fr]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *ecmulCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := ECMul(api, &c.X0, &c.U)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECMul(t *testing.T) (circ, wit frontend.Circuit) {
	_, _, G, _ := bn254.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P bn254.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	var expected bn254.G1Affine
	expected.ScalarMultiplication(&P, v.BigInt(new(big.Int)))
	circuit := ecmulCircuit{}
	witness := ecmulCircuit{
		X0: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](P.X),
			Y: emulated.ValueOf[emulated.BN254Fp](P.Y),
		},
		U: emulated.ValueOf[emulated.BN254Fr](v),
		Expected: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](expected.X),
			Y: emulated.ValueOf[emulated.BN254Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func TestECMulCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECMul(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254, ecc.BLS12_377))
}

type ecPairBatchCircuit struct {
	P  sw_bn254.G1Affine
	NP sw_bn254.G1Affine
	DP sw_bn254.G1Affine
	Q  sw_bn254.G2Affine
	n  int
}

func (c *ecPairBatchCircuit) Define(api frontend.API) error {
	Q := make([]*sw_bn254.G2Affine, c.n)
	for i := range Q {
		Q[i] = &c.Q
	}
	switch c.n {
	case 2:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP}, Q)
	case 3:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.NP, &c.NP, &c.DP}, Q)
	case 4:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP, &c.P, &c.NP}, Q)
	case 5:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	case 6:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP}, Q)
	case 7:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	case 8:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP}, Q)
	case 9:
		ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	default:
		return fmt.Errorf("not handled %d", c.n)
	}
	return nil
}

func TestECPairMulBatch(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p, q := bn254.Generators()

	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()

	p.ScalarMultiplication(&p, u.BigInt(new(big.Int)))
	q.ScalarMultiplication(&q, v.BigInt(new(big.Int)))

	var dp, np bn254.G1Affine
	dp.Double(&p)
	np.Neg(&p)

	for i := 2; i < 10; i++ {
		err := test.IsSolved(&ecPairBatchCircuit{n: i}, &ecPairBatchCircuit{
			n:  i,
			P:  sw_bn254.NewG1Affine(p),
			NP: sw_bn254.NewG1Affine(np),
			DP: sw_bn254.NewG1Affine(dp),
			Q:  sw_bn254.NewG2Affine(q),
		}, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type ecPairSingleCircuit struct {
	P sw_bn254.G1Affine
	Q sw_bn254.G2Affine
}

func (c *ecPairSingleCircuit) Define(api frontend.API) error {
	ECPair(api, []*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P}, []*sw_bn254.G2Affine{&c.Q})
	return nil
}

// a single pair is a valid input for the precompile. e(0, Q) == 1 so the check
// must pass for P at infinity, and fail for a non-trivial pair.
func TestECPairSinglePair(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p, q := bn254.Generators()
	var inf bn254.G1Affine

	err := test.IsSolved(&ecPairSingleCircuit{}, &ecPairSingleCircuit{
		P: sw_bn254.NewG1Affine(inf),
		Q: sw_bn254.NewG2Affine(q),
	}, ecc.BN254.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(&ecPairSingleCircuit{}, &ecPairSingleCircuit{
		P: sw_bn254.NewG1Affine(p),
		Q: sw_bn254.NewG2Affine(q),
	}, ecc.BN254.ScalarField())
	assert.Error(err)
}
