package evmprecompiles

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// 11: G1 Add
type ecaddG1BLSCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	X1       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Expected sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *ecaddG1BLSCircuit) Define(api frontend.API) error {
	ECAddG1BLS(api, &c.X0, &c.X1, &c.Expected)
	return nil
}

func testRoutineECAddG1BLS() (circ, wit frontend.Circuit) {
	_, _, G, _ := bls12381.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bls12381.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bls12381.G1Affine
	expected.Add(&P, &Q)
	circuit := ecaddG1BLSCircuit{}
	witness := ecaddG1BLSCircuit{
		X0:       sw_bls12381.NewG1Affine(P),
		X1:       sw_bls12381.NewG1Affine(Q),
		Expected: sw_bls12381.NewG1Affine(expected),
	}
	return &circuit, &witness
}

func TestECAddG1BLSCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddG1BLS()
	err := test.IsSolved(circuit, witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECAddG1BLSCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd()
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
}

// 12: G1 MSM
type ecmsmg1BLSCircuit struct {
	Accumulator [11]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Points      [10]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Scalars     [10]emulated.Element[emulated.BLS12381Fr]
}

func (c *ecmsmg1BLSCircuit) Define(api frontend.API) error {
	for i := range c.Points {
		if err := ECG1ScalarMulSumBLS(api, &c.Accumulator[i], &c.Points[i], &c.Scalars[i], &c.Accumulator[i+1]); err != nil {
			return fmt.Errorf("circuit %d: %w", i, err)
		}
	}
	return nil
}

func TestECMSMG1BLSCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	P := make([]bls12381.G1Affine, 10)
	S := make([]fr.Element, 10)
	for i := 0; i < 10; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var cP [10]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range cP {
		cP[i] = sw_bls12381.NewG1Affine(P[i])
	}
	var cS [10]emulated.Element[emulated.BLS12381Fr]
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}
	var cA [11]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	var zero bls12381.G1Affine
	zero.SetInfinity()
	cA[0] = sw_bls12381.NewG1Affine(zero)

	var res bls12381.G1Affine
	for i := range P {
		var tmp bls12381.G1Affine
		tmp.ScalarMultiplication(&P[i], S[i].BigInt(new(big.Int)))
		res.Add(&res, &tmp)
		cA[i+1] = sw_bls12381.NewG1Affine(res)
	}

	err := test.IsSolved(&ecmsmg1BLSCircuit{}, &ecmsmg1BLSCircuit{
		Accumulator: cA,
		Points:      cP,
		Scalars:     cS,
	}, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// 13: G2 Add
type ecaddG2BLSCircuit struct {
	X0       sw_bls12381.G2Affine
	X1       sw_bls12381.G2Affine
	Expected sw_bls12381.G2Affine
}

func (c *ecaddG2BLSCircuit) Define(api frontend.API) error {
	ECAddG2BLS(api, &c.X0, &c.X1, &c.Expected)
	return nil
}

func testRoutineECAddG2BLS() (circ, wit frontend.Circuit) {
	_, _, _, G := bls12381.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bls12381.G2Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bls12381.G2Affine
	expected.Add(&P, &Q)
	circuit := ecaddG2BLSCircuit{}
	witness := ecaddG2BLSCircuit{
		X0:       sw_bls12381.NewG2Affine(P),
		X1:       sw_bls12381.NewG2Affine(Q),
		Expected: sw_bls12381.NewG2Affine(expected),
	}
	return &circuit, &witness
}

func TestECAddG2BLSCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddG2BLS()
	err := test.IsSolved(circuit, witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECAddG2BLSCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddG2BLS()
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
}

// 14: G2 MSM
type ecmsmg2BLSCircuit struct {
	Accumulators [11]sw_bls12381.G2Affine
	Points       [10]sw_bls12381.G2Affine
	Scalars      [10]sw_bls12381.Scalar
}

func (c *ecmsmg2BLSCircuit) Define(api frontend.API) error {
	for i := range c.Points {
		if err := ECG2ScalarMulSumBLS(api, &c.Accumulators[i], &c.Points[i], &c.Scalars[i], &c.Accumulators[i+1]); err != nil {
			return fmt.Errorf("circuit %d: %w", i, err)
		}
	}
	return nil
}

func TestECMSMG2BLSCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	P := make([]bls12381.G2Affine, 10)
	S := make([]fr.Element, 10)
	for i := 0; i < 10; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var cP [10]sw_bls12381.G2Affine
	for i := range cP {
		cP[i] = sw_bls12381.NewG2Affine(P[i])
	}
	var cS [10]emulated.Element[emulated.BLS12381Fr]
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}
	var cA [11]sw_bls12381.G2Affine
	var zero bls12381.G2Affine
	zero.SetInfinity()
	cA[0] = sw_bls12381.NewG2Affine(zero)

	var res bls12381.G2Affine
	for i := range P {
		var tmp bls12381.G2Affine
		tmp.ScalarMultiplication(&P[i], S[i].BigInt(new(big.Int)))
		res.Add(&res, &tmp)
		cA[i+1] = sw_bls12381.NewG2Affine(res)
	}
	err := test.IsSolved(&ecmsmg2BLSCircuit{}, &ecmsmg2BLSCircuit{
		Accumulators: cA,
		Points:       cP,
		Scalars:      cS,
	}, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// 15: multi-pairing check
type ecPairBLSBatchCircuit struct {
	P  sw_bls12381.G1Affine
	NP sw_bls12381.G1Affine
	DP sw_bls12381.G1Affine
	Q  sw_bls12381.G2Affine
	n  int
}

func (c *ecPairBLSBatchCircuit) Define(api frontend.API) error {
	Q := make([]*sw_bls12381.G2Affine, c.n)
	for i := range Q {
		Q[i] = &c.Q
	}
	switch c.n {
	case 2:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP}, Q)
	case 3:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.NP, &c.NP, &c.DP}, Q)
	case 4:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP}, Q)
	case 5:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	case 6:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP}, Q)
	case 7:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	case 8:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP}, Q)
	case 9:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	default:
		return fmt.Errorf("not handled %d", c.n)
	}
	return nil
}

func TestECPairBLSBLSMulBatch(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p, q := bls12381.Generators()

	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()

	p.ScalarMultiplication(&p, u.BigInt(new(big.Int)))
	q.ScalarMultiplication(&q, v.BigInt(new(big.Int)))

	var dp, np bls12381.G1Affine
	dp.Double(&p)
	np.Neg(&p)

	for i := 2; i < 10; i++ {
		err := test.IsSolved(&ecPairBLSBatchCircuit{n: i}, &ecPairBLSBatchCircuit{
			n:  i,
			P:  sw_bls12381.NewG1Affine(p),
			NP: sw_bls12381.NewG1Affine(np),
			DP: sw_bls12381.NewG1Affine(dp),
			Q:  sw_bls12381.NewG2Affine(q),
		}, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
	}
}

type ecPairBLSSingleCircuit struct {
	P sw_bls12381.G1Affine
	Q sw_bls12381.G2Affine
}

func (c *ecPairBLSSingleCircuit) Define(api frontend.API) error {
	ECPairBLS(api, []*sw_bls12381.G1Affine{&c.P}, []*sw_bls12381.G2Affine{&c.Q})
	return nil
}

// a single pair is a valid input for the precompile. e(0, Q) == 1 so the check
// must pass for P at infinity, and fail for a non-trivial pair.
func TestECPairBLSSinglePair(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p, q := bls12381.Generators()
	var inf bls12381.G1Affine

	err := test.IsSolved(&ecPairBLSSingleCircuit{}, &ecPairBLSSingleCircuit{
		P: sw_bls12381.NewG1Affine(inf),
		Q: sw_bls12381.NewG2Affine(q),
	}, ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(&ecPairBLSSingleCircuit{}, &ecPairBLSSingleCircuit{
		P: sw_bls12381.NewG1Affine(p),
		Q: sw_bls12381.NewG2Affine(q),
	}, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

// 16: mapToG1 check
type eCMapToG1BLSCircuit struct {
	A emulated.Element[emulated.BLS12381Fp]
	R sw_bls12381.G1Affine
}

func (c *eCMapToG1BLSCircuit) Define(api frontend.API) error {
	return ECMapToG1BLS(api, &c.A, &c.R)
}

func TestECMapToG1(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToG1(a)

	witness := eCMapToG1BLSCircuit{
		A: emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		R: sw_bls12381.NewG1Affine(g),
	}

	err := test.IsSolved(&eCMapToG1BLSCircuit{}, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type ECMapToG2BLSCircuit struct {
	A fields_bls12381.E2
	R sw_bls12381.G2Affine
}

func (c *ECMapToG2BLSCircuit) Define(api frontend.API) error {
	return ECMapToG2BLS(api, &c.A, &c.R)
}

func TestECMapToG2(t *testing.T) {
	assert := test.NewAssert(t)
	var a bls12381.E2
	a.A0.SetRandom()
	a.A1.SetRandom()
	g := bls12381.MapToG2(a)

	witness := ECMapToG2BLSCircuit{
		A: fields_bls12381.FromE2(&a),
		R: sw_bls12381.NewG2Affine(g),
	}

	err := test.IsSolved(&ECMapToG2BLSCircuit{}, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}
