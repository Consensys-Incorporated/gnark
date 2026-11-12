package sw_bls12377

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func randomG1G2Affines() (bls12377.G1Affine, bls12377.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls12377.Generators()
	mod := bls12377.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bls12377.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bls12377.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type MuxG1CircuitTest struct {
	Selector frontend.Variable
	Inputs   [8]G1Affine
	Expected G1Affine
}

func (c *MuxG1CircuitTest) Define(api frontend.API) error {
	cr, err := NewCurve(api)
	if err != nil {
		return err
	}
	els := make([]*G1Affine, len(c.Inputs))
	for i := range c.Inputs {
		els[i] = &c.Inputs[i]
	}
	res := cr.Mux(c.Selector, els...)
	cr.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMuxG1(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MuxG1CircuitTest{}
	r := make([]fr_bls12377.Element, len(circuit.Inputs))
	for i := range r {
		r[i].SetRandom()
	}
	selector, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r))))
	expectedR := r[selector.Int64()]
	expected := new(bls12377.G1Affine).ScalarMultiplicationBase(expectedR.BigInt(new(big.Int)))
	witness := MuxG1CircuitTest{
		Selector: selector,
		Expected: NewG1Affine(*expected),
	}
	for i := range r {
		eli := new(bls12377.G1Affine).ScalarMultiplicationBase(r[i].BigInt(new(big.Int)))
		witness.Inputs[i] = NewG1Affine(*eli)
	}
	err := test.IsSolved(&circuit, &witness, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

type MuxG2GtCircuit struct {
	InG2       []G2Affine
	InGt       []GT
	SelG2      frontend.Variable
	SelGt      frontend.Variable
	ExpectedG2 G2Affine
	ExpectedGt GT
}

func (c *MuxG2GtCircuit) Define(api frontend.API) error {
	pairing := NewPairing(api)
	var inG2 []*G2Affine
	for i := range c.InG2 {
		inG2 = append(inG2, &c.InG2[i])
	}
	var inGt []*GT
	for i := range c.InGt {
		inGt = append(inGt, &c.InGt[i])
	}
	g2 := pairing.MuxG2(c.SelG2, inG2...)
	gt := pairing.MuxGt(c.SelGt, inGt...)
	if len(c.InG2) == 0 {
		if g2 != nil {
			return fmt.Errorf("mux G2: expected nil, got %v", g2)
		}
	} else {
		c.ExpectedG2.P.AssertIsEqual(api, g2.P)
	}
	if len(c.InGt) == 0 {
		if gt != nil {
			return fmt.Errorf("mux Gt: expected nil, got %v", gt)
		}
	} else {
		pairing.AssertIsEqual(gt, &c.ExpectedGt)
	}
	return nil
}

func TestPairingMuxes(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	for _, nbPairs := range []int{0, 1, 2, 3, 4, 5} {
		assert.Run(func(assert *test.Assert) {
			g2s := make([]bls12377.G2Affine, nbPairs)
			gts := make([]bls12377.GT, nbPairs)
			var p bls12377.G1Affine
			witG2s := make([]G2Affine, nbPairs)
			witGts := make([]GT, nbPairs)
			for i := range nbPairs {
				p, g2s[i] = randomG1G2Affines()
				gts[i], err = bls12377.Pair([]bls12377.G1Affine{p}, []bls12377.G2Affine{g2s[i]})
				assert.NoError(err)
				witG2s[i] = NewG2Affine(g2s[i])
				witGts[i] = NewGTEl(gts[i])
			}
			circuit := MuxG2GtCircuit{InG2: make([]G2Affine, nbPairs), InGt: make([]GT, nbPairs)}
			var witness MuxG2GtCircuit
			if nbPairs > 0 {
				selG2, err := rand.Int(rand.Reader, big.NewInt(int64(nbPairs)))
				assert.NoError(err)
				selGt, err := rand.Int(rand.Reader, big.NewInt(int64(nbPairs)))
				assert.NoError(err)
				expectedG2 := witG2s[selG2.Int64()]
				expectedGt := witGts[selGt.Int64()]
				witness = MuxG2GtCircuit{
					InG2:       witG2s,
					InGt:       witGts,
					SelG2:      selG2,
					SelGt:      selGt,
					ExpectedG2: expectedG2,
					ExpectedGt: expectedGt,
				}
			} else {
				witness = MuxG2GtCircuit{
					InG2:       witG2s,
					InGt:       witGts,
					SelG2:      big.NewInt(0),
					SelGt:      big.NewInt(0),
					ExpectedG2: NewG2Affine(bls12377.G2Affine{}),
					ExpectedGt: NewGTEl(bls12377.GT{}),
				}
			}
			err = test.IsSolved(&circuit, &witness, ecc.BW6_761.ScalarField())
			assert.NoError(err)
		}, fmt.Sprintf("nbPairs=%d", nbPairs))
	}
}

type assertIsOnG1InfinityCircuit struct {
	P G1Affine
}

func (c *assertIsOnG1InfinityCircuit) Define(api frontend.API) error {
	pr := NewPairing(api)
	pr.AssertIsOnG1(&c.P)
	return nil
}

func TestAssertIsOnG1Infinity(t *testing.T) {
	assert := test.NewAssert(t)
	var inf bls12377.G1Affine
	_, _, g1, _ := bls12377.Generators()
	assert.CheckCircuit(&assertIsOnG1InfinityCircuit{},
		test.WithValidAssignment(&assertIsOnG1InfinityCircuit{P: NewG1Affine(inf)}),
		test.WithValidAssignment(&assertIsOnG1InfinityCircuit{P: NewG1Affine(g1)}),
		// (0,1) is on the curve but has order 3, so it is not in G1.
		test.WithInvalidAssignment(&assertIsOnG1InfinityCircuit{P: G1Affine{X: 0, Y: 1}}),
		// (1,0) is not on the curve.
		test.WithInvalidAssignment(&assertIsOnG1InfinityCircuit{P: G1Affine{X: 1, Y: 0}}),
		// only one coordinate is zero, so this is not the point at infinity.
		test.WithInvalidAssignment(&assertIsOnG1InfinityCircuit{P: G1Affine{X: 0, Y: 2}}),
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16, backend.PLONK))
}
