package sw_bw6761

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type mulG2Circuit struct {
	In, Res G2Affine
	S       Scalar

	incompleteArithmetic bool
}

func (c *mulG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	opts := []algopts.AlgebraOption{}
	if c.incompleteArithmetic {
		opts = append(opts, algopts.WithIncompleteArithmetic())
	}
	res := g2.ScalarMul(&c.In, &c.S, opts...)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2EdgeCases(t *testing.T) {
	_, _, _, gen := bw6761.Generators()
	var zero, negGen, sevenGen bw6761.G2Affine
	negGen.Neg(&gen)
	sevenGen.ScalarMultiplication(&gen, big.NewInt(7))

	testCases := []struct {
		name                 string
		point                bw6761.G2Affine
		scalar               *big.Int
		expected             bw6761.G2Affine
		incompleteArithmetic bool
	}{
		{name: "zero-scalar", point: gen, scalar: big.NewInt(0), expected: zero},
		{name: "one", point: gen, scalar: big.NewInt(1), expected: gen},
		{name: "minus-one", point: gen, scalar: big.NewInt(-1), expected: negGen},
		{name: "zero-point", point: zero, scalar: big.NewInt(7), expected: zero},
		{name: "incomplete-option", point: gen, scalar: big.NewInt(7), expected: sevenGen, incompleteArithmetic: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := mulG2Circuit{
				incompleteArithmetic: tc.incompleteArithmetic,
			}
			witness := mulG2Circuit{
				In:                   NewG2Affine(tc.point),
				S:                    emulated.ValueOf[ScalarField](tc.scalar),
				Res:                  NewG2Affine(tc.expected),
				incompleteArithmetic: tc.incompleteArithmetic,
			}
			err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
			assert.NoError(err)
		})
	}
}

// TestScalarMulG2ClassicGLVSound checks that G2 ScalarMul — now routed through
// classic GLV, which *computes* the output rather than hinting it — is sound
// against the cofactor-torsion forgery: the honest result solves, and a
// torsion-shifted output (the forgery the old [c]S == R binding guarded against)
// is rejected, because the computed output is always the true in-subgroup point.
func TestScalarMulG2ClassicGLVSound(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, _, gen := bw6761.Generators()
	var pt, res bw6761.G2Affine
	pt.ScalarMultiplication(&gen, big.NewInt(12345)) // in-subgroup base
	res.ScalarMultiplication(&pt, big.NewInt(7))     // [7]pt

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mulG2Circuit{})
	assert.NoError(err)

	// honest output -> solves
	w := &mulG2Circuit{In: NewG2Affine(pt), S: emulated.ValueOf[ScalarField](7), Res: NewG2Affine(res)}
	fullw, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	assert.NoError(err)
	assert.NoError(ccs.IsSolved(fullw), "honest scalar-mul must solve")

	// torsion-shifted output [7]pt + T (T = order-3 point (0,2)) must be rejected:
	// classic GLV computes the true [7]pt ∈ G2, so it never equals [7]pt + T.
	var T, t3, tampered bw6761.G2Affine
	T.X.SetZero()
	T.Y.SetUint64(2) // (0,2): on y² = x³ + 4
	t3.ScalarMultiplication(&T, big.NewInt(3))
	assert.True(T.IsOnCurve() && !T.IsInfinity() && t3.IsInfinity(), "T must be a nonzero order-3 cofactor point")
	tampered.Add(&res, &T)
	assert.False(tampered.Equal(&res), "torsion-shifted output must differ from the true result")
	wBad := &mulG2Circuit{In: NewG2Affine(pt), S: emulated.ValueOf[ScalarField](7), Res: NewG2Affine(tampered)}
	fullwBad, err := frontend.NewWitness(wBad, ecc.BN254.ScalarField())
	assert.NoError(err)
	assert.Error(ccs.IsSolved(fullwBad), "a torsion-shifted output must be rejected")
}
