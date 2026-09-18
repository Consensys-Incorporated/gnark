package sw_bn254

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type addG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *addG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.add(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Add(&in1, &in2)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type doubleG2Circuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *doubleG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.double(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	var in1Jac, resJac bn254.G2Jac
	in1Jac.FromAffine(&in1)
	resJac.Double(&in1Jac)
	res.FromJacobian(&resJac)
	witness := doubleG2Circuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&doubleG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type doubleAndAddG2Circuit struct {
	In1, In2 G2Affine
	Res      G2Affine
}

func (c *doubleAndAddG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.doubleAndAdd(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleAndAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Double(&in1).
		Add(&res, &in2)
	witness := doubleAndAddG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&doubleAndAddG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

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
	_, _, _, gen := bn254.Generators()
	var zero, negGen, sevenGen bn254.G2Affine
	negGen.Neg(&gen)
	sevenGen.ScalarMultiplication(&gen, big.NewInt(7))

	testCases := []struct {
		name                 string
		point                bn254.G2Affine
		scalar               *big.Int
		expected             bn254.G2Affine
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

type scalarMulConstG2Circuit struct {
	S   Scalar
	Res G2Affine

	px0, px1 *big.Int
	py0, py1 *big.Int
}

func (c *scalarMulConstG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	P := G2Affine{P: g2AffP{
		X: fields_bn254.E2{
			A0: emulated.ValueOf[BaseField](c.px0),
			A1: emulated.ValueOf[BaseField](c.px1),
		},
		Y: fields_bn254.E2{
			A0: emulated.ValueOf[BaseField](c.py0),
			A1: emulated.ValueOf[BaseField](c.py1),
		},
	}}
	res := g2.ScalarMul(&P, &c.S)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulConstG2Comb(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, _, gen := bn254.Generators()
	var P bn254.G2Affine
	P.ScalarMultiplication(&gen, big.NewInt(12345))
	px0, px1 := P.X.A0.BigInt(new(big.Int)), P.X.A1.BigInt(new(big.Int))
	py0, py1 := P.Y.A0.BigInt(new(big.Int)), P.Y.A1.BigInt(new(big.Int))
	r := fr_bn.Modulus()
	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Sub(r, big.NewInt(1)),
		new(big.Int).Sub(r, big.NewInt(2)),
		new(big.Int).Lsh(big.NewInt(1), 128),
	}
	for _, s := range scalars {
		var S bn254.G2Affine
		S.ScalarMultiplication(&P, s)
		circuit := scalarMulConstG2Circuit{px0: px0, px1: px1, py0: py0, py1: py1}
		witness := scalarMulConstG2Circuit{
			px0: px0, px1: px1, py0: py0, py1: py1,
			S:   emulated.ValueOf[ScalarField](s),
			Res: NewG2Affine(S),
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "s=%s", s.String())
	}
}

type scalarMulG2BySeedCircuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *scalarMulG2BySeedCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res := g2.scalarMulBySeed(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2BySeedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	x0, _ := new(big.Int).SetString("4965661367192848881", 10)
	res.ScalarMultiplication(&in1, x0)
	witness := scalarMulG2BySeedCircuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2BySeedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type endomorphismG2Circuit struct {
	In1 G2Affine
}

func (c *endomorphismG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		panic(err)
	}
	res1 := g2.phi(&c.In1)
	res2 := g2.psi(&c.In1)
	res2 = g2.psi(res2)
	g2.AssertIsEqual(res1, res2)
	return nil
}

func TestEndomorphismG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	witness := endomorphismG2Circuit{
		In1: NewG2Affine(in1),
	}
	err := test.IsSolved(&endomorphismG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// bogusG2PreimageHint returns [2·s·c⁻¹ mod r]·Q instead of [s·c⁻¹ mod r]·Q — an
// on-curve point that is NOT a preimage of R = [s]Q under [c]. It passes the
// on-curve assertion but must fail the [c]S == R check, proving the subgroup
// binding is live and load-bearing (not vacuous).
func bogusG2PreimageHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		cInv := new(big.Int).ModInverse(g2CofactorClearingConstant, scalarModulus)
		if cInv == nil {
			return fmt.Errorf("not invertible")
		}
		m := new(big.Int).Mul(scalarInputs[0], cInv)
		m.Mul(m, big.NewInt(2)) // tamper: doubles the preimage
		m.Mod(m, scalarModulus)
		var Q bn254.G2Affine
		Q.X.A0.SetBigInt(baseInputs[0])
		Q.X.A1.SetBigInt(baseInputs[1])
		Q.Y.A0.SetBigInt(baseInputs[2])
		Q.Y.A1.SetBigInt(baseInputs[3])
		Q.ScalarMultiplication(&Q, m)
		Q.X.A0.BigInt(baseOutputs[0])
		Q.X.A1.BigInt(baseOutputs[1])
		Q.Y.A0.BigInt(baseOutputs[2])
		Q.Y.A1.BigInt(baseOutputs[3])
		return nil
	})
}

// TestScalarMulG2SubgroupBindingLive checks that the [c]S == R subgroup binding
// (cofactor-torsion fix) is enforced: honest preimage solves; a wrong-but-on-curve
// preimage is rejected.
func TestScalarMulG2SubgroupBindingLive(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, _, gen := bn254.Generators()
	var pt, res bn254.G2Affine
	pt.ScalarMultiplication(&gen, big.NewInt(12345))
	res.ScalarMultiplication(&pt, big.NewInt(7))

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mulG2Circuit{})
	assert.NoError(err)

	w := &mulG2Circuit{
		In:  NewG2Affine(pt),
		S:   emulated.ValueOf[ScalarField](7),
		Res: NewG2Affine(res),
	}
	fullw, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.NoError(ccs.IsSolved(fullw), "honest scalar-mul must solve")

	err = ccs.IsSolved(fullw, solver.OverrideHint(solver.GetHintID(scalarMulG2CofactorPreimageHint), bogusG2PreimageHint))
	assert.Error(err, "a preimage that does not satisfy [c]S == R must be rejected")
}
