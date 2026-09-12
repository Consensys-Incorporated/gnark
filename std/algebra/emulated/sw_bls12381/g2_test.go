package sw_bls12381

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type mulG2Circuit struct {
	In, Res G2Affine
	S       Scalar

	incompleteArithmetic bool
	skipGeneric          bool
}

func (c *mulG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	opts := []algopts.AlgebraOption{}
	if c.incompleteArithmetic {
		opts = append(opts, algopts.WithIncompleteArithmetic())
	}
	res1 := g2.ScalarMul(&c.In, &c.S, opts...)
	g2.AssertIsEqual(res1, &c.Res)
	if !c.skipGeneric {
		res2 := g2.scalarMulGeneric(&c.In, &c.S)
		g2.AssertIsEqual(res2, &c.Res)
	}
	return nil
}

func TestScalarMulG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr_bls12381.Element
	_, _ = r.SetRandom()
	s := new(big.Int)
	r.BigInt(s)
	var res bls12381.G2Affine
	_, _, _, gen := bls12381.Generators()
	res.ScalarMultiplication(&gen, s)

	witness := mulG2Circuit{
		In:  NewG2Affine(gen),
		S:   NewScalar(r),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&mulG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestScalarMulG2EdgeCases(t *testing.T) {
	_, _, _, gen := bls12381.Generators()
	var zero, negGen, sevenGen bls12381.G2Affine
	negGen.Neg(&gen)
	sevenGen.ScalarMultiplication(&gen, big.NewInt(7))

	testCases := []struct {
		name                 string
		point                bls12381.G2Affine
		scalar               *big.Int
		expected             bls12381.G2Affine
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
				skipGeneric:          true,
			}
			witness := mulG2Circuit{
				In:                   NewG2Affine(tc.point),
				S:                    emulated.ValueOf[ScalarField](tc.scalar),
				Res:                  NewG2Affine(tc.expected),
				incompleteArithmetic: tc.incompleteArithmetic,
				skipGeneric:          true,
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
		return fmt.Errorf("new G2 struct: %w", err)
	}
	P := G2Affine{P: g2AffP{
		X: fields_bls12381.E2{
			A0: emulated.ValueOf[BaseField](c.px0),
			A1: emulated.ValueOf[BaseField](c.px1),
		},
		Y: fields_bls12381.E2{
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
	_, _, _, gen := bls12381.Generators()
	var P bls12381.G2Affine
	P.ScalarMultiplication(&gen, big.NewInt(12345))
	px0, px1 := P.X.A0.BigInt(new(big.Int)), P.X.A1.BigInt(new(big.Int))
	py0, py1 := P.Y.A0.BigInt(new(big.Int)), P.Y.A1.BigInt(new(big.Int))
	r := fr_bls12381.Modulus()
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
		var S bls12381.G2Affine
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

type addG2Circuit struct {
	In1, In2   G2Affine
	Res        G2Affine
	unifiedAdd bool // if true, use the unified addition method
}

func (c *addG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	var res *G2Affine
	if c.unifiedAdd {
		res = g2.AddUnified(&c.In1, &c.In2)
	} else {
		res = g2.add(&c.In1, &c.In2)
	}
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Add(&in1, &in2)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{unifiedAdd: false}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err, "expected success for random inputs")
}

func TestAddG2FailureCaseTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Double(&in1)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{unifiedAdd: false}, &witness, ecc.BN254.ScalarField())
	// the add() function cannot handle identical inputs
	assert.Error(err, "expected solver error for identical inputs")
}

func TestAddG2UnifiedTestSolveAdd(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Add(&in1, &in2)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in2),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestAddG2UnifiedTestSolveDbl(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Double(&in1)
	witness := addG2Circuit{
		In1: NewG2Affine(in1),
		In2: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestAddG2UnifiedTestSolveEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	_, p := randomG1G2Affines()
	var np, zero bls12381.G2Affine
	np.Neg(&p)
	zero.Sub(&p, &p)

	assert.Run(func(assert *test.Assert) {
		// p + (-p) == (0, 0)
		witness := addG2Circuit{
			In1: NewG2Affine(p),
			In2: NewG2Affine(np),
			Res: NewG2Affine(zero),
		}
		err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=inverse")

	assert.Run(func(assert *test.Assert) {
		// (-p) + p == (0, 0)
		witness2 := addG2Circuit{
			In1: NewG2Affine(np),
			In2: NewG2Affine(p),
			Res: NewG2Affine(zero),
		}
		err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness2, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=inverse2")

	assert.Run(func(assert *test.Assert) {
		// p + (0, 0) == p
		witness3 := addG2Circuit{
			In1: NewG2Affine(p),
			In2: NewG2Affine(zero),
			Res: NewG2Affine(p),
		}
		err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness3, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=zero")

	assert.Run(func(assert *test.Assert) {
		// (0, 0) + p == p
		witness4 := addG2Circuit{
			In1: NewG2Affine(zero),
			In2: NewG2Affine(p),
			Res: NewG2Affine(p),
		}
		err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness4, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=zero2")

	assert.Run(func(assert *test.Assert) {
		// (0, 0) + (0, 0) == (0, 0)
		witness5 := addG2Circuit{
			In1: NewG2Affine(zero),
			In2: NewG2Affine(zero),
			Res: NewG2Affine(zero),
		}
		err5 := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness5, ecc.BN254.ScalarField())
		assert.NoError(err5)
	}, "case=zero3")

	assert.Run(func(assert *test.Assert) {
		// j=0 cube-root edge case: Q = (ω²·P.X, -P.Y) with ω cube root of
		// unity ∈ Fp ⊂ Fp². Then y_P + y_Q = 0, P ≠ -Q (since ω² ≠ 1), and
		// the correct sum is finite. The old Brier–Joye AddUnified returned
		// ([0,0],[0,0]) — soundness break.
		var omegaSq fp.Element
		omegaSq.SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
		omegaSq.Square(&omegaSq)
		var Q bls12381.G2Affine
		Q.X.A0.Mul(&p.X.A0, &omegaSq)
		Q.X.A1.Mul(&p.X.A1, &omegaSq)
		Q.Y.A0.Neg(&p.Y.A0)
		Q.Y.A1.Neg(&p.Y.A1)
		var R bls12381.G2Affine
		R.Add(&p, &Q)
		assert.False(R.IsInfinity(), "expected finite sum")
		witness := addG2Circuit{
			In1: NewG2Affine(p),
			In2: NewG2Affine(Q),
			Res: NewG2Affine(R),
		}
		err := test.IsSolved(&addG2Circuit{unifiedAdd: true}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}, "case=cubeRoot")

}

type doubleG2Circuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *doubleG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.double(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	var in1Jac, resJac bls12381.G2Jac
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
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.doubleAndAdd(&c.In1, &c.In2)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoubleAndAddG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bls12381.G2Affine
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

type scalarMulG2BySeedCircuit struct {
	In1 G2Affine
	Res G2Affine
}

func (c *scalarMulG2BySeedCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.scalarMulBySeed(&c.In1)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2BySeedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in1 := randomG1G2Affines()
	var res bls12381.G2Affine
	x0, _ := new(big.Int).SetString("15132376222941642752", 10)
	res.ScalarMultiplication(&in1, x0).Neg(&res)
	witness := scalarMulG2BySeedCircuit{
		In1: NewG2Affine(in1),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2BySeedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiScalarMulTest struct {
	Points  []G2Affine
	Scalars []Scalar
	Res     G2Affine
}

func (c *MultiScalarMulTest) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	ps := make([]*G2Affine, len(c.Points))
	for i := range c.Points {
		ps[i] = &c.Points[i]
	}
	ss := make([]*Scalar, len(c.Scalars))
	for i := range c.Scalars {
		ss[i] = &c.Scalars[i]
	}
	res, err := g2.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]bls12381.G2Affine, nbLen)
	S := make([]fr_bls12381.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res bls12381.G2Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]G2Affine, len(P))
	for i := range cP {
		cP[i] = G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](P[i].X.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](P[i].X.A1)},
				Y: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](P[i].Y.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](P[i].Y.A1)},
			},
			Lines: nil,
		}
	}
	cS := make([]Scalar, len(S))
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}
	assignment := MultiScalarMulTest{
		Points:  cP,
		Scalars: cS,
		Res: G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](res.X.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](res.X.A1)},
				Y: fields_bls12381.E2{A0: emulated.ValueOf[emulated.BLS12381Fp](res.Y.A0), A1: emulated.ValueOf[emulated.BLS12381Fp](res.Y.A1)},
			},
			Lines: nil,
		},
	}
	err = test.IsSolved(&MultiScalarMulTest{
		Points:  make([]G2Affine, nbLen),
		Scalars: make([]Scalar, nbLen),
	}, &assignment, ecc.BN254.ScalarField())
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
		var Q bls12381.G2Affine
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

	_, _, _, gen := bls12381.Generators()
	var pt, res bls12381.G2Affine
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
