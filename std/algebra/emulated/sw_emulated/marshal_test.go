package sw_emulated

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// decomposeToLimbs returns the limb decomposition of v in the representation
// used by the emulated field T. Note that v is *not* reduced modulo the
// modulus of T -- this is on purpose, it allows building witnesses which are
// non-canonical representations of a field element (the limbs are only
// range-checked to T.BitsPerLimb(), so any representative which fits into
// T.NbLimbs()*T.BitsPerLimb() bits is accepted by the circuit).
func decomposeToLimbs[T emulated.FieldParams](v *big.Int) []frontend.Variable {
	var fp T
	nbLimbs := int(fp.NbLimbs())
	ls := make([]*big.Int, nbLimbs)
	for i := range ls {
		ls[i] = new(big.Int)
	}
	if err := limbs.Decompose(v, fp.BitsPerLimb(), ls); err != nil {
		panic(fmt.Sprintf("decompose: %v", err))
	}
	res := make([]frontend.Variable, nbLimbs)
	for i := range ls {
		res[i] = ls[i]
	}
	return res
}

// -----------------------------------------------------------------------------
// Canonical marshalling (item 1)
// -----------------------------------------------------------------------------

type marshalScalarCanonicalCircuit[B, S emulated.FieldParams] struct {
	Limbs1 []frontend.Variable
	Limbs2 []frontend.Variable
}

func (c *marshalScalarCanonicalCircuit[B, S]) Define(api frontend.API) error {
	cr, err := New[B, S](api, GetCurveParams[B]())
	if err != nil {
		return err
	}
	s1 := emulated.Element[S]{Limbs: c.Limbs1}
	s2 := emulated.Element[S]{Limbs: c.Limbs2}
	// the two elements are equal as field elements...
	cr.scalarApi.AssertIsEqual(&s1, &s2)
	// ... so they must have the same marshalling.
	b1 := cr.MarshalScalar(s1)
	b2 := cr.MarshalScalar(s2)
	if len(b1) != len(b2) {
		return fmt.Errorf("different bit lengths %d != %d", len(b1), len(b2))
	}
	for i := range b1 {
		api.AssertIsEqual(b1[i], b2[i])
	}
	return nil
}

type marshalG1CanonicalCircuit[B, S emulated.FieldParams] struct {
	X1 []frontend.Variable
	X2 []frontend.Variable
	Y  []frontend.Variable
}

func (c *marshalG1CanonicalCircuit[B, S]) Define(api frontend.API) error {
	cr, err := New[B, S](api, GetCurveParams[B]())
	if err != nil {
		return err
	}
	p1 := AffinePoint[B]{X: emulated.Element[B]{Limbs: c.X1}, Y: emulated.Element[B]{Limbs: c.Y}}
	p2 := AffinePoint[B]{X: emulated.Element[B]{Limbs: c.X2}, Y: emulated.Element[B]{Limbs: c.Y}}
	// the two points are equal as curve points...
	cr.AssertIsEqual(&p1, &p2)
	// ... so they must have the same marshalling.
	b1 := cr.MarshalG1(p1)
	b2 := cr.MarshalG1(p2)
	if len(b1) != len(b2) {
		return fmt.Errorf("different bit lengths %d != %d", len(b1), len(b2))
	}
	for i := range b1 {
		api.AssertIsEqual(b1[i], b2[i])
	}
	return nil
}

// TestMarshalIsCanonical checks that two different limb representations of the
// same field element marshal to the same bit string. This is what the
// Fiat-Shamir transcript depends on: MarshalScalar/MarshalG1 feed the
// transcript hash, so a prover able to pick between several accepted
// encodings of the same value can grind the challenge.
func TestMarshalIsCanonical(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		var fr emparams.BN254Fr
		r := fr.Modulus()
		v := big.NewInt(5)
		vPlusR := new(big.Int).Add(v, r)

		circuit := &marshalScalarCanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			Limbs1: make([]frontend.Variable, fr.NbLimbs()),
			Limbs2: make([]frontend.Variable, fr.NbLimbs()),
		}
		witness := &marshalScalarCanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			Limbs1: decomposeToLimbs[emparams.BN254Fr](v),
			Limbs2: decomposeToLimbs[emparams.BN254Fr](vPlusR),
		}
		err := test.IsSolved(circuit, witness, testCurve.ScalarField())
		assert.NoError(err)
	}, "scalar")

	assert.Run(func(assert *test.Assert) {
		var fp emparams.BN254Fp
		p := fp.Modulus()
		x := big.NewInt(5)
		xPlusP := new(big.Int).Add(x, p)

		circuit := &marshalG1CanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			X1: make([]frontend.Variable, fp.NbLimbs()),
			X2: make([]frontend.Variable, fp.NbLimbs()),
			Y:  make([]frontend.Variable, fp.NbLimbs()),
		}
		witness := &marshalG1CanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			X1: decomposeToLimbs[emparams.BN254Fp](x),
			X2: decomposeToLimbs[emparams.BN254Fp](xPlusP),
			Y:  decomposeToLimbs[emparams.BN254Fp](big.NewInt(7)),
		}
		err := test.IsSolved(circuit, witness, testCurve.ScalarField())
		assert.NoError(err)
	}, "g1")
}
