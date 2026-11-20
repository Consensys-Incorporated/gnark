package emulated

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/test"
)

// expNonCanonicalCircuit computes Base^Exp where the exponent is given as raw
// limbs. This allows assigning a non-canonical representative (e+p) of the
// exponent e, which a plain ValueOf never produces.
type expNonCanonicalCircuit[T FieldParams] struct {
	Base     Element[T]
	ExpLimbs []frontend.Variable
	Expected Element[T]
}

func (c *expNonCanonicalCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	exp := f.newInternalElement(c.ExpLimbs, 0)
	res := f.Exp(&c.Base, exp)
	f.AssertIsEqual(&c.Expected, res)
	return nil
}

// testExpNonCanonicalExponent is a regression test for the malleability
// described in #1148: Exp(a, e) and Exp(a, e+p) must be the same value, since
// e and e+p are the same field element. Exp must reduce the exponent strictly
// before decomposing it into bits.
func testExpNonCanonicalExponent[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		p := fp.Modulus()
		base := big.NewInt(7)
		// e is small so that e+p still fits into NbLimbs limbs of BitsPerLimb bits.
		for _, e := range []int64{0, 1, 5} {
			exp := big.NewInt(e)
			nonCanonical := new(big.Int).Add(exp, p)
			expLimbs := make([]*big.Int, int(fp.NbLimbs()))
			for i := range expLimbs {
				expLimbs[i] = new(big.Int)
			}
			err := limbs.Decompose(nonCanonical, fp.BitsPerLimb(), expLimbs)
			assert.NoError(err)

			circuit := &expNonCanonicalCircuit[T]{ExpLimbs: make([]frontend.Variable, int(fp.NbLimbs()))}
			witness := &expNonCanonicalCircuit[T]{
				Base:     ValueOf[T](base),
				ExpLimbs: make([]frontend.Variable, int(fp.NbLimbs())),
				Expected: ValueOf[T](new(big.Int).Exp(base, exp, p)),
			}
			for i := range expLimbs {
				witness.ExpLimbs[i] = expLimbs[i]
			}
			assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
		}
	}, testName[T]())
}

func TestExpNonCanonicalExponent(t *testing.T) {
	testExpNonCanonicalExponent[Goldilocks](t)
	testExpNonCanonicalExponent[BN254Fr](t)
}
