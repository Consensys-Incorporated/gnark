package maptocurve_increment

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type yIncrementCircuit struct {
	M    frontend.Variable
	X, Y frontend.Variable // expected honest map-to-curve point
}

func (c *yIncrementCircuit) Define(api frontend.API) error {
	x, y, err := YIncrement(api, c.M)
	if err != nil {
		return err
	}
	// correctness: the computed point must match the honest reference point.
	api.AssertIsEqual(x, c.X)
	api.AssertIsEqual(y, c.Y)
	return nil
}

// expectedYIncrement runs the honest reference search out-of-circuit and
// returns the resulting point (x, y), with Y = msg·T + K mod q reconstructed
// exactly as the in-circuit gadget does.
func expectedYIncrement(t *testing.T, msg, q *big.Int) (x, y *big.Int) {
	t.Helper()
	outputs := []*big.Int{new(big.Int), new(big.Int)}
	if err := yIncrementHint(nil, []*big.Int{msg}, outputs); err != nil {
		t.Fatalf("reference y-increment search: %v", err)
	}
	x = outputs[1]
	y = new(big.Int).Mul(msg, big.NewInt(T))
	y.Add(y, outputs[0])
	y.Mod(y, q)
	return x, y
}

func TestYIncrement(t *testing.T) {
	assert := test.NewAssert(t)

	q := bls12377fp.Modulus()
	// largest message with the documented 8-bit headroom (bitlen(q)−8 bits).
	maxSafe := new(big.Int).Lsh(big.NewInt(1), uint(q.BitLen()-8))
	maxSafe.Sub(maxSafe, big.NewInt(1))

	msgs := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(42),
		big.NewInt(123456789),
		maxSafe,
	}

	opts := []test.TestingOption{test.WithCurves(ecc.BW6_761)}
	for _, msg := range msgs {
		x, y := expectedYIncrement(t, msg, q)
		opts = append(opts, test.WithValidAssignment(&yIncrementCircuit{M: msg, X: x, Y: y}))
	}

	assert.CheckCircuit(&yIncrementCircuit{}, opts...)
}
