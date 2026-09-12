package maptocurve_increment

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const (
	// T is the increment window size: K is searched in [0, T).
	T = 256
	// B is the curve coefficient: BLS12-377 is y² = x³ + 1.
	B = 1
)

// YIncrement maps msg to a point (x, y) on the BLS12-377 curve y² = x³ + 1
// using the y-increment method:
//
//	Y = msg·256 + K, Y² = X³ + 1
//
// Caller-side precondition: msg < q/256. The precondition is NOT enforced
// in-circuit — see the package doc.
func YIncrement(api frontend.API, msg frontend.Variable) (x, y frontend.Variable, err error) {
	// hint outputs: [K, X]
	res, err := api.Compiler().NewHint(yIncrementHint, 2, msg)
	if err != nil {
		return nil, nil, err
	}
	k := res[0]
	x = res[1]

	// reconstruct Y = msg·T + K
	y = api.Add(api.Mul(msg, T), k)

	// (1) Y² = X³ + B
	lhs := api.Mul(y, y)
	rhs := api.Mul(x, x)
	rhs = api.Mul(rhs, x)
	rhs = api.Add(rhs, B)
	api.AssertIsEqual(lhs, rhs)

	// (2) 0 ≤ K < T
	rangecheck.New(api).Check(k, 8)

	return x, y, nil
}
