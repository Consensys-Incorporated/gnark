package sw_bw6761

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type assertIsOnG2Circuit struct{ Q G2Affine }

func (c *assertIsOnG2Circuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG2(&c.Q)
	return nil
}

// mulNaiveG2 is a plain double-and-add, independent of gnark-crypto's
// endomorphism-based shortcuts, used as ground truth for [r]Q == O.
func mulNaiveG2(P *bw6761.G2Affine, k *big.Int) bw6761.G2Jac {
	var acc, base bw6761.G2Jac
	base.FromAffine(P)
	acc.X.SetOne()
	acc.Y.SetOne() // Z = 0: infinity
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc.DoubleAssign()
		if k.Bit(i) == 1 {
			acc.AddAssign(&base)
		}
	}
	return acc
}

// TestAssertIsOnG2Torsion is a regression test for AssertIsOnG2 using the
// relation [x₀+1]Q + [x₀³−x₀²+1]ϕ(Q) = O, which has norm 3r and also holds on
// the rational 3-torsion (0, ±2) of y² = x³ + 4: a point of G2 shifted by it
// used to be accepted.
func TestAssertIsOnG2Torsion(t *testing.T) {
	assert := test.NewAssert(t)
	r := fr.Modulus()
	solve := func(P bw6761.G2Affine) error {
		return test.IsSolved(&assertIsOnG2Circuit{}, &assertIsOnG2Circuit{Q: NewG2Affine(P)}, ecc.BN254.ScalarField())
	}
	inG2 := func(P bw6761.G2Affine) bool {
		rp := mulNaiveG2(&P, r)
		return rp.Z.IsZero()
	}

	_, _, _, gen := bw6761.Generators()
	for _, k := range []int64{1, 5, 123456789} {
		var P bw6761.G2Affine
		P.ScalarMultiplication(&gen, big.NewInt(k))
		assert.True(inG2(P))
		assert.NoError(solve(P), "[%d]g2 must be accepted", k)
	}
	var Pr bw6761.G2Affine
	Pr.ScalarMultiplication(&gen, new(big.Int).SetBytes([]byte("random-looking scalar for G2 membership")))
	assert.NoError(solve(Pr), "random G2 point must be accepted")

	var T, g5, shifted bw6761.G2Affine
	T.Y.SetUint64(2) // (0, 2): order 3 on y² = x³ + 4
	g5.ScalarMultiplication(&gen, big.NewInt(5))
	shifted.Add(&g5, &T)
	assert.True(T.IsOnCurve() && shifted.IsOnCurve())
	assert.False(inG2(T))
	assert.False(inG2(shifted))
	assert.Error(solve(T), "order-3 point must be rejected")
	assert.Error(solve(shifted), "[5]g2 + (0,2) must be rejected")
	var Tm bw6761.G2Affine
	Tm.Neg(&T)
	shifted.Add(&g5, &Tm)
	assert.Error(solve(shifted), "[5]g2 + (0,-2) must be rejected")

	// a generic on-curve point outside G2
	for x := uint64(1); ; x++ {
		var X, y2, Y fp.Element
		X.SetUint64(x)
		y2.Square(&X).Mul(&y2, &X).Add(&y2, new(fp.Element).SetUint64(4))
		if y2.Legendre() != 1 {
			continue
		}
		Y.Sqrt(&y2)
		P := bw6761.G2Affine{X: X, Y: Y}
		if inG2(P) {
			continue
		}
		assert.Error(solve(P), "off-subgroup point must be rejected")
		break
	}
}

// TestScalarMulG2OffSubgroupInput is a regression test for G2.ScalarMul
// (classic GLV) accepting a twist point outside G2: with honest hints it
// computes [s1]Q + [s2]ϕ(Q), which differs from [s]Q off G2, and that value
// used to satisfy ScalarMul(Q, s) == R.
func TestScalarMulG2OffSubgroupInput(t *testing.T) {
	assert := test.NewAssert(t)
	params := bw6761G2ClassicParams
	// a generic on-curve point outside G2 (a pure 3-torsion shift does not
	// separate the two values: ϕ fixes (0, ±2))
	var Q bw6761.G2Affine
	for x := uint64(1); ; x++ {
		var X, y2 fp.Element
		X.SetUint64(x)
		y2.Square(&X).Mul(&y2, &X).Add(&y2, new(fp.Element).SetUint64(4))
		if y2.Legendre() != 1 {
			continue
		}
		Q.X = X
		Q.Y.Sqrt(&y2)
		if rq := mulNaiveG2(&Q, fr.Modulus()); !rq.Z.IsZero() {
			break
		}
	}

	s := new(big.Int).SetBytes([]byte("classic glv off-subgroup scalar"))
	s.Mod(s, fr.Modulus())
	var lat ecc.Lattice
	ecc.PrecomputeLattice(fr.Modulus(), params.Eigenvalue, &lat)
	sp := ecc.SplitScalar(s, &lat)
	var omega fp.Element
	omega.SetBigInt(params.ThirdRootOne)
	phiQ := Q
	phiQ.X.Mul(&phiQ.X, &omega)
	signed := func(P bw6761.G2Affine, k *big.Int) bw6761.G2Jac {
		if k.Sign() < 0 {
			P.Neg(&P)
		}
		return mulNaiveG2(&P, new(big.Int).Abs(k))
	}
	a := signed(Q, &sp[0])
	b := signed(phiQ, &sp[1])
	a.AddAssign(&b)
	want := mulNaiveG2(&Q, s)
	assert.False(a.Equal(&want), "test vector must distinguish [s1]Q+[s2]ϕ(Q) from [s]Q")
	var glvRes bw6761.G2Affine
	glvRes.FromJacobian(&a)

	w := &mulG2Circuit{In: NewG2Affine(Q), S: emulated.ValueOf[ScalarField](s), Res: NewG2Affine(glvRes)}
	assert.Error(test.IsSolved(&mulG2Circuit{}, w, ecc.BN254.ScalarField()),
		"ScalarMul must reject an off-subgroup input")
}
