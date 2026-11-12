package sw_bw6761

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/test"
)

type assertIsOnG1Circuit struct{ P G1Affine }

func (c *assertIsOnG1Circuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P)
	return nil
}

func mulNaiveG1(P *bw6761.G1Affine, k *big.Int) bw6761.G1Jac {
	var acc, base bw6761.G1Jac
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

// TestAssertIsOnG1Torsion pins that AssertIsOnG1 rejects every kind of
// cofactor torsion on BW6-761 G1 (h₁ = 2²·127·3841927·C₁, E[2] = Z₂×Z₂).
//
// The relation [x₀+1]P + [x₀³−x₀²+1]ϕ(P) = O is exact on E(Fp)
// (gcd(h₁, k₁²−k₁k₂+k₂²) = 1). The chains are incomplete, but a chord on equal
// points [a]P = [b]P needs ord(P) | a−b, and for every chord in the chain
// gcd(h₁, a−b) ∈ {1, 2, 4}: only pure 2-torsion P could reach one, and those
// already fail the first tripling (tangent 3x²/2y with y = 0, x ≠ 0).
func TestAssertIsOnG1Torsion(t *testing.T) {
	assert := test.NewAssert(t)
	r := fr.Modulus()
	solve := func(P bw6761.G1Affine) error {
		return test.IsSolved(&assertIsOnG1Circuit{}, &assertIsOnG1Circuit{P: NewG1Affine(P)}, ecc.BN254.ScalarField())
	}
	inG1 := func(P bw6761.G1Affine) bool {
		rp := mulNaiveG1(&P, r)
		return rp.Z.IsZero()
	}

	_, _, gen, _ := bw6761.Generators()
	var g5 bw6761.G1Affine
	g5.ScalarMultiplication(&gen, big.NewInt(5))
	assert.NoError(solve(gen), "generator must be accepted")
	assert.NoError(solve(g5), "[5]g1 must be accepted")

	var torsion []bw6761.G1Affine
	// 2-torsion: (ω^i, 0), ω a primitive cube root of unity in Fp.
	var omega fp.Element
	omega.SetBigInt(sw_emulated.GetBW6761Params().ThirdRootOne)
	x := new(fp.Element).SetOne()
	for i := 0; i < 3; i++ {
		torsion = append(torsion, bw6761.G1Affine{X: *x})
		x = new(fp.Element).Mul(x, &omega)
	}
	// order-127 point (the classic-GLV torsion offset)
	off := sw_emulated.GetBW6761Params().GLVTorsionOffset
	var t127 bw6761.G1Affine
	t127.X.SetBigInt(off[0])
	t127.Y.SetBigInt(off[1])
	torsion = append(torsion, t127)

	for i, T := range torsion {
		assert.True(T.IsOnCurve())
		assert.False(inG1(T))
		assert.Error(solve(T), "torsion point %d must be rejected", i)
		var shifted bw6761.G1Affine
		shifted.Add(&g5, &T)
		assert.False(inG1(shifted))
		assert.Error(solve(shifted), "[5]g1 + torsion point %d must be rejected", i)
	}
}
