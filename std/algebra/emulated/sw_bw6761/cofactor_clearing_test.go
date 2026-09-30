package sw_bw6761

import (
	"math/big"
	"testing"
)

// TestG2CofactorClearingCoversReachablePrimes guards g2CofactorClearingConstant
// against under-scoping: it must be divisible by every BW6-761 G2 cofactor prime
// < 2^nbits (nbits = 97), else a chosen-scalar torsion forgery of the omitted
// order is accepted. Reachable set (verified by exact factorization): 3·13·
// 261812779·10233228391030511371 (10233228391030511371 ≈ 2^63 < 2^97); the
// remaining 118-bit and 170-bit primes are ≫ 2^nbits.
func TestG2CofactorClearingCoversReachablePrimes(t *testing.T) {
	q4, _ := new(big.Int).SetString("10233228391030511371", 10)
	reach := []*big.Int{
		big.NewInt(3), big.NewInt(13), big.NewInt(261812779), q4,
	}
	zero := new(big.Int)
	for _, q := range reach {
		if new(big.Int).Mod(g2CofactorClearingConstant, q).Cmp(zero) != 0 {
			t.Errorf("g2CofactorClearingConstant %s not divisible by reachable prime %s",
				g2CofactorClearingConstant, q)
		}
	}
}
