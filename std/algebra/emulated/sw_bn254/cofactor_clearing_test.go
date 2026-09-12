package sw_bn254

import (
	"math/big"
	"testing"
)

// TestG2CofactorClearingCoversReachablePrimes guards g2CofactorClearingConstant
// against under-scoping: it must be divisible by every BN254 G2 cofactor prime
// < 2^nbits, else a chosen-scalar torsion forgery of the omitted order is
// accepted. Reachable set (verified by exact factorization): 10069·5864401·
// 1875725156269 (1875725156269 ≈ 2^41 < 2^nbits = 2^66); the remaining 177-bit
// prime is ≫ 2^nbits.
func TestG2CofactorClearingCoversReachablePrimes(t *testing.T) {
	reach := []*big.Int{
		big.NewInt(10069), big.NewInt(5864401), big.NewInt(1875725156269),
	}
	zero := new(big.Int)
	for _, q := range reach {
		if new(big.Int).Mod(g2CofactorClearingConstant, q).Cmp(zero) != 0 {
			t.Errorf("g2CofactorClearingConstant %s not divisible by reachable prime %s",
				g2CofactorClearingConstant, q)
		}
	}
}
