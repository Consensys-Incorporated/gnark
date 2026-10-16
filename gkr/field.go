package gkr

import "math/big"

// Field describes F_p[X]/(f), with f = Xⁿ + MinPoly[n-1]·Xⁿ⁻¹ + … + MinPoly[0] monic and
// irreducible over F_p, n = len(MinPoly). Coefficients are in increasing degree: X is [0],
// X² + 1 is [1, 0].
type Field struct {
	Modulus *big.Int
	MinPoly []*big.Int
}

// PrimeField describes F_p itself, as F_p[X]/(X).
func PrimeField(p *big.Int) Field {
	return Field{Modulus: p, MinPoly: []*big.Int{big.NewInt(0)}}
}

// Degree returns n, the extension degree of the field over F_p.
func (f Field) Degree() int {
	return len(f.MinPoly)
}

// KoalaBearE6 describes KoalaBear's degree-6 extension E6, whose tower generator v has minimal
// polynomial X⁶ - 2X³ - 2.
func KoalaBearE6() Field {
	return Field{
		Modulus: big.NewInt(2130706433), // 2^31 - 2^24 + 1
		MinPoly: []*big.Int{big.NewInt(-2), big.NewInt(0), big.NewInt(0), big.NewInt(-2), big.NewInt(0), big.NewInt(0)},
	}
}
