package poseidon2

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/mamabear"
	poseidonmamabear "github.com/consensys/gnark-crypto/field/mamabear/poseidon2"
	"github.com/consensys/gnark/internal/utils"
)

// GetDefaultParametersForField returns the default Poseidon2 parameters for a
// native modulus, covering both the scalar fields of the supported curves and
// the small fields.
//
// [GetDefaultParameters] only takes a curve ID, so it cannot reach the small
// fields: they have no curve ID at all.
func GetDefaultParametersForField(modulus *big.Int) (Parameters, error) {
	if curve := utils.FieldToCurve(modulus); curve != ecc.UNKNOWN {
		return GetDefaultParameters(curve)
	}
	if modulus.Cmp(mamabear.Modulus()) == 0 {
		return mamabearParameters()
	}
	return Parameters{}, fmt.Errorf("field %s not supported", modulus)
}

// mamabearDiag16 returns the diagonal of the internal matrix for width 16.
//
// The entries are
//
//	[-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
//
// matching gnark-crypto's mamabear Poseidon2, which applies them as shifts and
// adds rather than exposing them as constants. They are derived here from their
// definitions rather than copied as literals; TestMamabearMatchesNative checks
// the whole permutation against the native one, which is what actually pins
// them.
func mamabearDiag16() []big.Int {
	// negative of the field element n
	neg := func(n uint64) mamabear.Element {
		var e mamabear.Element
		e.SetUint64(n).Neg(&e)
		return e
	}
	// 1/2^k
	invPow2 := func(k uint64) mamabear.Element {
		var e, two mamabear.Element
		two.SetUint64(2)
		e.Exp(two, new(big.Int).SetUint64(k))
		e.Inverse(&e)
		return e
	}
	// -1/2^k
	negInvPow2 := func(k uint64) mamabear.Element {
		e := invPow2(k)
		e.Neg(&e)
		return e
	}
	pos := func(n uint64) mamabear.Element {
		var e mamabear.Element
		e.SetUint64(n)
		return e
	}

	diag := []mamabear.Element{
		neg(2),        // -2
		pos(1),        // 1
		pos(2),        // 2
		invPow2(1),    // 1/2
		pos(3),        // 3
		pos(4),        // 4
		negInvPow2(1), // -1/2
		neg(3),        // -3
		neg(4),        // -4
		invPow2(8),    // 1/2^8
		invPow2(3),    // 1/8
		invPow2(24),   // 1/2^24
		negInvPow2(8), // -1/2^8
		negInvPow2(3), // -1/8
		negInvPow2(4), // -1/16
		negInvPow2(24),
	}

	res := make([]big.Int, len(diag))
	for i := range diag {
		diag[i].BigInt(&res[i])
	}
	return res
}

// mamabearParameters builds the in-circuit parameters from gnark-crypto's
// mamabear Poseidon2 defaults: width 16, 6 full rounds, 21 partial rounds and a
// degree-3 S-box.
func mamabearParameters() (Parameters, error) {
	p := poseidonmamabear.GetDefaultParameters()
	res := Parameters{
		Width:           p.Width,
		DegreeSBox:      poseidonmamabear.DegreeSBox(),
		NbFullRounds:    p.NbFullRounds,
		NbPartialRounds: p.NbPartialRounds,
		RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		DiagM1:          mamabearDiag16(),
		ExternalMatrix:  ExternalMatrixPlonky3,
	}
	if res.Width != len(res.DiagM1) {
		return Parameters{}, fmt.Errorf("mamabear poseidon2: width %d does not match the %d diagonal entries", res.Width, len(res.DiagM1))
	}
	for i := range res.RoundKeys {
		res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
		for j := range res.RoundKeys[i] {
			p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
		}
	}
	return res, nil
}
