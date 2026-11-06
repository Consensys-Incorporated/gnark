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

// mamabearParameters builds the in-circuit parameters from gnark-crypto's
// mamabear Poseidon2 defaults: width 16, 6 full rounds, 21 partial rounds and a
// degree-3 S-box.
//
// The round keys, the internal diagonal and the choice of external matrix are
// all read off the gnark-crypto parameters, so no constant is transcribed here
// and a change on that side surfaces as an error rather than as a permutation
// which silently disagrees with the native one.
func mamabearParameters() (Parameters, error) {
	p := poseidonmamabear.GetDefaultParameters()

	diagM1, err := diagM1Of(elementsToBigInts(p.InternalMatrix()), mamabear.Modulus())
	if err != nil {
		return Parameters{}, fmt.Errorf("mamabear poseidon2: internal matrix: %w", err)
	}
	externalMatrix, err := externalMatrixOf(elementsToBigInts(p.ExternalMatrix()))
	if err != nil {
		return Parameters{}, fmt.Errorf("mamabear poseidon2: external matrix: %w", err)
	}

	res := Parameters{
		Width:           p.Width,
		DegreeSBox:      poseidonmamabear.DegreeSBox(),
		NbFullRounds:    p.NbFullRounds,
		NbPartialRounds: p.NbPartialRounds,
		RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		DiagM1:          diagM1,
		ExternalMatrix:  externalMatrix,
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

// elementsToBigInts converts a matrix of mamabear elements to big integers.
func elementsToBigInts(m [][]mamabear.Element) [][]big.Int {
	res := make([][]big.Int, len(m))
	for i := range m {
		res[i] = make([]big.Int, len(m[i]))
		for j := range m[i] {
			m[i][j].BigInt(&res[i][j])
		}
	}
	return res
}

// diagM1Of extracts the diagonal the in-circuit internal layer needs from the
// dense internal matrix M_I. gnark-crypto defines M_I = J + diag(d) with J the
// all-ones matrix, and the gadget computes state[i]*d[i] + Σstate, so d is the
// diagonal of M_I less one.
func diagM1Of(internal [][]big.Int, modulus *big.Int) ([]big.Int, error) {
	one := big.NewInt(1)
	res := make([]big.Int, len(internal))
	for i := range internal {
		if len(internal[i]) != len(internal) {
			return nil, fmt.Errorf("matrix is %d rows but row %d has %d entries", len(internal), i, len(internal[i]))
		}
		res[i].Sub(&internal[i][i], one)
		res[i].Mod(&res[i], modulus)
	}
	return res, nil
}

// m4Poseidon2 is the matrix of https://eprint.iacr.org/2023/323.pdf appendix B,
// used by gnark-crypto for every curve scalar field.
var m4Poseidon2 = [4][4]int64{
	{5, 7, 1, 3},
	{4, 6, 1, 1},
	{1, 3, 5, 7},
	{1, 1, 4, 6},
}

// m4Plonky3 is the cheaper matrix used by Plonky3, and by gnark-crypto for its
// small fields.
var m4Plonky3 = [4][4]int64{
	{2, 3, 1, 1},
	{1, 2, 3, 1},
	{1, 1, 2, 3},
	{3, 1, 1, 2},
}

// externalMatrixOf identifies which 4x4 matrix M4 the dense external matrix is
// built from, so the gadget can pick the matching addition chain. The gadget
// implements the external layer as that chain rather than as a dense
// multiplication, which is what keeps the linear layer cheap, so it cannot take
// an arbitrary matrix: a matrix it does not recognise is an error rather than
// something to fall back on.
//
// The external matrix is M4 itself at width 4, and circ(2*M4, M4, ..., M4) at
// wider multiples of 4, so the off-diagonal block carries M4 unscaled.
func externalMatrixOf(external [][]big.Int) (ExternalMatrix, error) {
	width := len(external)
	if width < 4 || width%4 != 0 {
		return 0, fmt.Errorf("width %d is not a positive multiple of 4", width)
	}
	for i := range external {
		if len(external[i]) != width {
			return 0, fmt.Errorf("matrix is %d rows but row %d has %d entries", width, i, len(external[i]))
		}
	}
	// at width 4 the only block is M4 itself; beyond it the diagonal blocks are
	// doubled, so read M4 off an off-diagonal one.
	colOffset := 0
	if width > 4 {
		colOffset = 4
	}
	var m4 [4][4]big.Int
	for i := range 4 {
		for j := range 4 {
			m4[i][j].Set(&external[i][colOffset+j])
		}
	}

	switch {
	case matchesM4(m4, m4Plonky3):
		return ExternalMatrixPlonky3, nil
	case matchesM4(m4, m4Poseidon2):
		return ExternalMatrixPoseidon2, nil
	default:
		return 0, fmt.Errorf("M4 block %v matches neither the Poseidon2 nor the Plonky3 matrix", m4)
	}
}

// matchesM4 reports whether a 4x4 block equals the given small-integer matrix.
func matchesM4(got [4][4]big.Int, want [4][4]int64) bool {
	for i := range 4 {
		for j := range 4 {
			if got[i][j].Cmp(big.NewInt(want[i][j])) != 0 {
				return false
			}
		}
	}
	return true
}
