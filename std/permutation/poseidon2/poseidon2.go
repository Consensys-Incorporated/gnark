package poseidon2

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	poseidonbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	poseidonbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
)

var (
	ErrInvalidSizebuffer = errors.New("the size of the input should match the size of the hash buffer")
)

type Permutation struct {
	api    frontend.API
	params Parameters
}

// ExternalMatrix selects the 4x4 matrix M4 the external layer is built from.
// The two in use are not interchangeable: a permutation is only compatible with
// an implementation that picked the same one.
type ExternalMatrix int

const (
	// ExternalMatrixPoseidon2 is the matrix of https://eprint.iacr.org/2023/323.pdf
	// appendix B:
	//
	//	(5 7 1 3)
	//	(4 6 1 1)
	//	(1 3 5 7)
	//	(1 1 4 6)
	//
	// It is what gnark-crypto uses for every curve scalar field, and is the zero
	// value so that existing parameters keep their behaviour.
	ExternalMatrixPoseidon2 ExternalMatrix = iota

	// ExternalMatrixPlonky3 is the cheaper matrix used by Plonky3, and by
	// gnark-crypto for its small fields:
	//
	//	(2 3 1 1)
	//	(1 2 3 1)
	//	(1 1 2 3)
	//	(3 1 1 2)
	ExternalMatrixPlonky3
)

// Parameters describing the poseidon2 implementation
type Parameters struct {
	// len(preimage)+len(digest)=len(preimage)+ceil(log(2*<security_level>/r))
	Width int

	// sbox degree
	DegreeSBox int

	// number of full rounds (even number)
	NbFullRounds int

	// number of partial rounds
	NbPartialRounds int

	// round keys: ordered by round then variable
	RoundKeys [][]big.Int
	// ExternalMatrix selects the 4x4 matrix the external layer is built from.
	// The zero value is the one from the Poseidon2 paper, used by every curve
	// scalar field; the small fields in gnark-crypto use the Plonky3 one.
	ExternalMatrix ExternalMatrix

	// DiagM1 holds the diagonal entries of the internal matrix for width >= 4.
	// For width 2 and 3 the internal matrix is hardcoded and this field is unused.
	// See https://eprint.iacr.org/2023/323.pdf page 15.
	DiagM1 []big.Int
}

func GetDefaultParameters(curve ecc.ID) (Parameters, error) {
	switch curve { // TODO: assumes pairing based builder, reconsider when supporting other backends
	case ecc.BN254:
		p := poseidonbn254.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbn254.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		if len(p.DiagM1) > 0 {
			res.DiagM1 = make([]big.Int, len(p.DiagM1))
			for i := range res.DiagM1 {
				p.DiagM1[i].BigInt(&res.DiagM1[i])
			}
		}
		return res, nil
	case ecc.BLS12_381:
		p := poseidonbls12381.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbls12381.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BLS12_377:
		p := poseidonbls12377.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbls12377.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	case ecc.BW6_761:
		p := poseidonbw6761.GetDefaultParameters()
		res := Parameters{
			Width:           p.Width,
			DegreeSBox:      poseidonbw6761.DegreeSBox(),
			NbFullRounds:    p.NbFullRounds,
			NbPartialRounds: p.NbPartialRounds,
			RoundKeys:       make([][]big.Int, len(p.RoundKeys)),
		}
		for i := range res.RoundKeys {
			res.RoundKeys[i] = make([]big.Int, len(p.RoundKeys[i]))
			for j := range res.RoundKeys[i] {
				p.RoundKeys[i][j].BigInt(&res.RoundKeys[i][j])
			}
		}
		return res, nil
	default:
		return Parameters{}, fmt.Errorf("curve %s not supported", curve)
	}
}

// NewPoseidon2 returns a new Poseidon2 hasher with default parameters as
// defined in the gnark-crypto library.
func NewPoseidon2(api frontend.API) (*Permutation, error) {
	params, err := GetDefaultParametersForField(api.Compiler().Field())
	if err != nil {
		return nil, err
	}
	return &Permutation{
		api:    api,
		params: params,
	}, nil
}

// NewPoseidon2FromParameters returns a new Poseidon2 hasher with the given parameters.
// The parameters are used to precompute the round keys. The round key computation
// is deterministic and depends on the curve ID. See the corresponding NewParameters
// function in the gnark-crypto library poseidon2 packages for more details.
func NewPoseidon2FromParameters(api frontend.API, width, nbFullRounds, nbPartialRounds int) (*Permutation, error) {
	params := Parameters{Width: width, NbFullRounds: nbFullRounds, NbPartialRounds: nbPartialRounds}
	switch utils.FieldToCurve(api.Compiler().Field()) { // TODO: assumes pairing based builder, reconsider when supporting other backends
	case ecc.BN254:
		params.DegreeSBox = poseidonbn254.DegreeSBox()
		concreteParams := poseidonbn254.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
		if len(concreteParams.DiagM1) > 0 {
			params.DiagM1 = make([]big.Int, len(concreteParams.DiagM1))
			for i := range params.DiagM1 {
				concreteParams.DiagM1[i].BigInt(&params.DiagM1[i])
			}
		}
	case ecc.BLS12_381:
		params.DegreeSBox = poseidonbls12381.DegreeSBox()
		concreteParams := poseidonbls12381.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BLS12_377:
		params.DegreeSBox = poseidonbls12377.DegreeSBox()
		concreteParams := poseidonbls12377.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	case ecc.BW6_761:
		params.DegreeSBox = poseidonbw6761.DegreeSBox()
		concreteParams := poseidonbw6761.NewParameters(width, nbFullRounds, nbPartialRounds)
		params.RoundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
		for i := range params.RoundKeys {
			params.RoundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
			for j := range params.RoundKeys[i] {
				concreteParams.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
			}
		}
	default:
		return nil, fmt.Errorf("field %s not supported", api.Compiler().Field().String())
	}
	return &Permutation{api: api, params: params}, nil
}

// sBox applies the sBox on buffer[index]
func (h *Permutation) sBox(index int, input []frontend.Variable) {
	tmp := input[index]
	switch h.params.DegreeSBox {
	case 3:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(tmp, input[index])
	case 5:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case 7:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case 17:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case -1:
		input[index] = h.api.Inverse(input[index])
	default:
		panic("sbox degree not supported")
	}
}

// matMulM4 computes
// s <- M4*s
// where M4=
// (5 7 1 3)
// (4 6 1 1)
// (1 3 5 7)
// (1 1 4 6)
// on chunks of 4 elements on each part of the buffer
// see https://eprint.iacr.org/2023/323.pdf appendix B for the addition chain
func (h *Permutation) matMulM4InPlace(s []frontend.Variable) {
	if h.params.ExternalMatrix == ExternalMatrixPlonky3 {
		h.matMulM4Plonky3InPlace(s)
		return
	}
	c := len(s) / 4
	for i := 0; i < c; i++ {
		t0 := h.api.Add(s[4*i], s[4*i+1])   // s0+s1
		t1 := h.api.Add(s[4*i+2], s[4*i+3]) // s2+s3
		t2 := h.api.Mul(s[4*i+1], 2)
		t2 = h.api.Add(t2, t1) // 2s1+t1
		t3 := h.api.Mul(s[4*i+3], 2)
		t3 = h.api.Add(t3, t0) // 2s3+t0
		t4 := h.api.Mul(t1, 4)
		t4 = h.api.Add(t4, t3) // 4t1+t3
		t5 := h.api.Mul(t0, 4)
		t5 = h.api.Add(t5, t2)  // 4t0+t2
		t6 := h.api.Add(t3, t5) // t3+t5
		t7 := h.api.Add(t2, t4) // t2+t4
		s[4*i] = t6
		s[4*i+1] = t5
		s[4*i+2] = t7
		s[4*i+3] = t4
	}
}

// matMulM4Plonky3InPlace computes s <- M4*s for the Plonky3 matrix
//
//	(2 3 1 1)
//	(1 2 3 1)
//	(1 1 2 3)
//	(3 1 1 2)
//
// following the same addition chain as gnark-crypto's small-field Poseidon2.
func (h *Permutation) matMulM4Plonky3InPlace(s []frontend.Variable) {
	c := len(s) / 4
	for i := 0; i < c; i++ {
		t01 := h.api.Add(s[4*i], s[4*i+1])
		t23 := h.api.Add(s[4*i+2], s[4*i+3])
		t0123 := h.api.Add(t01, t23)
		t01123 := h.api.Add(t0123, s[4*i+1])
		t01233 := h.api.Add(t0123, s[4*i+3])

		s3 := h.api.Add(h.api.Mul(s[4*i], 2), t01233)
		s1 := h.api.Add(h.api.Mul(s[4*i+2], 2), t01123)
		s0 := h.api.Add(t01, t01123)
		s2 := h.api.Add(t23, t01233)

		s[4*i] = s0
		s[4*i+1] = s1
		s[4*i+2] = s2
		s[4*i+3] = s3
	}
}

// when t=2,3 the buffer is multiplied by circ(2,1) and circ(2,1,1)
// see https://eprint.iacr.org/2023/323.pdf page 15, case t=2,3
//
// when t=0[4], the buffer is multiplied by circ(2M4,M4,..,M4)
// see https://eprint.iacr.org/2023/323.pdf
func (h *Permutation) matMulExternalInPlace(input []frontend.Variable) {

	switch h.params.Width {
	case 2:
		tmp := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(tmp, input[0])
		input[1] = h.api.Add(tmp, input[1])
	case 3:
		tmp := h.api.Add(input[0], input[1])
		tmp = h.api.Add(tmp, input[2])
		input[0] = h.api.Add(input[0], tmp)
		input[1] = h.api.Add(input[1], tmp)
		input[2] = h.api.Add(input[2], tmp)
	case 4:
		h.matMulM4InPlace(input)
	default:
		// at this stage t is supposed to be a multiple of 4
		// the MDS matrix is circ(2M4,M4,..,M4)
		h.matMulM4InPlace(input)
		tmp := []frontend.Variable{0, 0, 0, 0}
		for i := 0; i < h.params.Width/4; i++ {
			tmp[0] = h.api.Add(tmp[0], input[4*i])
			tmp[1] = h.api.Add(tmp[1], input[4*i+1])
			tmp[2] = h.api.Add(tmp[2], input[4*i+2])
			tmp[3] = h.api.Add(tmp[3], input[4*i+3])
		}
		for i := 0; i < h.params.Width/4; i++ {
			input[4*i] = h.api.Add(input[4*i], tmp[0])
			input[4*i+1] = h.api.Add(input[4*i+1], tmp[1])
			input[4*i+2] = h.api.Add(input[4*i+2], tmp[2])
			input[4*i+3] = h.api.Add(input[4*i+3], tmp[3])
		}
	}
}

// when t=2,3 the matrix are respectively [[2,1][1,3]] and [[2,1,1][1,2,1][1,1,3]]
// otherwise the matrix is filled with ones except on the diagonal,
func (h *Permutation) matMulInternalInPlace(input []frontend.Variable) {
	switch h.params.Width {
	case 2:
		sum := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Mul(2, input[1])
		input[1] = h.api.Add(input[1], sum)
	case 3:
		sum := h.api.Add(input[0], input[1])
		sum = h.api.Add(sum, input[2])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Add(input[1], sum)
		input[2] = h.api.Mul(input[2], 2)
		input[2] = h.api.Add(input[2], sum)
	default:
		// General case for width >= 4: state[i] = state[i] * diag[i] + Σstate.
		// Mirrors gnark-crypto's matMulInternalInPlace for t >= 4.
		// See https://eprint.iacr.org/2023/323.pdf page 15.
		if len(h.params.DiagM1) != h.params.Width {
			panic("poseidon2: missing DiagM1 for width >= 4")
		}
		sum := input[0]
		for i := 1; i < h.params.Width; i++ {
			sum = h.api.Add(sum, input[i])
		}
		for i := 0; i < h.params.Width; i++ {
			input[i] = h.api.Add(h.api.Mul(input[i], &h.params.DiagM1[i]), sum)
		}
	}
}

// addRoundKeyInPlace adds the round-th key to the buffer
func (h *Permutation) addRoundKeyInPlace(round int, input []frontend.Variable) {
	for i := 0; i < len(h.params.RoundKeys[round]); i++ {
		input[i] = h.api.Add(input[i], h.params.RoundKeys[round][i])
	}
}

// Permutation applies the permutation on input, and stores the result in input.
func (h *Permutation) Permutation(input []frontend.Variable) error {
	if len(input) != h.params.Width {
		return ErrInvalidSizebuffer
	}

	// Use optimized implementation for width=2 (merges round key additions with matrix ops)
	if h.params.Width == 2 {
		return h.permutationWidth2(input)
	}

	// external matrix multiplication, cf https://eprint.iacr.org/2023/323.pdf page 14 (part 6)
	h.matMulExternalInPlace(input)

	rf := h.params.NbFullRounds / 2
	for i := 0; i < rf; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.Width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}

	for i := rf; i < rf+h.params.NbPartialRounds; i++ {
		// one round = matMulInternal(sBox_sparse(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		h.sBox(0, input)
		h.matMulInternalInPlace(input)
	}
	for i := rf + h.params.NbPartialRounds; i < h.params.NbFullRounds+h.params.NbPartialRounds; i++ {
		// one round = matMulExternal(sBox_Full(addRoundKey))
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.Width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}

	return nil
}

// permutationWidth2 is an optimized permutation for width=2.
// It merges round key additions with matrix multiplications to minimize constraints.
//
// Matrix operations for width=2:
//   - External: M_E * [a, b] = [2a + b, a + 2b]
//   - Internal: M_I * [a, b] = [2a + b, a + 3b]
//
// Round keys are merged: instead of separate addRoundKey + matrix operations,
// we compute (matrix * state + key) in one step, saving constraints.
func (h *Permutation) permutationWidth2(input []frontend.Variable) error {
	rf := h.params.NbFullRounds / 2
	rp := h.params.NbPartialRounds

	// matMulExternal applies M_E and merges round keys k0, k1 (k1 may be nil for partial rounds)
	matMulExternal := func(k0, k1 *big.Int) {
		a, b := input[0], input[1]
		if k1 != nil {
			input[0] = h.api.Add(h.api.Mul(a, 2), b, k0)
			input[1] = h.api.Add(a, h.api.Mul(b, 2), k1)
		} else {
			input[0] = h.api.Add(h.api.Mul(a, 2), b, k0)
			input[1] = h.api.Add(a, h.api.Mul(b, 2))
		}
	}

	// matMulInternal applies M_I and merges next round key k0 (only first element gets key)
	matMulInternal := func(k0 *big.Int) {
		a, b := input[0], input[1]
		input[0] = h.api.Add(h.api.Mul(a, 2), b, k0)
		input[1] = h.api.Add(a, h.api.Mul(b, 3))
	}

	// matMulInternalFull applies M_I and merges full round keys k0, k1
	matMulInternalFull := func(k0, k1 *big.Int) {
		a, b := input[0], input[1]
		input[0] = h.api.Add(h.api.Mul(a, 2), b, k0)
		input[1] = h.api.Add(a, h.api.Mul(b, 3), k1)
	}

	// Initial: M_E + round key 0
	matMulExternal(&h.params.RoundKeys[0][0], &h.params.RoundKeys[0][1])

	// First half full rounds (0 to rf-1)
	for i := 0; i < rf-1; i++ {
		h.sBox(0, input)
		h.sBox(1, input)
		matMulExternal(&h.params.RoundKeys[i+1][0], &h.params.RoundKeys[i+1][1])
	}

	// Transition: last full round of first half -> first partial round
	h.sBox(0, input)
	h.sBox(1, input)
	matMulExternal(&h.params.RoundKeys[rf][0], nil)

	// Partial rounds (rf to rf+rp-1): sBox only on first element, internal matrix
	for i := rf; i < rf+rp-1; i++ {
		h.sBox(0, input)
		matMulInternal(&h.params.RoundKeys[i+1][0])
	}

	// Last partial round -> first full round of second half
	h.sBox(0, input)
	matMulInternalFull(&h.params.RoundKeys[rf+rp][0], &h.params.RoundKeys[rf+rp][1])

	// Second half full rounds (rf+rp to 2*rf+rp-1)
	for i := rf + rp; i < 2*rf+rp-1; i++ {
		h.sBox(0, input)
		h.sBox(1, input)
		matMulExternal(&h.params.RoundKeys[i+1][0], &h.params.RoundKeys[i+1][1])
	}

	// Final round: no round key merge
	h.sBox(0, input)
	h.sBox(1, input)
	a, b := input[0], input[1]
	input[0] = h.api.Add(h.api.Mul(a, 2), b)
	input[1] = h.api.Add(a, h.api.Mul(b, 2))

	return nil
}

// Compress applies the permutation on left and right and returns the right lane
// of the result. Panics if the permutation instance is not initialized with a
// width of 2.
//
// Implements the [hash.Compressor] interface for building a Merkle-Damgard
// hash construction.
func (h *Permutation) Compress(left, right frontend.Variable) frontend.Variable {
	if h.params.Width != 2 {
		panic("poseidon2: Compress can only be used when t=2")
	}
	vars := [2]frontend.Variable{left, right}
	if err := h.Permutation(vars[:]); err != nil {
		panic(err) // this would never happen
	}
	return h.api.Add(vars[1], right)
}
