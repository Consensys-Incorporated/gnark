package sha3

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type digest struct {
	api           frontend.API
	bapi          *uints.Bytes
	uapi          *uints.BinaryField[uints.U64]
	state         [25]uints.U64 // 1600 bits state: 25 x 64
	in            []uints.U8    // input to be digested
	dsbyte        byte          // dsbyte contains the "domain separation" bits and the first bit of the padding
	rate          int           // the number of bytes of state to use
	outputLen     int           // the default output size in bytes
	minimalLength int           // lower bound on the length of the input to optimize fixed length hashing
}

func (d *digest) Write(in []uints.U8) {
	d.in = append(d.in, in...)
}

func (d *digest) Size() int { return d.outputLen }

func (d *digest) BlockSize() int { return d.rate }

func (d *digest) Reset() {
	d.in = nil
	d.state = newState()
}

func (d *digest) Sum() []uints.U8 {
	padded := d.padding()

	blocks := d.composeBlocks(padded)
	d.absorbing(blocks)
	return d.squeezeBlocks()
}

func (d *digest) FixedLengthSum(length frontend.Variable) []uints.U8 {
	padded, numberOfBlocks := d.paddingFixedWidth(length)

	blocks := d.composeBlocks(padded)

	d.absorbingFixedWidth(blocks, numberOfBlocks)

	return d.squeezeBlocks()
}

func (d *digest) padding() []uints.U8 {
	padded := make([]uints.U8, len(d.in))
	copy(padded[:], d.in[:])

	switch q := d.rate - (len(padded) % d.rate); q {
	case 1:
		padded = append(padded, uints.NewU8(d.dsbyte^0x80))
	case 2:
		padded = append(padded, uints.NewU8(d.dsbyte))
		padded = append(padded, uints.NewU8(0x80))
	default:
		padded = append(padded, uints.NewU8(d.dsbyte))
		padded = append(padded, uints.NewU8Array(make([]uint8, q-2))...)
		padded = append(padded, uints.NewU8(0x80))
	}

	return padded
}

func (d *digest) paddingFixedWidth(length frontend.Variable) (padded []uints.U8, numberOfBlocks frontend.Variable) {
	maxLen := len(d.in)
	maxPaddingCount := d.rate - maxLen%d.rate
	maxTotalLen := maxLen + maxPaddingCount

	comparator := cmp.NewBoundedComparator(d.api, big.NewInt(int64(maxTotalLen)), false)
	// assert that the length is not larger than the maximum length of the
	// hashed input. I don't currently see how it could be exploited if it was,
	// but just to be safe.
	comparator.AssertIsLessEq(length, maxLen)
	// in case the lower bound on the length of input is given, check that the input is long enough
	if d.minimalLength > 0 {
		comparator.AssertIsLessEq(d.minimalLength, length)
	}

	padded = make([]uints.U8, maxLen)
	copy(padded[:], d.in[:])
	padded = append(padded, uints.NewU8Array(make([]uint8, maxPaddingCount))...)

	quotient, remainder := d.quoRemRate(length)
	// Bind the Euclidean relation length = quotient*rate + remainder over the
	// integers. quoRemRate only range-checks remainder ∈ [0, rate) and derives
	// quotient = (length-remainder)*rate⁻¹ as a linear expression (rate is a
	// constant, so DivUnchecked adds no constraint). Without a bound on
	// quotient a malicious prover could pick any in-range remainder and the
	// mod-P identity would still hold via wraparound, unpinning remainder from
	// length mod rate and forging the padding position. Bounding quotient to
	// the max block count keeps quotient*rate + remainder well below the native
	// modulus, so the identity holds over the integers and remainder is pinned.
	comparator.AssertIsLessEq(quotient, maxTotalLen/d.rate)

	// When i < minLen or i > maxLen, padding dsbyte is completely unnecessary
	padDsbyte := uints.NewU8(d.dsbyte)
	for i := d.minimalLength; i <= maxLen; i++ {
		reachEnd := cmp.IsEqual(d.api, i, length)
		padded[i] = d.bapi.Select(reachEnd, padDsbyte, padded[i])
	}

	// When i <= minLen or i >= maxLen, padding 0 is completely unnecessary
	pad0 := uints.NewU8(0x00)
	for i := d.minimalLength + 1; i < maxLen; i++ {
		isPaddingPos := comparator.IsLess(length, i)
		padded[i] = d.bapi.Select(isPaddingPos, pad0, padded[i])
	}

	paddingCount := d.api.Sub(d.rate, remainder)
	totalLen := d.api.Add(length, paddingCount)
	lastPaddingPos := d.api.Sub(totalLen, 1)

	isOnlyPaddedOneCount := cmp.IsEqual(d.api, paddingCount, 1)
	padDsbyteMask := uints.NewU8(d.dsbyte ^ 0x80)
	pad0x80 := uints.NewU8(0x80)
	lastPaddedByte := d.bapi.Select(isOnlyPaddedOneCount, padDsbyteMask, pad0x80)

	// When i < minLen, padding 0x80 is completely unnecessary
	for i := d.minimalLength; i < maxTotalLen; i++ {
		isLastPaddingPos := cmp.IsEqual(d.api, i, lastPaddingPos)
		padded[i] = d.bapi.Select(isLastPaddingPos, lastPaddedByte, padded[i])
	}

	return padded, d.api.Add(quotient, 1)
}

func (d *digest) composeBlocks(padded []uints.U8) [][]uints.U64 {
	blocks := make([][]uints.U64, len(padded)/d.rate)

	for i := range blocks {
		block := make([]uints.U64, d.rate/8)
		for j := range block {
			u64 := padded[j*8 : j*8+8]
			block[j] = d.uapi.PackLSB(u64...)
		}
		blocks[i] = block
		padded = padded[d.rate:]
	}

	return blocks
}

func (d *digest) absorbing(blocks [][]uints.U64) {
	for _, block := range blocks {
		for i := range block {
			d.state[i] = d.uapi.Xor(d.state[i], block[i])
		}
		d.state = keccakf.Permute(d.uapi, d.state)
	}
}

func (d *digest) absorbingFixedWidth(blocks [][]uints.U64, nbBlocks frontend.Variable) {
	minNbOfBlocks := d.minimalLength / d.rate
	var state [25]uints.U64
	var resultState [25]uints.U64
	copy(state[:], d.state[:])

	comparator := cmp.NewBoundedComparator(d.api, big.NewInt(int64(len(blocks))), false)

	for i, block := range blocks {
		for j := range block {
			state[j] = d.uapi.Xor(state[j], block[j])
		}
		state = keccakf.Permute(d.uapi, state)

		// When i < minNbOfBlocks, state cannot be resultState, and proceed to the next loop directly
		if i < minNbOfBlocks {
			continue
		} else if i == minNbOfBlocks { // init resultState
			copy(resultState[:], state[:])
			continue
		}

		isInRange := comparator.IsLess(i, nbBlocks)
		// only select blocks that are in range. Only process the first outputLen data relevant to the result
		for j := 0; j < d.outputLen/8; j++ {
			for k := 0; k < 8; k++ {

				resultState[j][k] = d.bapi.Select(isInRange, state[j][k], resultState[j][k])
			}
		}
	}
	copy(d.state[:], resultState[:])
}

func (d *digest) squeezeBlocks() (result []uints.U8) {
	for i := 0; i < d.outputLen/8; i++ {
		result = append(result, d.uapi.UnpackLSB(d.state[i])...)
	}
	return
}

// quoRemRate returns quotient = x / d.rate and remainder = x % d.rate with
func (d *digest) quoRemRate(x frontend.Variable) (quotient, remainder frontend.Variable) {
	var err error
	// we can use api.AssertIsLessOrEqual when the bound is constant. It has a short path for case when bound is constant.
	res, err := d.api.NewHint(remHint, 1, d.rate, x)
	if err != nil {
		panic(fmt.Sprintf("call remHint: %v", err))
	}
	c := cmp.NewBoundedComparator(d.api, big.NewInt(int64(d.rate)), false)
	c.AssertIsLess(res[0], d.rate)
	quotient = d.api.DivUnchecked(d.api.Sub(x, res[0]), d.rate)
	return quotient, res[0]
}

func newState() (state [25]uints.U64) {
	for i := range state {
		state[i] = uints.NewU64(0)
	}
	return
}
