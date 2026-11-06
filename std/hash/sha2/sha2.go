// Package sha2 implements SHA2 hash computation.
//
// This package extends the SHA2 permutation function [sha2] into a full SHA2
// hash.
package sha2

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/sha2"
)

var _seed = uints.NewU32Array([]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
})

type digest struct {
	api  frontend.API
	bapi *uints.Bytes
	uapi *uints.BinaryField[uints.U32]
	in   []uints.U8

	minimalLength int
}

func New(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	cfg := new(hash.HasherConfig)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("initializing bytes: %w", err)
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, fmt.Errorf("initializing uints: %w", err)
	}
	return &digest{api: api, bapi: bapi, uapi: uapi, minimalLength: cfg.MinimalLength}, nil
}

func (d *digest) Write(data []uints.U8) {
	d.in = append(d.in, data...)
}

func (d *digest) padded(bytesLen int) []uints.U8 {
	zeroPadLen := 55 - bytesLen%64
	if zeroPadLen < 0 {
		zeroPadLen += 64
	}
	if cap(d.in) < len(d.in)+9+zeroPadLen {
		// in case this is the first time this method is called increase the
		// capacity of the slice to fit the padding.
		d.in = append(d.in, make([]uints.U8, 9+zeroPadLen)...)
		d.in = d.in[:len(d.in)-9-zeroPadLen]
	}
	buf := d.in
	buf = append(buf, uints.NewU8(0x80))
	buf = append(buf, uints.NewU8Array(make([]uint8, zeroPadLen))...)
	lenbuf := make([]uint8, 8)
	binary.BigEndian.PutUint64(lenbuf, uint64(8*bytesLen))
	buf = append(buf, uints.NewU8Array(lenbuf)...)
	return buf
}

func (d *digest) Sum() []uints.U8 {
	var runningDigest [8]uints.U32
	var buf [64]uints.U8
	copy(runningDigest[:], _seed)
	padded := d.padded(len(d.in))
	for i := 0; i < len(padded)/64; i++ {
		copy(buf[:], padded[i*64:(i+1)*64])
		runningDigest = sha2.Permute(d.uapi, runningDigest, buf)
	}

	return d.unpackU8Digest(runningDigest)
}

func (d *digest) unpackU8Digest(digest [8]uints.U32) []uints.U8 {
	var ret []uints.U8
	for i := range digest {
		ret = append(ret, d.uapi.UnpackMSB(digest[i])...)
	}
	return ret
}

func (d *digest) FixedLengthSum(length frontend.Variable) []uints.U8 {
	// we need to do two things here -- first the padding has to be put to the
	// right place. For that we need to know how many blocks we have used. We
	// need to fit at least 9 more bytes (padding byte and 8 bytes for input
	// length). Knowing the block, we have to keep running track if the current
	// block is the expected one.
	//
	// idea - have a mask for blocks where 1 is only for the block we want to
	// use.

	maxLen := len(d.in)
	if d.minimalLength < 0 || d.minimalLength > maxLen {
		panic(fmt.Sprintf("minimal length %d not in [0, %d]", d.minimalLength, maxLen))
	}
	maxPaddingCount := 64 - maxLen%64
	if maxPaddingCount <= 8 {
		maxPaddingCount += 64
	}
	maxTotalLen := maxLen + maxPaddingCount

	comparator := cmp.NewBoundedComparator(d.api, big.NewInt(int64(maxTotalLen)), false)
	// Assert minimalLength <= length <= maxLen over the integers. The
	// comparator is only sound when |a-b| <= maxTotalLen, which does not hold
	// for an arbitrary witness: with the upper bound alone a field-negative
	// length (e.g. P-1) wraps around and passes. Each check decomposes the
	// difference into bitlen(maxTotalLen) bits, so together they bound length
	// on both sides to a small non-negative integer. The lower bound is
	// checked also when minimalLength is 0, so that soundness does not depend
	// on the 64-bit decompositions of length done below (in mod64 and in
	// bigEndianPutUint64(length*8)).
	comparator.AssertIsLessEq(length, maxLen)
	// we use comparator as [frontend.API] doesn't have a fast path for case API.AssertIsLessOrEqual(constant, variable)
	comparator.AssertIsLessEq(d.minimalLength, length)

	data := make([]uints.U8, maxLen)
	copy(data, d.in)
	data = append(data, uints.NewU8Array(make([]uint8, maxPaddingCount))...)

	lenMod64 := d.mod64(length)
	lenMod64Less56 := comparator.IsLess(lenMod64, 56)

	paddingCount := d.api.Sub(64, lenMod64)
	paddingCount = d.api.Select(lenMod64Less56, paddingCount, d.api.Add(paddingCount, 64))

	totalLen := d.api.Add(length, paddingCount)
	last8BytesPos := d.api.Sub(totalLen, 8)

	// var dataLenBtyes [8]frontend.Variable
	dataLenBytes := d.bigEndianPutUint64(d.api.Mul(length, 8))

	// When i < minLen or i > maxLen, padding 0x80 is completely unnecessary
	pad0x80 := uints.NewU8(0x80)
	for i := d.minimalLength; i <= maxLen; i++ {
		isPaddingStartPos := cmp.IsEqual(d.api, i, length)
		data[i] = d.bapi.Select(isPaddingStartPos, pad0x80, data[i])
	}

	// When i <= minLen or i >= maxLen, padding 0 is completely unnecessary
	pad0x00 := uints.NewU8(0x00)
	for i := d.minimalLength + 1; i < maxLen; i++ {
		isPaddingPos := comparator.IsLess(length, i)
		data[i] = d.bapi.Select(isPaddingPos, pad0x00, data[i])
	}

	// When i <= minLen or i > maxTotalLen-8, padding length is completely unnecessary
	for i := d.minimalLength + 1; i <= maxTotalLen-8; i++ {
		isLast8BytesPos := cmp.IsEqual(d.api, i, last8BytesPos)
		for j := 0; j < 8; j++ {
			data[i+j] = d.bapi.Select(isLast8BytesPos, dataLenBytes[j], data[i+j])
		}
	}

	var runningDigest [8]uints.U32
	var resultDigest [8]uints.U32
	var buf [64]uints.U8
	copy(runningDigest[:], _seed)

	for i := 0; i < maxTotalLen/64; i++ {
		copy(buf[:], data[i*64:(i+1)*64])
		runningDigest = sha2.Permute(d.uapi, runningDigest, buf)

		// When i < minLen/64, runningDigest cannot be resultDigest, and proceed to the next loop directly
		if i < d.minimalLength/64 {
			continue
		} else if i == d.minimalLength/64 { // init resultDigests
			copy(resultDigest[:], runningDigest[:])
			continue
		}

		isInRange := comparator.IsLess(i*64, totalLen)
		for j := 0; j < 8; j++ {
			for k := 0; k < 4; k++ {
				resultDigest[j][k] = d.bapi.Select(isInRange, runningDigest[j][k], resultDigest[j][k])
			}
		}
	}

	return d.unpackU8Digest(resultDigest)
}

func (d *digest) Reset() {
	d.in = nil
}

func (d *digest) Size() int { return 32 }

func (d *digest) BlockSize() int { return 64 }

func (d *digest) mod64(v frontend.Variable) frontend.Variable {
	lower, _ := bitslice.Partition(d.api, v, 6, bitslice.WithNbDigits(64))
	return lower
}

func (d *digest) bigEndianPutUint64(x frontend.Variable) []uints.U8 {
	res := make([]uints.U8, 8)
	bts := bits.ToBinary(d.api, x, bits.WithNbDigits(64))
	for i := 0; i < 8; i++ {
		res[i] = d.bapi.ValueOf(bits.FromBinary(d.api, bts[(8-i-1)*8:(8-i)*8]))
	}
	return res
}
