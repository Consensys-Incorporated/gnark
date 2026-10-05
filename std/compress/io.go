package compress

import (
	"errors"
	"hash"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress/internal/plonk"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// Pack packs the words as tightly as possible, and works Big Endian: i.e. the first word is the most significant in the packed elem
// it is on the caller to make sure the words are within range
func Pack(api frontend.API, words []frontend.Variable, bitsPerWord int) []frontend.Variable {
	return PackN(api, words, bitsPerWord, (api.Compiler().FieldBitLen()-1)/bitsPerWord)
}

// PackN packs the words wordsPerElem at a time into field elements, and works Big Endian: i.e. the first word is the most significant in the packed elem
// it is on the caller to make sure the words are within range
func PackN(api frontend.API, words []frontend.Variable, bitsPerWord, wordsPerElem int) []frontend.Variable {
	res := make([]frontend.Variable, (len(words)+wordsPerElem-1)/wordsPerElem)

	r := make([]big.Int, wordsPerElem)
	r[wordsPerElem-1].SetInt64(1)
	for i := wordsPerElem - 2; i >= 0; i-- {
		r[i].Lsh(&r[i+1], uint(bitsPerWord))
	}

	for elemI := range res {
		res[elemI] = 0
		for wordI := 0; wordI < wordsPerElem; wordI++ {
			absWordI := elemI*wordsPerElem + wordI
			if absWordI >= len(words) {
				break
			}
			res[elemI] = api.Add(res[elemI], api.Mul(words[absWordI], r[wordI]))
		}
	}
	return res
}

// AssertChecksumEquals takes a MiMC hash of e and asserts it is equal to checksum
func AssertChecksumEquals(api frontend.API, e []frontend.Variable, checksum frontend.Variable) error {
	hsh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hsh.Write(e...)
	api.AssertIsEqual(hsh.Sum(), checksum)
	return nil
}

// ChecksumPaddedBytes packs b into field elements, then hashes the field elements along with validLength (encoded into a field element of its own)
func ChecksumPaddedBytes(b []byte, validLength int, hsh hash.Hash, fieldNbBits int) []byte {
	if validLength < 0 || validLength > len(b) {
		panic("invalid length")
	}
	usableBytesPerElem := (fieldNbBits+7)/8 - 1
	buf := make([]byte, usableBytesPerElem+1)
	for i := 0; i < len(b); i += usableBytesPerElem {
		copy(buf[1:], b[i:])
		for j := usableBytesPerElem; j+i > len(b) && j > 0; j-- {
			buf[j] = 0
		}
		hsh.Write(buf)
	}
	big.NewInt(int64(validLength)).FillBytes(buf)
	hsh.Write(buf)

	return hsh.Sum(nil)
}

// UnpackIntoBytes construes every element in packed as consisting of bytesPerElem bytes, returning those bytes
// it DOES NOT prove that the elements in unpacked are actually bytes
// nbBytes is the number of "valid" bytes according to the padding scheme in https://github.com/Consensys/zkevm-monorepo/blob/main/prover/lib/compressor/blob/blob_maker.go#L299
// TODO @tabaie @gbotrel move the padding/packing code to gnark or compress
// the very last non-zero byte in the unpacked stream is meant to encode the number of unused bytes in the last field element used.
// though UnpackIntoBytes includes that last byte in unpacked, it is not counted in nbBytes
func UnpackIntoBytes(api frontend.API, bytesPerElem int, packed []frontend.Variable) (unpacked []frontend.Variable, nbBytes frontend.Variable, err error) {
	if unpacked, err = api.Compiler().NewHint(UnpackIntoBytesHint, bytesPerElem*len(packed), packed...); err != nil {
		return
	}
	found := frontend.Variable(0)
	nbBytes = frontend.Variable(0)
	for i := len(unpacked) - 1; i >= 0; i-- {

		z := api.IsZero(unpacked[i])

		lastNonZero := plonk.EvaluateExpression(api, z, found, -1, -1, 1, 1)   // nz - found
		nbBytes = api.Add(nbBytes, api.Mul(lastNonZero, frontend.Variable(i))) // the last nonzero byte itself is useless

		//api.AssertIsEqual(api.Mul(api.Sub(bytesPerElem-i%bytesPerElem, unpacked[i]), lastNonZero), 0) // sanity check, technically unnecessary TODO @Tabaie make sure it's one constraint only or better yet, remove

		found = plonk.EvaluateExpression(api, z, found, -1, 0, 1, 1) // found ? 1 : nz = nz + found (1 - nz) = 1 - z + found z
	}
	return
}

func UnpackIntoBytesHint(_ *big.Int, ins, outs []*big.Int) error {
	bytesPerElem := len(outs) / len(ins)
	if len(ins)*bytesPerElem != len(outs) {
		return errors.New("in length must divide out length")
	}
	_256 := big.NewInt(256)
	var v big.Int
	for i := range ins {
		v.Set(ins[i])
		for j := bytesPerElem - 1; j >= 0; j-- {
			v.DivMod(&v, _256, outs[i*bytesPerElem+j])
		}
	}
	return nil
}

// ReadNum reads the slice c as a big endian number in base radix
func ReadNum(api frontend.API, c []frontend.Variable, radix *big.Int) frontend.Variable {
	if len(c) == 0 {
		return 0
	}

	res := c[0]
	for i := 1; i < len(c); i++ {
		res = api.Add(c[i], api.Mul(res, radix))
	}

	return res
}

// ShiftLeft erases shiftAmount many elements from the left of Slice and replaces them in the right with zeros
// it is the caller's responsibility to make sure that 0 \le shift < len(c)
func ShiftLeft(api frontend.API, slice []frontend.Variable, shiftAmount frontend.Variable) []frontend.Variable {
	res := make([]frontend.Variable, len(slice))
	l := logderivlookup.New(api)
	for i := range slice {
		l.Insert(slice[i])
	}
	for range slice {
		l.Insert(0)
	}
	for i := range slice {
		res[i] = l.Lookup(api.Add(i, shiftAmount))[0]
	}
	return res
}

// NumReader takes a sequence of words [ b₀ b₁ ... ], along with a base r and length n
// and returns the numbers (b₀ b₁ ... bₙ₋₁)ᵣ, (b₁ b₂ ... bₙ)ᵣ, ... upon successive calls to Next()
type NumReader struct {
	api         frontend.API
	toRead      []frontend.Variable
	radix       *big.Int
	numBound    *big.Int
	wordsPerNum int
	last        frontend.Variable
}

// NewNumReader returns a new NumReader
// toRead is the slice of words to read from
// numNbBits defines the radix as r = 2ⁿᵘᵐᴺᵇᴮⁱᵗˢ (or rather numNbBits = log₂(r) )
// wordNbBits defines the number of bits in each word such that n = numNbBits/wordNbBits
// it is the caller's responsibility to check 0 ≤ bᵢ < r ∀ i
func NewNumReader(api frontend.API, toRead []frontend.Variable, numNbBits, wordNbBits int) *NumReader {
	wordsPerNum := numNbBits / wordNbBits

	if wordsPerNum*wordNbBits != numNbBits {
		panic("wordNbBits must be a divisor of 8")
	}

	return &NumReader{
		api:         api,
		toRead:      toRead,
		radix:       twoPow(wordNbBits),
		numBound:    twoPow(numNbBits),
		wordsPerNum: wordsPerNum,
	}
}

func (nr *NumReader) SetNumNbBits(numNbBits int) {
	wordNbBits := nr.radix.BitLen() - 1 // TODO check
	wordsPerNum := numNbBits / wordNbBits
	if wordsPerNum*wordNbBits != numNbBits {
		panic("numNbBits must be divisible by wordNbBits")
	}
	if wordsPerNum < nr.wordsPerNum {
		panic("decreasing wordsPerNum not supported")
	}

	if nr.last != nil && wordsPerNum > nr.wordsPerNum { // nothing to compensate for if no values have yet been read
		// nr.last currently holds (b₀ b₁ ... bₙ₋₁)ᵣ where n = nr.wordsPerNum and r = nr.radix.
		// it must become (b₀ b₁ ... bₙ'₋₁)ᵣ where n' = wordsPerNum, i.e. the window is widened
		// in place: the reader head stays put and the words bₙ ... bₙ'₋₁ are the ones sitting
		// right after the current window. Words past the end of toRead are taken to be zero,
		// as in next(). Note that toRead is not consumed here: the window it defines always
		// starts at index 0, and next() is what shifts it.
		nbNewWords := wordsPerNum - nr.wordsPerNum
		nr.last = nr.api.Mul(nr.last, twoPow(nbNewWords*wordNbBits)) // × rⁿ'⁻ⁿ
		nbToRead := min(max(len(nr.toRead)-nr.wordsPerNum, 0), nbNewWords)
		if nbToRead > 0 {
			delta := ReadNum(nr.api, nr.toRead[nr.wordsPerNum:nr.wordsPerNum+nbToRead], nr.radix)
			if nbToRead < nbNewWords { // pad the missing least significant words with zeros
				delta = nr.api.Mul(delta, twoPow((nbNewWords-nbToRead)*wordNbBits))
			}
			nr.last = nr.api.Add(nr.last, delta)
		}
	}

	nr.wordsPerNum, nr.numBound = wordsPerNum, twoPow(numNbBits)
}

func twoPow(n int) *big.Int {
	res := big.NewInt(1)
	return res.Lsh(res, uint(n))
}

// Next returns the next number in the sequence and advances the reader head by one word. assumes bits past the end of the Slice are 0
func (nr *NumReader) Next() frontend.Variable {
	return nr.next(nil)
}

// AssertNextEquals is functionally equivalent to
//
//	z := nr.Next()
//	api.AssertIsEqual(v, z)
//
// while saving exactly one constraint
func (nr *NumReader) AssertNextEquals(v frontend.Variable) {
	nr.next(v)
}

// next returns the next number in the sequence.
// if v != nil, it returns v and asserts it is equal to the next number in the sequence (making a petty saving of one constraint by not creating a new variable)
func (nr *NumReader) next(v frontend.Variable) frontend.Variable {
	if len(nr.toRead) == 0 {
		return 0
	}

	if nr.last == nil { // the very first call
		nr.last = ReadNum(nr.api, nr.toRead[:min(len(nr.toRead), nr.wordsPerNum)], nr.radix)
		if v != nil {
			nr.api.AssertIsEqual(nr.last, v)
		}
		return nr.last
	}

	// let r := nr.radix, n := log(nr.maxCoeff)ᵣ
	// then (b₁ b₂ ... bₙ)ᵣ = r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
	nr.last = nr.api.Sub(nr.api.Mul(nr.last, nr.radix), nr.api.Mul(nr.toRead[0], nr.numBound)) // r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀
	if nr.wordsPerNum < len(nr.toRead) {
		if v == nil { // return r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
			nr.last = nr.api.Add(nr.last, nr.toRead[nr.wordsPerNum])
		} else { // assert v = r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
			plonk.AddConstraint(nr.api, nr.last, nr.toRead[nr.wordsPerNum], v, 1, 1, -1, 0, 0)
			nr.last = v
		}
	} else if v != nil {
		panic("todo refactoring required")
	}

	nr.toRead = nr.toRead[1:]
	return nr.last
}
