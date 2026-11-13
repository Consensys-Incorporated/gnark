package compress_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/internal"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func TestShiftLeft(t *testing.T) {
	for n := 4; n < 20; n++ {
		b := make([]byte, n)
		_, err := rand.Read(b)
		assert.NoError(t, err)

		shiftAmount, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		assert.NoError(t, err)

		shifted := make([]byte, n)
		for i := range shifted {
			if j := i + int(shiftAmount.Int64()); j < len(shifted) {
				shifted[i] = b[j]
			} else {
				shifted[i] = 0
			}
		}

		circuit := shiftLeftCircuit{
			Slice:   make([]frontend.Variable, len(b)),
			Shifted: make([]frontend.Variable, len(shifted)),
		}

		assignment := shiftLeftCircuit{
			Slice:       internal.ToVariableSlice(b),
			Shifted:     internal.ToVariableSlice(shifted),
			ShiftAmount: shiftAmount,
		}

		test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
	}
}

func BenchmarkShiftLeft(b *testing.B) {
	const n = 128 * 1024

	circuit := shiftLeftCircuit{
		Slice:   make([]frontend.Variable, n),
		Shifted: make([]frontend.Variable, n),
	}

	p := profile.Start()
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(b, err)
	p.Stop()
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

type shiftLeftCircuit struct {
	Slice       []frontend.Variable
	Shifted     []frontend.Variable
	ShiftAmount frontend.Variable
}

func (c *shiftLeftCircuit) Define(api frontend.API) error {
	if len(c.Slice) != len(c.Shifted) {
		panic("witness length mismatch")
	}
	shifted := compress.ShiftLeft(api, c.Slice, c.ShiftAmount)
	if len(shifted) != len(c.Shifted) {
		panic("wrong length")
	}
	for i := range shifted {
		api.AssertIsEqual(c.Shifted[i], shifted[i])
	}
	return nil
}

func TestChecksumBytes(t *testing.T) {

	for n := 1; n < 100; n++ {
		b := make([]byte, n)
		_, err := rand.Read(b)
		assert.NoError(t, err)

		checksum := compress.ChecksumPaddedBytes(b, len(b), hash.MIMC_BLS12_377.New(), fr.Bits)

		circuit := checksumTestCircuit{
			Bytes: make([]frontend.Variable, len(b)),
		}

		assignment := checksumTestCircuit{
			Bytes: internal.ToVariableSlice(b),
			Sum:   checksum,
		}

		test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	}
}

type checksumTestCircuit struct {
	Bytes []frontend.Variable
	Sum   frontend.Variable
}

func (c *checksumTestCircuit) Define(api frontend.API) error {
	Packed := append(compress.Pack(api, c.Bytes, 8), len(c.Bytes))
	return compress.AssertChecksumEquals(api, Packed, c.Sum)
}

func TestSetNumNbBits(t *testing.T) {

	runTest := func(words, increases []byte, nums []uint64) {
		test.NewAssert(t).CheckCircuit(
			&testSetNumNbBitsCircuit{
				increases:  increases,
				wordNbBits: 1,
				Words:      make([]frontend.Variable, len(words)),
				Nums:       make([]frontend.Variable, len(nums)),
			},
			test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.PLONK),
			test.WithValidAssignment(&testSetNumNbBitsCircuit{
				increases:  increases,
				wordNbBits: 1,
				Words:      internal.ToVariableSlice(words),
				Nums:       internal.ToVariableSlice(nums),
			}))
	}

	for n := 0; n < 1000; n++ {
		const maxNbWords = 1000
		buf := make([]byte, (maxNbWords+7)/8)

		// action plan
		_, err := rand.Read(buf)
		assert.NoError(t, err)
		nbWordsUsed := 0 // starting with one word per num
		nbWordsPerNum := 1
		increases := make([]byte, 0)
		for nbWordsUsed < maxNbWords && nbWordsPerNum < 64 && len(increases) < len(buf) {
			inc := buf[len(increases)] % 3 % 2 // double mod to make 0 more likely TODO try other increase values too
			nbWordsPerNum += int(inc)
			if nbWordsPerNum >= 64 {
				inc = byte(nbWordsPerNum) - 63
				nbWordsPerNum = 63
			}

			increases = append(increases, inc)
			nbWordsUsed += nbWordsPerNum
		}

		words := make([]byte, nbWordsUsed) // random bits
		_, err = rand.Read(buf[:min((nbWordsUsed+7)/8, len(buf))])
		assert.NoError(t, err)
		for i := range words {
			if i < len(buf)*8 {
				words[i] = (buf[i/8] >> (i % 8)) & 1
			}
		}

		nbWordsPerNum = 1
		nums := make([]uint64, len(increases))
		for i := range nums {
			nbWordsPerNum += int(increases[i])
			for j := 0; j < nbWordsPerNum && (i+j) < len(words); j++ {
				nums[i] |= uint64(words[i+j]) << (nbWordsPerNum - j - 1)
			}
		}

		runTest(words, increases, nums)
	}
}

// numReaderNums is a native reference implementation of NumReader: it returns the
// numbers read by a reader that starts with numNbBits bits per number and is resized
// by increases[i] bits (a multiple of wordNbBits) before each read.
// The words are assumed to lie in [0, 2^wordNbBits) and to be numerous enough that the
// sliding window never runs past the end of the slice.
func numReaderNums(words []uint64, wordNbBits, numNbBits int, increases []byte) []uint64 {
	radix := uint64(1) << wordNbBits
	nums := make([]uint64, len(increases))
	head := -1 // the reader head is moved to 0 by the very first Next
	for i, inc := range increases {
		numNbBits += int(inc)
		wordsPerNum := numNbBits / wordNbBits
		head++
		for j := 0; j < wordsPerNum; j++ {
			nums[i] = nums[i]*radix + words[head+j]
		}
	}
	return nums
}

// TestSetNumNbBitsAfterNext covers NumReader.SetNumNbBits called once the reader is
// already running, i.e. after Next has been called at least once. In that case the
// number currently held must be widened in place: (b₀ ... bₙ₋₁)ᵣ becomes
// (b₀ ... bₙ'₋₁)ᵣ, the extra words bₙ ... bₙ'₋₁ being the ones sitting right after the
// current window, and the reader head must not move.
func TestSetNumNbBitsAfterNext(t *testing.T) {
	// for each read, by how many words the window is widened
	schedules := [][]int{
		{0, 1, 0, 0, 1, 0},
		{0, 2, 0, 1, 0, 0},
		{1, 0, 0, 2, 0, 1},
		{0, 0, 1, 1, 1, 0},
		{0, 3, 0, 0, 2, 0},
	}

	for _, wordNbBits := range []int{1, 2, 4, 8} {
		for s, schedule := range schedules {
			t.Run(fmt.Sprintf("wordNbBits=%d/schedule=%d", wordNbBits, s), func(t *testing.T) {
				words := make([]uint64, len(schedule)+8)
				for i := range words {
					w, err := rand.Int(rand.Reader, big.NewInt(int64(1)<<wordNbBits))
					assert.NoError(t, err)
					words[i] = w.Uint64()
				}

				increases := make([]byte, len(schedule))
				for i := range increases {
					increases[i] = byte(schedule[i] * wordNbBits)
				}

				nums := numReaderNums(words, wordNbBits, wordNbBits, increases)

				test.NewAssert(t).CheckCircuit(
					&testSetNumNbBitsCircuit{
						increases:  increases,
						wordNbBits: wordNbBits,
						Words:      make([]frontend.Variable, len(words)),
						Nums:       make([]frontend.Variable, len(nums)),
					},
					test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.PLONK),
					test.WithValidAssignment(&testSetNumNbBitsCircuit{
						increases:  increases,
						wordNbBits: wordNbBits,
						Words:      internal.ToVariableSlice(words),
						Nums:       internal.ToVariableSlice(nums),
					}))
			})
		}
	}
}

type testSetNumNbBitsCircuit struct {
	increases  []byte
	wordNbBits int
	Words      []frontend.Variable
	Nums       []frontend.Variable
}

func (c *testSetNumNbBitsCircuit) Define(api frontend.API) error {
	if len(c.increases) != len(c.Nums) {
		return errors.New("must have as many steps as read values")
	}
	l := c.wordNbBits
	nr := compress.NewNumReader(api, c.Words, l, c.wordNbBits)
	for i := range c.increases {
		l += int(c.increases[i])
		nr.SetNumNbBits(l)
		api.AssertIsEqual(c.Nums[i], nr.Next())
	}
	return nil
}
