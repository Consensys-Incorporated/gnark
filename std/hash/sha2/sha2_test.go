package sha2

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (c *sha2Circuit) Define(api frontend.API) error {
	h, err := New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.AssertIsEqual(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA2(t *testing.T) {
	bts := make([]byte, 310)
	dgst := sha256.Sum256(bts)
	witness := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))
	err := test.IsSolved(&sha2Circuit{In: make([]uints.U8, len(bts))}, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
}

type sha2FixedLengthCircuit struct {
	In       []uints.U8
	Length   frontend.Variable
	Expected [32]uints.U8

	// minimal length of the input is the circuit parameter
	minimalLength int
}

func (c *sha2FixedLengthCircuit) Define(api frontend.API) error {
	h, err := New(api, hash.WithMinimalLength(c.minimalLength))
	if err != nil {
		return err
	}
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.FixedLengthSum(c.Length)
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.AssertIsEqual(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA2FixedLengthSum(t *testing.T) {
	const maxLen = 144
	assert := test.NewAssert(t)
	bts := make([]byte, maxLen)
	_, err := rand.Reader.Read(bts)
	assert.NoError(err)

	for _, lengthBound := range []int{0, 1, 63, 64, 65, len(bts)} {
		circuit := &sha2FixedLengthCircuit{In: make([]uints.U8, len(bts)), minimalLength: lengthBound}
		for _, length := range []int{0, 1, 63, 64, 65, len(bts)} {
			assert.Run(func(assert *test.Assert) {
				dgst := sha256.Sum256(bts[:length])
				witness := &sha2FixedLengthCircuit{
					In:       uints.NewU8Array(bts),
					Length:   length,
					Expected: [32]uints.U8(uints.NewU8Array(dgst[:])),
				}

				err = test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
				if length >= lengthBound {
					assert.NoError(err)
				} else if length < lengthBound {
					assert.Error(err, "expected error for length < lengthBound")
				}
			}, fmt.Sprintf("bound=%d/length=%d", lengthBound, length))
		}
	}
}

// TestSHA2NegativeMinimalLength checks that New returns an error for a
// negative minimal length, rather than panicking later in FixedLengthSum.
func TestSHA2NegativeMinimalLength(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &sha2FixedLengthCircuit{In: make([]uints.U8, 144), minimalLength: -1}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.ErrorContains(err, "minimal length must be non-negative, got -1")
}
