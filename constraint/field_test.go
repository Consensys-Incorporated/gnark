package constraint

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/stretchr/testify/require"
)

const (
	testCaseRandom = iota
	testCaseZero
	testCaseOne
	testCaseNegOne
)

func TestNewElementRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		scenario int
	}{
		{testCaseRandom},
		{testCaseZero},
		{testCaseOne},
		{testCaseNegOne},
	} {
		t.Run(fmt.Sprintf("case=%d", tc.scenario), func(t *testing.T) {
			var r1 fr_bn254.Element  // [4]uint64
			var r2 fr_bw6761.Element // [6]uint64
			var r3 babybear.Element  // [1]uint32

			switch tc.scenario {
			case testCaseRandom:
				r1.SetRandom()
				r2.SetRandom()
				r3.SetRandom()
			case testCaseZero:
				r1.SetZero()
				r2.SetZero()
				r3.SetZero()
			case testCaseOne:
				r1.SetOne()
				r2.SetOne()
				r3.SetOne()
			case testCaseNegOne:
				r1.SetOne()
				r1.Neg(&r1)
				r2.SetOne()
				r2.Neg(&r2)
				r3.SetOne()
				r3.Neg(&r3)
			}

			r1b := r1.Bytes()
			r2b := r2.Bytes()
			r3b := r3.Bytes()

			r1bp := append(r1b[:], make([]byte, 48-len(r1b))...)

			e1 := NewElement[U64](r1bp[:])
			e2 := NewElement[U64](r2b[:])
			e3 := NewElement[U32](r3b[:])

			e1b := e1.Bytes()
			e2b := e2.Bytes()
			e3b := e3.Bytes()

			if len(e1b) != len(r1bp) {
				t.Fatalf("expected %d, got %d", len(r1bp), len(e1b))
			}
			if len(e1b[:32]) != len(r1b) {
				t.Fatalf("expected %d, got %d", len(r1b), len(e1b[:32]))
			}
			if len(e2b) != len(r2b) {
				t.Fatalf("expected %d, got %d", len(r2b), len(e2b))
			}
			if len(e3b) != len(r3b) {
				t.Fatalf("expected %d, got %d", len(r3b), len(e3b))
			}

			if !bytes.Equal(e1b[:32], r1b[:]) {
				t.Fatalf("expected %x, got %x", r1b, e1b)
			}
			if !bytes.Equal(e1b, r1bp[:]) {
				t.Fatalf("expected %x, got %x", r1bp, e1b)
			}
			if !bytes.Equal(e2b, r2b[:]) {
				t.Fatalf("expected %x, got %x", r2b, e2b)
			}
			if !bytes.Equal(e3b, r3b[:]) {
				t.Fatalf("expected %x, got %x", r3b, e3b)
			}
		})
	}

}

func TestFitsElement(t *testing.T) {
	type tc struct {
		isU32        bool
		field        *big.Int
		expectedFits bool
	}
	var tcs []tc
	for _, c := range gnark.Curves() {
		tcs = append(tcs, tc{
			isU32:        false,
			field:        c.ScalarField(),
			expectedFits: true},
			tc{
				isU32:        true,
				field:        c.ScalarField(),
				expectedFits: false,
			})
	}
	for _, c := range smallfields.Supported() {
		// A small field is represented in U32 only if it fits a single uint32.
		// Wider small fields, such as the 49-bit mamabear, use U64.
		fitsU32 := c.BitLen() <= 32
		tcs = append(tcs,
			tc{
				isU32:        true,
				field:        c,
				expectedFits: fitsU32},
			tc{
				isU32:        false,
				field:        c,
				expectedFits: !fitsU32,
			})
	}
	for _, tc := range tcs {
		t.Run(fmt.Sprintf("isU32=%v,field=%s", tc.isU32, tc.field), func(t *testing.T) {
			var res bool
			if tc.isU32 {
				res = FitsElement[U32](tc.field)
			} else {
				res = FitsElement[U64](tc.field)
			}
			if res != tc.expectedFits {
				t.Fatalf("expected %v, got %v", tc.expectedFits, res)
			}
		})
	}
}

func TestNewElement(t *testing.T) {
	assert := require.New(t)
	assert.Panics(func() {
		NewElement[U64](nil)
	})
	assert.Panics(func() {
		NewElement[U32](nil)
	})
	for _, l := range []int{0, 1, 2, 3, 5, 6} {
		assert.Panics(func() {
			NewElement[U32](make([]byte, l))
		})
	}
	for _, l := range []int{0, 1, 2, 3, 4, 5, 7, 8, 9} {
		assert.Panics(func() {
			NewElement[U64](make([]byte, l))
		})
	}
}
