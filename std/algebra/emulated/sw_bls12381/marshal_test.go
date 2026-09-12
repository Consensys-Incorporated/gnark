package sw_bls12381

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type unmarshalPoint struct {
	CP []uints.U8
	P  G1Affine
}

func (c *unmarshalPoint) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}

	point, err := g.UnmarshalCompressed(c.CP)
	if err != nil {
		return fmt.Errorf("unmarshal compressed: %w", err)
	}
	g.AssertIsEqual(point, &c.P)
	return nil
}

func TestUnmarshalPoint(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, g, _ := bls12381.Generators()

	// randG1 returns a random G1 point satisfying pred.
	randG1 := func(pred func(*bls12381.G1Affine) bool) bls12381.G1Affine {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		for {
			s.MustSetRandom()
			p.ScalarMultiplication(&g, s.BigInt(b))
			if pred(&p) {
				return p
			}
		}
	}
	anyY := func(*bls12381.G1Affine) bool { return true }
	smallY := func(p *bls12381.G1Affine) bool { return !p.Y.LexicographicallyLargest() }
	largeY := func(p *bls12381.G1Affine) bool { return p.Y.LexicographicallyLargest() }

	infinity := func() bls12381.G1Affine {
		var p bls12381.G1Affine
		p.SetInfinity()
		return p
	}

	// marshal returns the compressed encoding of p as a slice.
	marshal := func(p bls12381.G1Affine) []byte {
		b := p.Bytes()
		return b[:]
	}
	// remask replaces the 3-bit mask of a compressed encoding in place.
	remask := func(b []byte, mask byte) []byte {
		b[0] = (b[0] &^ mMask) | mask
		return b
	}

	type namedCase struct {
		name string
		a    frontend.Circuit
	}
	var valid, invalid []namedCase
	add := func(dst *[]namedCase, name string, cp []byte, p bls12381.G1Affine) {
		*dst = append(*dst, namedCase{name, &unmarshalPoint{CP: uints.NewU8Array(cp), P: NewG1Affine(p)}})
	}

	// -- valid cases
	//  - compressed point, smallest y coordinate
	p := randG1(smallY)
	add(&valid, "valid/small-y", marshal(p), p)
	//  - compressed point, largest y coordinate
	p = randG1(largeY)
	add(&valid, "valid/large-y", marshal(p), p)
	//  - compressed point, infinity
	p = infinity()
	add(&valid, "valid/infinity", marshal(p), p)

	// -- invalid cases:
	//  - compressed point, have smallest y coordinate but mask for largest y coordinate
	p = randG1(smallY)
	pm := marshal(p)
	assert.Equal(mCompressedSmallest, pm[0]&mMask, "mask should be for smallest y coordinate")
	add(&invalid, "invalid/small-y-mask-large-y", remask(pm, mCompressedLargest), p)
	//  - compressed point, have largest y coordinate but mask for smallest y coordinate
	p = randG1(largeY)
	pm = marshal(p)
	assert.Equal(mCompressedLargest, pm[0]&mMask, "mask should be for largest y coordinate")
	add(&invalid, "invalid/large-y-mask-small-y", remask(pm, mCompressedSmallest), p)
	//  - compressed point, have mask for infinity but not infinity
	p = randG1(anyY)
	pm = marshal(p)
	assert.Equal(byte(0b100)<<5, pm[0]&(0b110<<5), "mask should be for compressed point")
	add(&invalid, "invalid/infinity-mask-not-infinity", remask(pm, mCompressedInfinity), p)
	//  - compressed point, mask for smallest y coordinate but point at infinity
	p = infinity()
	pm = marshal(p)
	assert.Equal(mCompressedInfinity, pm[0]&mMask, "mask should be compressed infinity")
	add(&invalid, "invalid/infinity-mask-smallest-y", remask(pm, mCompressedSmallest), p)
	//  - compressed point, mask for largest y coordinate but point at infinity
	p = infinity()
	pm = marshal(p)
	assert.Equal(mCompressedInfinity, pm[0]&mMask, "mask should be compressed infinity")
	add(&invalid, "invalid/infinity-mask-large-y", remask(pm, mCompressedLargest), p)
	//  - compressed point, not in group
	var sfp fp_bls12381.Element
	sfp.MustSetRandom()
	pj := bls12381.GeneratePointNotInG1(sfp)
	p.FromJacobian(&pj)
	pm = marshal(p)
	assert.Equal(byte(0b100)<<5, pm[0]&(0b110<<5), "mask should be compressed regular")
	add(&invalid, "invalid/not-in-group", pm, p)
	//  - compressed point, not on curve
	for {
		p.X.SetRandom()
		p.Y.SetRandom()
		if !p.IsOnCurve() {
			break
		}
	}
	pm = marshal(p)
	assert.Equal(byte(0b100)<<5, pm[0]&(0b110<<5), "mask should be compressed regular")
	add(&invalid, "invalid/not-on-curve", pm, p)

	// -- invalid mask. The mask is 3 bits, so walk every encoding that is not a
	// well-formed compressed point, against both a random point and infinity.
	badMasks := []struct {
		name string
		mask byte
	}{
		{"uncompressed", mUncompressed},                  // 0b000 << 5
		{"uncompressed-infinity", mUncompressedInfinity}, // 0b010 << 5
		{"explicit-invalid-001", 0b001 << 5},
		{"explicit-invalid-011", 0b011 << 5},
		{"explicit-invalid-111", 0b111 << 5},
	}
	for _, bm := range badMasks {
		p = randG1(anyY)
		pm = marshal(p)
		assert.Equal(byte(0b100)<<5, pm[0]&(0b110<<5), "mask should be compressed regular")
		add(&invalid, "invalid/"+bm.name+"-random", remask(pm, bm.mask), p)

		p = infinity()
		pm = marshal(p)
		assert.Equal(mCompressedInfinity, pm[0]&mMask, "mask should be compressed infinity")
		add(&invalid, "invalid/"+bm.name+"-infinity", remask(pm, bm.mask), p)
	}

	// - x coordinate overflows the field
	x := new(big.Int)
	xof := new(big.Int)
	for {
		p = randG1(anyY)
		p.X.BigInt(x)
		xof.Add(x, fp_bls12381.Modulus())     // overflow x coordinate
		if xof.BitLen() <= fp_bls12381.Bits { // to ensure we can fit the mask
			break
		}
	}
	pm = marshal(p)
	var xBytes, xofBytes [bls12381.SizeOfG1AffineCompressed]byte
	xof.FillBytes(xofBytes[:])
	x.FillBytes(xBytes[:])
	xofBytes[0] |= pm[0] & mMask // add the mask
	xBytes[0] |= pm[0] & mMask   // add the mask
	if !bytes.Equal(xBytes[:], pm) {
		assert.Fail("sanity check for correct serialization failed")
	}
	add(&invalid, "invalid/x-overflow", xofBytes[:], p)

	// All of the cases above check the same circuit shape, so they are handed to a
	// single CheckCircuit call: it compiles once per {curve, backend} and then
	// solves every assignment against that one constraint system. Calling
	// CheckCircuit per case instead recompiled the identical circuit 2 curves x 2
	// backends x 21 cases = 84 times, which cost ~93s outside -short -- over half
	// the package. The per-case checks themselves are unchanged; each assignment
	// still gets its own test-engine solve and its own ccs.Solve subtest.
	//
	// CheckCircuit names those subtests valid_witness/invalid_witness (with Go's
	// #NN suffix for repeats), so log the index -> case mapping to keep failures
	// attributable. t.Log output only surfaces on failure or under -v.
	for i, c := range valid {
		if i == 0 {
			t.Logf("valid_witness      -> %s", c.name)
		} else {
			t.Logf("valid_witness#%02d   -> %s", i, c.name)
		}
	}
	for i, c := range invalid {
		if i == 0 {
			t.Logf("invalid_witness    -> %s", c.name)
		} else {
			t.Logf("invalid_witness#%02d -> %s", i, c.name)
		}
	}

	opts := make([]test.TestingOption, 0, len(valid)+len(invalid))
	for _, c := range valid {
		opts = append(opts, test.WithValidAssignment(c.a))
	}
	for _, c := range invalid {
		opts = append(opts, test.WithInvalidAssignment(c.a))
	}
	assert.CheckCircuit(
		&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
		opts...,
	)
}
