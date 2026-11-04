package sha3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// This file contains soundness regression tests for FixedLengthSum. Each test
// assigns a witness that does not describe the honest hash of In[:Length],
// together with a malicious remainder hint, and checks that the constraint
// system rejects it.

// nativeKeccakF1600 is a compact reference Keccak-f[1600] permutation. It is
// checked against golang.org/x/crypto/sha3 in [TestNativeSpongeReference].
func nativeKeccakF1600(a *[25]uint64) {
	rc := [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
		0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}
	rotc := [24]uint{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
	piln := [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}
	rotl := func(x uint64, n uint) uint64 { return x<<n | x>>(64-n) }
	var bc [5]uint64
	for r := range 24 {
		for i := range 5 {
			bc[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20]
		}
		for i := range 5 {
			t := bc[(i+4)%5] ^ rotl(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				a[j+i] ^= t
			}
		}
		t := a[1]
		for i := range 24 {
			j := piln[i]
			t, a[j] = a[j], rotl(t, rotc[i])
		}
		for j := 0; j < 25; j += 5 {
			for i := range 5 {
				bc[i] = a[j+i]
			}
			for i := range 5 {
				a[j+i] ^= ^bc[(i+1)%5] & bc[(i+2)%5]
			}
		}
		a[0] ^= rc[r]
	}
}

// nativeSpongeRaw absorbs the already padded input (len(padded) must be a
// multiple of rate) without adding any padding and squeezes outLen bytes.
func nativeSpongeRaw(padded []byte, rate, outLen int) []byte {
	if len(padded)%rate != 0 {
		panic("padded input not a multiple of rate")
	}
	var st [25]uint64
	for len(padded) > 0 {
		for i := 0; i < rate/8; i++ {
			st[i] ^= binary.LittleEndian.Uint64(padded[8*i:])
		}
		nativeKeccakF1600(&st)
		padded = padded[rate:]
	}
	out := make([]byte, 25*8)
	for i := range st {
		binary.LittleEndian.PutUint64(out[8*i:], st[i])
	}
	return out[:outLen]
}

// nativePad applies the honest pad10*1 padding with domain separation byte.
func nativePad(msg []byte, dsbyte byte, rate int) []byte {
	q := rate - len(msg)%rate
	padded := append(bytes.Clone(msg), make([]byte, q)...)
	padded[len(msg)] ^= dsbyte
	padded[len(padded)-1] ^= 0x80
	return padded
}

type fixedLengthParams struct {
	dsbyte byte
	rate   int
}

var fixedLengthParamsByName = map[string]fixedLengthParams{
	"SHA3-256":   {0x06, 136},
	"SHA3-384":   {0x06, 104},
	"SHA3-512":   {0x06, 72},
	"Keccak-256": {0x01, 136},
	"Keccak-512": {0x01, 72},
}

func TestNativeSpongeReference(t *testing.T) {
	msg := []byte("the quick brown fox jumps over the lazy dog, again and again and again")
	for name, tc := range testCases {
		p := fixedLengthParamsByName[name]
		for _, l := range []int{0, 1, len(msg)} {
			h := tc.native()
			h.Write(msg[:l])
			want := h.Sum(nil)
			got := nativeSpongeRaw(nativePad(msg[:l], p.dsbyte, p.rate), p.rate, len(want))
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: reference sponge mismatch for length %d", name, l)
			}
		}
	}
}

// signedRemHint is a malicious replacement for remHint. It interprets x as a
// signed integer in (-P/2, P/2] and returns its Euclidean remainder modulo
// rate, shifted by offset. With offset = 0 and honest (small, non-negative)
// x it agrees with remHint.
func signedRemHint(offset int64) solver.Hint {
	return func(mod *big.Int, inputs, outputs []*big.Int) error {
		rate, x := inputs[0], new(big.Int).Set(inputs[1])
		half := new(big.Int).Rsh(mod, 1)
		if x.Cmp(half) > 0 {
			x.Sub(x, mod)
		}
		r := new(big.Int).Mod(x, rate) // Euclidean, in [0, rate)
		r.Add(r, big.NewInt(offset))
		outputs[0].Mod(r, mod)
		return nil
	}
}

// forgery describes a malicious witness for FixedLengthSum.
type forgery struct {
	name   string
	length *big.Int // assigned Length (field element)
	hint   solver.Hint
	digest []byte // the digest the malicious prover claims
}

// negativeLengthForgeries returns forgeries with Length = P - k. With the
// remainder hint returning rate - k we get quotient = -1, no padding is
// written, bytes 1.. are zeroed and the result is Keccak-f(in[0] || 0...0).
func negativeLengthForgeries(field *big.Int, in []byte, p fixedLengthParams, outLen int) []forgery {
	block := make([]byte, p.rate)
	block[0] = in[0]
	digest := nativeSpongeRaw(block, p.rate, outLen)
	var res []forgery
	for _, k := range []int64{1, 2, int64(p.rate) / 2, int64(p.rate)} {
		res = append(res, forgery{
			name:   fmt.Sprintf("length=P-%d", k),
			length: new(big.Int).Sub(field, big.NewInt(k)),
			hint:   signedRemHint(0),
			digest: digest,
		})
	}
	return res
}

// negativeRemainderForgery returns a forgery for an honest length L where the
// remainder hint returns (L mod rate) - rate, i.e. a negative remainder. The
// one-sided check remainder < rate accepts it when L mod rate >= 2*rate -
// 2^bitlen(rate). Then quotient = L/rate + 1 and the padding is moved one
// block further, yielding a second digest for the same input. It picks the
// largest such L <= len(in) and returns false if there is none.
func negativeRemainderForgery(in []byte, p fixedLengthParams, outLen int) (forgery, bool) {
	maxLen := len(in)
	maxTotalLen := maxLen + p.rate - maxLen%p.rate
	threshold := 2*p.rate - (1 << big.NewInt(int64(p.rate)).BitLen())
	length := maxLen
	for length >= 0 && length%p.rate < threshold {
		length--
	}
	if length < 0 {
		return forgery{}, false
	}
	q0, r0 := length/p.rate, length%p.rate
	padded := make([]byte, maxTotalLen)
	copy(padded, in[:length])
	padded[length] = p.dsbyte
	if lastPos := (q0+2)*p.rate - 1; lastPos < maxTotalLen {
		padded[lastPos] = 0x80
	}
	nbBlocks := min(q0+2, maxTotalLen/p.rate)
	return forgery{
		name:   fmt.Sprintf("length=%d/remainder=%d", length, r0-p.rate),
		length: big.NewInt(int64(length)),
		hint:   signedRemHint(-int64(p.rate)),
		digest: nativeSpongeRaw(padded[:nbBlocks*p.rate], p.rate, outLen),
	}, true
}

func TestSHA3FixedLengthSumForgery(t *testing.T) {
	assert := test.NewAssert(t)
	// 40 bytes: shorter than all rates. 170 bytes: spans two blocks for
	// rate=136 and three blocks for rate 72/104.
	inputs := map[string][]byte{}
	for _, n := range []int{40, 170} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i*7 + 1)
		}
		inputs[fmt.Sprintf("maxLen=%d", n)] = in
	}
	fields := map[string]*big.Int{
		"BN254":     ecc.BN254.ScalarField(),
		"BLS12-377": ecc.BLS12_377.ScalarField(),
		"BLS12-381": ecc.BLS12_381.ScalarField(),
		"BW6-761":   ecc.BW6_761.ScalarField(),
	}
	remHintID := solver.GetHintID(remHint)

	for hname, tc := range testCases {
		p := fixedLengthParamsByName[hname]
		outLen := tc.native().Size()
		for iname, in := range inputs {
			for fname, field := range fields {
				forgeries := negativeLengthForgeries(field, in, p, outLen)
				if f, ok := negativeRemainderForgery(in, p, outLen); ok {
					forgeries = append(forgeries, f)
				}
				circuit := &sha3FixedLengthSumCircuit{
					In:       make([]uints.U8, len(in)),
					Expected: make([]uints.U8, outLen),
					hasher:   hname,
				}
				for _, f := range forgeries {
					assert.Run(func(assert *test.Assert) {
						// sanity: the forged digest is not the honest digest of any prefix
						for l := 0; l <= len(in); l++ {
							h := tc.native()
							h.Write(in[:l])
							assert.NotEqual(h.Sum(nil), f.digest, "forged digest equals honest digest of in[:%d]", l)
						}
						witness := &sha3FixedLengthSumCircuit{
							In:       uints.NewU8Array(in),
							Expected: uints.NewU8Array(f.digest),
							Length:   f.length,
						}
						err := test.IsSolved(circuit, witness, field, test.WithReplacementHint(remHintID, f.hint))
						assert.Error(err, "forged witness accepted")
					}, hname, iname, fname, f.name)
				}
			}
		}
	}
}

// TestSHA3FixedLengthSumForgeryCompiled checks the same forgeries against the
// compiled constraint systems (R1CS and PLONK) on BN254, to make sure the
// soundness also holds outside of the test engine.
func TestSHA3FixedLengthSumForgeryCompiled(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()
	in := make([]byte, 40)
	for i := range in {
		in[i] = byte(i*7 + 1)
	}
	const hname = "Keccak-256"
	p := fixedLengthParamsByName[hname]
	outLen := testCases[hname].native().Size()
	forgeries := negativeLengthForgeries(field, in, p, outLen)
	f, ok := negativeRemainderForgery(in, p, outLen)
	assert.True(ok)
	forgeries = append(forgeries, f)
	remHintID := solver.GetHintID(remHint)

	for _, builder := range []string{"r1cs", "scs"} {
		circuit := &sha3FixedLengthSumCircuit{
			In:       make([]uints.U8, len(in)),
			Expected: make([]uints.U8, outLen),
			hasher:   hname,
		}
		var ccs constraint.ConstraintSystem
		var err error
		if builder == "r1cs" {
			ccs, err = frontend.Compile(field, r1cs.NewBuilder, circuit)
		} else {
			ccs, err = frontend.Compile(field, scs.NewBuilder, circuit)
		}
		assert.NoError(err)

		// honest witness must still be accepted
		for _, l := range []int{0, 1, len(in) - 1, len(in)} {
			h := testCases[hname].native()
			h.Write(in[:l])
			w, err := frontend.NewWitness(&sha3FixedLengthSumCircuit{
				In:       uints.NewU8Array(in),
				Expected: uints.NewU8Array(h.Sum(nil)),
				Length:   l,
			}, field)
			assert.NoError(err)
			assert.NoError(ccs.IsSolved(w), "%s: honest length %d rejected", builder, l)
		}

		for _, f := range forgeries {
			assert.Run(func(assert *test.Assert) {
				w, err := frontend.NewWitness(&sha3FixedLengthSumCircuit{
					In:       uints.NewU8Array(in),
					Expected: uints.NewU8Array(f.digest),
					Length:   f.length,
				}, field)
				assert.NoError(err)
				err = ccs.IsSolved(w, solver.OverrideHint(remHintID, f.hint))
				assert.Error(err, "forged witness accepted")
			}, builder, f.name)
		}
	}
}

// TestSHA3FixedLengthSumInvalidMinimalLength checks that a minimal length
// larger than the input is rejected at compile time instead of silently
// producing an unsatisfiable circuit.
func TestSHA3FixedLengthSumInvalidMinimalLength(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &sha3FixedLengthSumCircuit{
		In:            make([]uints.U8, 40),
		Expected:      make([]uints.U8, 32),
		hasher:        "Keccak-256",
		minimalLength: 41,
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.ErrorContains(err, "minimal length 41 not in [0, 40]")
}

// TestSHA3NegativeMinimalLength checks that all constructors return an error
// for a negative minimal length, rather than failing later (or never) when
// FixedLengthSum is called.
func TestSHA3NegativeMinimalLength(t *testing.T) {
	assert := test.NewAssert(t)
	for name := range testCases {
		assert.Run(func(assert *test.Assert) {
			circuit := &sha3FixedLengthSumCircuit{
				In:            make([]uints.U8, 40),
				Expected:      make([]uints.U8, 32),
				hasher:        name,
				minimalLength: -1,
			}
			_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
			assert.ErrorContains(err, "minimal length must be non-negative, got -1")
		}, name)
	}
}
