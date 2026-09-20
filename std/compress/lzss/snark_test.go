package lzss

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark/std/compress/internal"

	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNothingRoundTrip(t *testing.T) {
	testCompressionRoundTrip(t, nil, nil)
}

func TestPaddedNothingRoundTrip(t *testing.T) {

	d := []frontend.Variable{0, 0, 0}
	c := []frontend.Variable{0, 1, 0, 255}

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(c)),
		D:                make([]frontend.Variable, len(d)),
		Dict:             nil,
		CheckCorrectness: true,
	}
	assignment := &DecompressionTestCircuit{
		C:       c,
		D:       d,
		CBegin:  0,
		CLength: 3,
		DLength: 0,
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

}

func Test1One(t *testing.T) {
	testCompressionRoundTrip(t, []byte{1}, nil)
}

func TestOneTwo(t *testing.T) {
	testCompressionRoundTrip(t, []byte{1, 2}, nil)
}

func Test0To10Explicit(t *testing.T) {
	testCompressionRoundTrip(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

const inputExtraBytes = 5

func craftExpandingInput(dict []byte, size int) []byte {
	const nbBytesExpandingBlock = 4 // TODO @gbotrel check that

	// the following two methods convert between a byte slice and a number; just for convenient use as map keys and counters
	bytesToNum := func(b []byte) uint64 {
		var res uint64
		for i := range b {
			res += uint64(b[i]) << uint64(i*8)
		}
		return res
	}

	fillNum := func(dst []byte, n uint64) {
		for i := range dst {
			dst[i] = byte(n)
			n >>= 8
		}
	}

	covered := make(map[uint64]struct{}) // combinations present in the dictionary, to avoid
	for i := range dict {
		if dict[i] == 255 {
			covered[bytesToNum(dict[i+1:i+nbBytesExpandingBlock])] = struct{}{}
		}
	}
	isCovered := func(n uint64) bool {
		_, ok := covered[n]
		return ok
	}

	res := make([]byte, size)
	var blockCtr uint64
	for i := 0; i < len(res); i += nbBytesExpandingBlock {
		for isCovered(blockCtr) {
			blockCtr++
			if blockCtr == 0 {
				panic("overflow")
			}
		}
		res[i] = 255
		fillNum(res[i+1:i+nbBytesExpandingBlock], blockCtr)
		blockCtr++
		if blockCtr == 0 {
			panic("overflow")
		}
	}
	return res
}

func TestNoCompression(t *testing.T) {

	dict := getDictionary()

	d := craftExpandingInput(dict, 1000)

	compressor, err := lzss.NewCompressor(dict)
	require.NoError(t, err)
	_, err = compressor.Write(d)
	require.NoError(t, err)

	require.True(t, compressor.ConsiderBypassing(), "not expanding; refer back to the compress repo for an updated craftExpandingInput implementation.")

	c := compressor.Bytes()

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(c)+inputExtraBytes),
		D:                make([]frontend.Variable, len(d)),
		Dict:             dict,
		CheckCorrectness: true,
	}
	assignment := &DecompressionTestCircuit{
		C:       internal.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		D:       internal.ToVariableSlice(d),
		CBegin:  0,
		CLength: len(c),
		DLength: len(d),
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func Test255_254_253(t *testing.T) {
	testCompressionRoundTrip(t, []byte{255, 254, 253}, nil)
}

func Test3c2943(t *testing.T) {
	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	testCompressionRoundTrip(t, d, dict)
}

func Test3c2943withHeader(t *testing.T) {
	d, err := os.ReadFile("./testdata/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	compressor, err := lzss.NewCompressor(dict)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)
	c = append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, c...)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(c)+inputExtraBytes),
		D:                make([]frontend.Variable, len(d)),
		Dict:             dict,
		CheckCorrectness: true,
	}
	assignment := &DecompressionTestCircuit{
		C:       internal.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		D:       internal.ToVariableSlice(d),
		CBegin:  10,
		CLength: len(c) - 10,
		DLength: len(d),
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func TestOutBufTooShort(t *testing.T) {
	const truncationAmount = 3
	d := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	compressor, err := lzss.NewCompressor(nil)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	circuit := decompressionLengthTestCircuit{
		C: make([]frontend.Variable, len(c)+inputExtraBytes),
		D: make([]frontend.Variable, len(d)-truncationAmount), // not enough room

	}

	assignment := decompressionLengthTestCircuit{
		C:               internal.ToVariableSlice(append(c, make([]byte, inputExtraBytes)...)),
		CLength:         len(c),
		D:               internal.ToVariableSlice(d[:len(d)-truncationAmount]),
		ExpectedDLength: -1,
	}

	// Decompress writes into D, so the wires the circuit declares for it are
	// never read by a constraint.
	RegisterHints()
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_377), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

// Fuzz test the decompression
func Fuzz(f *testing.F) { // TODO This is always skipped
	f.Fuzz(func(t *testing.T, input, dict []byte) {
		if len(input) > lzss.MaxInputSize {
			t.Skip("input too large")
		}
		if len(dict) > lzss.MaxDictSize {
			t.Skip("dict too large")
		}
		if len(input) == 0 {
			t.Skip("input too small")
		}
		testCompressionRoundTrip(t, input, dict)
	})
}

type testCompressionRoundTripSettings struct {
	cBegin               int
	compressedPaddingLen int
	compressedPaddedLen  int
	compressed           []byte
}

type testCompressionRoundTripOption func(settings *testCompressionRoundTripSettings)

func withCBegin(cBegin int) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.cBegin = cBegin
	}
}

func withCompressedPaddingLen(compressedPaddingLen int) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.compressedPaddingLen = compressedPaddingLen
	}
}

// withCompressedPaddedLen overrides withCompressedPaddingLen
func withCompressedPaddedLen(compressedPaddedLen int) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.compressedPaddedLen = compressedPaddedLen
	}
}

func withCompressed(compressed []byte) testCompressionRoundTripOption {
	return func(s *testCompressionRoundTripSettings) {
		s.compressed = compressed
	}
}

func checksum(b []byte) string {
	hsh := sha256.New()
	hsh.Write(b)
	sum := hsh.Sum(nil)
	return hex.EncodeToString(sum[:128/8])
}

func testCompressionRoundTrip(t *testing.T, d, dict []byte, options ...testCompressionRoundTripOption) {

	t.Log("using dict", checksum(dict))

	s := testCompressionRoundTripSettings{
		compressedPaddedLen: -1,
	}

	for _, option := range options {
		option(&s)
	}

	if s.compressed == nil {
		compressor, err := lzss.NewCompressor(dict)
		require.NoError(t, err)
		s.compressed, err = compressor.Compress(d)
		require.NoError(t, err)
	}

	t.Log("compressed checksum:", checksum(s.compressed))

	// duplicating tests from the compress repo, for sanity checking
	dBack, err := lzss.Decompress(s.compressed, dict)
	require.NoError(t, err)
	if d == nil {
		d = []byte{}
	}
	assert.Equal(t, d, dBack)

	/*info, err := lzss.CompressedStreamInfo(s.compressed, dict)
	require.NoError(t, err)
	assert.NoError(t, os.WriteFile("compress.csv", info.ToCSV(), 0600))*/

	if s.compressedPaddedLen != -1 {
		s.compressedPaddingLen = s.compressedPaddedLen - len(s.compressed)
		require.LessOrEqual(t, len(s.compressed), s.compressedPaddedLen, "length must not be greater than padded length")
	} else {
		require.GreaterOrEqual(t, s.compressedPaddingLen, 0, "padding length must be non-negative")
	}

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, len(s.compressed)+s.compressedPaddingLen),
		D:                make([]frontend.Variable, len(d)),
		Dict:             dict,
		CheckCorrectness: true,
	}
	assignment := &DecompressionTestCircuit{
		C:       internal.ToVariableSlice(append(s.compressed, make([]byte, s.compressedPaddingLen)...)),
		D:       internal.ToVariableSlice(d),
		CBegin:  s.cBegin,
		CLength: len(s.compressed),
		DLength: len(d),
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func getDictionary() []byte {
	d, err := os.ReadFile("./testdata/dict_naive")
	if err != nil {
		panic(err)
	}
	return d
}

type decompressionLengthTestCircuit struct {
	C, D            []frontend.Variable
	CLength         frontend.Variable
	ExpectedDLength frontend.Variable
}

func (c *decompressionLengthTestCircuit) Define(api frontend.API) error {
	dict := internal.ToVariableSlice(lzss.AugmentDict(nil))
	if dLength, err := Decompress(api, c.C, c.CLength, c.D, dict); err != nil {
		return err
	} else {
		api.AssertIsEqual(dLength, c.ExpectedDLength)
		return nil
	}
}

func TestBuildDecompress1KBto7KB(t *testing.T) {
	// Decompress writes into D, so the wires the circuit declares for it are
	// never read by a constraint.
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &decompressionLengthTestCircuit{
		C: make([]frontend.Variable, 1024),
		D: make([]frontend.Variable, 7*1024),
	}, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(t, err)
	fmt.Println(cs.GetNbConstraints())
}

func TestBuildDecompress1KBto9KB(t *testing.T) {
	// Decompress writes into D, so the wires the circuit declares for it are
	// never read by a constraint.
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &decompressionLengthTestCircuit{
		C: make([]frontend.Variable, 1024),
		D: make([]frontend.Variable, 9*1024),
	}, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(t, err)
	fmt.Println(cs.GetNbConstraints())
}

func TestNoZeroPaddingOutput(t *testing.T) {
	assignment := testNoZeroPaddingOutputCircuit{
		C:    []frontend.Variable{0, 1, 0, 2, 3, 0, 0, 0},
		D:    []frontend.Variable{2, 3, 3},
		CLen: 4,
		DLen: 1,
	}
	circuit := testNoZeroPaddingOutputCircuit{
		C: make([]frontend.Variable, len(assignment.C)),
		D: make([]frontend.Variable, len(assignment.D)),
	}

	RegisterHints()
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type testNoZeroPaddingOutputCircuit struct {
	CLen, DLen frontend.Variable
	C, D       []frontend.Variable
}

func (c *testNoZeroPaddingOutputCircuit) Define(api frontend.API) error {
	dict := []frontend.Variable{254, 255}
	d := make([]frontend.Variable, len(c.D))
	dLen, err := Decompress(api, c.C, c.CLen, d, dict, WithoutZeroPaddingOutput)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.DLen, dLen)
	for i := range c.D {
		api.AssertIsEqual(c.D[i], d[i])
	}
	return nil
}
