package expand

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type expandMsgXmdCircuit struct {
	Msg      []uints.U8
	Dst      []byte
	Len      int
	Expected []uints.U8
}

type expandMsgXmdTestCase struct {
	msg             string
	lenInBytes      int
	uniformBytesHex string
}

func (c *expandMsgXmdCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	expanded, err := ExpandMsgXmd(api, c.Msg, c.Dst, c.Len)
	if err != nil {
		return err
	}

	for i := 0; i < c.Len; i++ {
		uapi.ByteAssertEq(expanded[i], c.Expected[i])
	}

	return nil
}

// adapted from gnark-crypto/field/hash/hashutils_test.go
func TestExpandMsgXmd(t *testing.T) {
	assert := test.NewAssert(t)
	//name := "expand_message_xmd"
	dst := "QUUX-V01-CS02-with-expander-SHA256-128"
	//hash := "SHA256"
	//k := 128

	testCases := []expandMsgXmdTestCase{
		{
			"",
			0x20,
			"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
		},

		{
			"abc",
			0x20,
			"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
		},

		{
			"abcdef0123456789",
			0x20,
			"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
		},

		{
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			0x20,
			"b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
		},

		{
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			0x20,
			"4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
		},
		{
			"",
			0x80,
			"af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
		},
		{
			"",
			0x20,
			"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
		},
		{
			"abc",
			0x80,
			"abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
		},
		{
			"abcdef0123456789",
			0x80,
			"ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
		},
		{
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			0x80,
			"80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
		},
		{
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			0x80,
			"546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487",
		},
		//test cases not in the standard
		{
			"",
			0x30,
			"3808e9bb0ade2df3aa6f1b459eb5058a78142f439213ddac0c97dcab92ae5a8408d86b32bbcc87de686182cbdf65901f",
		},
		{
			"abc",
			0x30,
			"2b877f5f0dfd881405426c6b87b39205ef53a548b0e4d567fc007cb37c6fa1f3b19f42871efefca518ac950c27ac4e28",
		},
		{
			"abcdef0123456789",
			0x30,
			"226da1780b06e59723714f80da9a63648aebcfc1f08e0db87b5b4d16b108da118214c1450b0e86f9cefeb44903fd3aba",
		},
		{
			"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			0x30,
			"12b23ae2e888f442fd6d0d85d90a0d7ed5337d38113e89cdc7c22db91bd0abaec1023e9a8f0ef583a111104e2f8a0637",
		},
		{
			"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			0x30,
			"1aaee90016547a85ab4dc55e4f78a364c2e239c0e58b05753453c63e6e818334005e90d9ce8f047bddab9fbb315f8722",
		},
	}

	for _, testCase := range testCases {
		uniformBytes, err := hex.DecodeString(testCase.uniformBytesHex)
		assert.NoError(err, "failed to decode uniform bytes hex")
		circuit := expandMsgXmdCircuit{
			Msg:      make([]uints.U8, len(testCase.msg)),
			Dst:      []uint8(dst),
			Len:      testCase.lenInBytes,
			Expected: make([]uints.U8, len(uniformBytes)),
		}
		witness := expandMsgXmdCircuit{
			Msg:      uints.NewU8Array([]byte(testCase.msg)),
			Expected: uints.NewU8Array(uniformBytes),
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "circuit should be solved")
	}
}

// expandMsgXmdSHA256 follows RFC 9380 section 5.3.1, gnark-crypto's version
// panics for lenInBytes < 32 as well.
func expandMsgXmdSHA256(msg, dst []byte, lenInBytes int) []byte {
	ell := (lenInBytes + 31) / 32
	dstPrime := append(append([]byte{}, dst...), byte(len(dst)))
	h := sha256.New()
	h.Write(make([]byte, h.BlockSize()))
	h.Write(msg)
	h.Write([]byte{byte(lenInBytes >> 8), byte(lenInBytes), 0})
	h.Write(dstPrime)
	b0 := h.Sum(nil)
	bi := b0
	var out []byte
	for i := 1; i <= ell; i++ {
		x := make([]byte, len(b0))
		for j := range x {
			x[j] = b0[j]
			if i > 1 {
				x[j] ^= bi[j]
			}
		}
		h.Reset()
		h.Write(x)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bi = h.Sum(nil)
		out = append(out, bi...)
	}
	return out[:lenInBytes]
}

func TestExpandMsgXmdShortOutput(t *testing.T) {
	assert := test.NewAssert(t)
	dst := []byte("QUUX-V01-CS02-with-expander-SHA256-128")
	msg := []byte("abc")
	assert.Equal("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615", hex.EncodeToString(expandMsgXmdSHA256(msg, dst, 32)))
	for _, l := range []int{1, 16, 31} {
		expected := expandMsgXmdSHA256(msg, dst, l)
		circuit := &expandMsgXmdCircuit{Msg: make([]uints.U8, len(msg)), Dst: dst, Len: l, Expected: make([]uints.U8, l)}
		witness := &expandMsgXmdCircuit{Msg: uints.NewU8Array(msg), Dst: dst, Len: l, Expected: uints.NewU8Array(expected)}
		err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
		assert.NoError(err, "lenInBytes=%d", l)
	}
}
