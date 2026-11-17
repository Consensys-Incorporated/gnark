package bls

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type blsG2SigCircuit struct {
	Pub PublicKeyG1
	Msg []uints.U8
	Sig SignatureG2
}

func (c *blsG2SigCircuit) Define(api frontend.API) error {
	return c.Pub.Verify(api, &c.Sig, c.Msg)
}

type testCaseG2 struct {
	pubkey string
	msg    string
	sig    string
	output bool
}

// testCasesG2Sig is a list of test vectors for BLS signature verification on G2. Obtained from
// https://github.com/ethereum/bls12-381-tests by parsing tests in `verify/` folder
var testCasesG2Sig = []testCaseG2{
	{"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "1212121212121212121212121212121212121212121212121212121212121212", "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", false},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "abababababababababababababababababababababababababababababababab", "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9ffffffff", false},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "5656565656565656565656565656565656565656565656565656565656565656", "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972ffffffff", false},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "0000000000000000000000000000000000000000000000000000000000000000", "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dffffffff", false},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "5656565656565656565656565656565656565656565656565656565656565656", "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363ffffffff", false},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "5656565656565656565656565656565656565656565656565656565656565656", "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffffffff", false},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "abababababababababababababababababababababababababababababababab", "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5ffffffff", false},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "abababababababababababababababababababababababababababababababab", "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b71ffffffff", false},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "0000000000000000000000000000000000000000000000000000000000000000", "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075effffffff", false},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "0000000000000000000000000000000000000000000000000000000000000000", "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff", false},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "abababababababababababababababababababababababababababababababab", "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9", true},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "5656565656565656565656565656565656565656565656565656565656565656", "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb", true},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "0000000000000000000000000000000000000000000000000000000000000000", "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9", true},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "5656565656565656565656565656565656565656565656565656565656565656", "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe", true},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "5656565656565656565656565656565656565656565656565656565656565656", "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6", true},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "abababababababababababababababababababababababababababababababab", "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df", true},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "abababababababababababababababababababababababababababababababab", "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121", true},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "0000000000000000000000000000000000000000000000000000000000000000", "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115", true},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "0000000000000000000000000000000000000000000000000000000000000000", "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55", true},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "abababababababababababababababababababababababababababababababab", "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df", false},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "5656565656565656565656565656565656565656565656565656565656565656", "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6", false},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "0000000000000000000000000000000000000000000000000000000000000000", "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55", false},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "5656565656565656565656565656565656565656565656565656565656565656", "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb", false},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "5656565656565656565656565656565656565656565656565656565656565656", "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe", false},
	{"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "abababababababababababababababababababababababababababababababab", "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121", false},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "abababababababababababababababababababababababababababababababab", "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9", false},
	{"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f", "0000000000000000000000000000000000000000000000000000000000000000", "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9", false},
	{"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a", "0000000000000000000000000000000000000000000000000000000000000000", "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115", false},
	{"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", "1212121212121212121212121212121212121212121212121212121212121212", "a42ae16f1c2a5fa69c04cb5998d2add790764ce8dd45bf25b29b4700829232052b52352dcff1cf255b3a7810ad7269601810f03b2bc8b68cf289cf295b206770605a190b6842583e47c3d1c0f73c54907bfb2a602157d46a4353a20283018763", true},
}

// blsG2PrehashedCircuit exercises the exported [PublicKeyG1.VerifyG2] directly,
// with the hashed message supplied by the caller instead of being derived from
// the message inside the circuit.
type blsG2PrehashedCircuit struct {
	Pub       PublicKeyG1
	Sig       SignatureG2
	Prehashed sw_bls12381.G2Affine
}

func (c *blsG2PrehashedCircuit) Define(api frontend.API) error {
	return c.Pub.VerifyG2(api, &c.Sig, &c.Prehashed)
}

// TestVerifyG2RejectsInfinityMessage is a regression test for the degenerate
// case where both the caller-supplied hashed message and the signature are the
// point at infinity. In that case the pairing check reduces to e(-G₁, O)·e(pk,
// O) = 1·1 = 1 which holds for *any* public key, i.e. a universal forgery for
// callers of the exported VerifyG2 that do not themselves constrain the
// prehashed point.
func TestVerifyG2RejectsInfinityMessage(t *testing.T) {
	assert := test.NewAssert(t)

	// a valid, non-infinity public key from the test vectors above
	pubB, err := hex.DecodeString("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a")
	assert.NoError(err)
	var pub bls12381.G1Affine
	_, err = pub.SetBytes(pubB)
	assert.NoError(err)

	// the point at infinity in affine coordinates is represented as (0, 0)
	var inf bls12381.G2Affine

	err = test.IsSolved(&blsG2PrehashedCircuit{}, &blsG2PrehashedCircuit{
		Pub:       PublicKeyG1(sw_bls12381.NewG1Affine(pub)),
		Sig:       SignatureG2(sw_bls12381.NewG2Affine(inf)),
		Prehashed: sw_bls12381.NewG2Affine(inf),
	}, ecc.BN254.ScalarField())
	assert.Error(err, "VerifyG2 must reject the point at infinity as the hashed message")
}

// TestVerifyG2PrehashedCompleteness checks that the infinity check added for
// the test above does not break the honest path through VerifyG2.
func TestVerifyG2PrehashedCompleteness(t *testing.T) {
	assert := test.NewAssert(t)

	tc := testCasesG2Sig[len(testCasesG2Sig)-1]
	assert.True(tc.output, "expected a positive test vector")

	pubB, err := hex.DecodeString(tc.pubkey)
	assert.NoError(err)
	msgB, err := hex.DecodeString(tc.msg)
	assert.NoError(err)
	sigB, err := hex.DecodeString(tc.sig)
	assert.NoError(err)

	var pub bls12381.G1Affine
	_, err = pub.SetBytes(pubB)
	assert.NoError(err)
	var sig bls12381.G2Affine
	_, err = sig.SetBytes(sigB)
	assert.NoError(err)

	h, err := bls12381.HashToG2(msgB, []byte(g2_dst))
	assert.NoError(err)

	err = test.IsSolved(&blsG2PrehashedCircuit{}, &blsG2PrehashedCircuit{
		Pub:       PublicKeyG1(sw_bls12381.NewG1Affine(pub)),
		Sig:       SignatureG2(sw_bls12381.NewG2Affine(sig)),
		Prehashed: sw_bls12381.NewG2Affine(h),
	}, ecc.BN254.ScalarField())
	assert.NoError(err, "VerifyG2 must accept a valid (pk, H(m), sig) triple")
}

// TestMinimalPublicKeyNegativeSolve asserts that the negative vectors of
// [testCasesG2Sig] are rejected: either the encoded point is malformed /
// not in the subgroup (so the witness cannot even be built), or the circuit is
// unsatisfiable.
func TestMinimalPublicKeyNegativeSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for i, tc := range testCasesG2Sig {
		if tc.output {
			continue
		}
		assert.Run(func(assert *test.Assert) {
			pubB, err := hex.DecodeString(tc.pubkey)
			assert.NoError(err, "failed to decode pubkey hex")
			msgB, err := hex.DecodeString(tc.msg)
			assert.NoError(err, "failed to decode msg hex")
			sigB, err := hex.DecodeString(tc.sig)
			assert.NoError(err, "failed to decode sig hex")

			var pub bls12381.G1Affine
			if _, err := pub.SetBytes(pubB); err != nil {
				// malformed or infinity public key: rejected out of circuit at
				// deserialization time.
				t.Logf("case %d: rejected at pubkey deserialization: %v", i, err)
				return
			}
			var sig bls12381.G2Affine
			if _, err := sig.SetBytes(sigB); err != nil {
				// malformed signature: rejected out of circuit at
				// deserialization time.
				t.Logf("case %d: rejected at signature deserialization: %v", i, err)
				return
			}

			err = test.IsSolved(&blsG2SigCircuit{Msg: make([]uints.U8, len(msgB))}, &blsG2SigCircuit{
				Pub: PublicKeyG1(sw_bls12381.NewG1Affine(pub)),
				Msg: uints.NewU8Array(msgB),
				Sig: SignatureG2(sw_bls12381.NewG2Affine(sig)),
			}, ecc.BN254.ScalarField())
			assert.Error(err, "circuit must be unsatisfiable for negative vector %d", i)
		}, fmt.Sprintf("case=%d", i))
	}
}

func TestMinimalPublicKeyTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for _, tc := range testCasesG2Sig {
		if !tc.output {
			// negative cases are covered by TestMinimalPublicKeyNegativeSolve
			continue
		}
		pubB, err := hex.DecodeString(tc.pubkey)
		assert.NoError(err, "failed to decode pubkey hex")
		msgB, err := hex.DecodeString(tc.msg)
		assert.NoError(err, "failed to decode msg hex")
		sigB, err := hex.DecodeString(tc.sig)
		assert.NoError(err, "failed to decode sig hex")

		var pub bls12381.G1Affine
		n, err := pub.SetBytes(pubB)
		assert.NoError(err, "failed to set pubkey bytes")
		assert.Equal(n, len(pubB), "pubkey bytes length mismatch")
		var sig bls12381.G2Affine
		n, err = sig.SetBytes(sigB)
		assert.NoError(err, "failed to set signature bytes")
		assert.Equal(n, len(sigB), "signature bytes length mismatch")

		err = test.IsSolved(&blsG2SigCircuit{Msg: make([]uints.U8, len(msgB))}, &blsG2SigCircuit{
			Pub: PublicKeyG1(sw_bls12381.NewG1Affine(pub)),
			Msg: uints.NewU8Array(msgB),
			Sig: SignatureG2(sw_bls12381.NewG2Affine(sig)),
		}, ecc.BN254.ScalarField())
		assert.NoError(err, "test solve failed")
		if testing.Short() {
			t.Log("skipping rest of tests in short mode")
			return
		}
	}
}
