package evmprecompiles

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

// fixedNativeKzgSrsVk is the KZG verifying key in native gnark-crypto form.
// It is decoded once at startup and never modified thereafter, making it safe
// to read from concurrent goroutines.
var fixedNativeKzgSrsVk kzg_bls12381.VerifyingKey

func init() {
	fixedNativeKzgSrsVk = decodeNativeVerifyingKey()
}

var (
	// srs contains concatenated G1 and G2 elements of the KZG SRS in compressed form.
	srs = []byte{
		// G1 part
		0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
		0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
		0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
		// G2[0] part
		0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
		0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
		0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
		0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
		0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
		0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
		// G2[1] part
		0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28, 0x84, 0x3b, 0xc2, 0x87, 0x23, 0x0a, 0xf3, 0x89,
		0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xa8, 0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a, 0xc5, 0x3d,
		0x29, 0x14, 0xe5, 0x87, 0x0c, 0xb4, 0x52, 0xd2, 0xaf, 0xaa, 0xab, 0x24, 0xf3, 0x49, 0x9f, 0x72,
		0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14, 0x73, 0x44, 0x29, 0xb7, 0xb3, 0x86, 0x08, 0xe2,
		0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9, 0xa3, 0x68, 0x51, 0x47, 0x7b, 0xa4, 0xc6, 0x0b,
		0x08, 0x70, 0x41, 0xde, 0x62, 0x10, 0x00, 0xed, 0xc9, 0x8e, 0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2,
	}
)

// decodeNativeVerifyingKey decodes the SRS bytes into a native gnark-crypto
// verifying key. The result contains no gnark circuit types and is safe to
// store as a package-level variable.
func decodeNativeVerifyingKey() kzg_bls12381.VerifyingKey {
	var vk kzg_bls12381.VerifyingKey
	dec := bls12381.NewDecoder(bytes.NewBuffer(srs), bls12381.NoSubgroupChecks())
	if err := dec.Decode(&vk.G1); err != nil {
		panic(fmt.Sprintf("failed to set G1 element: %v", err))
	}
	if err := dec.Decode(&vk.G2[0]); err != nil {
		panic(fmt.Sprintf("failed to set G2[0] element: %v", err))
	}
	if err := dec.Decode(&vk.G2[1]); err != nil {
		panic(fmt.Sprintf("failed to set G2[1] element: %v", err))
	}
	vk.Lines[0] = bls12381.PrecomputeLines(vk.G2[0])
	vk.Lines[1] = bls12381.PrecomputeLines(vk.G2[1])
	return vk
}

// newVerifyingKey returns a fresh gnark circuit-level verifying key built
// from the cached crypto key. It must be called once per circuit compilation:
// kzg.ValueOfVerifyingKeyFixed produces emulated field elements whose metadata
// (modReduced, bitsDecomposition, …) is mutated in-place during circuit
// parsing, so sharing a single instance across concurrent compilations causes
// a data race.
func newVerifyingKey() *kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine] {
	vk, err := kzg.ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine](fixedNativeKzgSrsVk)
	if err != nil {
		panic(fmt.Sprintf("failed to convert verifying key to fixed: %v", err))
	}
	return &vk
}

const (
	// blobCommitmentVersionKZG is the version byte for the KZG point evaluation precompile.
	blobCommitmentVersionKZG uint8 = 0x01
	// evmBlockSize is the size of the SRS used in the KZG precompile. This
	// defines the polynomial degree and therefore the size of the blob. It is also the expected
	// return value of the POINTEVAL precompile.
	evmBlockSize = 4096
	// evmBlsModulus is the modulus of the BLS12-381 scalar field in hexadecimal
	// format, split into 16-byte high and low parts for the expected values.
	evmBlsModulusHi = "0x73eda753299d7d483339d80809a1d805"
	evmBlsModulusLo = "0x53bda402fffe5bfeffffffff00000001"
)

var (
	// evmBlsModulus16 is the modulus of the BLS12-381 scalar field in hexadecimal
	// format, split into 16 2-byte parts for the expected values.
	evmBlsModulus16 = [16]string{
		"0x73ed",
		"0xa753",
		"0x299d",
		"0x7d48",
		"0x3339",
		"0xd808",
		"0x09a1",
		"0xd805",
		"0x53bd",
		"0xa402",
		"0xfffe",
		"0x5bfe",
		"0xffff",
		"0xffff",
		"0x0000",
		"0x0001",
	}
	// evmBlobSize16 is the expected blob size (4096) encoded as 16 2-byte parts.
	// 4096 = 0x1000, so it's 15 zero limbs followed by 0x1000.
	evmBlobSize16 = [16]int{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, evmBlockSize,
	}
)

// KzgPointEvaluation implements the [KZG_POINT_EVALUATION] precompile at
// address 0xa using 128-bit limbs.
//
// The data is encoded as follows:
//
//	[ versioned_hash | point |  claim  | commitment |   proof   ]
//	 <---- 32b -----> <-32b-> <- 32b -> <-- 48b  --> <-- 48b -->
//
// Values point and claim are the evaluation point and the claimed value, they
// are represented as 32-byte scalar field elements. We use [2]frontend.Variable
// as the arithmetization provides them as 16-byte words.
//
// Values commitment and proof are the KZG commitment and proof respectively.
// They are given as compressed points, for which we use 3 native elements to
// represent. The method performs decompression and all necessary checks. The
// encoding is given by Appendix C of [PAIRING_FRIENDLY_CURVES].
//
// The method assumes that every limb of versionedHash, commitmentCompressed
// and proofCompressed is already range checked to 128 bits by the caller
// (e.g. the arithmetization). The method does not check this: it only uses the
// low 16 bytes of each limb, so a limb with non-zero high bits is treated
// the same as its low 16 bytes. Calling the method with limbs which are not
// range checked does not bind the limbs to a unique precompile input.
//
// [KZG_POINT_EVALUATION]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
// [PAIRING_FRIENDLY_CURVES]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
func KzgPointEvaluation(
	api frontend.API,
	versionedHash [2]frontend.Variable, // arithmetization gives us a 2-element array. We convert it ourselves to a byte array.
	evaluationPoint *emulated.Element[sw_bls12381.ScalarField],
	claimedValue *emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed [3]frontend.Variable, // commitment is a 48 byte compressed point. Arithmetization uses 16-byte words, so we use a 3-element array.
	proofCompressed [3]frontend.Variable, // proof is a 48 byte compressed point. Arithmetization uses 16-byte words, so we use a 3-element array.
	expectedBlobSize [2]frontend.Variable, // arithmetization uses 2-element array. It is constant for all purposes, but we check it anyway.
	expectedBlsModulus [2]frontend.Variable, // arithmetization uses 2-element array. It is constant for all purposes, but we check it anyway.
) error {
	if smallfields.IsSmallField(api.Compiler().Field()) {
		return fmt.Errorf("KzgPointEvaluation method cannot be called over small field compiler")
	}
	// check expected modulus against 128-bit format
	api.AssertIsEqual(expectedBlsModulus[0], evmBlsModulusHi)
	api.AssertIsEqual(expectedBlsModulus[1], evmBlsModulusLo)
	fixedKzgSrsVk := newVerifyingKey()
	return kzgPointEvaluation(api, fixedKzgSrsVk, versionedHash[:], evaluationPoint, claimedValue, commitmentCompressed[:], proofCompressed[:], expectedBlobSize[:], 16)
}

// KzgPointEvaluation16 implements the [KZG_POINT_EVALUATION] precompile at
// address 0xa using 16-bit limbs.
//
// The data is encoded as follows:
//
//	[ versioned_hash | point |  claim  | commitment |   proof   ]
//	 <---- 32b -----> <-32b-> <- 32b -> <-- 48b  --> <-- 48b -->
//
// Values point and claim are the evaluation point and the claimed value, they
// are represented as 32-byte scalar field elements. We use [16]frontend.Variable
// as the arithmetization provides them as 2-byte words.
//
// Values commitment and proof are the KZG commitment and proof respectively.
// They are given as compressed points, for which we use 24 native elements to
// represent. The method performs decompression and all necessary checks. The
// encoding is given by Appendix C of [PAIRING_FRIENDLY_CURVES].
//
// The method assumes that every limb of versionedHash, commitmentCompressed
// and proofCompressed is already range checked to 16 bits by the caller
// (e.g. the arithmetization). The method does not check this: it only uses the
// low 2 bytes of each limb, so a limb with non-zero high bits is treated
// the same as its low 2 bytes. Calling the method with limbs which are not
// range checked does not bind the limbs to a unique precompile input.
//
// [KZG_POINT_EVALUATION]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
// [PAIRING_FRIENDLY_CURVES]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
func KzgPointEvaluation16(
	api frontend.API,
	versionedHash [16]frontend.Variable, // arithmetization gives us a 16-element array. We convert it ourselves to a byte array.
	evaluationPoint *emulated.Element[sw_bls12381.ScalarField],
	claimedValue *emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed [24]frontend.Variable, // commitment is a 48 byte compressed point. Arithmetization uses 2-byte words, so we use a 24-element array.
	proofCompressed [24]frontend.Variable, // proof is a 48 byte compressed point. Arithmetization uses 2-byte words, so we use a 24-element array.
	expectedBlobSize [16]frontend.Variable, // arithmetization uses 16-element array (2-byte words). It is constant for all purposes, but we check it anyway.
	expectedBlsModulus [16]frontend.Variable, // arithmetization uses 16-element array. It is constant for all purposes, but we check it anyway.
) error {
	if !smallfields.IsSmallField(api.Compiler().Field()) {
		return fmt.Errorf("KzgPointEvaluation16 method cannot be called over large field compiler")
	}
	// check expected modulus against 16-bit format
	for i := range evmBlsModulus16 {
		api.AssertIsEqual(expectedBlsModulus[i], evmBlsModulus16[i])
	}
	fixedKzgSrsVk16 := newVerifyingKey()
	return kzgPointEvaluation(api, fixedKzgSrsVk16, versionedHash[:], evaluationPoint, claimedValue, commitmentCompressed[:], proofCompressed[:], expectedBlobSize[:], 2)
}

// kzgPointEvaluation is the generic implementation of KZG point evaluation.
// bytesPerLimb specifies how many bytes each limb represents (16 for 128-bit, 2 for 16-bit).
func kzgPointEvaluation(
	api frontend.API,
	fixedKzgSrsVk *kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine],
	versionedHash []frontend.Variable,
	evaluationPoint *emulated.Element[sw_bls12381.ScalarField],
	claimedValue *emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed []frontend.Variable,
	proofCompressed []frontend.Variable,
	expectedBlobSize []frontend.Variable,
	bytesPerLimb int,
) error {
	// -- perform conversion from limbs to 1-byte words
	totalNativeBytes := (api.Compiler().Field().BitLen() + 7) / 8

	// versioned hash
	var versionedHashBytes [sha256.Size]uints.U8
	for i := range versionedHash {
		res, err := conversion.NativeToBytes(api, versionedHash[i])
		if err != nil {
			return fmt.Errorf("convert versioned hash element %d to bytes: %w", i, err)
		}
		copy(versionedHashBytes[i*bytesPerLimb:(i+1)*bytesPerLimb], res[totalNativeBytes-bytesPerLimb:])
	}

	// commitment
	var comSerializedBytes [bls12381.SizeOfG1AffineCompressed]uints.U8
	for i := range commitmentCompressed {
		res, err := conversion.NativeToBytes(api, commitmentCompressed[i])
		if err != nil {
			return fmt.Errorf("convert commitment element %d to bytes: %w", i, err)
		}
		copy(comSerializedBytes[i*bytesPerLimb:(i+1)*bytesPerLimb], res[totalNativeBytes-bytesPerLimb:])
	}
	// proof
	var proofSerialisedBytes [bls12381.SizeOfG1AffineCompressed]uints.U8
	for i := range proofCompressed {
		res, err := conversion.NativeToBytes(api, proofCompressed[i])
		if err != nil {
			return fmt.Errorf("convert proof element %d to bytes: %w", i, err)
		}
		copy(proofSerialisedBytes[i*bytesPerLimb:(i+1)*bytesPerLimb], res[totalNativeBytes-bytesPerLimb:])
	}

	// -- unmarshal compressed commitment and proof into uncompressed points
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return fmt.Errorf("new g1: %w", err)
	}
	commitmentUncompressed, err := g1.UnmarshalCompressed(comSerializedBytes[:])
	if err != nil {
		return fmt.Errorf("unmarshal compressed commitment: %w", err)
	}
	proofUncompressed, err := g1.UnmarshalCompressed(proofSerialisedBytes[:])
	if err != nil {
		return fmt.Errorf("unmarshal compressed proof: %w", err)
	}

	// verify commitment matches versioned_hash
	h, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	h.Write(comSerializedBytes[:])
	hashedKzg := h.Sum()
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("new uints api: %w", err)
	}
	api.AssertIsEqual(bapi.ValueUnchecked(versionedHashBytes[0]), blobCommitmentVersionKZG)
	for i := 1; i < len(hashedKzg); i++ {
		bapi.AssertIsEqual(hashedKzg[i], versionedHashBytes[i])
	}

	v, err := kzg.NewVerifier[emulated.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
	if err != nil {
		return fmt.Errorf("new kzg verifier: %w", err)
	}

	// -- construct the commitment and opening proof what the interface expects
	kzgCommitment := kzg.Commitment[sw_bls12381.G1Affine]{
		G1El: *commitmentUncompressed,
	}
	kzgOpeningProof := kzg.OpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine]{
		Quotient:     *proofUncompressed,
		ClaimedValue: *claimedValue,
	}
	err = v.CheckOpeningProof(kzgCommitment, kzgOpeningProof, *evaluationPoint, *fixedKzgSrsVk)
	if err != nil {
		return fmt.Errorf("check opening proof: %w", err)
	}

	// -- check expected values. These are constant values, so we just check that they match the expected values.
	// For both 128-bit and 16-bit formats, all limbs except the last should be 0, and the last should be evmBlockSize.
	for i := 0; i < len(expectedBlobSize)-1; i++ {
		api.AssertIsEqual(expectedBlobSize[i], 0)
	}
	api.AssertIsEqual(expectedBlobSize[len(expectedBlobSize)-1], evmBlockSize)

	return nil
}

// KzgPointEvaluationFailure checks a failing case of KZG point evaluation precompile
// using 128-bit limbs.
// It has the same interface as [KzgPointEvaluation] but it allows to pass in
// inputs which should fail according to the [EIP-4844] specification. The
// method CAN NOT assert validity of valid inputs. The goal of the method is to
// allow proving that the precompile call failed in EVM.
//
// For data encoding (particularly for compressed inputs) and the range
// assumptions on the input limbs, see [KzgPointEvaluation] method
// documentation.
//
// The method checks that any of the following failure cases happen:
//   - the versioned hash version is incorrect
//   - the versioned hash does not match the commitment
//   - the compressed commitment or proof have invalid compression mask (allowed masks are 0b100, 0b101 and 0b110)
//   - x coordinate value in compressed commitment or proof does overflows
//   - x coordinate value in compressed commitment or proof differs from mask (for infinity mask x != 0, for non-infinity mask x == 0)
//   - the compressed commitment or proof do not represent curve points
//   - the compressed commitment or proof do not represent points in the correct subgroup
//   - pairing check fails for the inputs
//   - expected blob size is incorrect (should be 4096)
//   - expected BLS modulus is incorrect (should be BLS12-381 scalar field modulus)
//
// The checks are non-exclusive, i.e. multiple of them can fail at the same time.
//
// [EIP-4844]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
func KzgPointEvaluationFailure(
	api frontend.API,
	versionedHash [2]frontend.Variable,
	evaluationPoint *emulated.Element[sw_bls12381.ScalarField],
	claimedValue *emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed [3]frontend.Variable,
	proofCompressed [3]frontend.Variable,
	expectedBlobSize [2]frontend.Variable,
	expectedBlsModulus [2]frontend.Variable,
) error {
	if smallfields.IsSmallField(api.Compiler().Field()) {
		return fmt.Errorf("KzgPointEvaluationFailure method cannot be called over small field compiler")
	}
	fixedKzgSrsVk := newVerifyingKey()
	return kzgPointEvaluationFailure(api, fixedKzgSrsVk, versionedHash[:], evaluationPoint, claimedValue, commitmentCompressed[:], proofCompressed[:], expectedBlobSize[:], expectedBlsModulus[:], 16)
}

// KzgPointEvaluationFailure16 checks a failing case of KZG point evaluation precompile
// using 16-bit limbs.
// It has the same interface as [KzgPointEvaluation16] but it allows to pass in
// inputs which should fail according to the [EIP-4844] specification. The
// method CAN NOT assert validity of valid inputs. The goal of the method is to
// allow proving that the precompile call failed in EVM.
//
// For data encoding (particularly for compressed inputs) and the range
// assumptions on the input limbs, see [KzgPointEvaluation16] method
// documentation.
//
// The method checks that any of the following failure cases happen:
//   - the versioned hash version is incorrect
//   - the versioned hash does not match the commitment
//   - the compressed commitment or proof have invalid compression mask (allowed masks are 0b100, 0b101 and 0b110)
//   - x coordinate value in compressed commitment or proof does overflows
//   - x coordinate value in compressed commitment or proof differs from mask (for infinity mask x != 0, for non-infinity mask x == 0)
//   - the compressed commitment or proof do not represent curve points
//   - the compressed commitment or proof do not represent points in the correct subgroup
//   - pairing check fails for the inputs
//   - expected blob size is incorrect (should be 4096)
//   - expected BLS modulus is incorrect (should be BLS12-381 scalar field modulus)
//
// The checks are non-exclusive, i.e. multiple of them can fail at the same time.
//
// [EIP-4844]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
func KzgPointEvaluationFailure16(
	api frontend.API,
	versionedHash [16]frontend.Variable,
	evaluationPoint *emulated.Element[sw_bls12381.ScalarField],
	claimedValue *emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed [24]frontend.Variable,
	proofCompressed [24]frontend.Variable,
	expectedBlobSize [16]frontend.Variable,
	expectedBlsModulus [16]frontend.Variable,
) error {
	if !smallfields.IsSmallField(api.Compiler().Field()) {
		return fmt.Errorf("KzgPointEvaluationFailure16 method cannot be called over large field compiler")
	}
	fixedKzgSrsVk16 := newVerifyingKey()
	return kzgPointEvaluationFailure(api, fixedKzgSrsVk16, versionedHash[:], evaluationPoint, claimedValue, commitmentCompressed[:], proofCompressed[:], expectedBlobSize[:], expectedBlsModulus[:], 2)
}

// kzgPointEvaluationFailure is the generic implementation of KZG point evaluation failure.
// bytesPerLimb specifies how many bytes each limb represents (16 for 128-bit, 2 for 16-bit).
func kzgPointEvaluationFailure(
	api frontend.API,
	fixedKzgSrsVk *kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine],
	versionedHash []frontend.Variable,
	evaluationPoint *emulated.Element[sw_bls12381.ScalarField],
	claimedValue *emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed []frontend.Variable,
	proofCompressed []frontend.Variable,
	expectedBlobSize []frontend.Variable,
	expectedBlsModulus []frontend.Variable,
	bytesPerLimb int,
) error {
	totalNativeBytes := (api.Compiler().Field().BitLen() + 7) / 8

	// -- initialize the gadgets we use
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("new uints api: %w", err)
	}
	fr, err := emulated.NewField[sw_bls12381.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return fmt.Errorf("new g1: %w", err)
	}
	curve, err := algebra.GetCurve[sw_bls12381.ScalarField, sw_bls12381.G1Affine](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	h, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	// -- initialize the dummy values we use
	dummyEvaluationPoint := fr.NewElement(0)
	dummyClaimedValue := fr.NewElement(0)
	dummyComBytes := uints.NewU8Array([]uint8{
		0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
	dummyProofBytes := uints.NewU8Array([]uint8{
		0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
	dummyCommitment := &sw_bls12381.G1Affine{
		X: *fp.NewElement(0),
		Y: *fp.NewElement(0),
	}
	dummyProof := &sw_bls12381.G1Affine{
		X: *fp.NewElement(0),
		Y: *fp.NewElement(0),
	}
	// dummy versioned hash matching the number of limbs
	dummyVersionedHash := make([]frontend.Variable, len(versionedHash))
	if bytesPerLimb == 16 {
		// 128-bit format: 2 limbs
		dummyVersionedHash[0] = "0x010657f37554c781402a22917dee2f75"
		dummyVersionedHash[1] = "0xdef7ab966d7b770905398eba3c444014"
	} else {
		// 16-bit format: 16 limbs
		copy(dummyVersionedHash, []frontend.Variable{
			"0x0106", "0x57f3", "0x7554", "0xc781",
			"0x402a", "0x2291", "0x7dee", "0x2f75",
			"0xdef7", "0xab96", "0x6d7b", "0x7709",
			"0x0539", "0x8eba", "0x3c44", "0x4014",
		})
	}
	// -- check that the masks of compressed commitment and proof are correct
	// (infinity, small y, large y). If either of them is not correct, then we
	// swap all values to dummy values (for which rest of the checks will pass).
	// for checking that the mask is correct we use mux-8 as only three bits define
	// the mask
	// - first we unpack the packed commitment and proof into bytes
	var comSerializedBytes [bls12381.SizeOfG1AffineCompressed]uints.U8
	for i := range commitmentCompressed {
		res, err := conversion.NativeToBytes(api, commitmentCompressed[i])
		if err != nil {
			return fmt.Errorf("convert commitment element %d to bytes: %w", i, err)
		}
		copy(comSerializedBytes[i*bytesPerLimb:(i+1)*bytesPerLimb], res[totalNativeBytes-bytesPerLimb:])
	}
	var proofSerialisedBytes [bls12381.SizeOfG1AffineCompressed]uints.U8
	for i := range proofCompressed {
		res, err := conversion.NativeToBytes(api, proofCompressed[i])
		if err != nil {
			return fmt.Errorf("convert proof element %d to bytes: %w", i, err)
		}
		copy(proofSerialisedBytes[i*bytesPerLimb:(i+1)*bytesPerLimb], res[totalNativeBytes-bytesPerLimb:])
	}
	// - allowed bytes are 0b100<<5, 0b101<<5 and 0b110<<5. We mask the upper
	// three bits and then shift by division by 32.
	unmask := uints.NewU8(0b111 << 5)
	prefixCom := bapi.And(unmask, comSerializedBytes[0])                // prefix = commitment[0] & unmask
	prefixProof := bapi.And(unmask, proofSerialisedBytes[0])            // prefix = proof[0] & unmask
	prefixComShifted := api.Div(bapi.ValueUnchecked(prefixCom), 32)     // prefix >> 5
	prefixProofShifted := api.Div(bapi.ValueUnchecked(prefixProof), 32) // prefix >> 5
	isValidMaskCom := selector.Mux(api, prefixComShifted,
		0, // 0b000 << 5
		0, // 0b001 << 5
		0, // 0b010 << 5
		0, // 0b011 << 5
		1, // 0b100 << 5 - compressed regular point, with y lexicographically smallest
		1, // 0b101 << 5 - compressed regular point, with y lexicographically largest
		1, // 0b110 << 5 - compressed point at infinity
		0, // 0b111 << 5
	)
	isValidMaskProof := selector.Mux(api, prefixProofShifted, 0, 0, 0, 0, 1, 1, 1, 0)
	isValidMasks := api.And(isValidMaskCom, isValidMaskProof)
	// - if the masks are correct, then we will keep the values as they are.
	// however, if they are not correct then we will swap the bytes to dummy values.
	comSerializedBytes = selectSliceUint8(bapi, isValidMasks, comSerializedBytes, dummyComBytes)
	proofSerialisedBytes = selectSliceUint8(bapi, isValidMasks, proofSerialisedBytes, dummyProofBytes)
	evaluationPoint = fr.Select(isValidMasks, evaluationPoint, dummyEvaluationPoint)
	claimedValue = fr.Select(isValidMasks, claimedValue, dummyClaimedValue)
	versionedHash = selectSliceVariable(api, isValidMasks, versionedHash, dummyVersionedHash)
	// -- now we need to ensure that both compressed commitment and proof have x coordinate
	// values in range. Otherwise, the underlying call to UnmarshalCompress will fail as
	// we explicitly perform range check in the BytesToEmulated method.
	//
	// For this we do BytesToEmulated ourself, but without range checking. Then we perform strict
	// modular reduction and see if the values changed.
	mask := uints.NewU8(^byte(0b111 << 5))
	firstByteCom := bapi.And(mask, comSerializedBytes[0])
	firstByteProof := bapi.And(mask, proofSerialisedBytes[0])
	var xCoordComBytes, xCoordProofBytes [bls12381.SizeOfG1AffineCompressed]uints.U8
	copy(xCoordComBytes[1:], comSerializedBytes[1:])
	copy(xCoordProofBytes[1:], proofSerialisedBytes[1:])
	xCoordComBytes[0] = firstByteCom
	xCoordProofBytes[0] = firstByteProof
	// - here we convert from bytes to emulated without range checking. However,
	// below in EmulatedToBytes we do not pass any option. In this case
	// EmulatedToBytes will call [emulated.Field.ReduceStrict] on the input,
	// which ensures that we convert the in-range emulated value to bytes. Thus,
	// when the initial value xCoordComBytes/xCoordProofBytes is out of range,
	// then the value after EmulatedToBytes will be different.
	xCoordComEmul, err := conversion.BytesToEmulated[sw_bls12381.BaseField](api, xCoordComBytes[:], conversion.WithAllowOverflow())
	if err != nil {
		return fmt.Errorf("bytes to emulated commitment x coordinate: %w", err)
	}
	xCoordProofEmul, err := conversion.BytesToEmulated[sw_bls12381.BaseField](api, xCoordProofBytes[:], conversion.WithAllowOverflow())
	if err != nil {
		return fmt.Errorf("bytes to emulated proof x coordinate: %w", err)
	}
	xCoordComConverted, err := conversion.EmulatedToBytes(api, xCoordComEmul)
	if err != nil {
		return fmt.Errorf("emulated to bytes commitment x coordinate: %w", err)
	}
	xCoordProofConverted, err := conversion.EmulatedToBytes(api, xCoordProofEmul)
	if err != nil {
		return fmt.Errorf("emulated to bytes proof x coordinate: %w", err)
	}
	if len(xCoordComConverted) != len(xCoordComBytes) {
		return fmt.Errorf("unexpected length of converted commitment x coordinate: expected %d, got %d", len(xCoordComBytes), len(xCoordComConverted))
	}
	if len(xCoordProofConverted) != len(xCoordProofBytes) {
		return fmt.Errorf("unexpected length of converted proof x coordinate: expected %d, got %d", len(xCoordProofBytes), len(xCoordProofConverted))
	}
	// - check that the values are the same
	var isInRangeCom frontend.Variable = 1
	var isInRangeProof frontend.Variable = 1
	for i := range bls12381.SizeOfG1AffineCompressed {
		isInRangeCom = api.Mul(isInRangeCom, api.IsZero(api.Sub(bapi.ValueUnchecked(xCoordComBytes[i]), bapi.ValueUnchecked(xCoordComConverted[i]))))
		isInRangeProof = api.Mul(isInRangeProof, api.IsZero(api.Sub(bapi.ValueUnchecked(xCoordProofBytes[i]), bapi.ValueUnchecked(xCoordProofConverted[i]))))
	}
	isInRange := api.And(isInRangeCom, isInRangeProof)
	// - swap with dummy values if they are not in range
	comSerializedBytes = selectSliceUint8(bapi, isInRange, comSerializedBytes, dummyComBytes)
	proofSerialisedBytes = selectSliceUint8(bapi, isInRange, proofSerialisedBytes, dummyProofBytes)
	evaluationPoint = fr.Select(isInRange, evaluationPoint, dummyEvaluationPoint)
	claimedValue = fr.Select(isInRange, claimedValue, dummyClaimedValue)
	versionedHash = selectSliceVariable(api, isInRange, versionedHash, dummyVersionedHash)
	xCoordComEmul = fp.Select(isInRange, xCoordComEmul, fp.Zero())
	xCoordProofEmul = fp.Select(isInRange, xCoordProofEmul, fp.Zero())
	// -- if the mask is given for infinity then we need to ensure that x is zero
	// - load the prefix again. We may have overwritten the bytes above to dummy (zero) values.
	prefixCom = bapi.And(unmask, comSerializedBytes[0])
	prefixProof = bapi.And(unmask, proofSerialisedBytes[0])
	prefixComShifted = api.Div(bapi.ValueUnchecked(prefixCom), 32)
	prefixProofShifted = api.Div(bapi.ValueUnchecked(prefixProof), 32)
	// - check if the mask for infinity corresponds to the x coordinate being infinity
	isMaskInfinityCom := api.IsZero(api.Sub(prefixComShifted, 0b110))
	isMaskInfinityProof := api.IsZero(api.Sub(prefixProofShifted, 0b110))
	isValueXZeroCom := fp.IsZero(xCoordComEmul)
	isValueXZeroProof := fp.IsZero(xCoordProofEmul)
	isInvalidInfinityMaskCom := api.Xor(isMaskInfinityCom, isValueXZeroCom)
	isInvalidInfinityMaskProof := api.Xor(isMaskInfinityProof, isValueXZeroProof)
	isNotValidInfinityMask := api.Or(isInvalidInfinityMaskCom, isInvalidInfinityMaskProof)
	isValidInfinityMask := api.Sub(1, isNotValidInfinityMask)
	// - in case of invalid infinity mask, we swap to dummy values
	comSerializedBytes = selectSliceUint8(bapi, isValidInfinityMask, comSerializedBytes, dummyComBytes)
	proofSerialisedBytes = selectSliceUint8(bapi, isValidInfinityMask, proofSerialisedBytes, dummyProofBytes)
	evaluationPoint = fr.Select(isValidInfinityMask, evaluationPoint, dummyEvaluationPoint)
	claimedValue = fr.Select(isValidInfinityMask, claimedValue, dummyClaimedValue)
	versionedHash = selectSliceVariable(api, isValidInfinityMask, versionedHash, dummyVersionedHash)
	// -- uncompress the commitment and proof
	commitmentUncompressed, err := g1.UnmarshalCompressed(comSerializedBytes[:], algopts.WithNoSubgroupMembershipCheck())
	if err != nil {
		return fmt.Errorf("unmarshal compressed commitment: %w", err)
	}
	proofUncompressed, err := g1.UnmarshalCompressed(proofSerialisedBytes[:], algopts.WithNoSubgroupMembershipCheck())
	if err != nil {
		return fmt.Errorf("unmarshal compressed proof: %w", err)
	}
	// - check that the points are in subgroup
	isInGroupCom := pairing.IsOnG1(commitmentUncompressed)
	isInGroupProof := pairing.IsOnG1(proofUncompressed)
	isInSubgroups := api.And(isInGroupCom, isInGroupProof)
	// - replace with dummy values if they are not
	commitmentUncompressed = &sw_bls12381.G1Affine{
		X: *fp.Select(isInSubgroups, &commitmentUncompressed.X, &dummyCommitment.X),
		Y: *fp.Select(isInSubgroups, &commitmentUncompressed.Y, &dummyCommitment.Y),
	}
	proofUncompressed = &sw_bls12381.G1Affine{
		X: *fp.Select(isInSubgroups, &proofUncompressed.X, &dummyProof.X),
		Y: *fp.Select(isInSubgroups, &proofUncompressed.Y, &dummyProof.Y),
	}
	comSerializedBytes = selectSliceUint8(bapi, isInSubgroups, comSerializedBytes, dummyComBytes)
	proofSerialisedBytes = selectSliceUint8(bapi, isInSubgroups, proofSerialisedBytes, dummyProofBytes)
	evaluationPoint = fr.Select(isInSubgroups, evaluationPoint, dummyEvaluationPoint)
	claimedValue = fr.Select(isInSubgroups, claimedValue, dummyClaimedValue)
	versionedHash = selectSliceVariable(api, isInSubgroups, versionedHash, dummyVersionedHash)
	// -- now we check that the rest of hash is correct. If it is not, then we
	// swap the rest of the values to dummy values
	// - first we compute the hash of the commitment
	h.Write(comSerializedBytes[:])
	hashedKzg := h.Sum()
	// - first map the versioned hash to bytes
	var versionedHashBytes [sha256.Size]uints.U8
	for i := range versionedHash {
		res, err := conversion.NativeToBytes(api, versionedHash[i])
		if err != nil {
			return fmt.Errorf("convert versioned hash element %d to bytes: %w", i, err)
		}
		copy(versionedHashBytes[i*bytesPerLimb:(i+1)*bytesPerLimb], res[totalNativeBytes-bytesPerLimb:])
	}
	// - check the hash version
	isCorrectHashVersion := api.IsZero(api.Sub(bapi.ValueUnchecked(versionedHashBytes[0]), blobCommitmentVersionKZG))
	// - check the rest of the hash
	isCorrectHash := isCorrectHashVersion
	for i := 1; i < len(hashedKzg); i++ {
		isCorrectHash = api.Mul(isCorrectHash, api.IsZero(api.Sub(bapi.ValueUnchecked(hashedKzg[i]), bapi.ValueUnchecked(versionedHashBytes[i]))))
	}
	// - swap to dummy values if the hash is not correct
	evaluationPoint = fr.Select(isCorrectHash, evaluationPoint, dummyEvaluationPoint)
	claimedValue = fr.Select(isCorrectHash, claimedValue, dummyClaimedValue)
	commitmentUncompressed = &sw_bls12381.G1Affine{
		X: *fp.Select(isCorrectHash, &commitmentUncompressed.X, &dummyCommitment.X),
		Y: *fp.Select(isCorrectHash, &commitmentUncompressed.Y, &dummyCommitment.Y),
	}
	proofUncompressed = &sw_bls12381.G1Affine{
		X: *fp.Select(isCorrectHash, &proofUncompressed.X, &dummyProof.X),
		Y: *fp.Select(isCorrectHash, &proofUncompressed.Y, &dummyProof.Y),
	}
	// -- now check that the expected return values are correct
	// - we check the KZG blob size. All limbs except the last should be 0, and the last should be evmBlockSize.
	var isCorrectBlobSize frontend.Variable = 1
	for i := 0; i < len(expectedBlobSize)-1; i++ {
		isCorrectBlobSize = api.Mul(isCorrectBlobSize, api.IsZero(expectedBlobSize[i]))
	}
	isCorrectBlobSize = api.Mul(isCorrectBlobSize, api.IsZero(api.Sub(expectedBlobSize[len(expectedBlobSize)-1], evmBlockSize)))
	// - check the BLS modulus based on the format
	var isCorrectBlsModulus frontend.Variable = 1
	if bytesPerLimb == 16 {
		// 128-bit format: 2 limbs
		isCorrectBlsModulus = api.And(
			api.IsZero(api.Sub(expectedBlsModulus[0], evmBlsModulusHi)),
			api.IsZero(api.Sub(expectedBlsModulus[1], evmBlsModulusLo)),
		)
	} else {
		// 16-bit format: 16 limbs
		for i := range evmBlsModulus16 {
			isCorrectBlsModulus = api.Mul(isCorrectBlsModulus, api.IsZero(api.Sub(expectedBlsModulus[i], evmBlsModulus16[i])))
		}
	}
	isExpectedResult := api.And(
		isCorrectBlobSize,
		isCorrectBlsModulus,
	)
	// -- now, we are only left with a pairing check result. If any of the
	// previous checks has failed, then it means that we are using dummy values
	// and the pairing check should succeed. But if all previous checks have
	// passed, then we perform the pairing check and assert that it should fail.
	// This requires for us to inline the CheckOpeningProof method as it
	// currently only asserts correctness.
	// - first we perform sanity check that we only had up to a single failure before
	isNotValidMasks := api.Sub(1, isValidMasks)
	isNotInRange := api.Sub(1, isInRange)
	isNotInSubgroups := api.Sub(1, isInSubgroups)
	isNotCorrectHash := api.Sub(1, isCorrectHash)
	isAnyPreviousFailure := api.Add(
		isNotValidMasks,
		isNotInRange,
		isNotValidInfinityMask,
		isNotInSubgroups,
		isNotCorrectHash,
	)
	api.AssertIsBoolean(isAnyPreviousFailure)
	// - we perform the KZG verification. It is unrolled version of
	// [kzg.Verifier.CheckOpeningProof]
	evPointNeg := fr.Neg(evaluationPoint)
	totalG1, err := curve.MultiScalarMul(
		[]*sw_bls12381.G1Affine{&fixedKzgSrsVk.G1, proofUncompressed},
		[]*sw_bls12381.Scalar{claimedValue, evPointNeg},
	)
	if err != nil {
		return fmt.Errorf("multi scalar mul: %w", err)
	}
	commitmentNeg := curve.Neg(commitmentUncompressed)
	totalG1 = curve.AddUnified(totalG1, commitmentNeg)
	pairingResult, err := pairing.Pair(
		[]*sw_bls12381.G1Affine{totalG1, proofUncompressed},
		[]*sw_bls12381.G2Affine{&fixedKzgSrsVk.G2[0], &fixedKzgSrsVk.G2[1]},
	)
	if err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	isPairingOne := pairing.IsEqual(pairingResult, pairing.Ext12.One())
	// - now if there was any previous failure, then we have used dummy values
	// for the pairing and the result should be one. Otherwise, if there was not
	// any previous failures, then we either:
	//  * pairing result is not one
	//  * or the expected result (blob size, bls modulus) is not correct
	//
	// Tablewise, this corresponds to the following:
	//
	//   | isPrevFail | isPairingOne | isExpectedResult | valid case |
	//   |------------|--------------|------------------|------------|
	//   |     0      |      0       |        0         |      1     | pairing incorrect and result incorrect
	//   |     0      |      0       |        1         |      1     | pairing incorrect and result correct
	//   |     0      |      1       |        0         |      1     | pairing correct and result incorrect
	//   |     0      |      1       |        1         |      0     | cannot be, no previous failure (no replace), but pairing and result correct
	//   |     1      |      0       |        0         |      0     | cannot be, we swapped to dummy values but pairing incorrect
	//   |     1      |      0       |        1         |      0     | cannot be, we swapped to dummy values but pairing incorrect
	//   |     1      |      1       |        0         |      1     | previous checks failed, so pairing correct with dummy values and expected result incorrect
	//   |     1      |      1       |        1         |      1     | previous checks failed, so pairing correct with dummy values and expected result correct
	caseSelector := api.Add(
		isExpectedResult,
		api.Mul(isPairingOne, 2),         // shift by 1 bit to the left
		api.Mul(isAnyPreviousFailure, 4), // shift by 2 bits to the left
	)
	isValidCase := selector.Mux(api, caseSelector,
		1, // pairing incorrect and result incorrect
		1, // pairing incorrect and result correct
		1, // pairing correct and result incorrect
		0, // cannot be, no previous failure (no replace), but pairing and result correct
		0, // cannot be, we swapped to dummy values but pairing incorrect
		0, // cannot be, we swapped to dummy values but pairing incorrect
		1, // previous checks failed, so pairing correct with dummy values and expected result incorrect
		1, // previous checks failed, so pairing correct with dummy values and expected result correct
	)
	api.AssertIsEqual(isValidCase, 1)

	return nil
}

func selectSliceUint8(bapi *uints.Bytes, cond frontend.Variable, onTrue [bls12381.SizeOfG1AffineCompressed]uints.U8, onFalse []uints.U8) [bls12381.SizeOfG1AffineCompressed]uints.U8 {
	if len(onFalse) != bls12381.SizeOfG1AffineCompressed {
		panic("unexpected length of onFalse")
	}
	var res [bls12381.SizeOfG1AffineCompressed]uints.U8
	for i := range res {
		res[i] = bapi.Select(cond, onTrue[i], onFalse[i])
	}
	return res
}

func selectSliceVariable(api frontend.API, cond frontend.Variable, onTrue []frontend.Variable, onFalse []frontend.Variable) []frontend.Variable {
	if len(onTrue) != len(onFalse) {
		panic("selectSliceVariable: onTrue and onFalse must have the same length")
	}
	res := make([]frontend.Variable, len(onTrue))
	for i := range res {
		res[i] = api.Select(cond, onTrue[i], onFalse[i])
	}
	return res
}
