// Package emparams contains emulation parameters for well known fields.
//
// We define some well-known parameters in this package for compatibility and
// ease of use. When needing to use parameters not defined in this package it is
// sufficient to define a new type implementing [FieldParams]. For example, as:
//
//	type SmallField struct {}
//	func (SmallField) NbLimbs() uint { return 1 }
//	func (SmallField) BitsPerLimb() uint { return 11 }
//	func (SmallField) IsPrime() bool { return true }
//	func (SmallField) Modulus() *big.Int { return big.NewInt(1032) }
//
// If in addition the parameters should be aware of the underlying native field,
// then the type should implement [DynamicFieldParams] interface. For example,
// by adding the method:
//
//	 func (SmallField) BitsPerLimbDynamic(field *big.Int) uint {
//		if smallfields.IsSmallField(field) {
//			return 6
//	    }
//	    return 11
//	 }
//
// The number of limbs is not part of the interface - it is always derived from
// the limb size and the modulus.
package emparams

import (
	"crypto/elliptic"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/internal/smallfields"
)

// Small native fields need narrower emulated limbs so that multiplication
// carries admit an integer lift below the native modulus. The widths below are
// maximal for the corresponding parameter families over the supported 31-bit
// native fields (BabyBear and KoalaBear).
const (
	smallFieldFourLimbBits   uint = 11
	smallFieldSixLimbBits    uint = 10
	smallFieldTwelveLimbBits uint = 10
	smallFieldOneLimbBits    uint = 12
)

type fourLimbPrimeField struct{}

func (fourLimbPrimeField) NbLimbs() uint     { return 4 }
func (fourLimbPrimeField) BitsPerLimb() uint { return 64 }
func (fourLimbPrimeField) IsPrime() bool     { return true }
func (f fourLimbPrimeField) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return smallFieldFourLimbBits
	}
	return f.BitsPerLimb()
}

type sixLimbPrimeField struct{}

func (sixLimbPrimeField) NbLimbs() uint     { return 6 }
func (sixLimbPrimeField) BitsPerLimb() uint { return 64 }
func (sixLimbPrimeField) IsPrime() bool     { return true }
func (f sixLimbPrimeField) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return smallFieldSixLimbBits
	}
	return f.BitsPerLimb()
}

type twelveLimbPrimeField struct{}

func (twelveLimbPrimeField) NbLimbs() uint     { return 12 }
func (twelveLimbPrimeField) BitsPerLimb() uint { return 64 }
func (twelveLimbPrimeField) IsPrime() bool     { return true }
func (f twelveLimbPrimeField) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return smallFieldTwelveLimbBits
	}
	return f.BitsPerLimb()
}

type oneLimbPrimeField struct{}

func (oneLimbPrimeField) NbLimbs() uint { return 1 }
func (oneLimbPrimeField) IsPrime() bool { return true }

// Goldilocks provides type parametrization for field emulation:
//   - limbs: 1
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xffffffff00000001 (base 16)
//	18446744069414584321 (base 10)
type Goldilocks struct{ oneLimbPrimeField }

func (Goldilocks) BitsPerLimb() uint { return 64 }
func (Goldilocks) Modulus() *big.Int { return goldilocks.Modulus() }
func (Goldilocks) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return smallFieldOneLimbBits
	}
	return 64
}

// Secp256k1Fp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f (base 16)
//	115792089237316195423570985008687907853269984665640564039457584007908834671663 (base 10)
//
// This is the base field of the SECP256k1 curve.
type Secp256k1Fp struct{ fourLimbPrimeField }

func (Secp256k1Fp) Modulus() *big.Int { return ecc.SECP256K1.BaseField() }

// Secp256k1Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 (base 16)
//	115792089237316195423570985008687907852837564279074904382605163141518161494337 (base 10)
//
// This is the scalar field of the SECP256k1 curve.
type Secp256k1Fr struct{ fourLimbPrimeField }

func (Secp256k1Fr) Modulus() *big.Int { return ecc.SECP256K1.ScalarField() }

// BN254Fp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 (base 16)
//	21888242871839275222246405745257275088696311157297823662689037894645226208583 (base 10)
//
// This is the base field of the BN254 curve.
type BN254Fp struct{ fourLimbPrimeField }

func (BN254Fp) Modulus() *big.Int { return ecc.BN254.BaseField() }

// BN254Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 (base 16)
//	21888242871839275222246405745257275088548364400416034343698204186575808495617 (base 10)
//
// This is the scalar field of the BN254 curve.
type BN254Fr struct{ fourLimbPrimeField }

func (BN254Fr) Modulus() *big.Int { return ecc.BN254.ScalarField() }

// GrumpkinFp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 (base 16)
//	21888242871839275222246405745257275088548364400416034343698204186575808495617 (base 10)
//
// This is the base field of the GRUMPKIN curve.
type GrumpkinFp struct{ fourLimbPrimeField }

func (fp GrumpkinFp) Modulus() *big.Int { return ecc.GRUMPKIN.BaseField() }

// GrumpkinFr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 (base 16)
//	21888242871839275222246405745257275088696311157297823662689037894645226208583 (base 10)
//
// This is the scalar field of the GRUMPKIN curve.
type GrumpkinFr struct{ fourLimbPrimeField }

func (fp GrumpkinFr) Modulus() *big.Int { return ecc.GRUMPKIN.ScalarField() }

// BLS12377Fp provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001 (base 16)
//	258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177 (base 10)
//
// This is the base field of the BLS12-377 curve.
type BLS12377Fp struct{ sixLimbPrimeField }

func (BLS12377Fp) Modulus() *big.Int { return ecc.BLS12_377.BaseField() }

// BLS12377Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001 (base 16)
//	8444461749428370424248824938781546531375899335154063827935233455917409239041 (base 10)
//
// This is the scalar field of the BLS12-377 curve.
type BLS12377Fr struct{ fourLimbPrimeField }

func (BLS12377Fr) Modulus() *big.Int { return ecc.BLS12_377.ScalarField() }

// BLS12381Fp provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab (base 16)
//	4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 (base 10)
//
// This is the base field of the BLS12-381 curve.
type BLS12381Fp struct{ sixLimbPrimeField }

func (BLS12381Fp) Modulus() *big.Int { return ecc.BLS12_381.BaseField() }

// BLS12381Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 (base 16)
//	52435875175126190479447740508185965837690552500527637822603658699938581184513 (base 10)
//
// This is the scalar field of the BLS12-381 curve.
type BLS12381Fr struct{ fourLimbPrimeField }

func (BLS12381Fr) Modulus() *big.Int { return ecc.BLS12_381.ScalarField() }

// P256Fp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff (base 16)
//	115792089210356248762697446949407573530086143415290314195533631308867097853951 (base 10)
//
// This is the base field of the P-256 (also SECP256r1) curve.
type P256Fp struct{ fourLimbPrimeField }

func (P256Fp) Modulus() *big.Int { return elliptic.P256().Params().P }

// P256Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 (base 16)
//	115792089210356248762697446949407573529996955224135760342422259061068512044369 (base 10)
//
// This is the base field of the P-256 (also SECP256r1) curve.
type P256Fr struct{ fourLimbPrimeField }

func (P256Fr) Modulus() *big.Int { return elliptic.P256().Params().N }

// P384Fp provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff (base 16)
//	39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319 (base 10)
//
// This is the base field of the P-384 (also SECP384r1) curve.
type P384Fp struct{ sixLimbPrimeField }

func (P384Fp) Modulus() *big.Int { return elliptic.P384().Params().P }

// P384Fr provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973 (base 16)
//	39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643 (base 10)
//
// This is the scalar field of the P-384 (also SECP384r1) curve.
type P384Fr struct{ sixLimbPrimeField }

func (P384Fr) Modulus() *big.Int { return elliptic.P384().Params().N }

// BW6761Fp provides type parametrization for field emulation:
//   - limbs: 12
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x122e824fb83ce0ad187c94004faff3eb926186a81d14688528275ef8087be41707ba638e584e91903cebaff25b423048689c8ed12f9fd9071dcd3dc73ebff2e98a116c25667a8f8160cf8aeeaf0a437e6913e6870000082f49d00000000008b (base 16)
//	6891450384315732539396789682275657542479668912536150109513790160209623422243491736087683183289411687640864567753786613451161759120554247759349511699125301598951605099378508850372543631423596795951899700429969112842764913119068299 (base 10)
//
// This is the base field of the BW6-761 curve.
type BW6761Fp struct{ twelveLimbPrimeField }

func (BW6761Fp) Modulus() *big.Int { return ecc.BW6_761.BaseField() }

// BW6761Fr provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001 (base 16)
//	258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177 (base 10)
//
// This is the scalar field of the BW6-761 curve.
type BW6761Fr struct{ sixLimbPrimeField }

func (BW6761Fr) Modulus() *big.Int { return ecc.BW6_761.ScalarField() }

// STARKCurveFp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x800000000000011000000000000000000000000000000000000000000000001 (base 16)
//	3618502788666131213697322783095070105623107215331596699973092056135872020481 (base 10)
//
// This is the base field of the STARK curve.
type STARKCurveFp struct{ fourLimbPrimeField }

func (STARKCurveFp) Modulus() *big.Int { return ecc.STARK_CURVE.BaseField() }

// STARKCurveFr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f (base 16)
//	3618502788666131213697322783095070105526743751716087489154079457884512865583 (base 10)
//
// This is the scalar field of the STARK curve.
type STARKCurveFr struct{ fourLimbPrimeField }

func (STARKCurveFr) Modulus() *big.Int { return ecc.STARK_CURVE.ScalarField() }

// Mod1e4096 provides type parametrization for emulated arithmetic:
//   - limbs: 64
//   - limb width: 64 bits
//
// The modulus for type parametrisation is 2^4096-1.
//
// This is non-prime modulus. It is mainly targeted for using variable-modulus
// operations (ModAdd, ModMul, ModExp, ModAssertIsEqual) for variable modulus
// arithmetic.
type Mod1e4096 struct{}

func (Mod1e4096) NbLimbs() uint     { return 64 }
func (Mod1e4096) BitsPerLimb() uint { return 64 }
func (Mod1e4096) IsPrime() bool     { return false }
func (Mod1e4096) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}
func (f Mod1e4096) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return 9
	}
	return f.BitsPerLimb()
}

// Mod1e512 provides type parametrization for emulated arithmetic:
//   - limbs: 8
//   - limb width: 64 bits
//
// The modulus for type parametrisation is 2^512-1.
//
// This is non-prime modulus. It is mainly targeted for using variable-modulus
// operations (ModAdd, ModMul, ModExp, ModAssertIsEqual) for variable modulus
// arithmetic.
type Mod1e512 struct{}

func (Mod1e512) NbLimbs() uint     { return 8 }
func (Mod1e512) BitsPerLimb() uint { return 64 }
func (Mod1e512) IsPrime() bool     { return false }
func (Mod1e512) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}
func (f Mod1e512) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return 10
	}
	return f.BitsPerLimb()
}

// Mod1e256 provides type parametrization for emulated arithmetic:
//   - limbs: 4
//   - limb width: 64 bits
//
// The modulus for type parametrisation is 2^256-1.
//
// This is non-prime modulus. It is mainly targeted for using variable-modulus
// operations (ModAdd, ModMul, ModExp, ModAssertIsEqual) for variable modulus
// arithmetic.
type Mod1e256 struct{}

func (Mod1e256) NbLimbs() uint     { return 4 }
func (Mod1e256) BitsPerLimb() uint { return 64 }
func (Mod1e256) IsPrime() bool     { return false }
func (Mod1e256) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}
func (f Mod1e256) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return 11
	}
	return f.BitsPerLimb()
}

// BabyBear provides type parametrization for field emulation:
//   - limbs: 1
//   - limb width: 31 bits
//
// The prime modulus for type parametrisation is:
//
//	15*2^27+1
//	0x78000001 (base 16)
//	2013265921 (base 10)
//
// The field has 2-adicity of 27.
type BabyBear struct{ oneLimbPrimeField }

func (BabyBear) BitsPerLimb() uint { return 31 }
func (BabyBear) Modulus() *big.Int { return big.NewInt(2013265921) }
func (f BabyBear) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return smallFieldOneLimbBits
	}
	return f.BitsPerLimb()
}

// KoalaBear provides type parametrization for field emulation:
//   - limbs: 1
//   - limb width: 31 bits
//
// The prime modulus for type parametrisation is:
//
//	2^31-2^24+1
//	0x7f000001 (base 16)
//	2130706433 (base 10)
//
// The field has 2-adicity of 24.
type KoalaBear struct{ oneLimbPrimeField }

func (KoalaBear) BitsPerLimb() uint { return 31 }
func (KoalaBear) Modulus() *big.Int { return big.NewInt(2130706433) }
func (f KoalaBear) BitsPerLimbDynamic(field *big.Int) uint {
	if smallfields.IsSmallField(field) {
		return smallFieldOneLimbBits
	}
	return f.BitsPerLimb()
}
