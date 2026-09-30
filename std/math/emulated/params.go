package emulated

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// FieldParams describes the emulated field characteristics. For a list of
// included built-in emulation params refer to the [emparams] package.
// For backwards compatibility, the current package contains the following
// parameters:
//   - [Goldilocks]
//   - [Secp256k1Fp] and [Secp256k1Fr]
//   - [BN254Fp] and [BN254Fr]
//   - [BLS12377Fp]
//   - [BLS12381Fp] and [BLS12381Fr]
//   - [P256Fp] and [P256Fr]
//   - [P384Fp] and [P384Fr]
//   - [STARKCurveFp] and [STARKCurveFr]
//   - [BabyBear] and [KoalaBear]
type FieldParams interface {
	NbLimbs() uint     // number of limbs to represent field element
	BitsPerLimb() uint // number of bits per limb. Top limb may contain less than limbSize bits.
	IsPrime() bool     // indicates if the modulus is prime
	Modulus() *big.Int // returns modulus. Do not modify.
}

// DynamicFieldParams extends the FieldParams interface to allow for the limb
// size to depend on the native field size. If the field emulation parameters do
// not implement this interface, then the limb size and count are fixed to the
// values defined in the FieldParams interface.
//
// The interface allows for optimized emulation in case the native field is
// large (more than 256 bits) and enables field emulation when the native field
// is small (less than 128 bits).
//
// Only the limb size is part of the interface. The number of limbs is always
// derived from it and the modulus, see [GetEffectiveFieldParams].
//
// All defined parameters in the [emparams] package implement this interface.
type DynamicFieldParams interface {
	FieldParams

	BitsPerLimbDynamic(field *big.Int) uint
}

type (
	Goldilocks   = emparams.Goldilocks
	Secp256k1Fp  = emparams.Secp256k1Fp
	Secp256k1Fr  = emparams.Secp256k1Fr
	BN254Fp      = emparams.BN254Fp
	BN254Fr      = emparams.BN254Fr
	BLS12377Fp   = emparams.BLS12377Fp
	BLS12381Fp   = emparams.BLS12381Fp
	BLS12381Fr   = emparams.BLS12381Fr
	P256Fp       = emparams.P256Fp
	P256Fr       = emparams.P256Fr
	P384Fp       = emparams.P384Fp
	P384Fr       = emparams.P384Fr
	BW6761Fp     = emparams.BW6761Fp
	BW6761Fr     = emparams.BW6761Fr
	STARKCurveFp = emparams.STARKCurveFp
	STARKCurveFr = emparams.STARKCurveFr
	BabyBear     = emparams.BabyBear
	KoalaBear    = emparams.KoalaBear
)

// ensure that all parameters implement the DynamicFieldParams interface
var (
	_ DynamicFieldParams = (*Goldilocks)(nil)
	_ DynamicFieldParams = (*Secp256k1Fp)(nil)
	_ DynamicFieldParams = (*Secp256k1Fr)(nil)
	_ DynamicFieldParams = (*BN254Fp)(nil)
	_ DynamicFieldParams = (*BN254Fr)(nil)
	_ DynamicFieldParams = (*BLS12377Fp)(nil)
	_ DynamicFieldParams = (*BLS12381Fp)(nil)
	_ DynamicFieldParams = (*BLS12381Fr)(nil)
	_ DynamicFieldParams = (*P256Fp)(nil)
	_ DynamicFieldParams = (*P256Fr)(nil)
	_ DynamicFieldParams = (*P384Fp)(nil)
	_ DynamicFieldParams = (*P384Fr)(nil)
	_ DynamicFieldParams = (*BW6761Fp)(nil)
	_ DynamicFieldParams = (*BW6761Fr)(nil)
	_ DynamicFieldParams = (*STARKCurveFp)(nil)
	_ DynamicFieldParams = (*STARKCurveFr)(nil)
	_ DynamicFieldParams = (*BabyBear)(nil)
	_ DynamicFieldParams = (*KoalaBear)(nil)
)

// staticFieldParams is a wrapper to avoid calling the dynamic methods in DynamicFieldParams
// all the time. The native field stays intact and we can cache the values.
type staticFieldParams[T FieldParams] struct {
	fp              T
	nbLimbs, nbBits uint
}

func newStaticFieldParams[T FieldParams](field *big.Int) staticFieldParams[T] {
	var fp T
	nbLimbs, nbBits := GetEffectiveFieldParams[T](field)
	return staticFieldParams[T]{fp: fp, nbLimbs: nbLimbs, nbBits: nbBits}
}

func (s *staticFieldParams[T]) Modulus() *big.Int { return s.fp.Modulus() }
func (s *staticFieldParams[T]) IsPrime() bool     { return s.fp.IsPrime() }
func (s *staticFieldParams[T]) NbLimbs() uint     { return s.nbLimbs }
func (s *staticFieldParams[T]) BitsPerLimb() uint { return s.nbBits }

// GetEffectiveFieldParams returns the number of limbs and bits per limb for a
// given field. If the field implements the DynamicFieldParams interface, then
// the limb size is computed dynamically based on the field size and the number
// of limbs is derived from it. Otherwise, the values are taken from the
// FieldParams interface.
//
// The number of limbs is always the smallest count which fits the modulus, as
// required by [NewField]. It is derived rather than declared so that the two
// cannot drift apart.
func GetEffectiveFieldParams[T FieldParams](field *big.Int) (nbLimbs, nbBits uint) {
	var fp T
	if f, ok := any(fp).(DynamicFieldParams); ok {
		nbBits = f.BitsPerLimbDynamic(field)
		nbLimbs = (uint(fp.Modulus().BitLen()) + nbBits - 1) / nbBits
	} else {
		nbLimbs = fp.NbLimbs()
		nbBits = fp.BitsPerLimb()
	}
	return nbLimbs, nbBits
}
