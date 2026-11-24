package sw_emulated

import (
	"fmt"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	stark_curve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	fr_stark "github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// decomposeToLimbs returns the limb decomposition of v in the representation
// used by the emulated field T. Note that v is *not* reduced modulo the
// modulus of T -- this is on purpose, it allows building witnesses which are
// non-canonical representations of a field element (the limbs are only
// range-checked to T.BitsPerLimb(), so any representative which fits into
// T.NbLimbs()*T.BitsPerLimb() bits is accepted by the circuit).
func decomposeToLimbs[T emulated.FieldParams](v *big.Int) []frontend.Variable {
	var fp T
	nbLimbs := int(fp.NbLimbs())
	ls := make([]*big.Int, nbLimbs)
	for i := range ls {
		ls[i] = new(big.Int)
	}
	if err := limbs.Decompose(v, fp.BitsPerLimb(), ls); err != nil {
		panic(fmt.Sprintf("decompose: %v", err))
	}
	res := make([]frontend.Variable, nbLimbs)
	for i := range ls {
		res[i] = ls[i]
	}
	return res
}

// -----------------------------------------------------------------------------
// Canonical marshalling (item 1)
// -----------------------------------------------------------------------------

type marshalScalarCanonicalCircuit[B, S emulated.FieldParams] struct {
	Limbs1 []frontend.Variable
	Limbs2 []frontend.Variable
}

func (c *marshalScalarCanonicalCircuit[B, S]) Define(api frontend.API) error {
	cr, err := New[B, S](api, GetCurveParams[B]())
	if err != nil {
		return err
	}
	s1 := emulated.Element[S]{Limbs: c.Limbs1}
	s2 := emulated.Element[S]{Limbs: c.Limbs2}
	// the two elements are equal as field elements...
	cr.scalarApi.AssertIsEqual(&s1, &s2)
	// ... so they must have the same marshalling.
	b1 := cr.MarshalScalar(s1)
	b2 := cr.MarshalScalar(s2)
	if len(b1) != len(b2) {
		return fmt.Errorf("different bit lengths %d != %d", len(b1), len(b2))
	}
	for i := range b1 {
		api.AssertIsEqual(b1[i], b2[i])
	}
	return nil
}

type marshalG1CanonicalCircuit[B, S emulated.FieldParams] struct {
	X1 []frontend.Variable
	X2 []frontend.Variable
	Y  []frontend.Variable
}

func (c *marshalG1CanonicalCircuit[B, S]) Define(api frontend.API) error {
	cr, err := New[B, S](api, GetCurveParams[B]())
	if err != nil {
		return err
	}
	p1 := AffinePoint[B]{X: emulated.Element[B]{Limbs: c.X1}, Y: emulated.Element[B]{Limbs: c.Y}}
	p2 := AffinePoint[B]{X: emulated.Element[B]{Limbs: c.X2}, Y: emulated.Element[B]{Limbs: c.Y}}
	// the two points are equal as curve points...
	cr.AssertIsEqual(&p1, &p2)
	// ... so they must have the same marshalling.
	b1 := cr.MarshalG1(p1)
	b2 := cr.MarshalG1(p2)
	if len(b1) != len(b2) {
		return fmt.Errorf("different bit lengths %d != %d", len(b1), len(b2))
	}
	for i := range b1 {
		api.AssertIsEqual(b1[i], b2[i])
	}
	return nil
}

// TestMarshalIsCanonical checks that two different limb representations of the
// same field element marshal to the same bit string. This is what the
// Fiat-Shamir transcript depends on: MarshalScalar/MarshalG1 feed the
// transcript hash, so a prover able to pick between several accepted
// encodings of the same value can grind the challenge.
func TestMarshalIsCanonical(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		var fr emparams.BN254Fr
		r := fr.Modulus()
		v := big.NewInt(5)
		vPlusR := new(big.Int).Add(v, r)

		circuit := &marshalScalarCanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			Limbs1: make([]frontend.Variable, fr.NbLimbs()),
			Limbs2: make([]frontend.Variable, fr.NbLimbs()),
		}
		witness := &marshalScalarCanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			Limbs1: decomposeToLimbs[emparams.BN254Fr](v),
			Limbs2: decomposeToLimbs[emparams.BN254Fr](vPlusR),
		}
		err := test.IsSolved(circuit, witness, testCurve.ScalarField())
		assert.NoError(err)
	}, "scalar")

	assert.Run(func(assert *test.Assert) {
		var fp emparams.BN254Fp
		p := fp.Modulus()
		x := big.NewInt(5)
		xPlusP := new(big.Int).Add(x, p)

		circuit := &marshalG1CanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			X1: make([]frontend.Variable, fp.NbLimbs()),
			X2: make([]frontend.Variable, fp.NbLimbs()),
			Y:  make([]frontend.Variable, fp.NbLimbs()),
		}
		witness := &marshalG1CanonicalCircuit[emparams.BN254Fp, emparams.BN254Fr]{
			X1: decomposeToLimbs[emparams.BN254Fp](x),
			X2: decomposeToLimbs[emparams.BN254Fp](xPlusP),
			Y:  decomposeToLimbs[emparams.BN254Fp](big.NewInt(7)),
		}
		err := test.IsSolved(circuit, witness, testCurve.ScalarField())
		assert.NoError(err)
	}, "g1")
}

// -----------------------------------------------------------------------------
// Infinity flag overwriting a bit of X (item 2, GHSA-6qxq-hjjq-c9r4)
// -----------------------------------------------------------------------------

type marshalG1DifferCircuit[B, S emulated.FieldParams] struct {
	X1, X2, Y emulated.Element[B]
}

func (c *marshalG1DifferCircuit[B, S]) Define(api frontend.API) error {
	cr, err := New[B, S](api, GetCurveParams[B]())
	if err != nil {
		return err
	}
	b1 := cr.MarshalG1(AffinePoint[B]{X: c.X1, Y: c.Y})
	b2 := cr.MarshalG1(AffinePoint[B]{X: c.X2, Y: c.Y})
	if len(b1) != len(b2) {
		return fmt.Errorf("different bit lengths %d != %d", len(b1), len(b2))
	}
	differs := frontend.Variable(0)
	for i := range b1 {
		d := api.Sub(1, api.IsZero(api.Sub(b1[i], b2[i])))
		differs = api.Or(differs, d)
	}
	api.AssertIsEqual(differs, 1)
	return nil
}

func testMarshalG1NoFlagCollision[B, S emulated.FieldParams](assert *test.Assert) {
	var fp B
	bitLen := fp.Modulus().BitLen()
	nbBits := 8 * ((bitLen + 7) / 8)
	// res[1] of the marshalling is bit (nbBits-2) of X. If that bit is above
	// the bit length of the modulus then it is structurally zero for any
	// canonical X and the overwrite is harmless.
	bitPos := nbBits - 2
	if bitPos >= bitLen {
		// nothing to check: no canonical X has that bit set, so overwriting it
		// is harmless and the infinity flag legitimately lives there.
		return
	}
	x1 := new(big.Int).Lsh(big.NewInt(1), uint(bitPos))
	x1.Add(x1, big.NewInt(12345))
	x2 := big.NewInt(12345)
	assert.True(x1.Cmp(fp.Modulus()) < 0, "x1 must be canonical")

	circuit := &marshalG1DifferCircuit[B, S]{}
	witness := &marshalG1DifferCircuit[B, S]{
		X1: emulated.ValueOf[B](x1),
		X2: emulated.ValueOf[B](x2),
		Y:  emulated.ValueOf[B](7),
	}
	err := test.IsSolved(circuit, witness, testCurve.ScalarField())
	assert.NoError(err)
}

// TestMarshalG1NoFlagCollision checks that MarshalG1 does not clobber a bit of
// X with the point-at-infinity flag on curves whose modulus leaves no spare
// bits in the leading byte (secp256k1, P-256, P-384).
func TestMarshalG1NoFlagCollision(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		testMarshalG1NoFlagCollision[emparams.P256Fp, emparams.P256Fr](assert)
	}, "P256")
	assert.Run(func(assert *test.Assert) {
		testMarshalG1NoFlagCollision[emparams.P384Fp, emparams.P384Fr](assert)
	}, "P384")
	assert.Run(func(assert *test.Assert) {
		testMarshalG1NoFlagCollision[emparams.Secp256k1Fp, emparams.Secp256k1Fr](assert)
	}, "secp256k1")
	assert.Run(func(assert *test.Assert) {
		testMarshalG1NoFlagCollision[emparams.BN254Fp, emparams.BN254Fr](assert)
	}, "bn254")
	assert.Run(func(assert *test.Assert) {
		testMarshalG1NoFlagCollision[emparams.BLS12381Fp, emparams.BLS12381Fr](assert)
	}, "bls12381")
}

// -----------------------------------------------------------------------------
// Cross-check against gnark-crypto
// -----------------------------------------------------------------------------

// testMarshalG1AgainstBytes compares the in-circuit marshalling of (x,y)
// against the expected byte serialization produced by gnark-crypto.
func testMarshalG1AgainstBytes[B, S emulated.FieldParams](assert *test.Assert, x, y *big.Int, expected []byte) {
	nbBits := len(expected) * 8
	circuit := &MarshalG1Test[B, S]{R: make([]frontend.Variable, nbBits)}
	witness := &MarshalG1Test[B, S]{
		G: AffinePoint[B]{X: emulated.ValueOf[B](x), Y: emulated.ValueOf[B](y)},
		R: make([]frontend.Variable, nbBits),
	}
	for i := 0; i < len(expected); i++ {
		for j := 0; j < 8; j++ {
			witness.R[i*8+j] = (expected[i] >> (7 - j)) & 1
		}
	}
	err := test.IsSolved(circuit, witness, testCurve.ScalarField())
	assert.NoError(err)
}

// TestMarshalG1MatchesGnarkCrypto pins the infinity-flag table against
// gnark-crypto for every pairing-friendly curve supported by this package, for
// a random point and for the point at infinity. A newly supported curve which
// does not agree with gnark-crypto must fail here.
//
// NB: BLS12-377 is not covered because GetCurveParams has no entry for it.
func TestMarshalG1MatchesGnarkCrypto(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		var r fr_bn254.Element
		_, err := r.SetRandom()
		assert.NoError(err)
		var P bn254.G1Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		testMarshalG1AgainstBytes[emparams.BN254Fp, emparams.BN254Fr](assert,
			P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int)), P.Marshal())
	}, "bn254/random")
	assert.Run(func(assert *test.Assert) {
		var P bn254.G1Affine // infinity
		assert.True(P.IsInfinity())
		testMarshalG1AgainstBytes[emparams.BN254Fp, emparams.BN254Fr](assert,
			new(big.Int), new(big.Int), P.Marshal())
	}, "bn254/infinity")

	assert.Run(func(assert *test.Assert) {
		var r fr_bls12381.Element
		_, err := r.SetRandom()
		assert.NoError(err)
		var P bls12381.G1Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		testMarshalG1AgainstBytes[emparams.BLS12381Fp, emparams.BLS12381Fr](assert,
			P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int)), P.Marshal())
	}, "bls12381/random")
	assert.Run(func(assert *test.Assert) {
		var P bls12381.G1Affine // infinity
		assert.True(P.IsInfinity())
		testMarshalG1AgainstBytes[emparams.BLS12381Fp, emparams.BLS12381Fr](assert,
			new(big.Int), new(big.Int), P.Marshal())
	}, "bls12381/infinity")

	assert.Run(func(assert *test.Assert) {
		var r fr_bw6761.Element
		_, err := r.SetRandom()
		assert.NoError(err)
		var P bw6761.G1Affine
		P.ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		testMarshalG1AgainstBytes[emparams.BW6761Fp, emparams.BW6761Fr](assert,
			P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int)), P.Marshal())
	}, "bw6761/random")
	assert.Run(func(assert *test.Assert) {
		var P bw6761.G1Affine // infinity
		assert.True(P.IsInfinity())
		testMarshalG1AgainstBytes[emparams.BW6761Fp, emparams.BW6761Fr](assert,
			new(big.Int), new(big.Int), P.Marshal())
	}, "bw6761/infinity")
}

// TestMarshalOnSmallNativeField checks that MarshalScalar and MarshalG1 work
// when the native field is a small field (KoalaBear, BabyBear). There the limbs
// are narrow and the limb decomposition can cover fewer bits than the
// byte-aligned encoding (e.g. 253 bits for STARK curve elements, encoded on
// 256 bits), so the bit decomposition must be padded.
func TestMarshalOnSmallNativeField(t *testing.T) {
	assert := test.NewAssert(t)
	var s fr_stark.Element
	_, err := s.SetRandom()
	assert.NoError(err)
	var P stark_curve.G1Affine
	P.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
	sBytes := s.Marshal()
	pBytes := P.Marshal()
	for _, field := range []*big.Int{koalabear.Modulus(), babybear.Modulus()} {
		assert.Run(func(assert *test.Assert) {
			circuit := &MarshalScalarTest[emparams.STARKCurveFp, emparams.STARKCurveFr]{
				R: make([]frontend.Variable, 8*len(sBytes)),
			}
			witness := &MarshalScalarTest[emparams.STARKCurveFp, emparams.STARKCurveFr]{
				X: emulated.ValueOf[emparams.STARKCurveFr](s),
				R: bytesToBits(sBytes),
			}
			assert.NoError(test.IsSolved(circuit, witness, field))
		}, fmt.Sprintf("scalar/%s", field))
		assert.Run(func(assert *test.Assert) {
			circuit := &MarshalG1Test[emparams.STARKCurveFp, emparams.STARKCurveFr]{
				R: make([]frontend.Variable, 8*len(pBytes)),
			}
			witness := &MarshalG1Test[emparams.STARKCurveFp, emparams.STARKCurveFr]{
				G: AffinePoint[emparams.STARKCurveFp]{
					X: emulated.ValueOf[emparams.STARKCurveFp](P.X),
					Y: emulated.ValueOf[emparams.STARKCurveFp](P.Y),
				},
				R: bytesToBits(pBytes),
			}
			assert.NoError(test.IsSolved(circuit, witness, field))
		}, fmt.Sprintf("g1/%s", field))
	}
}

// bytesToBits returns the big-endian bit decomposition of b.
func bytesToBits(b []byte) []frontend.Variable {
	res := make([]frontend.Variable, 8*len(b))
	for i := range b {
		for j := 0; j < 8; j++ {
			res[i*8+j] = (b[i] >> (7 - j)) & 1
		}
	}
	return res
}
