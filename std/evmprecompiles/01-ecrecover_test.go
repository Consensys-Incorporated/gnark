package evmprecompiles

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestSignForRecoverCorrectness(t *testing.T) {
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	_, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	var sig ecdsa.Signature
	r.FillBytes(sig.R[:fr.Bytes])
	s.FillBytes(sig.S[:fr.Bytes])
	sigM := sig.Bytes()
	ok, err := pk.Verify(sigM, msg, nil)
	if err != nil {
		t.Fatal("verify", err)
	}
	if !ok {
		t.Fatal("not verified")
	}
}

func TestECRecoverGeneratorCommitment(t *testing.T) {
	assert := test.NewAssert(t)

	// Use k=1 and d=1, so the ECDSA commitment is R=G. This forces r=G.x,
	// which is a degenerate input for incomplete JointScalarMulBase.
	_, generator := secp256k1.Generators()
	msgDigest := sha256.Sum256([]byte("ecrecover regression: r = G.x"))
	msgHash := ecdsa.HashToInt(msgDigest[:])
	r := generator.X.BigInt(new(big.Int))
	s := new(big.Int).Add(msgHash, r)
	s.Mod(s, fr.Modulus())
	if s.Sign() == 0 {
		t.Fatal("constructed zero s")
	}
	v := uint(generator.Y.BigInt(new(big.Int)).Bit(0))

	var pk ecdsa.PublicKey
	err := pk.RecoverFrom(msgDigest[:], v, r, s)
	assert.NoError(err)

	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](msgHash),
		V:         v + 27,
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ecrecoverCircuit struct {
	Message   emulated.Element[emulated.Secp256k1Fr]
	V         frontend.Variable
	R         emulated.Element[emulated.Secp256k1Fr]
	S         emulated.Element[emulated.Secp256k1Fr]
	Strict    frontend.Variable
	IsFailure frontend.Variable
	Expected  sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

func (c *ecrecoverCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	res := ECRecover(api, c.Message, c.V, c.R, c.S, c.Strict, c.IsFailure)
	curve.AssertIsEqual(&c.Expected, res)
	return nil
}

func testRoutineECRecover(t *testing.T, forceLargeS bool) (circ, wit *ecrecoverCircuit) {
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))

	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	// SignForRecover always returns s < r_mod/2. But in the tests we want
	// to check that the circuit fails when s > r_mod/2 in strict mode.
	if forceLargeS {
		// first we make s large
		s.Sub(fr.Modulus(), s)
		// but we also have to swap the sign of the recovered public key
		v ^= 1
	}

	strict := 1
	if forceLargeS {
		strict = 0
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    strict,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	return &circuit, &witness
}

func TestECRecoverCircuitShortStrict(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortLax(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, true)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))
	var circuit, witness *ecrecoverCircuit
	circuit, witness = testRoutineECRecover(t, true)
	witness.Strict = 1
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
}

func TestECRecoverCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	_, witness2 := testRoutineECRecover(t, true)

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(witness),
		test.WithValidAssignment(witness2),
		test.WithCurves(ecc.BN254, ecc.BLS12_377),
		test.NoProverChecks(),
	)
}

func TestECRecoverQNR(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	_, err := sk.SetBytes([]byte{0x80, 0x95, 0xb4, 0x19, 0x78, 0xe3, 0x7c, 0xb2, 0x44, 0x76, 0xd3, 0x76, 0x90, 0x87, 0x33, 0x61, 0x89, 0xcf, 0xac, 0xc2, 0x60, 0x2d, 0xf9, 0x83, 0xcc, 0xb5, 0xb2, 0x5c, 0x84, 0xe9, 0x41, 0x76, 0x7e, 0xe7, 0x47, 0x4b, 0x89, 0xbb, 0x50, 0xe0, 0x6, 0xf6, 0x11, 0x25, 0xf2, 0xe8, 0xf7, 0xb2, 0x59, 0x9d, 0xa8, 0x7, 0x48, 0x2b, 0x6d, 0x8c, 0x3e, 0x28, 0x5, 0x93, 0xf8, 0x5c, 0xcc, 0xc9, 0xe, 0x40, 0x3d, 0x19, 0x13, 0xad, 0x7f, 0xc1, 0x63, 0x93, 0x71, 0xb6, 0x8d, 0x3d, 0x43, 0x7a, 0x7f, 0x8, 0x9f, 0xaa, 0x8f, 0xc, 0xf6, 0xf8, 0x5, 0xad, 0xaf, 0x23, 0x93, 0x34, 0x97, 0xba})
	assert.NoError(err)
	msg := []byte("test")
	v := 1
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 1,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](0),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECRecoverQNRWoFailure(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	_, err := sk.SetBytes([]byte{0x80, 0x95, 0xb4, 0x19, 0x78, 0xe3, 0x7c, 0xb2, 0x44, 0x76, 0xd3, 0x76, 0x90, 0x87, 0x33, 0x61, 0x89, 0xcf, 0xac, 0xc2, 0x60, 0x2d, 0xf9, 0x83, 0xcc, 0xb5, 0xb2, 0x5c, 0x84, 0xe9, 0x41, 0x76, 0x7e, 0xe7, 0x47, 0x4b, 0x89, 0xbb, 0x50, 0xe0, 0x6, 0xf6, 0x11, 0x25, 0xf2, 0xe8, 0xf7, 0xb2, 0x59, 0x9d, 0xa8, 0x7, 0x48, 0x2b, 0x6d, 0x8c, 0x3e, 0x28, 0x5, 0x93, 0xf8, 0x5c, 0xcc, 0xc9, 0xe, 0x40, 0x3d, 0x19, 0x13, 0xad, 0x7f, 0xc1, 0x63, 0x93, 0x71, 0xb6, 0x8d, 0x3d, 0x43, 0x7a, 0x7f, 0x8, 0x9f, 0xaa, 0x8f, 0xc, 0xf6, 0xf8, 0x5, 0xad, 0xaf, 0x23, 0x93, 0x34, 0x97, 0xba})
	assert.NoError(err)
	msg := []byte("test")
	v := 1
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](0),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

func TestECRecoverInfinity(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	var err error
	pk := sk.Public().(*ecdsa.PublicKey)
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 1,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECRecoverInfinityWoFailure(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	var err error
	pk := sk.Public().(*ecdsa.PublicKey)
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

func TestInvalidFailureTag(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	witness.IsFailure = 1
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
	_, witness2 := testRoutineECRecover(t, true)
	witness2.IsFailure = 1
	err = test.IsSolved(circuit, witness2, ecc.BN254.ScalarField())
	assert.Error(err)
}

func TestLargeV(t *testing.T) {
	assert := test.NewAssert(t)
	var pk ecdsa.PublicKey
	msg := []byte("test")
	var rE, sE fr.Element
	r, s := new(big.Int), new(big.Int)
	for _, v := range []uint{2, 3} {
		for {
			rE.SetRandom()
			sE.SetRandom()
			rE.BigInt(r)
			sE.BigInt(s)
			if err := pk.RecoverFrom(msg, v, r, s); errors.Is(err, ecdsa.ErrNoSqrtR) {
				continue
			} else {
				assert.NoError(err)
				break
			}
		}
		circuit := ecrecoverCircuit{}
		witness := ecrecoverCircuit{
			Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
			V:         v + 27, // EVM constant
			R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
			S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
			Strict:    0,
			IsFailure: 0,
			Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
			},
		}
		err := test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
		assert.Error(err)
	}
}

func TestOverKoalabear(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, koalabear.Modulus())
	assert.NoError(err)
}

// TestECRecoverNonCanonicalSqrtRoot is a regression test for a soundness
// issue in ECRecover: the parity of Ry was taken from Field.ToBits, which
// decomposes the element as-is. Sqrt only enforces that the hinted root fits
// the limb width and squares to the input, so for roots y < 2^32 + 977 a
// prover could return the non-canonical encoding y + p. As p is odd, this
// flips the parity bit, the circuit then selects the negated point -R, and
// the recovered public key diverges from what the EVM ecrecover returns for
// the same (msg, v, r, s). The fix reads the parity from
// Field.ToBitsCanonical instead.
func TestECRecoverNonCanonicalSqrtRoot(t *testing.T) {
	assert := test.NewAssert(t)
	p := emulated.Secp256k1Fp{}.Modulus()
	n := fr.Modulus()

	// Craft a curve point R = (x, y) with y < 2^32 + 977 so that y + p still
	// fits the limb width. We need y^2 - 7 to be a cubic residue mod p
	// (p = 1 mod 3, so this holds for about one y in three); x is then a cube
	// root of y^2 - 7.
	pm1over3 := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(3))
	cubeRootExp := new(big.Int).ModInverse(big.NewInt(3), pm1over3)
	limit := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(977))
	var x, y *big.Int
	for yi := int64(1); ; yi++ {
		y = big.NewInt(yi)
		c := new(big.Int).Mul(y, y)
		c.Sub(c, big.NewInt(7)).Mod(c, p)
		if c.Sign() == 0 || new(big.Int).Exp(c, pm1over3, p).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		xi := new(big.Int).Exp(c, cubeRootExp, p)
		x3 := new(big.Int).Exp(xi, big.NewInt(3), p)
		x3.Add(x3, big.NewInt(7)).Mod(x3, p)
		y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), p)
		if x3.Cmp(y2) != 0 || xi.Sign() == 0 || xi.Cmp(n) >= 0 {
			continue
		}
		x = xi
		break
	}
	if y.Cmp(limit) >= 0 {
		t.Fatal("no small-y point found")
	}

	// signature material: r = R.x, v = parity of the small root y, any s.
	r := new(big.Int).Set(x)
	v := uint(y.Bit(0))
	s := big.NewInt(42)
	msg := big.NewInt(123456789)

	// qHonest is what the EVM returns; qForged is recovery with -R.
	var pkHonest, pkForged ecdsa.PublicKey
	assert.NoError(pkHonest.RecoverFrom(msg.Bytes(), v, r, s))
	assert.NoError(pkForged.RecoverFrom(msg.Bytes(), v^1, r, s))

	mkAssignment := func(pk *ecdsa.PublicKey) *ecrecoverCircuit {
		return &ecrecoverCircuit{
			Message:   emulated.ValueOf[emulated.Secp256k1Fr](msg),
			V:         v + 27,
			R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
			S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
			Strict:    0,
			IsFailure: 0,
			Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
			},
		}
	}
	witnessHonest := mkAssignment(&pkHonest)
	witnessForged := mkAssignment(&pkForged)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ecrecoverCircuit{})
	assert.NoError(err)

	// the malicious prover returns y + p from the Sqrt hint whenever the
	// non-canonical encoding fits the limb width.
	forgedSqrtHint := func(_ *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHint(in, out, func(mod *big.Int, inputs, outputs []*big.Int) error {
			a := new(big.Int).Mod(inputs[0], mod)
			z := new(big.Int).ModSqrt(a, mod)
			if z == nil {
				return nil
			}
			if w := new(big.Int).Sub(mod, z); z.Cmp(limit) >= 0 && w.Cmp(limit) < 0 {
				z.Set(w)
			}
			if z.Cmp(limit) < 0 {
				outputs[0].Add(z, mod)
			} else {
				outputs[0].Set(z)
			}
			return nil
		})
	}
	// and returns the wrong public key from the recovery hint.
	nbFpLimbs, nbFpBits := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fp](ecc.BN254.ScalarField())
	forgedPKHint := func(_ *big.Int, _, outputs []*big.Int) error {
		qx := pkForged.A.X.BigInt(new(big.Int))
		qy := pkForged.A.Y.BigInt(new(big.Int))
		if err := limbs.Decompose(qx, uint(nbFpBits), outputs[:nbFpLimbs]); err != nil {
			return err
		}
		if err := limbs.Decompose(qy, uint(nbFpBits), outputs[nbFpLimbs:2*nbFpLimbs]); err != nil {
			return err
		}
		outputs[2*nbFpLimbs].SetInt64(0)
		return nil
	}
	sqrtID := solver.GetHintID(emulated.SqrtHint)
	pkID := solver.GetHintID(recoverPublicKeyHint)

	wHonest, err := frontend.NewWitness(witnessHonest, ecc.BN254.ScalarField())
	assert.NoError(err)
	wForged, err := frontend.NewWitness(witnessForged, ecc.BN254.ScalarField())
	assert.NoError(err)

	// sanity: the honest assignment solves with the honest hints.
	assert.NoError(ccs.IsSolved(wHonest))

	// the fix makes the circuit agnostic to the root encoding: even with the
	// forged Sqrt hint the proof still attests the EVM-correct key.
	assert.NoError(ccs.IsSolved(wHonest, solver.OverrideHint(sqrtID, forgedSqrtHint)))

	// but claiming the divergent key must be rejected. Before the fix, this
	// witness was accepted: the flipped parity made the in-circuit
	// recomputation match the forged key.
	err = ccs.IsSolved(wForged,
		solver.OverrideHint(sqrtID, forgedSqrtHint),
		solver.OverrideHint(pkID, forgedPKHint))
	assert.Error(err, "forged witness claiming the non-EVM key must be rejected")
}
