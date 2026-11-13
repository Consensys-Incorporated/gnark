package evmprecompiles

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// The tests in this file model a MALICIOUS prover. The bugs they cover live at
// the constraint level and are completely masked by the honest hints -- a
// malicious prover simply does not run them. So neither test.IsSolved nor the
// test engine can see these: every test here compiles the circuit to R1CS and
// calls ccs.IsSolved with solver.OverrideHint.

// forgedPublicKeyHint replaces recoverPublicKeyHint by one that returns the
// attacker-chosen point (x, y) together with the attacker-chosen zero flag.
func forgedPublicKeyHint(nativeField, x, y *big.Int, pIsZero int64) solver.Hint {
	nbFpLimbs, nbFpBits := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fp](nativeField)
	return func(_ *big.Int, _, outputs []*big.Int) error {
		if err := limbs.Decompose(x, uint(nbFpBits), outputs[:nbFpLimbs]); err != nil {
			return err
		}
		if err := limbs.Decompose(y, uint(nbFpBits), outputs[nbFpLimbs:2*nbFpLimbs]); err != nil {
			return err
		}
		outputs[2*nbFpLimbs].SetInt64(pIsZero)
		return nil
	}
}

// forgedDivHint replaces emulated.DivHint. It behaves honestly everywhere
// except when the denominator is zero modulo the emulated modulus: there the
// honest hint has no answer, but Div only ever constrains out*denom == nom, so
// when the numerator is zero as well *any* output satisfies the circuit. The
// malicious prover returns k.
func forgedDivHint(k *big.Int) solver.Hint {
	return func(mod *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) < 4 {
			return emulated.DivHint(mod, inputs, outputs)
		}
		nbBits := uint(inputs[0].Uint64())
		nbLimbs := int(inputs[1].Int64())
		nbNomLimbs := int(inputs[3].Int64())
		p := new(big.Int)
		if err := limbs.Recompose(inputs[4:4+nbLimbs], nbBits, p); err != nil {
			return emulated.DivHint(mod, inputs, outputs)
		}
		denom := new(big.Int)
		if err := limbs.Recompose(inputs[4+nbLimbs+nbNomLimbs:], nbBits, denom); err != nil {
			return emulated.DivHint(mod, inputs, outputs)
		}
		if denom.Sign() != 0 && new(big.Int).Mod(denom, p).Sign() == 0 {
			return limbs.Decompose(new(big.Int).Mod(k, p), nbBits, outputs)
		}
		return emulated.DivHint(mod, inputs, outputs)
	}
}

// liftX returns the point of secp256k1 with the given x coordinate and the
// requested y parity, plus that parity. It fails if x is not on the curve.
func liftX(t *testing.T, x *big.Int) (secp256k1.G1Affine, uint) {
	t.Helper()
	var xe, y2, y, b fp.Element
	xe.SetBigInt(x)
	b.SetUint64(7)
	y2.Square(&xe).Mul(&y2, &xe).Add(&y2, &b)
	if y.Sqrt(&y2) == nil {
		t.Fatalf("x = %s is not on the curve", x)
	}
	var P secp256k1.G1Affine
	P.X = xe
	P.Y = y
	if !P.IsOnCurve() {
		t.Fatal("lifted point not on curve")
	}
	return P, uint(y.BigInt(new(big.Int)).Bit(0))
}

// randomValidR returns an (r, v) pair coming from an honest commitment R=[t]G
// with r = R.x < n, together with R itself.
func randomValidR(t *testing.T) (*big.Int, uint, secp256k1.G1Affine) {
	t.Helper()
	n := fr.Modulus()
	for i := int64(2); i < 100; i++ {
		var R secp256k1.G1Affine
		R.ScalarMultiplicationBase(big.NewInt(i))
		r := R.X.BigInt(new(big.Int))
		if r.Sign() == 0 || r.Cmp(n) >= 0 {
			continue
		}
		return r, uint(R.Y.BigInt(new(big.Int)).Bit(0)), R
	}
	t.Fatal("no valid r found")
	return nil, 0, secp256k1.G1Affine{}
}

func mkECRecoverWitness(msg, r, s *big.Int, v uint, strict, isFailure int, Q secp256k1.G1Affine) *ecrecoverCircuit {
	return &ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](msg),
		V:         v + 27,
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    strict,
		IsFailure: isFailure,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Q.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Q.Y),
		},
	}
}

// TestECRecoverRModulusUniversalForgery is the headline regression test.
//
// With msg = 0, r = n and s = 0 the circuit was universally forgeable:
//
//   - the range checks used AssertIsLessOrEqual, which is INCLUSIVE, so r = n
//     and s = 0 were both inside the admitted set [0, n] even though the EVM
//     requires 0 < r, s < n;
//   - u1 = Div(msg, r) and u2 = Div(s, r) only constrain u*r == a in Fr. With
//     r = n we have r == 0 mod n and with msg = s = 0 both constraints become
//     0 == 0, i.e. vacuous: u1 and u2 are completely unconstrained;
//   - C = [u1]G + [u2]R then ranges over the whole group, and the "public key"
//     the gadget returns is whatever the prover wants.
//
// n < p and n^3+7 is a quadratic residue mod p, so R really is a point of
// secp256k1 and the QNR branch is not taken. All four inputs are raw precompile
// calldata: no hash preimage is required, and the attack works in both lax and
// strict mode (s = 0 <= (n-1)/2).
func TestECRecoverRModulusUniversalForgery(t *testing.T) {
	assert := test.NewAssert(t)
	n := fr.Modulus()

	// R is the curve point whose x-coordinate is exactly n.
	R, v := liftX(t, n)

	// The two vacuous divisions both receive (nom = 0, denom = n), so a
	// stateless malicious hint returns the same k for both. That gives
	// u1 = -k and u2 = k, hence C = [k](R - G), a point of the attacker's
	// choosing that no signature attests.
	k := big.NewInt(42)
	_, g := secp256k1.Generators()
	var negG, forged secp256k1.G1Affine
	negG.Neg(&g)
	forged.Add(&R, &negG)
	forged.ScalarMultiplication(&forged, k)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ecrecoverCircuit{})
	assert.NoError(err)

	divID := solver.GetHintID(emulated.DivHint)
	pkID := solver.GetHintID(recoverPublicKeyHint)
	fx := forged.X.BigInt(new(big.Int))
	fy := forged.Y.BigInt(new(big.Int))

	for _, strict := range []int{0, 1} {
		t.Run(fmt.Sprintf("strict=%d", strict), func(t *testing.T) {
			assert := test.NewAssert(t)
			w := mkECRecoverWitness(big.NewInt(0), n, big.NewInt(0), v, strict, 0, forged)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			assert.NoError(err)
			err = ccs.IsSolved(witness,
				solver.OverrideHint(divID, forgedDivHint(k)),
				solver.OverrideHint(pkID, forgedPublicKeyHint(ecc.BN254.ScalarField(), fx, fy, 0)))
			assert.Error(err, "universal forgery with msg=0, r=n, s=0 must be rejected")
		})
	}
}

// TestECRecoverRejectsZeroAndModulusRS checks the boundary of the (r, s) range
// checks. The EVM requires 0 < r, s < n; the gadget used an inclusive
// AssertIsLessOrEqual against n and never excluded zero, so the admitted set
// was [0, n].
//
// The s = 0 and s = n rows are forgeries in their own right and need no
// tampering with the division hint at all: with s == 0 mod n we get u2 = 0 and
// the gadget returns [-msg/r]G -- a key whose private key -msg*r^{-1} mod n the
// attacker knows, for an r and a msg he picks freely. These three rows solved
// before the fix.
//
// The r = 0 and r = n rows were already unsatisfiable before the fix, but only
// by accident: for r == 0 mod n the honest division hint has no inverse to
// return, and overriding it does not help unless the numerator is zero too
// (which is the headline forgery above). They are kept here to nail the
// boundary of the range check itself.
func TestECRecoverRejectsZeroAndModulusRS(t *testing.T) {
	assert := test.NewAssert(t)
	n := fr.Modulus()
	r, v, _ := randomValidR(t)
	msg := big.NewInt(123456789)

	// s == 0 mod n => u2 = 0 and C = [-msg/r]G.
	d := new(big.Int).ModInverse(r, n)
	d.Mul(d, msg).Mod(d, n)
	d.Neg(d).Mod(d, n)
	var zeroSKey secp256k1.G1Affine
	zeroSKey.ScalarMultiplicationBase(d)

	var origin secp256k1.G1Affine // (0,0), the gadget's encoding of a failure

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ecrecoverCircuit{})
	assert.NoError(err)
	pkID := solver.GetHintID(recoverPublicKeyHint)

	for _, tc := range []struct {
		name      string
		msg       *big.Int
		r, s      *big.Int
		v         uint
		strict    []int
		isFailure int
		Q         secp256k1.G1Affine
		pIsZero   int64
	}{
		{
			name: "s=0", msg: msg, r: r, s: big.NewInt(0), v: v,
			strict: []int{0, 1}, isFailure: 0, Q: zeroSKey, pIsZero: 0,
		},
		{
			name: "s=n", msg: msg, r: r, s: new(big.Int).Set(n), v: v,
			strict: []int{0}, isFailure: 0, Q: zeroSKey, pIsZero: 0,
		},
		{
			// r = 0 forces the QNR branch (7 is a non-residue mod p), so the
			// gadget happily reports a failure for an r the EVM rejects
			// outright.
			name: "r=0", msg: msg, r: big.NewInt(0), s: big.NewInt(42), v: v,
			strict: []int{0, 1}, isFailure: 1, Q: origin, pIsZero: 0,
		},
		{
			name: "r=n", msg: msg, r: new(big.Int).Set(n), s: big.NewInt(42), v: v,
			strict: []int{0, 1}, isFailure: 0, Q: zeroSKey, pIsZero: 0,
		},
	} {
		for _, strict := range tc.strict {
			t.Run(fmt.Sprintf("%s/strict=%d", tc.name, strict), func(t *testing.T) {
				assert := test.NewAssert(t)
				w := mkECRecoverWitness(tc.msg, tc.r, tc.s, tc.v, strict, tc.isFailure, tc.Q)
				witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				assert.NoError(err)
				qx := tc.Q.X.BigInt(new(big.Int))
				qy := tc.Q.Y.BigInt(new(big.Int))
				err = ccs.IsSolved(witness,
					solver.OverrideHint(pkID, forgedPublicKeyHint(ecc.BN254.ScalarField(), qx, qy, tc.pIsZero)))
				assert.Error(err, "out-of-range input must be rejected")
			})
		}
	}
}

// TestECRecoverFailurePinsBothCoordinates covers the QNR failure branch. The
// gadget asserted only IsZero(P.X) == isFailure, and in that branch the
// equality against the in-circuit recomputation is discharged by
// xIsEqual == 0 alone, so P.Y was bound by nothing at all. P is the gadget's
// return value, so a caller that hashes X || Y into an address got a
// prover-chosen value.
func TestECRecoverFailurePinsBothCoordinates(t *testing.T) {
	assert := test.NewAssert(t)
	// the QNR input from TestECRecoverQNR
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	msg := new(big.Int).SetBytes([]byte("test"))

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ecrecoverCircuit{})
	assert.NoError(err)
	pkID := solver.GetHintID(recoverPublicKeyHint)

	for _, y := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(424242)} {
		t.Run(fmt.Sprintf("P.Y=%s", y), func(t *testing.T) {
			assert := test.NewAssert(t)
			var Q secp256k1.G1Affine
			Q.Y.SetBigInt(y) // Q.X stays zero
			w := mkECRecoverWitness(msg, r, s, 1, 0, 1, Q)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			assert.NoError(err)
			err = ccs.IsSolved(witness,
				solver.OverrideHint(pkID, forgedPublicKeyHint(ecc.BN254.ScalarField(), big.NewInt(0), y, 0)))
			if y.Sign() == 0 {
				// (0,0) is the documented failure return and must stay solvable.
				assert.NoError(err, "the honest (0,0) failure return must stay satisfiable")
			} else {
				assert.Error(err, "failure must pin P = (0,0), prover chose P.Y freely")
			}
		})
	}
}

// TestECRecoverHonestStillSolvesR1CS is the completeness counterpart of the
// tests above: the same compiled R1CS, honest hints, honest witnesses.
func TestECRecoverHonestStillSolvesR1CS(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ecrecoverCircuit{})
	assert.NoError(err)
	for _, largeS := range []bool{false, true} {
		_, w := testRoutineECRecover(t, largeS)
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		assert.NoError(err)
		assert.NoError(ccs.IsSolved(witness), "honest witness must still solve (largeS=%v)", largeS)
	}
}
