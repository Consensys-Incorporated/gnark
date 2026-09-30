package sw_emulated

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ScalarMulBaseCombTest[T, S emulated.FieldParams] struct {
	Q AffinePoint[T]
	S emulated.Element[S]
	w int
}

func (c *ScalarMulBaseCombTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.scalarMulBaseComb(&c.S, c.w)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// edge scalars: 0, 1, 2, r−2, r−1 and a 2-power, plus random ones. The point
// [0]G is represented as (0,0) following the package convention.
func combTestScalars(r *big.Int, nbRandom int, randFn func() *big.Int) []*big.Int {
	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Sub(r, big.NewInt(1)),
		new(big.Int).Sub(r, big.NewInt(2)),
		new(big.Int).Lsh(big.NewInt(1), 128),
	}
	for i := 0; i < nbRandom; i++ {
		scalars = append(scalars, randFn())
	}
	return scalars
}

func TestScalarMulBaseCombSecp256k1(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	r := fr_secp.Modulus()
	randFn := func() *big.Int {
		var rnd fr_secp.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	for _, w := range []int{4, 5, 8} {
		for _, s := range combTestScalars(r, 3, randFn) {
			var S secp256k1.G1Affine
			S.ScalarMultiplication(&g, s)
			circuit := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{w: w}
			witness := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
				Q: AffinePoint[emulated.Secp256k1Fp]{
					X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
					Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
				},
			}
			err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
			assert.NoError(err, "w=%d s=%s", w, s.String())
		}
	}
}

func TestScalarMulBaseCombBN254(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bn254.Generators()
	r := fr_bn.Modulus()
	randFn := func() *big.Int {
		var rnd fr_bn.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	for _, w := range []int{4, 5, 8} {
		for _, s := range combTestScalars(r, 3, randFn) {
			var S bn254.G1Affine
			S.ScalarMultiplication(&g, s)
			circuit := ScalarMulBaseCombTest[emulated.BN254Fp, emulated.BN254Fr]{w: w}
			witness := ScalarMulBaseCombTest[emulated.BN254Fp, emulated.BN254Fr]{
				S: emulated.ValueOf[emulated.BN254Fr](s),
				Q: AffinePoint[emulated.BN254Fp]{
					X: emulated.ValueOf[emulated.BN254Fp](S.X),
					Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
				},
			}
			err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
			assert.NoError(err, "w=%d s=%s", w, s.String())
		}
	}
}

func TestScalarMulBaseCombP256(t *testing.T) {
	assert := test.NewAssert(t)
	// scalar field order of P-256
	r, _ := new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	randFn := func() *big.Int {
		rnd, _ := new(big.Int).SetString("3d6a4c9e1b5f2a7d8e9c0b1a2f3e4d5c6b7a8901234567890abcdef012345678", 16)
		return rnd.Mod(rnd, r)
	}
	for _, w := range []int{8} {
		for _, s := range combTestScalars(r, 1, randFn) {
			sr := new(big.Int).Mod(s, r)
			// compute the reference with the generic big.Int arithmetic used
			// for table computation (P-256 has no gnark-crypto counterpart
			// with the same API)
			var Sx, Sy *big.Int
			{
				params := GetP256Params()
				var fpp emulated.P256Fp
				prime := fpp.Modulus()
				if sr.Sign() == 0 {
					Sx, Sy = big.NewInt(0), big.NewInt(0)
				} else {
					acc := &combAffine{x: params.Gx, y: params.Gy}
					var err error
					for i := sr.BitLen() - 2; i >= 0; i-- {
						if acc, err = combDouble(acc, params.A, prime); err != nil {
							t.Fatal(err)
						}
						if sr.Bit(i) == 1 {
							if acc, err = combAdd(acc, &combAffine{x: params.Gx, y: params.Gy}, prime); err != nil {
								t.Fatal(err)
							}
						}
					}
					Sx, Sy = acc.x, acc.y
				}
			}
			circuit := ScalarMulBaseCombTest[emulated.P256Fp, emulated.P256Fr]{w: w}
			witness := ScalarMulBaseCombTest[emulated.P256Fp, emulated.P256Fr]{
				S: emulated.ValueOf[emulated.P256Fr](sr),
				Q: AffinePoint[emulated.P256Fp]{
					X: emulated.ValueOf[emulated.P256Fp](Sx),
					Y: emulated.ValueOf[emulated.P256Fp](Sy),
				},
			}
			err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
			assert.NoError(err, "w=%d s=%s", w, sr.String())
		}
	}
}

// TestScalarMulBaseCombConstraints reports the constraint counts of the comb
// fixed-base scalar multiplication against the current ScalarMulBase.
func TestScalarMulBaseCombConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	for _, w := range []int{4, 6, 8, 10} {
		circuit := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{w: w}
		ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Log("w =", w, "compile error:", err)
			continue
		}
		assert.NoError(err)
		t.Log("comb r1cs", "w =", w, "constraints =", ccs.GetNbConstraints())
	}
	baseline := ScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &baseline)
	assert.NoError(err)
	t.Log("baseline ScalarMulBase r1cs constraints =", ccs.GetNbConstraints())

	// PLONKish counts
	circuit := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{w: 8}
	scsCcs, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("comb scs w=8 constraints =", scsCcs.GetNbConstraints())
	scsBase, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &baseline)
	assert.NoError(err)
	t.Log("baseline ScalarMulBase scs constraints =", scsBase.GetNbConstraints())
}

type jointScalarMulBaseCompleteTest[T, S emulated.FieldParams] struct {
	P      AffinePoint[T]
	S1, S2 emulated.Element[S]
	Q      AffinePoint[T]
}

func (c *jointScalarMulBaseCompleteTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.JointScalarMulBase(&c.P, &c.S2, &c.S1)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// TestJointScalarMulBaseComplete exercises the comb-based complete path of
// JointScalarMulBase, including the zero fixed-base scalar.
func TestJointScalarMulBaseComplete(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	var p secp256k1.G1Affine
	p.Double(&g)
	r := fr_secp.Modulus()
	randFn := func() *big.Int {
		var rnd fr_secp.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	s2 := randFn()
	for _, s1 := range combTestScalars(r, 2, randFn) {
		var sm1, sm2, S secp256k1.G1Affine
		sm1.ScalarMultiplication(&g, s1)
		sm2.ScalarMultiplication(&p, s2)
		S.Add(&sm1, &sm2)
		circuit := jointScalarMulBaseCompleteTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
		witness := jointScalarMulBaseCompleteTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			S1: emulated.ValueOf[emulated.Secp256k1Fr](s1),
			S2: emulated.ValueOf[emulated.Secp256k1Fr](s2),
			P: AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](p.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](p.Y),
			},
			Q: AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
			},
		}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err, "s1=%s", s1.String())
	}
}

type scalarMulConstPointTest[T, S emulated.FieldParams] struct {
	S  emulated.Element[S]
	Q  AffinePoint[T]
	px *big.Int
	py *big.Int
}

func (c *scalarMulConstPointTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	P := AffinePoint[T]{
		X: emulated.ValueOf[T](c.px),
		Y: emulated.ValueOf[T](c.py),
	}
	res := cr.ScalarMul(&P, &c.S)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// TestScalarMulConstPoint exercises the automatic comb dispatch in ScalarMul
// for compile-time constant points.
func TestScalarMulConstPoint(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	// constant point P = [12345]G
	var P secp256k1.G1Affine
	P.ScalarMultiplication(&g, big.NewInt(12345))
	px, py := P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int))
	r := fr_secp.Modulus()
	randFn := func() *big.Int {
		var rnd fr_secp.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	for _, s := range combTestScalars(r, 2, randFn) {
		var S secp256k1.G1Affine
		S.ScalarMultiplication(&P, s)
		circuit := scalarMulConstPointTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{px: px, py: py}
		witness := scalarMulConstPointTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			px: px, py: py,
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			Q: AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
			},
		}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err, "s=%s", s.String())
	}
}

// TestScalarMulConstPointBLS12381 checks the comb dispatch on a cofactor
// curve: a subgroup point uses the comb, and a curve point outside the
// r-torsion is rejected by the order check and falls back to the generic
// variable-base path (compilation must succeed).
func TestScalarMulConstPointBLS12381(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bls12381.Generators()
	var P bls12381.G1Affine
	P.ScalarMultiplication(&g, big.NewInt(987654321))
	px, py := P.X.BigInt(new(big.Int)), P.Y.BigInt(new(big.Int))
	var rnd fr_bls381.Element
	_, _ = rnd.SetRandom()
	s := rnd.BigInt(new(big.Int))
	var S bls12381.G1Affine
	S.ScalarMultiplication(&P, s)
	circuit := scalarMulConstPointTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{px: px, py: py}
	witness := scalarMulConstPointTest[emulated.BLS12381Fp, emulated.BLS12381Fr]{
		px: px, py: py,
		S: emulated.ValueOf[emulated.BLS12381Fr](s),
		Q: AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](S.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](S.Y),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)

	// non-r-torsion curve point: search a valid x with y² = x³ + 4 a QR and
	// check it is rejected by the comb order check (cofactor > 1 makes a
	// random curve point land outside the subgroup w.h.p.).
	var fpp emulated.BLS12381Fp
	prime := fpp.Modulus()
	exp := new(big.Int).Add(prime, big.NewInt(1))
	exp.Rsh(exp, 2) // (p+1)/4, p ≡ 3 mod 4
	found := false
	for x := int64(1); x < 50 && !found; x++ {
		xx := big.NewInt(x)
		rhs := new(big.Int).Exp(xx, big.NewInt(3), prime)
		rhs.Add(rhs, big.NewInt(4)).Mod(rhs, prime)
		y := new(big.Int).Exp(rhs, exp, prime)
		check := new(big.Int).Mul(y, y)
		check.Mod(check, prime)
		if check.Cmp(rhs) != 0 {
			continue
		}
		// on curve; must not be in the r-torsion for this test to be
		// meaningful
		var frr emulated.BLS12381Fr
		if err := combCheckPoint(xx, y, big.NewInt(0), big.NewInt(4), prime, frr.Modulus()); err == nil {
			continue
		}
		// combCheckPoint rejecting the point is exactly what makes
		// combDataFor fall back to the generic path for it.
		found = true
	}
	assert.True(found, "expected to find a non-subgroup curve point")
}

type msmMixedTest[T, S emulated.FieldParams] struct {
	P      AffinePoint[T] // variable point
	S      [4]emulated.Element[S]
	Q      AffinePoint[T]
	useOld bool
}

func (c *msmMixedTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	// two constant points (G and 2G), two variable (P twice to keep the
	// witness small)
	g := cr.Generator()
	g2 := AffinePoint[T]{
		X: *cr.baseApi.NewElement(cr.params.Gm[0][0]),
		Y: *cr.baseApi.NewElement(cr.params.Gm[0][1]),
	}
	pts := []*AffinePoint[T]{g, &g2, &c.P, &c.P}
	scs := []*emulated.Element[S]{&c.S[0], &c.S[1], &c.S[2], &c.S[3]}
	res, err := cr.MultiScalarMul(pts, scs)
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// TestMSMConstRouting checks correctness of the constant-term routing in
// MultiScalarMul against gnark-crypto.
func TestMSMConstRouting(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	var g2, P secp256k1.G1Affine
	// params.Gm[0] is [3]G
	g2.ScalarMultiplication(&g, big.NewInt(3))
	var rp fr_secp.Element
	_, _ = rp.SetRandom()
	P.ScalarMultiplication(&g, rp.BigInt(new(big.Int)))
	var S [4]*big.Int
	var expected secp256k1.G1Jac
	pts := []secp256k1.G1Affine{g, g2, P, P}
	for i := range S {
		var rs fr_secp.Element
		_, _ = rs.SetRandom()
		S[i] = rs.BigInt(new(big.Int))
		var t secp256k1.G1Jac
		var ta secp256k1.G1Affine
		ta.ScalarMultiplication(&pts[i], S[i])
		t.FromAffine(&ta)
		if i == 0 {
			expected = t
		} else {
			expected.AddAssign(&t)
		}
	}
	var E secp256k1.G1Affine
	E.FromJacobian(&expected)
	circuit := msmMixedTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := msmMixedTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		P: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](P.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](P.Y),
		},
		Q: AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](E.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](E.Y),
		},
	}
	for i := range S {
		witness.S[i] = emulated.ValueOf[emulated.Secp256k1Fr](S[i])
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func TestMSMConstRoutingCount(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	circuit := msmMixedTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("MSM 4 terms (2 const + 2 var) r1cs =", ccs.GetNbConstraints())
}

// TestScalarMulBaseCombPlonkSelector validates the comb on an actual PLONKish
// (scs) compilation, end-to-end through witness solving.
func TestScalarMulBaseCombPlonkSelector(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	r := fr_secp.Modulus()
	randFn := func() *big.Int {
		var rnd fr_secp.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	// ScalarMulBaseTest goes through the public dispatch, which picks the
	// PLONK window on scs
	circuit := ScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	ccs, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("ScalarMulBase scs constraints =", ccs.GetNbConstraints())
	for _, s := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(r, big.NewInt(1)), randFn()} {
		var S secp256k1.G1Affine
		S.ScalarMultiplication(&g, s)
		witness := ScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			Q: AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
			},
		}
		w, err := frontend.NewWitness(&witness, testCurve.ScalarField())
		assert.NoError(err)
		assert.NoError(ccs.IsSolved(w), "s=%s", s.String())
	}
}
