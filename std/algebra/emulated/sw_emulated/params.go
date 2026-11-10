package sw_emulated

import (
	"crypto/elliptic"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	stark_curve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	"github.com/consensys/gnark/std/math/emulated"
)

// CurveParams defines parameters of an elliptic curve in short Weierstrass form
// given by the equation
//
//	Y² = X³ + aX + b
//
// The base point is defined by (Gx, Gy).
type CurveParams struct {
	A            *big.Int      // a in curve equation
	B            *big.Int      // b in curve equation
	Gx           *big.Int      // base point x
	Gy           *big.Int      // base point y
	Gm           [][2]*big.Int // m*base point coords
	Eigenvalue   *big.Int      // endomorphism eigenvalue
	ThirdRootOne *big.Int      // endomorphism image scaler

	// CofactorClearing is the constant c used to bind the hinted output of the
	// fake-GLV / GLV+fake-GLV scalar multiplications into the prime-order
	// subgroup, via a preimage check [c]S == R.
	//
	// Soundness requires [c]E(Fp) ⊆ G1, i.e. c must be divisible by the
	// *exponent* of the cofactor torsion subgroup. Completeness requires
	// gcd(c, r) = 1 so that [c] stays a bijection on G1. Clearing every
	// cofactor prime-power ℓ^k ∥ h is sufficient but usually not necessary:
	// when the torsion has rank > 1 the exponent is strictly smaller than h,
	// and the smaller constant is what should be used (see BLS12-381 G1, where
	// the exponent is (x-1) and h = (x-1)²/3).
	//
	// For prime-order groups (cofactor 1) it is nil and the check is skipped;
	// such curves must set [CurveParams.PrimeOrder] to say so explicitly.
	CofactorClearing *big.Int

	// PrimeOrder records that #E(Fp) = r, i.e. the curve has cofactor 1 and
	// every on-curve point already lies in the prime-order subgroup. It is the
	// only thing that licenses [Curve.AssertIsInSubgroup] to be a no-op.
	//
	// It must NOT be set for a curve with a nontrivial cofactor. Such a curve
	// needs either a [CurveParams.CofactorClearing] constant, or it has no
	// supported membership check at all — in which case
	// [Curve.AssertIsInSubgroup] panics rather than silently accepting
	// off-subgroup points. The zero value therefore fails closed: a newly added
	// cofactor curve is rejected until its membership check is supplied.
	PrimeOrder bool

	// EndoSubgroupTest, when set to (k1, k2), is an endomorphism-based
	// subgroup membership test: an on-curve point P is in the prime-order
	// subgroup iff [k1]P + [k2]Φ(P) = O, with Φ(x, y) = (ThirdRootOne·x, y).
	// It is used by [Curve.AssertIsInSubgroup] on cofactor curves that have
	// no [CurveParams.CofactorClearing] constant. Compile-time validation
	// requires k1 + k2·Eigenvalue ≡ 0 mod r (completeness on G1); soundness
	// (that the relation excludes every off-subgroup point) is a property of
	// the curve and must come from the literature.
	EndoSubgroupTest [2]*big.Int

	// PreferClassicGLV routes [Curve.ScalarMul] through classic GLV instead of
	// GLV+fake-GLV. It is set for cofactor curves where the fake-GLV
	// subgroup-clearing ([CofactorClearing]) costs more than the r^(1/4) loop
	// saves — measured on BLS12-381 G1 (classic GLV ≈ 105k vs GLV+fake-GLV+clearing
	// ≈ 116k R1CS).
	//
	// Classic GLV takes its sub-scalars from a hint and only constrains
	// s1 + λ·s2 ≡ s mod r, which admits bounded dishonest decompositions that
	// steer its incomplete main loop into exceptional additions. It therefore
	// requires [CurveParams.GLVTorsionOffset] (see [Curve.scalarMulGLV]).
	PreferClassicGLV bool

	// GLVTorsionOffset is a rational point T0 = (x, y) of small odd prime order
	// GLVTorsionOffsetOrder (hence outside the prime-order subgroup). Classic
	// GLV adds T0 to its accumulator so that, for inputs in the prime-order
	// subgroup, no step of the incomplete main loop can hit an exceptional
	// case whatever decomposition the prover supplies. Required when
	// [CurveParams.PreferClassicGLV] is set; validated at compile time.
	GLVTorsionOffset      [2]*big.Int
	GLVTorsionOffsetOrder uint64
}

// GetSecp256k1Params returns curve parameters for the curve secp256k1. When
// initialising new curve, use the base field [emulated.Secp256k1Fp] and scalar
// field [emulated.Secp256k1Fr].
func GetSecp256k1Params() CurveParams {
	_, g1aff := secp256k1.Generators()
	lambda, _ := new(big.Int).SetString("37718080363155996902926221483475020450927657555482586988616620542887997980018", 10)
	omega, _ := new(big.Int).SetString("55594575648329892869085402983802832744385952214688224221778511981742606582254", 10)
	return CurveParams{
		A:            big.NewInt(0),
		B:            big.NewInt(7),
		Gx:           g1aff.X.BigInt(new(big.Int)),
		Gy:           g1aff.Y.BigInt(new(big.Int)),
		Gm:           computeSecp256k1Table(),
		Eigenvalue:   lambda,
		ThirdRootOne: omega,
		PrimeOrder:   true, // h = 1 (SEC 2 §2.4.1)
	}
}

// GetBN254Params returns the curve parameters for the curve BN254 (alt_bn128).
// When initialising new curve, use the base field [emulated.BN254Fp] and scalar
// field [emulated.BN254Fr].
func GetBN254Params() CurveParams {
	_, _, g1aff, _ := bn254.Generators()
	lambda, _ := new(big.Int).SetString("4407920970296243842393367215006156084916469457145843978461", 10)
	omega, _ := new(big.Int).SetString("2203960485148121921418603742825762020974279258880205651966", 10)
	return CurveParams{
		A:            big.NewInt(0),
		B:            big.NewInt(3),
		Gx:           g1aff.X.BigInt(new(big.Int)),
		Gy:           g1aff.Y.BigInt(new(big.Int)),
		Gm:           computeBN254Table(),
		Eigenvalue:   lambda,
		ThirdRootOne: omega,
		PrimeOrder:   true, // BN curves have h = 1 on G1
	}
}

// GetBLS12381Params returns the curve parameters for the curve BLS12-381.
// When initialising new curve, use the base field [emulated.BLS12381Fp] and scalar
// field [emulated.BLS12381Fr].
func GetBLS12381Params() CurveParams {
	_, _, g1aff, _ := bls12381.Generators()
	lambda, _ := new(big.Int).SetString("228988810152649578064853576960394133503", 10)
	omega, _ := new(big.Int).SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436", 10)
	return CurveParams{
		A:            big.NewInt(0),
		B:            big.NewInt(4),
		Gx:           g1aff.X.BigInt(new(big.Int)),
		Gy:           g1aff.Y.BigInt(new(big.Int)),
		Gm:           computeBLS12381Table(),
		Eigenvalue:   lambda,
		ThirdRootOne: omega,
		// c = |x-1| = 0xd201000000010001 (64 bits), NOT the full cofactor
		// h = (x-1)²/3 = 3·11²·10177²·859267²·52437899² (126 bits).
		//
		// Write n = (x-1)/3 = 11·10177·859267·52437899, so that
		//
		//	h = 3n²  and  x-1 = 3n,  with 3 ∤ n.
		//
		// El Housni-Guillevic (eprint 2021/1359 §3.2, Cor. 1) prove for every
		// BLS curve that the *full* n-torsion is rational, E[n] ⊂ E(Fp): there
		// are n² points of order n and none of order n². So the n-part of the
		// cofactor torsion is Z_n × Z_n — rank 2, exponent n rather than n².
		// The remaining lone factor 3 of h is exactly the 3 in 3n = x-1, and it
		// contributes a *cyclic* Z_3; it is not squared in h and no rank-2 claim
		// is made about it. The cofactor torsion is therefore Z_n × Z_{3n} of
		// order 3n² = h and exponent lcm(n, 3n) = 3n = x-1. Equivalently
		// E(Fp) ≅ Z_{(x-1)/3} × Z_{(x-1)·r} (Wahby-Boneh, eprint 2019/403 §5).
		//
		// Multiplying by the exponent kills the torsion, so [x-1]E(Fp) = G1
		// exactly — which is what the binding needs: a torsion-tainted R has no
		// on-curve preimage under [x-1]. Completeness holds because
		// gcd(x-1, r) = 1 makes [x-1] a bijection on G1, so an honest R keeps a
		// preimage (take it in G1).
		//
		// This is the same constant gnark-crypto's G1 ClearCofactor uses.
		// Halving the bit length halves the binding ladder: 178k -> 80k R1CS.
		CofactorClearing: new(big.Int).SetUint64(0xd201000000010001),
		// classic GLV is cheaper here than GLV+fake-GLV once the (expensive)
		// cofactor clearing is included — see benchmarks.
		PreferClassicGLV: true,
		// (0, 2) is a flex of y² = x³ + 4, hence of order 3; 3 | h.
		GLVTorsionOffset:      [2]*big.Int{big.NewInt(0), big.NewInt(2)},
		GLVTorsionOffsetOrder: 3,
	}
}

// GetP256Params returns the curve parameters for the curve P-256 (also
// SECP256r1). When initialising new curve, use the base field
// [emulated.P256Fp] and scalar field [emulated.P256Fr].
func GetP256Params() CurveParams {
	pr := elliptic.P256().Params()
	a := new(big.Int).Sub(pr.P, big.NewInt(3))
	return CurveParams{
		A:            a,
		B:            pr.B,
		Gx:           pr.Gx,
		Gy:           pr.Gy,
		Gm:           computeP256Table(),
		Eigenvalue:   nil,
		ThirdRootOne: nil,
		PrimeOrder:   true, // h = 1 (FIPS 186-4 D.1.2.3)
	}
}

// GetP384Params returns the curve parameters for the curve P-384 (also
// SECP384r1). When initialising new curve, use the base field
// [emulated.P384Fp] and scalar field [emulated.P384Fr].
func GetP384Params() CurveParams {
	pr := elliptic.P384().Params()
	a := new(big.Int).Sub(pr.P, big.NewInt(3))
	return CurveParams{
		A:            a,
		B:            pr.B,
		Gx:           pr.Gx,
		Gy:           pr.Gy,
		Gm:           computeP384Table(),
		Eigenvalue:   nil,
		ThirdRootOne: nil,
		PrimeOrder:   true, // h = 1 (FIPS 186-4 D.1.2.4)
	}
}

// GetBW6761Params returns the curve parameters for the curve BW6-761.
// When initialising new curve, use the base field [emulated.BW6761Fp] and scalar
// field [emulated.BW6761Fr].
func GetBW6761Params() CurveParams {
	_, _, g1aff, _ := bw6761.Generators()
	lambda, _ := new(big.Int).SetString("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945", 10)
	omega, _ := new(big.Int).SetString("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650", 10)
	return CurveParams{
		A:            big.NewInt(0),
		B:            big.NewInt(-1),
		Gx:           g1aff.X.BigInt(new(big.Int)),
		Gy:           g1aff.Y.BigInt(new(big.Int)),
		Gm:           computeBW6761Table(),
		Eigenvalue:   lambda,
		ThirdRootOne: omega,
		// Routed through classic GLV (PreferClassicGLV below), so no
		// cofactor-clearing binding of a hinted output is used on this curve.
		// This also avoids the pitfall that a *minimal* clearing constant is
		// unsound here: a chosen-scalar forgery with a rational φ-eigenvector
		// reaches torsion up to ~r^(1/2) (not ~r^(1/4)), so the reachable
		// factors inside the ~330-bit cofactor remainder can't be cheaply
		// isolated — only full-cofactor clearing (expensive) or classic GLV
		// (chosen here) is sound.
		//
		// G1 here has a nontrivial cofactor, so PrimeOrder stays false, and
		// subgroup membership is tested with the endomorphism relation below
		// instead of a clearing constant.
		CofactorClearing: nil,
		// P ∈ G1 iff [x₀+1]P + [x₀³−x₀²+1]Φ(P) = O, x₀ the BW6-761 seed — the
		// test of gnark-crypto's G1Jac.IsInSubGroup (El Housni, Guillevic,
		// Piellard, eprint 2022/352).
		EndoSubgroupTest: bw6761EndoSubgroupTest(),
		PreferClassicGLV: true,
		// h = #E(Fp)/r has 127 as its only odd prime factor below 2000 (and no
		// factor 3, as p ≡ 3 mod 4 rules out the flexes (0, ±√−1)); T0 is a
		// rational point of order 127.
		GLVTorsionOffset: [2]*big.Int{
			bigFromBase10("1434769365449908722802650638853586550298320408571751379216229371506488989810944560601789689087742361676675704914361237568882018836145558640600409088250822516223703875978215095442766754683162324833595711343045717730150466189723767"),
			bigFromBase10("152702845304058593839850200988551178776963134603511191116689150194420556452493895139323098043772273107327467304551829563471423055519359472446073191082377464259113341265445112056659438161617692153632812933765649407989035862534041"),
		},
		GLVTorsionOffsetOrder: 127,
	}
}

// bw6761EndoSubgroupTest returns (x₀+1, x₀³−x₀²+1) for the BW6-761 seed
// x₀ = 9586122913090633729. The same relation holds on BW6-761 G2 with its own
// Φ (gnark-crypto's G2Jac.IsInSubGroup).
func bw6761EndoSubgroupTest() [2]*big.Int {
	x0 := new(big.Int).SetUint64(9586122913090633729)
	k1 := new(big.Int).Add(x0, big.NewInt(1))
	x2 := new(big.Int).Mul(x0, x0)
	k2 := new(big.Int).Mul(x2, x0)
	k2.Sub(k2, x2).Add(k2, big.NewInt(1))
	return [2]*big.Int{k1, k2}
}

func bigFromBase10(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid base-10 constant " + s)
	}
	return v
}

// GetStarkCurveParams returns the curve parameters for the STARK curve.
// When initialising new curve, use the base field [emulated.STARKCurveFp] and scalar
// field [emulated.STARKCurveFr].
func GetStarkCurveParams() CurveParams {
	_, g1aff := stark_curve.Generators()
	b, _ := new(big.Int).SetString("3141592653589793238462643383279502884197169399375105820974944592307816406665", 10)
	return CurveParams{
		A:            big.NewInt(1),
		B:            b,
		Gx:           g1aff.X.BigInt(new(big.Int)),
		Gy:           g1aff.Y.BigInt(new(big.Int)),
		Gm:           computeStarkCurveTable(),
		Eigenvalue:   nil,
		ThirdRootOne: nil,
		PrimeOrder:   true, // h = 1
	}
}

// GetCurveParams returns suitable curve parameters given the parametric type
// Base as base field. It caches the parameters and modifying the values in the
// parameters struct leads to undefined behaviour.
func GetCurveParams[Base emulated.FieldParams]() CurveParams {
	var t Base
	switch t.Modulus().String() {
	case emulated.Secp256k1Fp{}.Modulus().String():
		return secp256k1Params
	case emulated.BN254Fp{}.Modulus().String():
		return bn254Params
	case emulated.BLS12381Fp{}.Modulus().String():
		return bls12381Params
	case emulated.P256Fp{}.Modulus().String():
		return p256Params
	case emulated.P384Fp{}.Modulus().String():
		return p384Params
	case emulated.BW6761Fp{}.Modulus().String():
		return bw6761Params
	case emulated.STARKCurveFp{}.Modulus().String():
		return starkCurveParams
	default:
		panic("no stored parameters")
	}
}

var (
	secp256k1Params  CurveParams
	bn254Params      CurveParams
	bls12381Params   CurveParams
	p256Params       CurveParams
	p384Params       CurveParams
	bw6761Params     CurveParams
	starkCurveParams CurveParams
)

func init() {
	secp256k1Params = GetSecp256k1Params()
	bn254Params = GetBN254Params()
	bls12381Params = GetBLS12381Params()
	p256Params = GetP256Params()
	p384Params = GetP384Params()
	bw6761Params = GetBW6761Params()
	starkCurveParams = GetStarkCurveParams()
}
