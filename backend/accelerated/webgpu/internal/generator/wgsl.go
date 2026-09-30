package main

import (
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/consensys/bavard"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	bls12377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// wgslField describes a prime field as laid out in the WGSL shaders: 32-bit
// little-endian limbs for storage and add/sub, 16-bit limbs for the
// schoolbook Montgomery multiplication (WGSL has no 64-bit integers, so the
// 16x16 -> 32-bit product is the widest exact multiply available).
//
// All constants are derived from the modulus at generation time.
type wgslField struct {
	Prefix  string // "fp" or "fr" (function prefix)
	UPrefix string // "FP" or "FR" (constant prefix)
	Type    string // "Fp" or "Fr" (struct name)
	Type16  string // struct name of the 16-bit limb representation ("Fp16", "Fp24", "Fr16")
	Limbs   int    // number of 32-bit limbs
	Limbs16 int    // number of 16-bit limbs (2*Limbs)

	// section marker names used by the TypeScript runtime to extract fragments.
	SectionTypes  string
	SectionConsts string
	SectionCore   string

	// Inverse emits <prefix>_inverse (Fermat exponentiation by q-2) and the
	// <UPREFIX>_MODULUS_MINUS_TWO constant it needs.
	Inverse bool

	Modulus         []uint32 // q, 32-bit limbs
	Modulus16       []uint32 // q, 16-bit limbs
	ModulusMinusTwo []uint32 // q-2, 32-bit limbs
	One             []uint32 // R mod q (Montgomery form of 1), 32-bit limbs
	RSquare         []uint32 // R² mod q as a regular integer, 32-bit limbs
	QInvNeg16       uint32   // -q⁻¹ mod 2¹⁶

	wgslTuning
}

// wgslCurve groups the two fields of a curve and the parameters of its
// quadratic extension Fp2 = Fp[u]/(u² + NonResidue).
type wgslCurve struct {
	Name string // shader directory name (bn254, bls12_377, bls12_381)
	Fp   wgslField
	Fr   wgslField
	// NonResidue is the positive integer k such that Fp2 = Fp[u]/(u² + k),
	// i.e. u² = -k. It is validated against gnark-crypto's G2 arithmetic.
	NonResidue int
}

// MulByNonResidueAbs returns a WGSL expression computing NonResidue*expr.
func (c wgslCurve) MulByNonResidueAbs(expr string) string {
	if c.NonResidue == 1 {
		return expr
	}
	return fmt.Sprintf("fp_mul_by_%d(%s)", c.NonResidue, expr)
}

// KTimes returns "k·expr" for use in comments, or expr when k == 1.
func (c wgslCurve) KTimes(expr string) string {
	if c.NonResidue == 1 {
		return expr
	}
	return fmt.Sprintf("%d·%s", c.NonResidue, expr)
}

// Fp2SquareC0 returns the WGSL expression for the c0 component of an Fp2
// square given a = (c0+c1)(c0-k*c1) = c0² - k*c1² + (1-k)*c0*c1 and
// b = 2*c0*c1; the result must be c0² - k*c1² = a + ((k-1)/2)*b.
func (c wgslCurve) Fp2SquareC0() string {
	if c.NonResidue == 1 {
		return "a"
	}
	return fmt.Sprintf("fp_add(a, %s)", mulBySmall((c.NonResidue-1)/2, "b"))
}

// mulBySmall returns a WGSL double-and-add expression computing k*expr using
// fp_double and fp_add only. k must be >= 1.
func mulBySmall(k int, expr string) string {
	if k < 1 {
		panic("mulBySmall: k must be >= 1")
	}
	acc := expr
	for bit := bitLen(k) - 2; bit >= 0; bit-- {
		acc = fmt.Sprintf("fp_double(%s)", acc)
		if (k>>bit)&1 == 1 {
			acc = fmt.Sprintf("fp_add(%s, %s)", acc, expr)
		}
	}
	return acc
}

func bitLen(k int) int {
	n := 0
	for k > 0 {
		n++
		k >>= 1
	}
	return n
}

// newWGSLField derives every field constant from the modulus q. limbs is the
// number of 32-bit limbs; R = 2^(32*limbs), which matches gnark-crypto's
// Montgomery radix (64-bit limbs, half as many) so Montgomery-form values are
// byte-compatible between the host and the shaders.
func newWGSLField(prefix string, limbs int, q *big.Int, inverse bool) (wgslField, error) {
	if q.BitLen() > 32*limbs {
		return wgslField{}, fmt.Errorf("%s: modulus has %d bits, does not fit in %d 32-bit limbs", prefix, q.BitLen(), limbs)
	}
	if q.BitLen() <= 32*(limbs-1) {
		return wgslField{}, fmt.Errorf("%s: modulus has %d bits, %d 32-bit limbs is too many", prefix, q.BitLen(), limbs)
	}
	if q.Bit(0) == 0 {
		return wgslField{}, fmt.Errorf("%s: modulus must be odd for Montgomery arithmetic", prefix)
	}

	r := new(big.Int).Lsh(big.NewInt(1), uint(32*limbs))
	one := new(big.Int).Mod(r, q)
	rSquare := new(big.Int).Mod(new(big.Int).Mul(r, r), q)
	qMinusTwo := new(big.Int).Sub(q, big.NewInt(2))

	// -q⁻¹ mod 2¹⁶
	two16 := big.NewInt(1 << 16)
	qInv := new(big.Int).ModInverse(new(big.Int).Mod(q, two16), two16)
	if qInv == nil {
		return wgslField{}, fmt.Errorf("%s: modulus not invertible mod 2^16", prefix)
	}
	qInvNeg := new(big.Int).Sub(two16, qInv)
	qInvNeg.Mod(qInvNeg, two16)

	upper := strings.ToUpper(prefix)
	typeName := strings.ToUpper(prefix[:1]) + prefix[1:]

	f := wgslField{
		Prefix:          prefix,
		UPrefix:         upper,
		Type:            typeName,
		Type16:          fmt.Sprintf("%s%d", typeName, 2*limbs),
		Limbs:           limbs,
		Limbs16:         2 * limbs,
		Inverse:         inverse,
		Modulus:         toLimbs(q, 32, limbs),
		Modulus16:       toLimbs(q, 16, 2*limbs),
		ModulusMinusTwo: toLimbs(qMinusTwo, 32, limbs),
		One:             toLimbs(one, 32, limbs),
		RSquare:         toLimbs(rSquare, 32, limbs),
		QInvNeg16:       uint32(qInvNeg.Uint64()),
		wgslTuning:      tuningFor(limbs),
	}
	return f, nil
}

// toLimbs splits v into count little-endian limbs of width bits each.
func toLimbs(v *big.Int, width uint, count int) []uint32 {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	out := make([]uint32, count)
	t := new(big.Int).Set(v)
	for i := 0; i < count; i++ {
		out[i] = uint32(new(big.Int).And(t, mask).Uint64())
		t.Rsh(t, width)
	}
	if t.Sign() != 0 {
		panic("toLimbs: value does not fit")
	}
	return out
}

// fp2 is a minimal Fp2 = Fp[u]/(u²+k) implementation over big.Int, used only
// to validate the non-residue against gnark-crypto's G2 group law.
type fp2 struct {
	p *big.Int
	k *big.Int
}

type fp2Elem struct{ c0, c1 *big.Int }

func (f fp2) red(x *big.Int) *big.Int { return x.Mod(x, f.p) }
func (f fp2) sub(a, b fp2Elem) fp2Elem {
	return fp2Elem{f.red(new(big.Int).Sub(a.c0, b.c0)), f.red(new(big.Int).Sub(a.c1, b.c1))}
}
func (f fp2) mul(a, b fp2Elem) fp2Elem {
	// (a0 + a1 u)(b0 + b1 u) = a0b0 - k a1b1 + (a0b1 + a1b0) u
	c0 := new(big.Int).Mul(a.c0, b.c0)
	c0.Sub(c0, new(big.Int).Mul(f.k, new(big.Int).Mul(a.c1, b.c1)))
	c1 := new(big.Int).Mul(a.c0, b.c1)
	c1.Add(c1, new(big.Int).Mul(a.c1, b.c0))
	return fp2Elem{f.red(c0), f.red(c1)}
}
func (f fp2) scalar(n int64, a fp2Elem) fp2Elem {
	return fp2Elem{f.red(new(big.Int).Mul(big.NewInt(n), a.c0)), f.red(new(big.Int).Mul(big.NewInt(n), a.c1))}
}
func (f fp2) inv(a fp2Elem) fp2Elem {
	// (a0 + a1 u)⁻¹ = (a0 - a1 u) / (a0² + k a1²)
	norm := new(big.Int).Mul(a.c0, a.c0)
	norm.Add(norm, new(big.Int).Mul(f.k, new(big.Int).Mul(a.c1, a.c1)))
	norm.Mod(norm, f.p)
	normInv := new(big.Int).ModInverse(norm, f.p)
	if normInv == nil {
		panic("fp2.inv: zero norm")
	}
	return fp2Elem{f.red(new(big.Int).Mul(a.c0, normInv)), f.red(new(big.Int).Mul(new(big.Int).Neg(a.c1), normInv))}
}
func (f fp2) equal(a, b fp2Elem) bool { return a.c0.Cmp(b.c0) == 0 && a.c1.Cmp(b.c1) == 0 }

// g2Coords holds the affine coordinates of a G2 point over Fp2.
type g2Coords struct{ x0, x1, y0, y1 *big.Int }

// verifyNonResidue checks that u² = -k is the Fp2 tower used by gnark-crypto
// for this curve by recomputing 2·G2 from the affine generator with the
// Fp2 arithmetic above (short Weierstrass doubling, a = 0) and comparing to
// gnark-crypto's result.
func verifyNonResidue(name string, p *big.Int, k int, gen, double g2Coords) error {
	if big.Jacobi(new(big.Int).Mod(big.NewInt(int64(-k)), p), p) != -1 {
		return fmt.Errorf("%s: -%d is a quadratic residue mod p, cannot define Fp2 = Fp[u]/(u²+%d)", name, k, k)
	}
	f := fp2{p: p, k: big.NewInt(int64(k))}
	x := fp2Elem{gen.x0, gen.x1}
	y := fp2Elem{gen.y0, gen.y1}
	// λ = 3x² / (2y); x' = λ² - 2x; y' = λ(x - x') - y
	lambda := f.mul(f.scalar(3, f.mul(x, x)), f.inv(f.scalar(2, y)))
	x2 := f.sub(f.mul(lambda, lambda), f.scalar(2, x))
	y2 := f.sub(f.mul(lambda, f.sub(x, x2)), y)
	if !f.equal(x2, fp2Elem{double.x0, double.x1}) || !f.equal(y2, fp2Elem{double.y0, double.y1}) {
		return fmt.Errorf("%s: 2·G2 computed with u² = -%d does not match gnark-crypto; wrong non-residue", name, k)
	}
	return nil
}

func wgslCurves() ([]wgslCurve, error) {
	var curves []wgslCurve

	// bn254: Fp2 = Fp[u]/(u²+1)
	{
		fp, err := newWGSLField("fp", 8, bn254fp.Modulus(), true)
		if err != nil {
			return nil, err
		}
		fr, err := newWGSLField("fr", 8, bn254fr.Modulus(), false)
		if err != nil {
			return nil, err
		}
		fpOne, frOne := bn254fp.One(), bn254fr.One()
		if err := checkMontgomeryOne(fp.One, fpOne[:], "bn254/fp"); err != nil {
			return nil, err
		}
		if err := checkMontgomeryOne(fr.One, frOne[:], "bn254/fr"); err != nil {
			return nil, err
		}
		_, g2Jac, _, g2Aff := bn254.Generators()
		var dbl bn254.G2Affine
		dbl.FromJacobian(g2Jac.DoubleAssign())
		gen := g2Coords{g2Aff.X.A0.BigInt(new(big.Int)), g2Aff.X.A1.BigInt(new(big.Int)), g2Aff.Y.A0.BigInt(new(big.Int)), g2Aff.Y.A1.BigInt(new(big.Int))}
		d := g2Coords{dbl.X.A0.BigInt(new(big.Int)), dbl.X.A1.BigInt(new(big.Int)), dbl.Y.A0.BigInt(new(big.Int)), dbl.Y.A1.BigInt(new(big.Int))}
		const k = 1
		if err := verifyNonResidue("bn254", bn254fp.Modulus(), k, gen, d); err != nil {
			return nil, err
		}
		curves = append(curves, wgslCurve{Name: "bn254", Fp: fp, Fr: fr, NonResidue: k})
	}

	// bls12-377: Fp2 = Fp[u]/(u²+5)
	{
		fp, err := newWGSLField("fp", 12, bls12377fp.Modulus(), true)
		if err != nil {
			return nil, err
		}
		fr, err := newWGSLField("fr", 8, bls12377fr.Modulus(), false)
		if err != nil {
			return nil, err
		}
		fpOne, frOne := bls12377fp.One(), bls12377fr.One()
		if err := checkMontgomeryOne(fp.One, fpOne[:], "bls12_377/fp"); err != nil {
			return nil, err
		}
		if err := checkMontgomeryOne(fr.One, frOne[:], "bls12_377/fr"); err != nil {
			return nil, err
		}
		_, g2Jac, _, g2Aff := bls12377.Generators()
		var dbl bls12377.G2Affine
		dbl.FromJacobian(g2Jac.DoubleAssign())
		gen := g2Coords{g2Aff.X.A0.BigInt(new(big.Int)), g2Aff.X.A1.BigInt(new(big.Int)), g2Aff.Y.A0.BigInt(new(big.Int)), g2Aff.Y.A1.BigInt(new(big.Int))}
		d := g2Coords{dbl.X.A0.BigInt(new(big.Int)), dbl.X.A1.BigInt(new(big.Int)), dbl.Y.A0.BigInt(new(big.Int)), dbl.Y.A1.BigInt(new(big.Int))}
		const k = 5
		if err := verifyNonResidue("bls12_377", bls12377fp.Modulus(), k, gen, d); err != nil {
			return nil, err
		}
		curves = append(curves, wgslCurve{Name: "bls12_377", Fp: fp, Fr: fr, NonResidue: k})
	}

	// bls12-381: Fp2 = Fp[u]/(u²+1)
	{
		fp, err := newWGSLField("fp", 12, bls12381fp.Modulus(), true)
		if err != nil {
			return nil, err
		}
		fr, err := newWGSLField("fr", 8, bls12381fr.Modulus(), false)
		if err != nil {
			return nil, err
		}
		fpOne, frOne := bls12381fp.One(), bls12381fr.One()
		if err := checkMontgomeryOne(fp.One, fpOne[:], "bls12_381/fp"); err != nil {
			return nil, err
		}
		if err := checkMontgomeryOne(fr.One, frOne[:], "bls12_381/fr"); err != nil {
			return nil, err
		}
		_, g2Jac, _, g2Aff := bls12381.Generators()
		var dbl bls12381.G2Affine
		dbl.FromJacobian(g2Jac.DoubleAssign())
		gen := g2Coords{g2Aff.X.A0.BigInt(new(big.Int)), g2Aff.X.A1.BigInt(new(big.Int)), g2Aff.Y.A0.BigInt(new(big.Int)), g2Aff.Y.A1.BigInt(new(big.Int))}
		d := g2Coords{dbl.X.A0.BigInt(new(big.Int)), dbl.X.A1.BigInt(new(big.Int)), dbl.Y.A0.BigInt(new(big.Int)), dbl.Y.A1.BigInt(new(big.Int))}
		const k = 1
		if err := verifyNonResidue("bls12_381", bls12381fp.Modulus(), k, gen, d); err != nil {
			return nil, err
		}
		curves = append(curves, wgslCurve{Name: "bls12_381", Fp: fp, Fr: fr, NonResidue: k})
	}

	// the sections the TypeScript runtime extracts (see web/src/curvegpu/curves.ts
	// and plonk_quotient_module.ts). Names are part of the runtime contract.
	for i := range curves {
		curves[i].Fp.SectionTypes = "fp-types"
		curves[i].Fp.SectionConsts = "fp-consts"
		curves[i].Fp.SectionCore = "fp-core"
		curves[i].Fr.SectionTypes = "fr_types"
		curves[i].Fr.SectionConsts = "fr_constants"
		curves[i].Fr.SectionCore = "fr_core"
	}
	return curves, nil
}

// checkMontgomeryOne cross-checks the big.Int derivation of R mod q against
// gnark-crypto's Montgomery representation of 1 (64-bit limbs).
func checkMontgomeryOne(limbs32 []uint32, limbs64 []uint64, label string) error {
	if len(limbs32) != 2*len(limbs64) {
		return fmt.Errorf("%s: limb count mismatch (%d x u32 vs %d x u64)", label, len(limbs32), len(limbs64))
	}
	for i, w := range limbs64 {
		if limbs32[2*i] != uint32(w) || limbs32[2*i+1] != uint32(w>>32) {
			return fmt.Errorf("%s: Montgomery R mismatch with gnark-crypto at limb %d", label, i)
		}
	}
	return nil
}

func wgslFuncs() template.FuncMap {
	return template.FuncMap{
		"hex32":      func(v uint32) string { return fmt.Sprintf("0x%08xu", v) },
		"hex16":      func(v uint32) string { return fmt.Sprintf("0x%04xu", v) },
		"mulBySmall": mulBySmall,
		// pairs groups a slice into consecutive pairs (for the 16-bit limb tables).
		"pairs": func(v []uint32) [][]uint32 {
			var out [][]uint32
			for i := 0; i+1 < len(v); i += 2 {
				out = append(out, v[i:i+2])
			}
			return out
		},
	}
}

// thisDir returns the directory containing this source file (the generator).
func thisDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot resolve generator directory")
	}
	return filepath.Dir(file), nil
}

// generateWGSL renders every shader under shadersDir/curves/<curve>/ from the
// templates in templates/wgsl/. Field constants are computed from
// gnark-crypto moduli; the non-residue of each Fp2 tower is validated
// against gnark-crypto's G2 group law.
func generateWGSL(shadersDir string) error {
	curves, err := wgslCurves()
	if err != nil {
		return err
	}

	generatorDir, err := thisDir()
	if err != nil {
		return err
	}
	tmplDir := filepath.Join(generatorDir, "templates", "wgsl")
	tmpl := func(names ...string) []string {
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = filepath.Join(tmplDir, n)
		}
		return out
	}
	const fragments = "field_fragments.wgsl.tmpl"

	opts := []func(*bavard.Bavard) error{
		bavard.GeneratedBy("gnark"),
		bavard.Funcs(wgslFuncs()),
		bavard.Verbose(true),
	}

	for _, c := range curves {
		dir := filepath.Join(shadersDir, "curves", c.Name)
		type job struct {
			file      string
			templates []string
			data      interface{}
		}
		jobs := []job{
			{"fp_arith.wgsl", tmpl("field_arith.wgsl.tmpl", fragments), c.Fp},
			{"fr_arith.wgsl", tmpl("field_arith.wgsl.tmpl", fragments), c.Fr},
			{"fr_ntt.wgsl", tmpl("fr_ntt.wgsl.tmpl", fragments), c.Fr},
			{"fr_vector.wgsl", tmpl("fr_vector.wgsl.tmpl", fragments), c.Fr},
			{"fr_plonk_quotient.wgsl", tmpl("fr_plonk_quotient.wgsl.tmpl", fragments), c.Fr},
			{"g1_io.wgsl", tmpl("g1_io.wgsl.tmpl", fragments), c.Fp},
			{"g2_io.wgsl", tmpl("g2_io.wgsl.tmpl", fragments), c.Fp},
			{"g2_arith.wgsl", tmpl("g2_arith.wgsl.tmpl", fragments), c},
		}
		for _, j := range jobs {
			if err := bavard.GenerateFromFiles(filepath.Join(dir, j.file), j.templates, j.data, opts...); err != nil {
				return fmt.Errorf("%s/%s: %w", c.Name, j.file, err)
			}
		}
	}
	return nil
}
