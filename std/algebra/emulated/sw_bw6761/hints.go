package sw_bw6761

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		finalExpHint,
		pairingCheckHint,
		scalarMulG2Hint,
		scalarMulG2CofactorPreimageHint,
		rationalReconstructExtG2,
	}
}

// g2CofactorClearingConstant is the cofactor-clearing constant for BW6-761 G2:
// the product of every cofactor prime < 2^nbits (h = 3·13·261812779·
// 10233228391030511371·(118-bit prime)·(170-bit prime)). All four small primes are
// reachable by the r^(1/4) sub-scalars (nbits = 97; 10233228391030511371 ≈ 2^63 <
// 2^97), so [c]·E'(𝔽ₚ) removes exactly the exploitable torsion; the 118-bit and
// 170-bit prime parts have order ≫ 2^nbits. Omitting e.g. 261812779 or
// 10233228391030511371 leaves a chosen-scalar torsion forgery of that order open.
var g2CofactorClearingConstant = func() *big.Int {
	c := big.NewInt(3 * 13)
	c.Mul(c, big.NewInt(261812779))
	q, _ := new(big.Int).SetString("10233228391030511371", 10)
	c.Mul(c, q)
	return c
}()

// scalarMulG2CofactorPreimageHint returns S = [s · c⁻¹ mod r]·Q, a preimage of
// R = [s]Q under multiplication by the cofactor-clearing constant c. The
// in-circuit check [c]S == R with S constrained on-curve forces R into the
// prime-order subgroup: a torsion-shifted R' = [s]Q + T (ord(T) | 39) has no
// on-curve preimage under [c], so no satisfying S exists.
func scalarMulG2CofactorPreimageHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 2 {
			return fmt.Errorf("expecting two base inputs (Q.X, Q.Y), got %d", len(baseInputs))
		}
		if len(baseOutputs) != 2 {
			return fmt.Errorf("expecting two base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 1 {
			return fmt.Errorf("expecting one scalar input, got %d", len(scalarInputs))
		}

		cInv := new(big.Int).ModInverse(g2CofactorClearingConstant, scalarModulus)
		if cInv == nil {
			return fmt.Errorf("cofactor-clearing constant not invertible mod r")
		}
		m := new(big.Int).Mul(scalarInputs[0], cInv)
		m.Mod(m, scalarModulus)

		// S = [s · c⁻¹ mod r]·Q, so [c]S = [s]Q = R.
		var Q bw6761.G2Affine
		Q.X.SetBigInt(baseInputs[0])
		Q.Y.SetBigInt(baseInputs[1])
		Q.ScalarMultiplication(&Q, m)
		Q.X.BigInt(baseOutputs[0])
		Q.Y.BigInt(baseOutputs[1])
		return nil
	})
}

func finalExpHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This adapted from section 4.3.2 of https://eprint.iacr.org/2024/640.pdf
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {

			var millerLoop bw6761.E6
			millerLoop.B0.A0.SetBigInt(inputs[0])
			millerLoop.B0.A1.SetBigInt(inputs[2])
			millerLoop.B0.A2.SetBigInt(inputs[4])
			millerLoop.B1.A0.SetBigInt(inputs[1])
			millerLoop.B1.A1.SetBigInt(inputs[3])
			millerLoop.B1.A2.SetBigInt(inputs[5])

			// m = (x₀+1+p(x₀³-x₀²-x₀)) / r
			// mInv = 1/m mod p^6-1/r
			var mInv big.Int
			mInv.SetString("105300887666978464659709343582542432109497460559010677145223399327335567156593762277982229043678237863242655241846768823344862796112034076814141083092751207576412334798103601349742476585775877619451019850167305863473223932142842098178714149254582966792063312581807532675011404956270444910983750120675327025908192761069674135173328190635728173483753211505851991073745950587829640934449952514784880889959559541546684726344944253403018397996950965921029567425987659358091464001225755716260618839676545930683009926269854751616319103606509390667378268460666742713527948268373325914395974070631687649214144656759247037859773349886114399692016935966157297580328600396352321897692663748248168657388300690175586203114387947411720168269584172401784701771662759756974275902513788431327670950496435721956320875507468132703494465092748348925165286946843554008708392819919707156205920861214337368776935547492934209453494196115576830279851512338758088097719490141268227027970070242059962020992385206924254152017997017283665944910844784993588814611604460594039341562723060932582754994971346320340801549001828241339646153773031765187339622798156846331769418880530957782348437016822638577491500694745694281480857816937650066502281171825041093314285283892479458782481150957342407", 10)

			residueWitness := finalExpWitness(&millerLoop, &mInv)

			residueWitness.B0.A0.BigInt(outputs[0])
			residueWitness.B0.A1.BigInt(outputs[2])
			residueWitness.B0.A2.BigInt(outputs[4])
			residueWitness.B1.A0.BigInt(outputs[1])
			residueWitness.B1.A1.BigInt(outputs[3])
			residueWitness.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func pairingCheckHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This adapted from section 4.3.2 of https://eprint.iacr.org/2024/640.pdf
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var P bw6761.G1Affine
			var Q bw6761.G2Affine
			n := len(inputs)
			p := make([]bw6761.G1Affine, 0, n/4)
			q := make([]bw6761.G2Affine, 0, n/4)
			// first half is G1 points
			for k := 0; k < n/2; k += 2 {
				P.X.SetBigInt(inputs[k])
				P.Y.SetBigInt(inputs[k+1])
				p = append(p, P)
			}
			// second half are G2 points
			for k := n / 2; k < n; k += 2 {
				Q.X.SetBigInt(inputs[k])
				Q.Y.SetBigInt(inputs[k+1])
				q = append(q, Q)
			}

			millerLoop, err := bw6761.MillerLoopDirect(p, q)
			if err != nil {
				return err
			}

			// m = (x₀+1+p(x₀³-x₀²-x₀)) / r
			// mInv = 1/m mod p^6-1/r
			var mInv big.Int
			mInv.SetString("105300887666978464659709343582542432109497460559010677145223399327335567156593762277982229043678237863242655241846768823344862796112034076814141083092751207576412334798103601349742476585775877619451019850167305863473223932142842098178714149254582966792063312581807532675011404956270444910983750120675327025908192761069674135173328190635728173483753211505851991073745950587829640934449952514784880889959559541546684726344944253403018397996950965921029567425987659358091464001225755716260618839676545930683009926269854751616319103606509390667378268460666742713527948268373325914395974070631687649214144656759247037859773349886114399692016935966157297580328600396352321897692663748248168657388300690175586203114387947411720168269584172401784701771662759756974275902513788431327670950496435721956320875507468132703494465092748348925165286946843554008708392819919707156205920861214337368776935547492934209453494196115576830279851512338758088097719490141268227027970070242059962020992385206924254152017997017283665944910844784993588814611604460594039341562723060932582754994971346320340801549001828241339646153773031765187339622798156846331769418880530957782348437016822638577491500694745694281480857816937650066502281171825041093314285283892479458782481150957342407", 10)

			residueWitnessInv := finalExpWitness(&millerLoop, &mInv)
			residueWitnessInv.Inverse(&residueWitnessInv)

			residueWitnessInv.B0.A0.BigInt(outputs[0])
			residueWitnessInv.B0.A1.BigInt(outputs[2])
			residueWitnessInv.B0.A2.BigInt(outputs[4])
			residueWitnessInv.B1.A0.BigInt(outputs[1])
			residueWitnessInv.B1.A1.BigInt(outputs[3])
			residueWitnessInv.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func finalExpWitness(millerLoop *bw6761.E6, mInv *big.Int) (residueWitness bw6761.E6) {

	var rInv big.Int
	// 1. compute r-th root:
	// Exponentiate to rInv where
	// rInv = 1/r mod (p^6-1)/r
	rInv.SetString("279142441805511726233822077180198394933430419224185936052953462287387912118470357993263103168031788043160461358474005435622327506926362567154401645657309519073154383052970657693950208844465818979551693587858245321454505472049236704031061301292776853925224359757586505231126091244204292668007110271845616234279927419974150119801003450133674289144711275201991607282264849765236206295842916353255855388186086438329721887082685697023028663652777877691341551982676874308309620809049793085180324511691754953492619183755890255644855765188965000691813063771086522132765764526955251054211157804606693386854395171192876178005945476647006847460976477055233044799299417913662363985523123796056692751028712679181978298499780752966303529102009307348414562366180130429432094237007700663759126264893082917308542509779442201840676518234962495304673134599305371982876385622279935346701152286347948653741121231188575146952014672242471261647823749129902237689180055673361938161119768341970519416039779128617354778773830515364777252518313057683396662835013368967463878342754251509207391537635831891662211848811733884861792121210263430418966889668537646457064092991696527814120385172941004264289812969796992647021735186941896252860419364971543301451924917610828019341224722038007513", 10)
	residueWitness.Exp(*millerLoop, &rInv)

	// 2. compute m-th root:
	residueWitness.Exp(residueWitness, mInv)

	return residueWitness
}

func scalarMulG2Hint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(field, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expecting two moduli, got %d", len(moduli))
		}
		baseModulus, scalarModulus := moduli[0], moduli[1]
		baseInputs, baseOutputs := hc.InputsOutputs(baseModulus)
		scalarInputs, _ := hc.InputsOutputs(scalarModulus)
		if len(baseInputs) != 2 {
			return fmt.Errorf("expecting two base inputs (Q.X, Q.Y), got %d", len(baseInputs))
		}
		if len(baseOutputs) != 2 {
			return fmt.Errorf("expecting two base outputs, got %d", len(baseOutputs))
		}
		if len(scalarInputs) != 1 {
			return fmt.Errorf("expecting one scalar input, got %d", len(scalarInputs))
		}

		// compute the resulting point [s]Q on G2
		var Q bw6761.G2Affine
		Q.X.SetBigInt(baseInputs[0])
		Q.Y.SetBigInt(baseInputs[1])
		Q.ScalarMultiplication(&Q, scalarInputs[0])
		Q.X.BigInt(baseOutputs[0])
		Q.Y.BigInt(baseOutputs[1])
		return nil
	})
}

func rationalReconstructExtG2(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expecting one modulus, got %d", len(moduli))
		}
		_, nativeOutputs := hc.NativeInputsOutputs()
		if len(nativeOutputs) != 4 {
			return fmt.Errorf("expecting four outputs, got %d", len(nativeOutputs))
		}
		emuInputs, emuOutputs := hc.InputsOutputs(moduli[0])
		if len(emuInputs) != 2 {
			return fmt.Errorf("expecting two inputs, got %d", len(emuInputs))
		}
		if len(emuOutputs) != 4 {
			return fmt.Errorf("expecting four outputs, got %d", len(emuOutputs))
		}

		// Use lattice reduction to find (x, y, z, t) such that
		// k ≡ (x + λ*y) / (z + λ*t) (mod r)
		//
		// in-circuit we check that R - [s]Q = 0 or equivalently R + [-s]Q = 0
		// so here we use k = -s.
		k := new(big.Int).Neg(emuInputs[0])
		k.Mod(k, moduli[0])
		rc := lattice.NewReconstructor(moduli[0]).SetLambda(emuInputs[1])
		res := rc.RationalReconstructExt(k)
		x, y, z, t := res[0], res[1], res[2], res[3]

		// u1 = x, u2 = y, v1 = z, v2 = t
		emuOutputs[0].Abs(x)
		emuOutputs[1].Abs(y)
		emuOutputs[2].Abs(z)
		emuOutputs[3].Abs(t)

		// signs
		nativeOutputs[0].SetUint64(0)
		nativeOutputs[1].SetUint64(0)
		nativeOutputs[2].SetUint64(0)
		nativeOutputs[3].SetUint64(0)

		if x.Sign() < 0 {
			nativeOutputs[0].SetUint64(1)
		}
		if y.Sign() < 0 {
			nativeOutputs[1].SetUint64(1)
		}
		if z.Sign() < 0 {
			nativeOutputs[2].SetUint64(1)
		}
		if t.Sign() < 0 {
			nativeOutputs[3].SetUint64(1)
		}
		return nil
	})
}
