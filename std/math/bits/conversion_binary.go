package bits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// ToBinary is an alias of ToBase(api, Binary, v, opts)
func ToBinary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	return ToBase(api, Binary, v, opts...)
}

// FromBinary is an alias of FromBase(api, Binary, digits)
func FromBinary(api frontend.API, digits []frontend.Variable, opts ...BaseConversionOption) frontend.Variable {
	return FromBase(api, Binary, digits, opts...)
}

func fromBinary(api frontend.API, digits []frontend.Variable, opts ...BaseConversionOption) frontend.Variable {

	cfg := baseConversionConfig{}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			panic(err)
		}
	}
	// check if the inputs are all constant. In this case, recompose without adding any constraints.
	allConst := true
	constDigits := make([]*big.Int, len(digits))
	for i := range digits {
		if constV, ok := api.Compiler().ConstantValue(digits[i]); !ok {
			// there is at least one digit which is not a constant. Break out to the general case.
			allConst = false
			break
		} else {
			constDigits[len(digits)-i-1] = constV
		}
	}
	if allConst {
		res := new(big.Int)
		for _, d := range constDigits {
			// check that the inputs are binary digits. 1 has 1 bit and 0 has 0 bits.
			if d.BitLen() > 1 {
				panic(fmt.Sprintf("constant input to FromBinary has more than 1 bit. Has %d bits", d.BitLen()))
			}
			res.Lsh(res, 1)
			res.Add(res, d)
		}
		res.Mod(res, api.Compiler().Field()) // ensure the result is mod reduced
		return res
	}
	// if we are here, then we have at least one unconstrained input or the inputs are not constant.

	// Σbi = Σ (2**i * b[i])
	Σbi := frontend.Variable(0)

	c := big.NewInt(1)

	for i := 0; i < len(digits); i++ {
		if !cfg.UnconstrainedInputs {
			api.AssertIsBoolean(digits[i]) // ensures the digits are actual bits
		}

		Σbi = api.Add(Σbi, api.Mul(c, digits[i])) // no constraint is recorded
		c.Lsh(c, 1)
	}

	return Σbi
}

func toBinary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	// parse options
	cfg := baseConversionConfig{
		NbDigits:             api.Compiler().FieldBitLen(),
		UnconstrainedOutputs: false,
	}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			panic(err)
		}
	}
	if cfg.upperBound != nil {
		if cfg.omitModulusCheck {
			panic("WithUpperBound and OmitModulusCheck are contradictory: one asks for a bound check, the other removes it")
		}
		// a bound at or above the modulus would readmit the multiple-decomposition
		// case the check exists to prevent, so it is rejected rather than silently
		// weakening the constraint.
		if cfg.upperBound.Cmp(new(big.Int).Sub(api.Compiler().Field(), big.NewInt(1))) > 0 {
			panic(fmt.Sprintf("WithUpperBound: bound has %d bits and exceeds the native modulus minus one", cfg.upperBound.BitLen()))
		}
	}
	// handle the case when the input is constant separately to avoid creating any constraints
	if constV, ok := api.Compiler().ConstantValue(v); ok {
		// first we ensure that the constant value is mod reduced
		constV.Mod(constV, api.Compiler().Field())
		// we still want to honor the number of bits requested. And we have a
		// promise that for non-constant input we would get unsatisfiable
		// constraint if the bitlength of the input is larger than the option.
		// For constant input, we panic instead. We can do it as it will happen
		// at circuit compile time, so the developer can fix it.
		if cfg.NbDigits > 0 && cfg.NbDigits < constV.BitLen() {
			panic(fmt.Sprintf("constant input to ToBinary has more bits than requested by WithNbDigits option. Has %d bits, requested %d bits", constV.BitLen(), cfg.NbDigits))
		}
		// for a variable input an out-of-range value yields an unsatisfiable
		// constraint; for a constant we can say so at compile time instead.
		if cfg.upperBound != nil && constV.Cmp(cfg.upperBound) > 0 {
			panic(fmt.Sprintf("constant input to ToBinary exceeds the bound set by WithUpperBound option. Value %s, bound %s", constV.String(), cfg.upperBound.String()))
		}
		res := make([]frontend.Variable, cfg.NbDigits)
		for i := range cfg.NbDigits {
			res[i] = constV.Bit(i)
		}
		return res
	}

	// by default, we also check that the value to be decomposed is less than the
	// modulus. However, we can omit the check when the number of bits we want
	// to decompose to is less than the modulus, or it was strictly requested.
	// an explicitly requested bound is always enforced: the caller is asking for
	// something the digit count alone does not imply.
	omitReducednessCheck := cfg.upperBound == nil &&
		(cfg.omitModulusCheck || cfg.NbDigits < api.Compiler().FieldBitLen())

	// when cfg.NbDigits == 1, v itself has to be a binary digit. This if-clause
	// saves one constraint.
	if cfg.NbDigits == 1 {
		api.AssertIsBoolean(v)
		return []frontend.Variable{v}
	}
	// if we decompose into more bits than fieldBitLen then the rest would be
	// always zeros. Reduce the always-zeros to have fewer edge-cases elsewhere.
	var paddingBits int
	if cfg.NbDigits > api.Compiler().FieldBitLen() {
		paddingBits = cfg.NbDigits - api.Compiler().FieldBitLen()
		cfg.NbDigits = api.Compiler().FieldBitLen()
	}

	c := big.NewInt(1)

	bits, err := api.Compiler().NewHint(nBits, cfg.NbDigits, v)
	if err != nil {
		panic(err)
	}

	var Σbi frontend.Variable
	Σbi = 0
	for i := 0; i < cfg.NbDigits; i++ {
		Σbi = api.Add(Σbi, api.Mul(bits[i], c))
		c.Lsh(c, 1)
		if !cfg.UnconstrainedOutputs {
			api.AssertIsBoolean(bits[i])
		}
	}

	// record the constraint Σ (2**i * b[i]) == a
	api.AssertIsEqual(Σbi, v)
	if !omitReducednessCheck {
		if cmper, ok := api.Compiler().(bitsComparatorConstant); ok {
			bound := cfg.upperBound
			if bound == nil {
				bound = new(big.Int).Sub(api.Compiler().Field(), big.NewInt(1))
			}
			cmper.MustBeLessOrEqCst(bits, bound, v)
		} else {
			panic("builder does not expose comparison to constant")
		}
	}

	// restore the zero bits which exceed the field bit-length when requested by
	// setting WithNbDigits larger than the field bitLength.
	bits = append(bits, make([]frontend.Variable, paddingBits)...)
	for i := cfg.NbDigits; i < len(bits); i++ {
		bits[i] = 0 // frontend.Variable is interface{}, we get nil pointer err if trying to access it.
	}

	return bits
}
