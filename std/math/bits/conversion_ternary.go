package bits

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// ToTernary is an alias of ToBase(api, Ternary, v, opts...)
func ToTernary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	return ToBase(api, Ternary, v, opts...)
}

// FromTernary is an alias of FromBase(api, Ternary, digits)
func FromTernary(api frontend.API, digits []frontend.Variable, opts ...BaseConversionOption) frontend.Variable {
	return FromBase(api, Ternary, digits, opts...)
}

func fromTernary(api frontend.API, digits []frontend.Variable, opts ...BaseConversionOption) frontend.Variable {
	cfg := baseConversionConfig{}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			panic(err)
		}
	}

	// Σti = Σ (3**i * b[i])
	Σti := frontend.Variable(0)

	c := big.NewInt(1)
	base := big.NewInt(3)

	for i := 0; i < len(digits); i++ {
		if !cfg.UnconstrainedInputs {
			// TODO ensures the digits are actual trits
			AssertIsTrit(api, digits[i])
		}
		Σti = api.Add(Σti, api.Mul(c, digits[i])) // no constraint is recorded
		c.Mul(c, base)
	}

	return Σti
}

// tritsOf returns the nbDigits least significant base-3 digits of n (n must be
// non-negative). If n needs more than nbDigits digits the excess is dropped.
func tritsOf(n *big.Int, nbDigits int) []int {
	res := make([]int, nbDigits)
	q, r := new(big.Int).Set(n), new(big.Int)
	three := big.NewInt(3)
	for i := 0; i < nbDigits; i++ {
		q.QuoRem(q, three, r)
		res[i] = int(r.Int64())
	}
	return res
}

// tritLen returns the number of base-3 digits needed to represent n.
func tritLen(n *big.Int) int {
	if n.Sign() == 0 {
		return 0
	}
	return len(n.Text(3))
}

// assertLessOrEqualTrits constrains the little-endian trit decomposition trits
// (every entry already constrained to be in {0,1,2}) to encode an integer
// smaller than or equal to bound.
//
// It is the base-3 analogue of the builders' MustBeLessOrEqCst, which is
// bit-specific and therefore cannot be reused here. The comparison walks the
// digits from the most significant one down, carrying a boolean eq which is 1
// exactly when the prefix read so far equals the corresponding prefix of the
// bound. While eq is 1 the current digit must not exceed the bound's digit;
// once a strictly smaller digit is read eq drops to 0 and the remaining digits
// are unconstrained.
//
// Because the digits are trits, the equality indicators are quadratic in the
// digit and no IsZero is needed:
//
//	[t == 0] = (t-1)(t-2)/2   [t == 1] = t(2-t)   [t == 2] = t(t-1)/2
//
// For a bound digit of 0 the constraint eq·t == 0 already forces t == 0
// whenever eq == 1, so eq is carried over unchanged and that digit costs a
// single constraint.
func assertLessOrEqualTrits(api frontend.API, trits []frontend.Variable, bound *big.Int) {
	bnd := tritsOf(bound, len(trits))

	// the trailing (least significant) run of 2s in the bound can never be
	// violated, so the walk can stop before it.
	last := 0
	for last < len(bnd) && bnd[last] == 2 {
		last++
	}

	var half big.Int
	half.ModInverse(big.NewInt(2), api.Compiler().Field())

	eq := frontend.Variable(1) // the empty prefix equals the bound's
	for i := len(trits) - 1; i >= last; i-- {
		t := trits[i]
		switch bnd[i] {
		case 0:
			// while eq, the digit must be 0; then it equals the bound's digit,
			// so eq is unchanged.
			api.AssertIsEqual(api.Mul(eq, t), 0)
		case 1:
			// while eq, the digit must not be 2.
			e := api.Mul(eq, t)
			api.AssertIsEqual(api.Mul(e, api.Sub(t, 1)), 0)
			// eq *= [t == 1] = t(2-t)
			eq = api.Mul(e, api.Sub(2, t))
		case 2:
			// any trit is <= 2, nothing to enforce.
			// eq *= [t == 2] = t(t-1)/2
			e := api.Mul(eq, t)
			eq = api.Mul(api.Mul(e, api.Sub(t, 1)), half)
		}
	}
}

func toTernary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	// parse options
	nbBits := api.Compiler().FieldBitLen()
	// 3**nbTrits > 2**nbBits > field, so nbTrits digits always suffice for any
	// field element -- and conversely the digit range always exceeds the field,
	// which is exactly why the canonicity check below is needed.
	nbTrits := int(float64(nbBits)/math.Log2(3.0)) + 1
	cfg := baseConversionConfig{
		NbDigits: nbTrits,
	}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			panic(err)
		}
	}

	field := api.Compiler().Field()
	fieldMinusOne := new(big.Int).Sub(field, big.NewInt(1))

	if cfg.upperBound != nil {
		if cfg.omitModulusCheck {
			panic("WithUpperBound and OmitModulusCheck are contradictory: one asks for a bound check, the other removes it")
		}
		// a bound at or above the modulus would readmit the
		// multiple-decomposition case the check exists to prevent.
		if cfg.upperBound.Cmp(fieldMinusOne) > 0 {
			panic(fmt.Sprintf("WithUpperBound: bound has %d bits and exceeds the native modulus minus one", cfg.upperBound.BitLen()))
		}
	}

	// handle the case when the input is constant separately to avoid creating
	// any constraints
	if constV, ok := api.Compiler().ConstantValue(v); ok {
		constV.Mod(constV, field)
		if cfg.NbDigits > 0 && cfg.NbDigits < tritLen(constV) {
			panic(fmt.Sprintf("constant input to ToTernary has more trits than requested by WithNbDigits option. Has %d trits, requested %d trits", tritLen(constV), cfg.NbDigits))
		}
		if cfg.upperBound != nil && constV.Cmp(cfg.upperBound) > 0 {
			panic(fmt.Sprintf("constant input to ToTernary exceeds the bound set by WithUpperBound option. Value %s, bound %s", constV.String(), cfg.upperBound.String()))
		}
		digits := tritsOf(constV, cfg.NbDigits)
		res := make([]frontend.Variable, cfg.NbDigits)
		for i := range res {
			res[i] = digits[i]
		}
		return res
	}

	// if we decompose into more trits than nbTrits then the rest would always
	// be zero. Reduce the always-zeros to have fewer edge-cases below.
	var paddingTrits int
	if cfg.NbDigits > nbTrits {
		paddingTrits = cfg.NbDigits - nbTrits
		cfg.NbDigits = nbTrits
	}

	c := big.NewInt(1)
	b := big.NewInt(3)

	trits, err := api.Compiler().NewHint(nTrits, cfg.NbDigits, v)
	if err != nil {
		panic(err)
	}

	var Σti frontend.Variable
	Σti = 0
	for i := 0; i < cfg.NbDigits; i++ {
		Σti = api.Add(Σti, api.Mul(trits[i], c))
		c.Mul(c, b)
		if !cfg.UnconstrainedOutputs {
			AssertIsTrit(api, trits[i])
		}
	}

	// record the constraint Σ (3**i * t[i]) == a
	api.AssertIsEqual(Σti, v)

	// The relation above holds in the native field only, so without a further
	// bound the digits of v, v+field, v+2*field, ... all satisfy it whenever
	// they still fit in cfg.NbDigits trits. Pin the decomposition down to the
	// canonical one. This mirrors what PR #836 did for the binary conversion.
	//
	// c is now 3**cfg.NbDigits, the exclusive upper end of the digit range. The
	// check is only needed when that range actually exceeds the bound; in
	// particular WithNbDigits(k) with 3**k <= field pays nothing.
	if !cfg.UnconstrainedOutputs {
		bound := fieldMinusOne
		if cfg.upperBound != nil {
			bound = cfg.upperBound
		}
		enforce := cfg.upperBound != nil || !cfg.omitModulusCheck
		// vacuous if every representable digit vector is already <= bound
		if enforce && new(big.Int).Sub(c, big.NewInt(1)).Cmp(bound) > 0 {
			assertLessOrEqualTrits(api, trits, bound)
		}
	}

	// restore the zero trits which exceed the full decomposition length when
	// requested by setting WithNbDigits larger than it.
	trits = append(trits, make([]frontend.Variable, paddingTrits)...)
	for i := cfg.NbDigits; i < len(trits); i++ {
		trits[i] = 0 // frontend.Variable is interface{}, we get nil pointer err if trying to access it.
	}

	return trits
}

// AssertIsTrit constrains digit to be 0, 1 or 2.
func AssertIsTrit(api frontend.API, v frontend.Variable) {
	if c, ok := api.Compiler().ConstantValue(v); ok {
		if c.IsUint64() && c.Uint64() <= 2 {
			return
		}
		panic("value " + c.String() + " is not 0, 1 or 2")
	}

	// v * (1 - v) * (2 - v) == 0
	// TODO this adds 3 constraint, not 2. Need api.Compiler().AddConstraint(...)
	y := api.Mul(api.Sub(1, v), api.Sub(2, v))
	api.AssertIsEqual(api.Mul(v, y), 0)
}
