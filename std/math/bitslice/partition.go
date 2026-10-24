// Package bitslice allows partitioning variables.
package bitslice

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/rangecheck"
)

// Partition partitions v into two parts split at bit numbered split. The
// following holds
//
//	v = lower + 2^split * upper.
//
// The method enforces that lower < 2^split and upper < 2^split', where
// split'=nbScalar-split. When giving the option [WithNbDigits], we instead use
// the bound split'=nbDigits-split.
//
// When split is greater than or equal to the effective width (nbDigits when
// [WithNbDigits] is set, otherwise the native field width), the upper part is
// necessarily empty: the function returns lower = v and upper = 0. This keeps
// the call well-defined and consistent between the constant and variable paths
// (the constant path already returns the same values via big.Int arithmetic).
func Partition(api frontend.API, v frontend.Variable, split uint, opts ...Option) (lower, upper frontend.Variable) {
	opt, err := parseOpts(opts...)
	if err != nil {
		panic(err)
	}
	// handle constant case
	if vc, ok := api.Compiler().ConstantValue(v); ok {
		if opt.digits > 0 && vc.BitLen() > opt.digits {
			panic("input larger than bound")
		}
		if split == 0 {
			return 0, vc
		}
		div := new(big.Int).Lsh(big.NewInt(1), split)
		l, u := new(big.Int), new(big.Int)
		u.QuoRem(vc, div, l)
		return l, u
	}
	rh := rangecheck.New(api)

	// effectiveBits is the width of the region we decompose. When WithNbDigits
	// is set (and smaller than the field width), the decomposition spans
	// nbDigits bits; otherwise it spans the whole native field. If split is at
	// or beyond that width, the upper part is necessarily empty (upper == 0 and
	// lower == v). We handle this explicitly so that the call stays well-defined
	// and consistent with the constant path, instead of panicking on a slice
	// bound or feeding a negative width to the range checker.
	effectiveBits := api.Compiler().FieldBitLen()
	if opt.digits > 0 && opt.digits < effectiveBits {
		effectiveBits = opt.digits
	}
	if split >= uint(effectiveBits) {
		if opt.digits > 0 {
			rh.Check(v, opt.digits)
		}
		return v, 0
	}

	if split == 0 {
		if opt.digits > 0 {
			rh.Check(v, opt.digits)
		}
		return 0, v
	}
	// when nbDigits is not set, then we assume the bound is the field size.
	// However, in that case the decomposition check is more involved as we need
	// to avoid the recomposed value to overflow the field. We do not have good
	// methods for avoiding it when using range checker gadget, so we defer it
	// to `bits.ToBinary`.
	if opt.digits == 0 || opt.digits >= api.Compiler().FieldBitLen() {
		bts := bits.ToBinary(api, v)
		lowerBts := bts[:split]
		upperBts := bts[split:]
		lower = bits.FromBinary(api, lowerBts)
		upper = bits.FromBinary(api, upperBts)
		return lower, upper
	}
	ret, err := api.Compiler().NewHint(partitionHint, 2, split, v)
	if err != nil {
		panic(err)
	}

	upper = ret[0]
	lower = ret[1]

	if opt.nocheck {
		if opt.digits > 0 {
			rh.Check(v, opt.digits)
		}
		return
	}
	rh.Check(upper, int(effectiveBits)-int(split))
	rh.Check(lower, int(split))

	m := big.NewInt(1)
	m.Lsh(m, split)
	// In PlonkAPI with split < 63, we can use AddPlonkConstraint to assert
	// lower + upper*m - v = 0 in a single constraint (qL=1, qR=m, qO=-1)
	if plonkAPI, ok := api.Compiler().(frontend.PlonkAPI); ok && split < 63 {
		plonkAPI.AddPlonkConstraint(lower, upper, v, 1, int(1<<split), -1, 0, 0)
	} else {
		composed := api.Add(lower, api.Mul(upper, m))
		api.AssertIsEqual(composed, v)
	}
	return
}
