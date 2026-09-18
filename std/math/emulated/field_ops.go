package emulated

import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/profile"
	mathbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/selector"
)

// Div computes a/b and returns it. It uses [DivHint] as a hint function.
func (f *Field[T]) Div(a, b *Element[T]) *Element[T] {
	// fast path when dividing 0
	if len(a.Limbs) == 0 {
		return f.Zero()
	}
	return f.reduceAndOp(f.div, f.divPreCond, a, b)
}

func (f *Field[T]) divPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	mulOf, err := f.mulPreCondReduced(&Element[T]{Limbs: make([]frontend.Variable, f.fParams.NbLimbs()), overflow: 0}, b)
	if err != nil {
		return mulOf, err
	}
	// we didn't need to reduce b. Inside div the result a/b is already reduced,
	// so can use overflow 0
	return f.subPreCond(a, &Element[T]{overflow: 0})
}

func (f *Field[T]) div(a, b *Element[T], _ uint) *Element[T] {
	// fast path - constant division can be folded eagerly and avoids calling a
	// hint for a value already known at compile time.
	if ba, aConst := f.constantValue(a); aConst {
		if bb, bConst := f.constantValue(b); bConst {
			if bb.Sign() == 0 {
				panic("division by zero")
			}
			if !f.fParams.IsPrime() {
				panic("modulus not a prime")
			}
			inv := new(big.Int).ModInverse(bb, f.fParams.Modulus())
			if inv == nil {
				panic("division undefined")
			}
			ba.Mul(ba, inv).Mod(ba, f.fParams.Modulus())
			return newConstElement[T](f.api.Compiler().Field(), ba, false)
		}
	}
	// omit width assertion as for a is done in AssertIsEqual and for b is done in Mul below
	if !f.fParams.IsPrime() {
		// TODO shouldn't we still try to do a classic int div in a hint, constraint the result, and let it fail?
		// that would enable things like uint32 div ?
		panic("modulus not a prime")
	}
	div, err := f.computeDivisionHint(a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute division: %v", err))
	}
	e := f.packLimbs(div, true)
	res := f.Mul(e, b)
	f.AssertIsEqual(res, a)
	return e
}

// Inverse compute 1/a and returns it. It uses [InverseHint].
func (f *Field[T]) Inverse(a *Element[T]) *Element[T] {
	return f.reduceAndOp(f.inverse, f.inversePreCond, a, nil)
}

func (f *Field[T]) inversePreCond(a, _ *Element[T]) (nextOverflow uint, err error) {
	// check if we need to reduce a first. Order is important here, we want to
	// reduce a first if needed.
	mulOf, err := f.mulPreCondReduced(a, f.One())
	if err != nil {
		return mulOf, err
	}
	// we didn't need to reduce a. Inside inverse the result 1/a is already reduced,
	// so can use overflow 0
	return 0, nil
}

func (f *Field[T]) inverse(a, _ *Element[T], _ uint) *Element[T] {
	// fast path - constant inversion can be computed directly without using a
	// hint or emitting a multiplication check.
	if ba, aConst := f.constantValue(a); aConst {
		if !f.fParams.IsPrime() {
			panic("modulus not a prime")
		}
		inv := new(big.Int).ModInverse(ba, f.fParams.Modulus())
		if inv == nil {
			panic("inverse undefined")
		}
		return newConstElement[T](f.api.Compiler().Field(), inv, false)
	}
	// omit width assertion as is done in Mul below
	if !f.fParams.IsPrime() {
		panic("modulus not a prime")
	}
	k, err := f.computeInverseHint(a.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute inverse: %v", err))
	}
	e := f.packLimbs(k, true)
	res := f.Mul(e, a)
	one := f.One()
	f.AssertIsEqual(res, one)
	return e
}

// Sqrt computes square root of a and returns it. It uses [SqrtHint].
func (f *Field[T]) Sqrt(a *Element[T]) *Element[T] {
	// fast path when input is zero
	if len(a.Limbs) == 0 {
		return f.Zero()
	}
	return f.reduceAndOp(f.sqrt, f.sqrtPreCond, a, nil)
}

func (f *Field[T]) sqrtPreCond(a, _ *Element[T]) (nextOverflow uint, err error) {
	// when we compute the square root, the result is always reduced, so we can use
	// overflow 0
	return f.subPreCond(a, &Element[T]{overflow: 0})
}

func (f *Field[T]) sqrt(a, _ *Element[T], _ uint) *Element[T] {
	// fast path - constant square roots can be computed eagerly when they
	// exist, avoiding a hint round-trip for compile-time values.
	if ba, aConst := f.constantValue(a); aConst {
		if !f.fParams.IsPrime() {
			panic("modulus not a prime")
		}
		root := new(big.Int).ModSqrt(ba, f.fParams.Modulus())
		if root == nil {
			panic("no square root")
		}
		return newConstElement[T](f.api.Compiler().Field(), root, false)
	}
	// omit width assertion as is done in Mul below
	if !f.fParams.IsPrime() {
		panic("modulus not a prime")
	}
	res, err := f.NewHint(SqrtHint, 1, a)
	if err != nil {
		panic(fmt.Sprintf("compute sqrt: %v", err))
	}
	_a := f.Mul(res[0], res[0])
	f.AssertIsEqual(_a, a)
	return res[0]
}

// Add computes a+b and returns it. If the result wouldn't fit into Element, then
// first reduces the inputs (larger first) and tries again. Doesn't mutate
// inputs.
func (f *Field[T]) Add(a, b *Element[T]) *Element[T] {
	return f.reduceAndOp(f.add, f.addPreCond, a, b)
}

func (f *Field[T]) addPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nextOverflow = max(a.overflow, b.overflow) + 1
	if nextOverflow > f.maxOverflow() {
		err = overflowError{op: "add", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *Field[T]) add(a, b *Element[T], nextOverflow uint) *Element[T] {
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Add(ba, bb).Mod(ba, f.fParams.Modulus())
		return newConstElement[T](f.api.Compiler().Field(), ba, false)
	}

	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	for i := range limbs {
		limbs[i] = 0
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Add(limbs[i], b.Limbs[i])
		}
	}

	// Record operation for profiling
	profile.RecordOperation("emulated.Add", len(a.Limbs)+len(b.Limbs))
	return f.newInternalElement(limbs, nextOverflow)
}

func (f *Field[T]) Sum(inputs ...*Element[T]) *Element[T] {
	if len(inputs) == 0 {
		return f.Zero()
	}
	if len(inputs) == 1 {
		return inputs[0]
	}
	overflow := uint(0)
	nbLimbs := 0
	for i := range inputs {
		f.enforceWidthConditional(inputs[i])
		if inputs[i].overflow > overflow {
			overflow = inputs[i].overflow
		}
		if len(inputs[i].Limbs) > nbLimbs {
			nbLimbs = len(inputs[i].Limbs)
		}
	}
	addOverflow := bits.Len(uint(len(inputs)))
	limbs := make([]frontend.Variable, nbLimbs)
	for i := range limbs {
		limbs[i] = 0
	}
	for i := range inputs {
		for j := range inputs[i].Limbs {
			limbs[j] = f.api.Add(limbs[j], inputs[i].Limbs[j])
		}
	}
	profile.RecordOperation("emulated.Sum", nbLimbs)
	return f.newInternalElement(limbs, overflow+uint(addOverflow))
}

// Sub subtracts b from a and returns it. Reduces locally if wouldn't fit into
// Element. Doesn't mutate inputs.
func (f *Field[T]) Sub(a, b *Element[T]) *Element[T] {
	return f.reduceAndOp(f.sub, f.subPreCond, a, b)
}

func (f *Field[T]) subPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < (b.overflow + 1)
	nextOverflow = max(b.overflow+1, a.overflow) + 1
	if nextOverflow > f.maxOverflow() {
		err = overflowError{op: "sub", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *Field[T]) sub(a, b *Element[T], nextOverflow uint) *Element[T] {
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Sub(ba, bb).Mod(ba, f.fParams.Modulus())
		return newConstElement[T](f.api.Compiler().Field(), ba, false)
	}

	// first we have to compute padding to ensure that the subtraction does not
	// underflow.
	nbLimbs := max(len(a.Limbs), len(b.Limbs), int(f.fParams.NbLimbs()))
	limbs := make([]frontend.Variable, nbLimbs)
	padLimbs := subPadding(f.fParams.Modulus(), f.fParams.BitsPerLimb(), b.overflow, uint(nbLimbs))
	for i := range limbs {
		limbs[i] = padLimbs[i]
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Sub(limbs[i], b.Limbs[i])
		}
	}

	// Record operation for profiling
	profile.RecordOperation("emulated.Sub", len(a.Limbs)+len(b.Limbs))
	return f.newInternalElement(limbs, nextOverflow)
}

func (f *Field[T]) Neg(a *Element[T]) *Element[T] {
	return f.Sub(f.Zero(), a)
}

// Select sets e to a if selector == 1 and to b otherwise. Sets the number of
// limbs and overflow of the result to be the maximum of the limb lengths and
// overflows. If the inputs are strongly unbalanced, then it would better to
// reduce the result after the operation.
func (f *Field[T]) Select(selector frontend.Variable, a, b *Element[T]) *Element[T] {
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	overflow := max(a.overflow, b.overflow)
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	e := f.newInternalElement(make([]frontend.Variable, nbLimbs), overflow)
	normalize := func(limbs []frontend.Variable) []frontend.Variable {
		if len(limbs) < nbLimbs {
			// Copy into a fresh slice instead of append: limbs may share backing
			// storage with the carry-limb slice of a pending deferred check
			// (allocated from the same hint-output block). append would then write
			// zeros over those committed carry limbs before the challenge is drawn,
			// corrupting the deferred check (a liveness fault).
			out := make([]frontend.Variable, nbLimbs)
			copy(out, limbs)
			for i := len(limbs); i < nbLimbs; i++ {
				out[i] = 0
			}
			return out
		}
		return limbs
	}
	aNormLimbs := normalize(a.Limbs)
	bNormLimbs := normalize(b.Limbs)
	for i := range e.Limbs {
		e.Limbs[i] = f.api.Select(selector, aNormLimbs[i], bNormLimbs[i])
	}

	// Record operation for profiling
	profile.RecordOperation("emulated.Select", 2*(len(a.Limbs)+len(b.Limbs)))
	return e
}

// Lookup2 performs two-bit lookup between a, b, c, d based on lookup bits b1
// and b2 such that:
//   - if b0=0 and b1=0, sets to a,
//   - if b0=1 and b1=0, sets to b,
//   - if b0=0 and b1=1, sets to c,
//   - if b0=1 and b1=1, sets to d.
//
// The number of the limbs and overflow in the result is the maximum of the
// inputs'. If the inputs are very unbalanced, then reduce the result.
func (f *Field[T]) Lookup2(b0, b1 frontend.Variable, a, b, c, d *Element[T]) *Element[T] {
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	f.enforceWidthConditional(c)
	f.enforceWidthConditional(d)
	overflow := max(a.overflow, b.overflow, c.overflow, d.overflow)
	nbLimbs := max(len(a.Limbs), len(b.Limbs), len(c.Limbs), len(d.Limbs))
	e := f.newInternalElement(make([]frontend.Variable, nbLimbs), overflow)
	normalize := func(limbs []frontend.Variable) []frontend.Variable {
		if len(limbs) < nbLimbs {
			// Copy into a fresh slice instead of append: limbs may share backing
			// storage with the carry-limb slice of a pending deferred check
			// (allocated from the same hint-output block). append would then write
			// zeros over those committed carry limbs before the challenge is drawn,
			// corrupting the deferred check (a liveness fault).
			out := make([]frontend.Variable, nbLimbs)
			copy(out, limbs)
			for i := len(limbs); i < nbLimbs; i++ {
				out[i] = 0
			}
			return out
		}
		return limbs
	}
	aNormLimbs := normalize(a.Limbs)
	bNormLimbs := normalize(b.Limbs)
	cNormLimbs := normalize(c.Limbs)
	dNormLimbs := normalize(d.Limbs)
	for i := range nbLimbs {
		e.Limbs[i] = f.api.Lookup2(b0, b1, aNormLimbs[i], bNormLimbs[i], cNormLimbs[i], dNormLimbs[i])
	}

	// Record operation for profiling
	profile.RecordOperation("emulated.Lookup2", 4*(len(a.Limbs)+len(b.Limbs)+len(c.Limbs)+len(d.Limbs)))
	return e
}

// Mux selects element inputs[sel] and returns it. The number of the limbs and
// overflow in the result is the maximum of the inputs'. If the inputs are very
// unbalanced, then reduce the inputs before calling the method. It is most
// efficient for power of two lengths of the inputs, but works for any
// number of inputs.
func (f *Field[T]) Mux(sel frontend.Variable, inputs ...*Element[T]) *Element[T] {
	if len(inputs) == 0 {
		return nil
	}
	nbInputs := len(inputs)
	if nbInputs == 1 {
		f.api.AssertIsEqual(sel, 0)
		return inputs[0]
	}
	overflow := uint(0)
	nbLimbs := 0
	for i := range inputs {
		f.enforceWidthConditional(inputs[i])
		if inputs[i].overflow > overflow {
			overflow = inputs[i].overflow
		}
		if len(inputs[i].Limbs) > nbLimbs {
			nbLimbs = len(inputs[i].Limbs)
		}
	}
	normalize := func(limbs []frontend.Variable) []frontend.Variable {
		if len(limbs) < nbLimbs {
			// Copy into a fresh slice instead of append: limbs may share backing
			// storage with the carry-limb slice of a pending deferred check
			// (allocated from the same hint-output block). append would then write
			// zeros over those committed carry limbs before the challenge is drawn,
			// corrupting the deferred check (a liveness fault).
			out := make([]frontend.Variable, nbLimbs)
			copy(out, limbs)
			for i := len(limbs); i < nbLimbs; i++ {
				out[i] = 0
			}
			return out
		}
		return limbs
	}
	normLimbs := make([][]frontend.Variable, nbInputs)
	for i := range inputs {
		normLimbs[i] = normalize(inputs[i].Limbs)
	}
	normLimbsTransposed := make([][]frontend.Variable, nbLimbs)
	for i := range normLimbsTransposed {
		normLimbsTransposed[i] = make([]frontend.Variable, nbInputs)
		for j := range normLimbsTransposed[i] {
			normLimbsTransposed[i][j] = normLimbs[j][i]
		}
	}

	e := f.newInternalElement(make([]frontend.Variable, nbLimbs), overflow)

	// Optimization: decompose sel into bits once and reuse for all limbs
	// instead of decomposing inside each selector.Mux call.
	n := uint(nbInputs)
	nbBits := bits.Len(n - 1) // we use n-1 as sel is 0-indexed
	selBits := mathbits.ToBinary(f.api, sel, mathbits.WithNbDigits(nbBits))

	paddedSize := 1 << nbBits
	if bits.OnesCount(n) != 1 {
		// Non-power of 2: need additional bound check sel <= n-1
		if cmper, ok := f.api.Compiler().(interface {
			MustBeLessOrEqCst(aBits []frontend.Variable, bound *big.Int, aForDebug frontend.Variable)
		}); ok {
			cmper.MustBeLessOrEqCst(selBits, big.NewInt(int64(n-1)), sel)
		} else {
			panic("builder does not expose comparison to constant")
		}
		// Pad each limb slice to next power of 2 with constant 0
		for i := range nbLimbs {
			padded := make([]frontend.Variable, paddedSize)
			copy(padded, normLimbsTransposed[i])
			for j := nbInputs; j < paddedSize; j++ {
				padded[j] = 0
			}
			normLimbsTransposed[i] = padded
		}
	}

	for i := range nbLimbs {
		e.Limbs[i] = selector.BinaryMux(f.api, selBits, normLimbsTransposed[i])
	}

	// Record operation for profiling
	profile.RecordOperation("emulated.Mux", nbInputs*nbLimbs)
	return e
}

// reduceAndOp applies op on the inputs. If the pre-condition check preCond
// errs, then first reduces the input arguments. The reduction is done
// one-by-one with the element with highest overflow reduced first.
func (f *Field[T]) reduceAndOp(op func(*Element[T], *Element[T], uint) *Element[T], preCond func(*Element[T], *Element[T]) (uint, error), a, b *Element[T]) *Element[T] {
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	var nextOverflow uint
	var err error
	var target overflowError

	var nbLoops int
	for nextOverflow, err = preCond(a, b); errors.As(err, &target); nextOverflow, err = preCond(a, b) {
		if nbLoops++; nbLoops > 2 {
			// we have tried reducing both sides and still the operation doesn't fit.
			// this should never happen as after reducing both sides, the operation
			// must fit.
			//
			// This is gnark-side error which needs to be fixed in the code, so we
			// panic here.
			panic("internal error: too many reduction loops")
		}
		if !target.reduceRight {
			a = f.Reduce(a)
		} else {
			b = f.Reduce(b)
		}
	}
	return op(a, b, nextOverflow)
}

type overflowError struct {
	op           string
	nextOverflow uint
	maxOverflow  uint
	reduceRight  bool
}

func (e overflowError) Error() string {
	return fmt.Sprintf("op %s overflow %d exceeds max %d", e.op, e.nextOverflow, e.maxOverflow)
}
