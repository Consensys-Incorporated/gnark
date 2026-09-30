package emulated

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"slices"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/internal/fieldextension"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/multicommit"
)

// bigIntPool for using in hints to avoid excessive allocations
var bigIntPool = sync.Pool{
	New: func() any {
		return new(big.Int)
	},
}

// deferredChecker is an interface for deferring a check in non-native
// arithmetic. The idea of the deferred check is that we do not compute the
// check immediately, but we store the values and the check to be done later.
// This allows us to share the verifier challenge computation between multiple
// checks.
//
// Currently used for multiplication and multivariate evaluation checks.
//
// The methods [evalRound1], [evalRound2] and [check] may receive as inputs
// either [frontend.Variable] or [fieldextension.Element]. The
// implementation should differentiate on the different input types and use the
// appropriate API (native or extension).
type deferredChecker interface {
	// toCommit outputs the variable which should be committed to. The checker
	// then uses the commitment to obtain the verifier challenge for the
	// Schwartz-Zippel lemma.
	toCommit() []frontend.Variable
	// maxLen returns the maximum number of limbs in the deferred check. This is
	// used for computing the number of powers of the verifier challenge to
	// compute
	maxLen() int

	// evalRound1 evaluates the first round of the check at with the random
	// challenge, given through its powers at. In the first round we do not
	// assume that any of the values is already evaluated as they come directly
	// from hint.
	//
	// The method should store the evaluation result inside the Element and mark
	// it as evaluated. If the method is called for already evaluated input then
	// should assume that the challenge is the same as the one used for the
	// evaluation.
	evalRound1(at []frontend.Variable)
	// evalRound2 evaluates the second round of the check at a given random point
	// at[0]. However, it may happen that some of the values are equal to the
	// result from a previous check. In that case we can reuse the evaluation to
	// save constraints.
	//
	// The method should store the evaluation result inside the Element and mark
	// it as evaluated. If the method is called for already evaluated input then
	// should assume that the challenge is the same as the one used for the
	// evaluation.
	evalRound2(at []frontend.Variable)
	// check checks the correctness of the deferred check. The method should use
	// the stored evaluations. We additionally provide the evaluation of
	// p(challenge) and (2^t-challenge) as they are static over all checks.
	check(api frontend.API, peval frontend.Variable, coef frontend.Variable)
	// cleanEvaluations cleans the cached evaluation values. This is necessary for
	// ensuring the circuit stability over many compilations.
	cleanEvaluations()
}

// mulCheck represents a single multiplication check. Instead of doing a
// multiplication exactly where called, we compute the result using hint and
// return it. Additionally, we store the correctness check for later checking
// (together with every other multiplication) to share the verifier challenge
// computation.
//
// With this approach this is important that we do not change the [Element]
// values after they are returned from [mulMod] as mulCheck keeps pointers and
// the check will fail if the values referred to by the pointers change. By
// following the [Field] public methods this shouldn't happen as we always take
// and return pointers, and to change the values the user has to explicitly
// dereference.
//
// We store the values a, b, r, k, c. They are as follows:
//   - a, b - the inputs what we are multiplying. Do not have to be reduced.
//   - r - the multiplication result reduced modulo the emulation parameter.
//   - k - the quotient for integer multiplication a*b divided by emulation parameter.
//   - c - element representing carry. Used only for aligning the limb widths.
//
// Given these values, the following holds:
//
//	a * b = r + k*p
//
// But for asserting that the previous equation holds, we instead use the
// polynomial representation of the elements. If a non-native element a is given
// by its limbs
//
//	a = (a_0, ..., a_n)
//
// then
//
//	a(X) = \sum_i a_i * X^i.
//
// Now, the multiplication check instead becomes
//
//	a(X) * b(X) = r(X) + k(X) * p(X) + (2^t-X) c(X),
//
// which can be checked only at a single random point. Here we need an
// additional polynomial c(X) which is used for carrying the overflow bits to
// the consecutive limbs. By subtracting 2^t c(X) we can remove the bits from
// the corresponding coefficients in r(X)+k(X)*p(X) and by adding X c(X) we can
// add the bits to X(r(X) + k(X) * p(X)) (i.e. to the next coefficient).
type mulCheck[T FieldParams] struct {
	f *Field[T]
	// a * b = r + k*p + c
	a, b *Element[T] // inputs
	r    *Element[T] // reduced value
	k    *Element[T] // coefficient
	c    *Element[T] // carry
	p    *Element[T] // modulus if non-nil
}

func (mc *mulCheck[T]) toCommit() []frontend.Variable {
	nbToCommit := len(mc.a.Limbs) + len(mc.b.Limbs) + len(mc.r.Limbs) + len(mc.k.Limbs) + len(mc.c.Limbs)
	if mc.p != nil {
		nbToCommit += len(mc.p.Limbs)
	}
	toCommit := make([]frontend.Variable, 0, nbToCommit)
	toCommit = append(toCommit, mc.a.Limbs...)
	toCommit = append(toCommit, mc.b.Limbs...)
	toCommit = append(toCommit, mc.r.Limbs...)
	toCommit = append(toCommit, mc.k.Limbs...)
	toCommit = append(toCommit, mc.c.Limbs...)
	if mc.p != nil {
		toCommit = append(toCommit, mc.p.Limbs...)
	}
	return toCommit
}

func (mc *mulCheck[T]) maxLen() int {
	maxLen := len(mc.a.Limbs)
	maxLen = max(maxLen, len(mc.b.Limbs))
	maxLen = max(maxLen, len(mc.r.Limbs))
	maxLen = max(maxLen, len(mc.k.Limbs))
	maxLen = max(maxLen, len(mc.c.Limbs))
	if mc.p != nil {
		maxLen = max(maxLen, len(mc.p.Limbs))
	}
	return maxLen
}

// evalRound1 evaluates first c(X), r(X) and k(X) at a given random point at[0].
// In the first round we do not assume that any of them is already evaluated as
// they come directly from hint.
func (mc *mulCheck[T]) evalRound1(at []frontend.Variable) {
	mc.c = mc.f.evalWithChallenge(mc.c, at)
	mc.r = mc.f.evalWithChallenge(mc.r, at)
	mc.k = mc.f.evalWithChallenge(mc.k, at)
	if mc.p != nil {
		mc.p = mc.f.evalWithChallenge(mc.p, at)
	}
}

// evalRound2 now evaluates a and b at a given random point at[0]. However, it
// may happen that a or b is equal to r from a previous mulcheck. In that case
// we can reuse the evaluation to save constraints.
func (mc *mulCheck[T]) evalRound2(at []frontend.Variable) {
	mc.a = mc.f.evalWithChallenge(mc.a, at)
	mc.b = mc.f.evalWithChallenge(mc.b, at)
}

// check checks a(ch) * b(ch) = r(ch) + k(ch) * p(ch) + (2^t - ch) c(ch). As the
// computation of p(ch) and (2^t-ch) can be shared over all mulCheck instances,
// then we get them already evaluated as peval and coef.
func (mc *mulCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	if mc.p != nil {
		peval = mc.p.evaluation
	}
	// we either have to perform the equality check in the native field or in
	// the extension field. It was already determined at the [Field]
	// initialization time which kind of check needs to be done.
	if mc.f.extensionApi == nil {
		ls := api.Mul(mc.a.evaluation, mc.b.evaluation)
		rs := api.Add(mc.r.evaluation, api.Mul(peval, mc.k.evaluation), api.Mul(mc.c.evaluation, coef))
		api.AssertIsEqual(ls, rs)
	} else {
		// here we use the fact that [frontend.Variable] is defined as any, but
		// we have actually provided [ExtensionVariable]. We type assert to be
		// able to use the fieldextension API.
		//
		// the computations are same as in the previous conditional block, but
		// only in the extension.
		aext := mc.a.evaluation.(fieldextension.Element)
		bext := mc.b.evaluation.(fieldextension.Element)
		ls := mc.f.extensionApi.Mul(aext, bext)

		rext := mc.r.evaluation.(fieldextension.Element)
		pevalext := peval.(fieldextension.Element)
		cext := mc.c.evaluation.(fieldextension.Element)
		kext := mc.k.evaluation.(fieldextension.Element)
		coefext := coef.(fieldextension.Element)
		pkext := mc.f.extensionApi.Mul(pevalext, kext)
		ccoefext := mc.f.extensionApi.Mul(coefext, cext)

		rs := mc.f.extensionApi.Add(rext, pkext)
		rs = mc.f.extensionApi.Add(rs, ccoefext)

		mc.f.extensionApi.AssertIsEqual(ls, rs)
	}
}

// cleanEvaluations cleans the cached evaluation values. This is necessary for
// ensuring the circuit stability over many compilations.
func (mc *mulCheck[T]) cleanEvaluations() {
	mc.a.evaluation = 0
	mc.a.isEvaluated = false
	mc.b.evaluation = 0
	mc.b.isEvaluated = false
	mc.r.evaluation = 0
	mc.r.isEvaluated = false
	mc.k.evaluation = 0
	mc.k.isEvaluated = false
	mc.c.evaluation = 0
	mc.c.isEvaluated = false
	if mc.p != nil {
		mc.p.evaluation = 0
		mc.p.isEvaluated = false
	}
}

// mulMod returns a*b mod r. In practice it computes the result using a hint and
// defers the actual multiplication check.
func (f *Field[T]) mulMod(a, b *Element[T], _ uint, p *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	if p == nil {
		// fast path - constant multiplication can be folded directly without
		// creating a hinted reduction or carrying synthetic overflow metadata.
		if ba, aConst := f.constantValue(a); aConst {
			if bb, bConst := f.constantValue(b); bConst {
				ba.Mul(ba, bb).Mod(ba, f.fParams.Modulus())
				return newConstElement[T](f.api.Compiler().Field(), ba, false)
			}
		}
	}
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)

	// Use small field optimization if available and no custom modulus
	if p == nil && f.useSmallFieldOptimization() {
		// For small field mode, ensure elements are single-limb
		// If they have more limbs due to witness initialization, convert them
		aLimb := f.toSingleLimbElement(a)
		bLimb := f.toSingleLimbElement(b)
		return f.smallMulMod(aLimb, bLimb)
	}

	f.enforceWidthConditional(p)
	k, r, c, err := f.callMulHint(a, b, true, p)
	if err != nil {
		panic(err)
	}
	mc := mulCheck[T]{
		f: f,
		a: a,
		b: b,
		c: c,
		k: k,
		r: r,
		p: p,
	}
	f.deferredChecks = append(f.deferredChecks, &mc)
	// Record operation for profiling - this tracks the operation at call site
	// independently of when the actual constraints are created in deferred callbacks.
	// Include limb count in the name for visibility in pprof flamegraphs.
	profile.RecordOperation("emulated.MulMod", len(a.Limbs)+len(b.Limbs)+len(r.Limbs)+len(k.Limbs)+len(c.Limbs))
	return r
}

// checkZero creates multiplication check a * 1 = 0 + k*p.
func (f *Field[T]) checkZero(a *Element[T], p *Element[T]) {
	// fast path - the result is on zero limbs. This means that it is constant zero
	if a.isStrictZero() {
		return
	}

	f.enforceWidthConditional(a)

	// Use small field optimization if available and no custom modulus
	if p == nil && f.useSmallFieldOptimization() {
		aLimb := f.toSingleLimbElement(a)
		f.smallCheckZero(aLimb)
		return
	}

	// the method works similarly to mulMod, but we know that we are multiplying
	// by one and expected result should be zero.
	f.enforceWidthConditional(p)
	b := f.One()
	k, r, c, err := f.callMulHint(a, b, false, p)
	if err != nil {
		panic(err)
	}
	mc := mulCheck[T]{
		f: f,
		a: a,
		b: b, // one on single limb to speed up the polynomial evaluation
		c: c,
		k: k,
		r: r, // expected to be zero on zero limbs.
		p: p,
	}
	f.deferredChecks = append(f.deferredChecks, &mc)

	// Record operation for profiling - this tracks the operation at call site
	// independently of when the actual constraints are created in deferred callbacks.
	profile.RecordOperation("emulated.CheckZero", len(a.Limbs)+len(k.Limbs)+len(c.Limbs))
}

// evalWithChallenge represents element a as a polynomial a(X) and evaluates at
// at[0]. For efficiency, we use already evaluated powers of at[0] given by at.
// It stores the evaluation result inside the Element and marks it as evaluated.
// If the method is called for already evaluated a then returns the known value.
func (f *Field[T]) evalWithChallenge(a *Element[T], at []frontend.Variable) *Element[T] {
	if a.isEvaluated {
		return a
	}
	if len(at) < len(a.Limbs)-1 {
		panic("evaluation powers less than limbs")
	}
	var sum frontend.Variable
	if f.extensionApi != nil {
		sum = f.evalWithChallengeExtension(a, at)
	} else {
		sum = f.evalWithChallengeNative(a, at)
	}
	a.isEvaluated = true
	a.evaluation = sum
	return a
}

func (f *Field[T]) evalWithChallengeNative(a *Element[T], at []frontend.Variable) frontend.Variable {
	var sum frontend.Variable = 0
	if len(a.Limbs) > 0 {
		sum = f.api.Mul(a.Limbs[0], 1) // copy because we use MulAcc
	}
	for i := 1; i < len(a.Limbs); i++ {
		sum = f.api.MulAcc(sum, a.Limbs[i], at[i-1])
	}
	return sum
}

func (f *Field[T]) evalWithChallengeExtension(a *Element[T], at []frontend.Variable) frontend.Variable {
	// even though at is []frontend.Variable, then we abuse the fact that
	// frontend.Variable is defined as any and at is []ExtensionVariable. We
	// type assert it.
	atext := make([]fieldextension.Element, len(at))
	for i := 0; i < len(at); i++ {
		atext[i] = at[i].(fieldextension.Element)
	}
	sum := f.extensionApi.Zero()
	if len(a.Limbs) > 0 {
		sum = f.extensionApi.AsExtensionVariable(a.Limbs[0])
	}
	for i := 1; i < len(a.Limbs); i++ {
		toAdd := f.extensionApi.MulByElement(atext[i-1], a.Limbs[i])
		sum = f.extensionApi.Add(sum, toAdd)
	}
	return sum
}

// performDeferredChecks should be deferred to actually perform all the
// multiplication checks.
func (f *Field[T]) performDeferredChecks(api frontend.API) error {
	// use given api. We are in defer and API may be different to what we have
	// stored.

	// there are no multiplication checks, nothing to do
	if len(f.deferredChecks) == 0 {
		return nil
	}

	// we construct a list of elements we want to commit to. Even though we have
	// committed when doing range checks, do it again here explicitly for safety.
	// TODO: committing is actually expensive in PLONK. We create a constraint
	// for every variable we commit to (to set the selector polynomial). So, it
	// is actually better not to commit again. However, if we would be to use
	// multi-commit and range checks are in different commitment, then we have
	// problem.
	var toCommit []frontend.Variable
	for i := range f.deferredChecks {
		toCommit = append(toCommit, f.deferredChecks[i].toCommit()...)
	}
	if f.extensionApi == nil {
		// we give all the inputs as inputs to obtain random verifier challenge.
		multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
			// for efficiency, we compute all powers of the challenge as slice at.
			coefsLen := int(f.fParams.NbLimbs())
			for i := range f.deferredChecks {
				coefsLen = max(coefsLen, f.deferredChecks[i].maxLen())
			}
			at := make([]frontend.Variable, coefsLen)
			at[0] = commitment
			for i := 1; i < len(at); i++ {
				at[i] = api.Mul(at[i-1], commitment)
			}
			// evaluate all r, k, c
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound1(at)
			}
			// assuming r is input to some other multiplication, then is already evaluated
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound2(at)
			}
			// evaluate p(X) at challenge
			pval := f.evalWithChallenge(f.Modulus(), at)
			// compute (2^t-X) at challenge
			coef := big.NewInt(1)
			coef.Lsh(coef, f.fParams.BitsPerLimb())
			ccoef := api.Sub(coef, commitment)
			// verify all mulchecks
			for i := range f.deferredChecks {
				f.deferredChecks[i].check(api, pval.evaluation, ccoef)
			}
			// clean cached evaluation. Helps in case we compile the same circuit
			// multiple times.
			for i := range f.deferredChecks {
				f.deferredChecks[i].cleanEvaluations()
			}
			return nil
		}, toCommit...)
	} else {
		// this is the same as above, but we have challenges in the extension
		// field. The commitment argument below is actually extension field
		// element, but we give it as []frontend.Variable for interface
		// compatibility.
		multicommit.WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
			// for efficiency, we compute all powers of the challenge as slice at.
			coefsLen := int(f.fParams.NbLimbs())
			for i := range f.deferredChecks {
				coefsLen = max(coefsLen, f.deferredChecks[i].maxLen())
			}
			at := make([]fieldextension.Element, coefsLen)
			at[0] = commitment
			for i := 1; i < len(at); i++ {
				at[i] = f.extensionApi.Mul(at[i-1], commitment)
			}
			atv := make([]frontend.Variable, len(at))
			for i := range at {
				atv[i] = at[i]
			}
			// evaluate all r, k, c
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound1(atv)
			}
			// assuming r is input to some other multiplication, then is already evaluated
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound2(atv)
			}
			// evaluate p(X) at challenge
			pval := f.evalWithChallenge(f.Modulus(), atv)
			// compute (2^t-X) at challenge
			coef := big.NewInt(1)
			coef.Lsh(coef, f.fParams.BitsPerLimb())
			coefext := f.extensionApi.AsExtensionVariable(coef)
			ccoef := f.extensionApi.Sub(coefext, commitment)
			// verify all mulchecks
			for i := range f.deferredChecks {
				f.deferredChecks[i].check(api, pval.evaluation, ccoef)
			}
			// clean cached evaluation. Helps in case we compile the same circuit
			// multiple times.
			for i := range f.deferredChecks {
				f.deferredChecks[i].cleanEvaluations()
			}
			return nil
		}, f.extensionApi.Degree(), toCommit...)
	}
	return nil
}

// mulCarryBound returns an upper bound on the bit-length of the honest
// (signed) carry limbs for a multiplication check of a*b with the given
// quotient parameters. The honest carries satisfy the recurrence
// c_i = (h_i + c_{i-1}) / 2^t where h_i = (a*b)_i - (r + k*p)_i.
//
// The (a*b)_i coefficient is a sum of at most min(len(a), len(b)) products of
// limbs of width bpl+ov_a and bpl+ov_b (when b is a compile-time constant,
// e.g. one in [Field.Reduce] and [Field.checkZero], we use its exact
// bit-length instead of the generic limb width).
//
// The (k*p)_i coefficient is bounded two ways and we take the minimum:
//   - coefficient bound: min(nbQuoLimbs, nbLimbs) products of bpl-bit limbs
//   - value bound: (k*p)_i <= K * 2^bpl where K < 2^quoValueBits is the
//     quotient value (tight when the quotient is small, e.g. in checkZero)
//
// Honest carries may be negative and are represented modulo the native field.
func (f *Field[T]) mulCarryBound(a, b *Element[T], nextOverflow uint, nbQuoLimbs uint, modbits uint) uint {
	bpl := f.fParams.BitsPerLimb()
	// contribution of the k*p (and remainder) limbs
	kpCoef := bpl + uint(bits.Len(uint(min(int(nbQuoLimbs), int(f.fParams.NbLimbs()))+1)))
	var kpVal uint
	if nbQuoLimbs == 0 {
		kpVal = 1
	} else {
		quoValueBits := uint(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))*bpl + nextOverflow + 1 - modbits + 1
		kpVal = quoValueBits + 1
	}
	kpTerm := min(kpCoef, kpVal)
	// contribution of the a*b limbs
	nbAB := uint(bits.Len(uint(min(len(a.Limbs), len(b.Limbs)))))
	// width of b's limbs: generically bpl + b.overflow. When b is a
	// compile-time constant its value bit-length may be smaller (e.g. one in
	// [Field.Reduce] and [Field.checkZero]); note that constant-folded
	// elements can have limbs wider than bpl (tracked by b.overflow), so the
	// value bound only ever tightens the generic one.
	limbWidthB := bpl + b.overflow
	if cbl, isConst := f.constBitLen(b); isConst && cbl < limbWidthB {
		limbWidthB = cbl
	}
	abTerm := a.overflow + limbWidthB + nbAB
	return max(abTerm, kpTerm) + 2
}

// constBitLen returns the bit-length of b when b is a compile-time constant
// and ok=false otherwise. Unlike [Field.constantValue], it also works in the
// test engine (which reports no constants) when all limbs are literals.
func (f *Field[T]) constBitLen(b *Element[T]) (uint, bool) {
	if bb, ok := f.constantValue(b); ok {
		return uint(bb.BitLen()), true
	}
	if len(b.Limbs) == 0 {
		// zero (or uninitialized) element
		return 0, true
	}
	constLimbs := make([]*big.Int, len(b.Limbs))
	for i, l := range b.Limbs {
		switch l.(type) {
		case big.Int, *big.Int, uint8, uint16, uint32, uint64, uint, int8, int16, int32, int64, int, string:
			v := utils.FromInterface(l)
			constLimbs[i] = &v
		default:
			return 0, false
		}
	}
	res := new(big.Int)
	if err := limbs.Recompose(constLimbs, f.fParams.BitsPerLimb(), res); err != nil {
		return 0, false
	}
	return uint(res.BitLen()), true
}

// crtLowCarries returns how many low carry limbs must be range-checked so
// that, together with the random-point identity modulo the native field, the
// integer equality a*b = r+k*p is uniquely determined.
//
// Exact low-carry recurrences show that a*b-r-k*p is divisible by
// 2^(BitsPerLimb*nbLow). The polynomial identity shows, except with its usual
// challenge soundness error, that it is also divisible by the odd native
// modulus q. Existing range checks bound its absolute value below 2^wBits, so
// it is enough to choose nbLow with q*2^(BitsPerLimb*nbLow) >= 2^wBits.
func (f *Field[T]) crtLowCarries(a, b *Element[T], nbQuoLimbs, modBits uint, nbCarryLimbs int) int {
	bpl := f.fParams.BitsPerLimb()
	// a and b are non-negative limb representations whose total widths are
	// tracked by their limb counts and overflow metadata.
	abBits := uint(len(a.Limbs))*bpl + a.overflow + uint(len(b.Limbs))*bpl + b.overflow
	// k is range-checked to nbQuoLimbs limbs. A custom modulus has modBits=0;
	// checkModulus guarantees zero-overflow limbs, so the full parameter width
	// is a conservative bound in that case. The extra bit covers adding r.
	if modBits == 0 {
		modBits = f.fParams.NbLimbs() * bpl
	}
	kprBits := nbQuoLimbs*bpl + modBits + 1
	wBits := max(abBits, kprBits)

	// A field with bit length F has q >= 2^(F-1).
	qBitsLowerBound := uint(f.api.Compiler().FieldBitLen()) - 1
	var remainingBits uint
	if wBits > qBitsLowerBound {
		remainingBits = wBits - qBitsLowerBound
	}
	nbLow := int((remainingBits + bpl - 1) / bpl)
	return max(0, min(nbLow, nbCarryLimbs))
}

// mvCarryBound returns an upper bound on the bit-length of the honest
// (signed) carry limbs for a multivariate evaluation check with the given
// quotient parameters. The limb coefficients of the evaluated polynomial are
// bounded term-wise by the sums of the factor widths plus the coefficient
// width, accumulated over the terms; the carries are these coefficients
// shifted down by BitsPerLimb. The k*p contribution is bounded both
// coefficient-wise and by the quotient value (see [Field.mulCarryBound]).
func (f *Field[T]) mvCarryBound(mv *multivariate[T], at []*Element[T], nbQuoLimbs uint, modbits uint, quoSize uint) uint {
	bpl := f.fParams.BitsPerLimb()
	var maxTerm uint
	for i, term := range mv.Terms {
		var termBits uint
		var factorLens []int
		for j, pow := range term {
			termBits += uint(pow) * (bpl + at[j].overflow)
			for range pow {
				factorLens = append(factorLens, len(at[j].Limbs))
			}
		}
		// Fixing all but one factor index determines the remaining index. The
		// number of products contributing to a coefficient is therefore bounded
		// by the product of the smallest len(factors)-1 factor lengths.
		if len(factorLens) > 1 {
			slices.Sort(factorLens)
			for _, factorLen := range factorLens[:len(factorLens)-1] {
				termBits += uint(bits.Len(uint(factorLen)))
			}
		}
		coef := mv.Coefficients[i]
		if coef < 0 {
			coef = -coef
		}
		termBits += uint(bits.Len(uint(coef)))
		if termBits > maxTerm {
			maxTerm = termBits
		}
	}
	var lhsTerm uint
	if maxTerm > bpl {
		lhsTerm = maxTerm + uint(bits.Len(uint(len(mv.Terms)))) - bpl
	}
	// contribution of the k*p limbs: minimum of the coefficient bound and the
	// quotient value bound
	kpCoef := bpl + uint(bits.Len(uint(min(int(nbQuoLimbs), int(f.fParams.NbLimbs()))+1)))
	var kpVal uint
	if nbQuoLimbs == 0 {
		kpVal = 1
	} else {
		var quoValueBits uint
		if quoSize > modbits {
			quoValueBits = quoSize - modbits + 1
		}
		kpVal = quoValueBits + 1
	}
	kpTerm := min(kpCoef, kpVal)
	return max(lhsTerm, kpTerm) + 2
}

// mvLowCarries returns how many low carry limbs must be range-checked for a
// multivariate evaluation. This uses the same CRT certificate as
// [Field.crtLowCarries]. quoSize bounds the evaluated expression; the
// additional modulus width and sign margin conservatively bound the signed
// relation checked by mvCheck.
func (f *Field[T]) mvLowCarries(quoSize, modBits uint, nbCarryLimbs int) int {
	bpl := f.fParams.BitsPerLimb()
	wBits := quoSize + modBits + 1
	qBitsLowerBound := uint(f.api.Compiler().FieldBitLen()) - 1
	var remainingBits uint
	if wBits > qBitsLowerBound {
		remainingBits = wBits - qBitsLowerBound
	}
	nbLow := int((remainingBits + bpl - 1) / bpl)
	return max(0, min(nbLow, nbCarryLimbs))
}

// constrainCarryLimbs enforces the soundness bound on the given carry limbs.
// The check is a signed check: honest carries satisfy -2^bound <= c < 2^bound
// but are represented modulo the native field.
func (f *Field[T]) constrainCarryLimbs(carryLimbs []frontend.Variable, bound uint) {
	if len(carryLimbs) == 0 {
		return
	}
	// For a native modulus with bit length F and t-bit limbs, this ensures
	// 2^(t+bound+1) <= 2^(F-1) < q. Thus a coefficient difference which is
	// zero modulo q cannot hide a non-zero multiple of q over the integers.
	maxBits := f.maxCarryBits()
	if bound > maxBits {
		panic(fmt.Sprintf("emulated: carry bound %d bits exceeds soundness limit %d bits: reduce the inputs before the operation", bound, maxBits))
	}
	off := new(big.Int).Lsh(big.NewInt(1), bound)
	for i := range carryLimbs {
		f.rangeCheck(f.api.Add(carryLimbs[i], off), int(bound)+1)
	}
}

// callMulHint uses hint to compute r, k and c.
func (f *Field[T]) callMulHint(a, b *Element[T], isMulMod bool, customMod *Element[T]) (quo, rem, carries *Element[T], err error) {
	// compute the expected overflow after the multiplication of a*b to be able
	// to estimate the number of bits required to represent the result.
	nextOverflow := f.mulResultOverflow(a, b)
	// skip error handle - it happens when we are supposed to reduce. But we
	// already check it as a precondition. We only need the overflow here.
	if !isMulMod {
		// b is one on single limb. We do not increase the overflow
		nextOverflow = a.overflow
	}
	nbLimbs, nbBits := f.fParams.NbLimbs(), f.fParams.BitsPerLimb()
	// we need to compute the number of limbs for the quotient. To compute it,
	// we compute the width of the product of a*b, then we divide it by the
	// width of the modulus. We add 1 to the result to ensure that we have
	// enough space for the quotient.
	modbits := uint(f.fParams.Modulus().BitLen())
	if customMod != nil {
		// when we're using custom modulus, then we do not really know its
		// length ahead of time. We assume worst case scenario and assume that
		// the quotient can be the total length of the multiplication result.
		modbits = 0
	}
	var nbQuoLimbs uint
	if uint(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))*nbBits+nextOverflow+nbBits > modbits {
		// when the product of a*b is wider than the modulus, then we need
		// non-zero limbs for the quotient. Otherwise the quotient is zero,
		// represented on zero limbs. But we already handle cases when the
		// quotient is zero in the calling functions, this is only for
		// additional safety.
		nbQuoLimbs = (uint(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))*nbBits + nextOverflow + 1 - //
			modbits + //
			nbBits - 1) /
			nbBits
	}
	// the remainder is always less than modulus so can represent on the same
	// number of limbs as the modulus.
	nbRemLimbs := nbLimbs
	// we need to compute the number of limbs for the carries. It is maximum of
	// the number of limbs of the product of a*b or k*p.
	nbCarryLimbs := max(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)), nbMultiplicationResLimbs(int(nbQuoLimbs), int(nbLimbs))) - 1
	// we encode the computed parameters and widths to the hint function so can
	// know how many limbs to expect.
	modulusLimbs := f.Modulus().Limbs
	if customMod != nil {
		modulusLimbs = customMod.Limbs
	}
	hintInputs := make([]frontend.Variable, 0, 4+len(modulusLimbs)+len(a.Limbs)+len(b.Limbs))
	hintInputs = append(hintInputs, nbBits, nbLimbs, len(a.Limbs), nbQuoLimbs)
	hintInputs = append(hintInputs, modulusLimbs...)
	hintInputs = append(hintInputs, a.Limbs...)
	hintInputs = append(hintInputs, b.Limbs...)
	ret, err := f.api.NewHint(mulHint, int(nbQuoLimbs)+int(nbRemLimbs)+int(nbCarryLimbs), hintInputs...)
	if err != nil {
		err = fmt.Errorf("call hint: %w", err)
		return
	}
	// quotient is always range checked according to how many limbs we expect.
	quo = f.packLimbs(ret[:nbQuoLimbs], false)
	// remainder is always range checked when we use it as a result of
	// multiplication (and it needs to be strictly less than modulus). However,
	// when we use the hint for equality assertion then we assume the result to
	// be 0 which can be represented by 0 limbs.
	if isMulMod {
		rem = f.packLimbs(ret[nbQuoLimbs:nbQuoLimbs+nbRemLimbs], true)
	} else {
		rem = &Element[T]{}
	}
	// pack the carries into element. Used in the deferred multiplication check
	// to align the limbs due to different overflows.
	carries = f.newInternalElement(ret[nbQuoLimbs+nbRemLimbs:], 0)
	// The low carries provide the power-of-two half of a CRT certificate; the
	// committed random-point check provides the native-modulus half.
	bound := f.mulCarryBound(a, b, nextOverflow, nbQuoLimbs, modbits)
	nbLow := f.crtLowCarries(a, b, nbQuoLimbs, modbits, len(carries.Limbs))
	f.constrainCarryLimbs(carries.Limbs[:nbLow], bound)
	return
}

func mulHint(field *big.Int, inputs, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbALen := int(inputs[2].Int64())
	nbQuoLen := int(inputs[3].Int64())
	nbBLen := len(inputs) - 4 - nbLimbs - nbALen
	ptr := 4
	plimbs := inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	alimbs := inputs[ptr : ptr+nbALen]
	ptr += nbALen
	blimbs := inputs[ptr : ptr+nbBLen]

	nbCarryLen := max(nbMultiplicationResLimbs(nbALen, nbBLen), nbMultiplicationResLimbs(nbQuoLen, nbLimbs)) - 1
	outptr := 0
	quoLimbs := outputs[outptr : outptr+nbQuoLen]
	outptr += nbQuoLen
	remLimbs := outputs[outptr : outptr+nbLimbs]
	outptr += nbLimbs
	carryLimbs := outputs[outptr : outptr+nbCarryLen]

	var (
		p = bigIntPool.Get().(*big.Int)
		a = bigIntPool.Get().(*big.Int)
		b = bigIntPool.Get().(*big.Int)
	)
	defer bigIntPool.Put(p)
	defer bigIntPool.Put(a)
	defer bigIntPool.Put(b)
	if err := limbs.Recompose(plimbs, uint(nbBits), p); err != nil {
		return fmt.Errorf("recompose p: %w", err)
	}
	if err := limbs.Recompose(alimbs, uint(nbBits), a); err != nil {
		return fmt.Errorf("recompose a: %w", err)
	}
	if err := limbs.Recompose(blimbs, uint(nbBits), b); err != nil {
		return fmt.Errorf("recompose b: %w", err)
	}
	quo := bigIntPool.Get().(*big.Int)
	rem := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(quo)
	defer bigIntPool.Put(rem)
	quo.SetInt64(0)
	rem.SetInt64(0)
	ab := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(ab)
	ab.Mul(a, b)
	if p.Sign() != 0 {
		quo.QuoRem(ab, p, rem)
	}
	if err := limbs.Decompose(quo, uint(nbBits), quoLimbs); err != nil {
		return fmt.Errorf("decompose quo: %w", err)
	}
	if err := limbs.Decompose(rem, uint(nbBits), remLimbs); err != nil {
		return fmt.Errorf("decompose rem: %w", err)
	}
	// to compute the carries, we need to perform multiplication on limbs
	lhs := limbMul(alimbs, blimbs)
	rhs := limbMul(quoLimbs, plimbs)
	// add the remainder to the rhs, it now only has k*p. This is only for very
	// edge cases where by adding the remainder we get additional bits in the
	// carry.
	for i := range remLimbs {
		if i < len(rhs) {
			rhs[i].Add(rhs[i], remLimbs[i])
		} else {
			remLimb := bigIntPool.Get().(*big.Int)
			defer bigIntPool.Put(remLimb)
			remLimb.Set(remLimbs[i])
			rhs = append(rhs, remLimb)
		}
	}
	carry := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(carry)
	carry.SetInt64(0)
	for i := range carryLimbs {
		if i < len(lhs) {
			carry.Add(carry, lhs[i])
		}
		if i < len(rhs) {
			carry.Sub(carry, rhs[i])
		}
		carry.Rsh(carry, uint(nbBits))
		carryLimbs[i].Set(carry)
	}
	return nil
}

// Mul computes a*b. Depending on the emulated field it either reduces the result
// modulo the field order or returns the full product.
//
// When emulating large field, the uses reducing multiplication by default.
//
// If the field is small (fits into single limb), then it uses non-reducing
// multiplication by default for efficiency. It only falls back to reducing
// multiplication when the overflow of the result would be too large.
//
// Doesn't mutate inputs.
//
// For multiplying by a constant, use [Field[T].MulConst] method which is more
// efficient.
func (f *Field[T]) Mul(a, b *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	if f.useSmallFieldOptimization() {
		// for small fields, it is more efficient to use non-reducing multiplication by default
		// we only fall back to reducing multiplication when modular reduction is necessary
		// to reduce the overflow
		return f.reduceAndOp(f.mulNoReduce, f.mulPreCondNoReduce, a, b)
	}
	return f.reduceAndOp(func(a, b *Element[T], u uint) *Element[T] { return f.mulMod(a, b, u, nil) }, f.mulPreCondReduced, a, b)
}

// MulMod computes a*b and reduces it modulo the field order. The returned Element
// has default number of limbs and zero overflow.
//
// Equivalent to [Field[T].Mul], kept for backwards compatibility.
func (f *Field[T]) MulMod(a, b *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	return f.reduceAndOp(func(a, b *Element[T], u uint) *Element[T] { return f.mulMod(a, b, u, nil) }, f.mulPreCondReduced, a, b)
}

// MulConst multiplies a by a constant c and returns it. We assume that the
// input constant is "small", so that we can compute the product by multiplying
// all individual limbs with the constant. If it is not small, then use the
// general [Field[T].Mul] or [Field[T].MulMod] with creating new Element from
// the constant on-the-fly.
func (f *Field[T]) MulConst(a *Element[T], c *big.Int) *Element[T] {
	if a.isStrictZero() {
		return f.Zero()
	}
	switch c.Sign() {
	case -1:
		return f.MulConst(f.Neg(a), new(big.Int).Neg(c))
	case 0:
		return f.Zero()
	}
	cbl := uint(c.BitLen())
	if cbl > f.maxOverflow() {
		panic(fmt.Sprintf("constant bit length %d exceeds max %d", cbl, f.maxOverflow()))
	}
	return f.reduceAndOp(
		func(a, _ *Element[T], u uint) *Element[T] {
			if ba, aConst := f.constantValue(a); aConst {
				ba.Mul(ba, c)
				return newConstElement[T](f.api.Compiler().Field(), ba, false)
			}
			limbs := make([]frontend.Variable, len(a.Limbs))
			for i := range a.Limbs {
				limbs[i] = f.api.Mul(a.Limbs[i], c)
			}
			return f.newInternalElement(limbs, a.overflow+cbl)
		},
		func(a, _ *Element[T]) (nextOverflow uint, err error) {
			nextOverflow = a.overflow + uint(cbl)
			if nextOverflow > f.maxOverflow() {
				err = overflowError{op: "mulConst", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow()}
			}
			return
		},
		a, nil,
	)
}

// mulResultOverflow computes the maximum overflow of the limbwise
// multiplications of a*b. This is used to determine whether the multiplication
// can be safely performed without exceeding the field limits.
func (f *Field[T]) mulResultOverflow(a, b *Element[T]) (overflow uint) {
	nbResLimbs := nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs))
	nbLimbsOverflow := uint(1)
	if nbResLimbs > 0 {
		nbLimbsOverflow = uint(bits.Len(uint(nbResLimbs)))
	}
	overflow = f.fParams.BitsPerLimb() + nbLimbsOverflow + a.overflow + b.overflow
	return overflow
}

// mulPreCondReduced is a precondition to check if the multiplication a*b can be safely
// checked, assuming the result will be reduced modulo the field order.
//
// As the result and quotient will be reduced (overflow=0), then this condition checks that
// only the carries can fit into the native field.
func (f *Field[T]) mulPreCondReduced(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nextOverflow = f.mulResultOverflow(a, b)
	// Use the actual per-call carry estimate instead of translating it into a
	// coarse overflow threshold. Assuming a full-length quotient is the worst
	// case for both fixed and variable moduli.
	carryBound := f.mulCarryBound(a, b, nextOverflow, f.fParams.NbLimbs(), 0)
	if carryBound > f.maxOverflowReducedResult() {
		err = overflowError{op: "mul", nextOverflow: carryBound, maxOverflow: f.maxOverflowReducedResult(), reduceRight: reduceRight}
	}
	return
}

// mulPreCondNoReduce is a precondition to check if the multiplication a*b can be safely
// checked, assuming the result will NOT be reduced modulo the field order.
//
// As the result will not be reduced, then we need to ensure that the full
// multiplication result can fit into the native field.
func (f *Field[T]) mulPreCondNoReduce(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nextOverflow = f.mulResultOverflow(a, b)
	if nextOverflow > f.maxOverflow() {
		err = overflowError{op: "mulNoReduce", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

// MulNoReduce computes a*b and returns the result without reducing it modulo
// the field order. The number of limbs of the returned element depends on the
// number of limbs of the inputs.
func (f *Field[T]) MulNoReduce(a, b *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	return f.reduceAndOp(f.mulNoReduce, f.mulPreCondNoReduce, a, b)
}

func (f *Field[T]) mulNoReduce(a, b *Element[T], nextoverflow uint) *Element[T] {
	// fast path - constant multiplication stays constant even on the
	// non-reducing path, so avoid growing overflow on a value the compiler can
	// still recognize as constant.
	if ba, aConst := f.constantValue(a); aConst {
		if bb, bConst := f.constantValue(b); bConst {
			ba.Mul(ba, bb).Mod(ba, f.fParams.Modulus())
			return newConstElement[T](f.api.Compiler().Field(), ba, false)
		}
	}
	resLimbs := make([]frontend.Variable, nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))
	for i := range resLimbs {
		resLimbs[i] = 0
	}
	for i := range a.Limbs {
		for j := range b.Limbs {
			resLimbs[i+j] = f.api.MulAcc(resLimbs[i+j], a.Limbs[i], b.Limbs[j])
		}
	}
	profile.RecordOperation("emulated.MulNoReduce", 2*len(resLimbs))
	return f.newInternalElement(resLimbs, nextoverflow)
}

// Exp computes base^exp modulo the field order. The returned Element has default
// number of limbs and zero overflow.
//
// The implementation uses windowed exponentiation with window size 4, which
// reduces the number of multiplications compared to binary square-and-multiply.
func (f *Field[T]) Exp(base, exp *Element[T]) *Element[T] {
	// fast path - if the base is zero, then the result is also zero
	if base.isStrictZero() {
		return f.Zero()
	}

	const windowSize = 4
	const tableSize = 1 << windowSize // 16

	// Build precomputation table: table[i] = base^i for i in [0, 2^windowSize)
	table := make([]*Element[T], tableSize)
	table[0] = f.One()
	table[1] = base
	for i := 2; i < tableSize; i++ {
		table[i] = f.MulMod(table[i-1], base)
	}

	// Get exponent bits (LSB first). The exponent is reduced strictly first:
	// ToBits decomposes the raw limb value, so a non-canonical representation
	// (exp vs exp+p, both valid post-Reduce) would decompose to different bits
	// and produce a different result g^(exp+p) for a circuit whose public
	// statement is about g^exp — a malleability hole for any circuit that
	// exponentiates a witness-controlled exponent.
	expBts := f.ToBits(f.ReduceStrict(exp))
	n := len(expBts)

	// Pad to multiple of windowSize
	padding := (windowSize - (n % windowSize)) % windowSize
	paddedLen := n + padding

	// Process windows from MSB to LSB
	// expBts is LSB-first, so expBts[n-1] is MSB
	numWindows := paddedLen / windowSize

	// Initialize result with table lookup for the MSB window
	// MSB window (window 0) covers bits [(numWindows-1)*windowSize, numWindows*windowSize-1]
	// in the padded representation. Bits at indices >= n are padding zeros.
	msbWindowBits := make([]frontend.Variable, windowSize)
	msbBaseIdx := (numWindows - 1) * windowSize
	for i := 0; i < windowSize; i++ {
		actualIdx := msbBaseIdx + i
		if actualIdx < n {
			msbWindowBits[i] = expBts[actualIdx]
		} else {
			msbWindowBits[i] = 0
		}
	}
	res := f.tableLookup(table, msbWindowBits)

	// Process remaining windows
	for w := 1; w < numWindows; w++ {
		// Square windowSize times
		for i := 0; i < windowSize; i++ {
			res = f.Mul(res, res)
		}

		// Extract window bits for this window
		// Window w covers bits from position (numWindows-1-w)*windowSize to (numWindows-w)*windowSize - 1
		// In the original LSB-first array
		windowBits := make([]frontend.Variable, windowSize)
		baseIdx := (numWindows - 1 - w) * windowSize
		for i := 0; i < windowSize; i++ {
			windowBits[i] = expBts[baseIdx+i]
		}

		// Table lookup and multiply
		selected := f.tableLookup(table, windowBits)
		res = f.Mul(res, selected)
	}

	return res
}

// multivariate represents a multivariate polynomial. It is a list of terms
// where each term is a list of exponents for each variable. The coefficients
// are stored in the same order as the terms.
//
// For example, if there are two inputs x and y and we compute the polynomial
//
//	x^2 + 2xy + y^2
//
// then we have the terms
//
//	[[2, 0], [1, 1], [0, 2]]
//
// and coefficients
//
//	[1, 1, 1].
//
// These definitions differ from how we expose the method in the [Field.Eval]
// method - there as we use pointers to the variables themselves, then we can
// allow to give the inputs directly a la
//
//	f.Eval([][]*Element[T]{{x,x}, {x,y}, {y,y}}, []int{1, 1, 1}),
//
// but we cannot use the references inside the hint function as we work with
// solved values.
type multivariate[T FieldParams] struct {
	Terms        [][]int
	Coefficients []int
}

// Eval evaluates the multivariate polynomial. The elements of the inner slices
// are multiplied together and then summed together with the corresponding
// coefficient.
//
// NB! This is experimental API. It does not check that computing the term
// wouldn't overflow the field.
//
// For example, for computing the expression x^2 + 2xy + y^2 we would call
//
//	f.Eval([][]*Element[T]{{x,x}, {x,y}, {y,y}}, []int{1, 2, 1})
//
// The method returns the result of the evaluation.
func (f *Field[T]) Eval(at [][]*Element[T], coefs []int) *Element[T] {
	// it is the obvious case - when we don't have any inputs then we need to
	// evaluate the zero polynomial which is always zero.
	if len(at) == 0 && len(coefs) == 0 {
		return f.Zero()
	}
	mv, allElems := f.polyMvPrep(at, coefs)

	// A high-degree identity may have coefficients wider than the native field
	// even when every input is reduced. Evaluate it through ordinary reduced
	// multiplications, each of which has a sound carry bound.
	if f.polyMvCarryBound(mv, allElems) > f.maxCarryBits() {
		return f.evalByMul(mv, allElems)
	}

	// we call the hint to compute the result. The hint returns the reduced
	// result, the quotient and the carries.
	k, r, c, kNeg, err := f.callPolyMvHint(mv, allElems, false)
	if err != nil {
		panic(err)
	}

	// finally, we store the deferred check which is performed later. The
	// `mvCheck` implements the deferredChecker interface, so that we use the
	// generic deferred check method.
	mvc := mvCheck[T]{
		f:    f,
		mv:   mv,
		vals: allElems,
		r:    r,
		k:    k,
		c:    c,
		kNeg: kNeg,
	}

	f.deferredChecks = append(f.deferredChecks, &mvc)

	// Record operation for profiling
	nbLimbs := 0
	for i := range allElems {
		nbLimbs += len(allElems[i].Limbs)
	}
	nbLimbs += len(r.Limbs) + len(k.Limbs) + len(c.Limbs)
	profile.RecordOperation("emulated.Eval", nbLimbs)
	return r
}

// AssertEvalIsZero asserts that the multivariate polynomial given by the terms
// at and coefficients coefs evaluates to zero modulo the field modulus. The
// interface is as in [Field.Eval]: the elements of the inner slices of at are
// multiplied together and summed with the corresponding coefficient.
//
// It is functionally equivalent to asserting that the result of [Field.Eval]
// is zero, but it is cheaper: the reduced remainder is never materialized as a
// witness (saving its allocation and range checks) and no separate equality
// check is needed.
//
// NB! This is experimental API. It does not check that computing the term
// wouldn't overflow the field.
func (f *Field[T]) AssertEvalIsZero(at [][]*Element[T], coefs []int) {
	// zero polynomial is always zero
	if len(at) == 0 && len(coefs) == 0 {
		return
	}
	mv, allElems := f.polyMvPrep(at, coefs)

	// A high-degree identity may have coefficients wider than the native field
	// even when every input is reduced. Evaluate it through ordinary reduced
	// multiplications (each with a sound carry bound) and assert the result is
	// zero, instead of a single unbounded deferred check.
	if f.polyMvCarryBound(mv, allElems) > f.maxCarryBits() {
		f.AssertIsEqual(f.evalByMul(mv, allElems), f.Zero())
		return
	}

	// we call the hint to compute the quotient and the carries. As the
	// remainder is asserted to be zero, the hint does not return it and we use
	// the zero-limb constant zero element in the deferred check instead.
	k, _, c, kNeg, err := f.callPolyMvHint(mv, allElems, true)
	if err != nil {
		panic(err)
	}

	mvc := mvCheck[T]{
		f:    f,
		mv:   mv,
		vals: allElems,
		r:    f.Zero(), // constant zero on zero limbs
		k:    k,
		c:    c,
		kNeg: kNeg,
	}

	f.deferredChecks = append(f.deferredChecks, &mvc)

	// Record operation for profiling
	nbLimbs := 0
	for i := range allElems {
		nbLimbs += len(allElems[i].Limbs)
	}
	nbLimbs += len(k.Limbs) + len(c.Limbs)
	profile.RecordOperation("emulated.AssertEvalIsZero", nbLimbs)
}

// polyMvPrep prepares the multivariate polynomial evaluation of the terms at
// with coefficients coefs: it deduplicates the elements appearing in the
// terms, converts the terms into exponent form and ensures that all elements
// have their limb widths enforced.
func (f *Field[T]) polyMvPrep(at [][]*Element[T], coefs []int) (*multivariate[T], []*Element[T]) {
	if len(at) != len(coefs) {
		panic("terms and coefficients mismatch")
	}
	for _, c := range coefs {
		if c == math.MinInt {
			panic("coefficient math.MinInt overflows on negation")
		}
	}
	// initialize the multivariate struct from the inputs. The current method
	// takes as input references to the elements. However, the hint function
	// works with solved values. So it would be better to work with the exact
	// exponents there.

	// we detect all different elements in the inputs.
	//
	// it would be easier to use a map to store the elements and then use the
	// map to get the inputs in the right order. However, for deterministic
	// circuit compilation we need to use the same order of inputs. So we use
	// slice instead.
	var allElems []*Element[T]
	for i := range at {
	AT_INNER:
		for j := range at[i] {
			for k := range allElems {
				if allElems[k] == at[i][j] {
					continue AT_INNER
				}
			}
			allElems = append(allElems, at[i][j])
		}
	}
	// we already know all different inputs. We now count the number of
	// occurrences in every term.
	terms := make([][]int, 0, len(at))
	for i := range at {
		term := make([]int, len(allElems))
		for j := range at[i] {
			term[slices.Index(allElems, at[i][j])]++
		}
		terms = append(terms, term)
	}

	// ensure that all the elements have the range checks enforced on limbs.
	// Necessary in case the input is a witness.
	for i := range allElems {
		f.enforceWidthConditional(allElems[i])
	}

	// multivariate is used for passing the terms and coefficients to the hint
	// in a compact form.
	mv := &multivariate[T]{
		Terms:        terms,
		Coefficients: coefs,
	}
	// Reduce lazy inputs until their overflow no longer pushes the carry above
	// the ordinary carry budget. Higher-degree expressions may have a larger
	// irreducible bound even with fully reduced inputs; the final soundness cap
	// is enforced by constrainCarryLimbs.
	for f.polyMvCarryBound(mv, allElems) > maxLazyOverflow {
		toReduce := -1
		for i := range allElems {
			if allElems[i].overflow > 0 && (toReduce == -1 || allElems[i].overflow > allElems[toReduce].overflow) {
				toReduce = i
			}
		}
		if toReduce == -1 {
			break
		}
		allElems[toReduce] = f.Reduce(allElems[toReduce])
	}
	return mv, allElems
}

// evalByMul evaluates mv using ordinary emulated operations. It is the
// soundness fallback for polynomial identities whose coefficients do not admit
// a bounded integer lift in the native field.
func (f *Field[T]) evalByMul(mv *multivariate[T], at []*Element[T]) *Element[T] {
	res := f.Zero()
	for i, powers := range mv.Terms {
		coef := mv.Coefficients[i]
		if coef == 0 {
			continue
		}

		var term *Element[T]
		for j, power := range powers {
			for range power {
				if term == nil {
					term = at[j]
				} else {
					term = f.Mul(term, at[j])
				}
			}
		}
		if term == nil {
			term = f.One()
		}

		// multiply in the coefficient. [Field.MulConst] folds it into the limbs
		// without creating a multiplication check and handles the sign itself,
		// but it only accepts constants fitting the overflow budget.
		c := big.NewInt(int64(coef))
		switch {
		case coef == 1:
			// nothing to multiply in
		case coef == -1:
			term = f.Neg(term)
		case uint(c.BitLen()) <= f.maxOverflow():
			term = f.MulConst(term, c)
		default:
			// the coefficient is too wide to fold into the limbs, fall back to a
			// general multiplication by a constant element.
			term = f.Mul(term, newConstElement[T](f.api.Compiler().Field(), new(big.Int).Abs(c), false))
			if coef < 0 {
				term = f.Neg(term)
			}
		}
		res = f.Add(res, term)
	}
	return f.Reduce(res)
}

// callPolyMvHint computes the multivariate evaluation given by mv at at. It
// returns the remainder (reduced result), the quotient and the carries. The
// computation is performed inside a hint, so it is the callers responsibility to
// perform the deferred multiplication check.
//
// When assertZero is set, the evaluation is asserted to be zero modulo the
// field modulus: the hint does not output the remainder limbs (the returned
// rem is the zero-limb constant zero) and it errors at solving time if the
// evaluation is not divisible by the modulus.
func (f *Field[T]) callPolyMvHint(mv *multivariate[T], at []*Element[T], assertZero bool) (quo, rem, carries *Element[T], kNeg frontend.Variable, err error) {
	// first compute the length of the result so that we know how many bits we need for the quotient.
	nbLimbs, nbBits := f.fParams.NbLimbs(), f.fParams.BitsPerLimb()
	modBits := uint(f.fParams.Modulus().BitLen())
	quoSize := f.polyMvEvalQuoSize(mv, at)
	var nbQuoLimbs uint
	if quoSize+nbBits > modBits {
		nbQuoLimbs = (quoSize - modBits + nbBits) / nbBits
	}
	nbRemLimbs := nbLimbs
	if assertZero {
		nbRemLimbs = 0
	}
	nbCarryLimbs := nbMultiplicationResLimbs(int(nbQuoLimbs), int(nbLimbs)) - 1

	nbHintInputs := 7 + len(mv.Coefficients) + len(at)*len(mv.Terms) + len(mv.Coefficients) + len(f.Modulus().Limbs)
	for i := range at {
		nbHintInputs += len(at[i].Limbs) + 1
	}
	hintInputs := make([]frontend.Variable, 0, nbHintInputs)
	hintInputs = append(hintInputs, nbBits, nbLimbs, len(mv.Terms), len(at), nbQuoLimbs, nbRemLimbs, nbCarryLimbs)
	// store per-coefficient signs: 0 = positive, 1 = negative
	for _, c := range mv.Coefficients {
		if c < 0 {
			hintInputs = append(hintInputs, 1)
		} else {
			hintInputs = append(hintInputs, 0)
		}
	}
	// store the terms in the hint input. First the exponents
	for i := range mv.Terms {
		for j := range mv.Terms[i] {
			hintInputs = append(hintInputs, mv.Terms[i][j])
		}
	}
	// and now the coefficients (absolute values)
	for i := range mv.Coefficients {
		c := mv.Coefficients[i]
		if c < 0 {
			c = -c
		}
		hintInputs = append(hintInputs, c)
	}
	// finally, we store the modulus and all the inputs
	hintInputs = append(hintInputs, f.Modulus().Limbs...)
	for i := range at {
		// keep in mind that not all inputs may be full length. We need to store
		// the length also.
		hintInputs = append(hintInputs, len(at[i].Limbs))
		hintInputs = append(hintInputs, at[i].Limbs...)
	}
	nbOutputs := int(nbQuoLimbs) + int(nbRemLimbs) + int(nbCarryLimbs) + 1
	ret, err := f.api.NewHint(polyMvHint, nbOutputs, hintInputs...)
	if err != nil {
		err = fmt.Errorf("call hint: %w", err)
		return
	}
	quo = f.packLimbs(ret[:nbQuoLimbs], false)
	if assertZero {
		rem = f.Zero()
	} else {
		rem = f.packLimbs(ret[nbQuoLimbs:nbQuoLimbs+nbRemLimbs], true)
	}
	carries = f.newInternalElement(ret[nbQuoLimbs+nbRemLimbs:nbQuoLimbs+nbRemLimbs+uint(nbCarryLimbs)], 0)
	// As in multiplication, only the low carries needed for the power-of-two
	// half of the CRT certificate need individual range checks.
	bound := f.mvCarryBound(mv, at, nbQuoLimbs, modBits, quoSize)
	nbLow := f.mvLowCarries(quoSize, modBits, int(nbCarryLimbs))
	f.constrainCarryLimbs(carries.Limbs[:nbLow], bound)
	kNeg = ret[nbQuoLimbs+nbRemLimbs+uint(nbCarryLimbs)]
	f.api.AssertIsBoolean(kNeg)
	return quo, rem, carries, kNeg, nil
}

func (f *Field[T]) polyMvCarryBound(mv *multivariate[T], at []*Element[T]) uint {
	nbBits := f.fParams.BitsPerLimb()
	modBits := uint(f.fParams.Modulus().BitLen())
	quoSize := f.polyMvEvalQuoSize(mv, at)
	var nbQuoLimbs uint
	if quoSize+nbBits > modBits {
		nbQuoLimbs = (quoSize - modBits + nbBits) / nbBits
	}
	return f.mvCarryBound(mv, at, nbQuoLimbs, modBits, quoSize)
}

// mvCheck is a deferred check for multivariate polynomial evaluation. It
// contains the multivariate polynomial, the values at which it is evaluated and
// the reduced result, quotient and carries. Implements deferredChecker and
// follows mulCheck implementation.
type mvCheck[T FieldParams] struct {
	f    *Field[T]
	mv   *multivariate[T]
	vals []*Element[T]
	r    *Element[T]       // reduced result
	k    *Element[T]       // quotient (absolute value)
	c    *Element[T]       // carry
	kNeg frontend.Variable // 1 if quotient is negative, 0 otherwise
}

func (mc *mvCheck[T]) toCommit() []frontend.Variable {
	nbToCommit := len(mc.r.Limbs) + len(mc.k.Limbs) + len(mc.c.Limbs) + 1
	for j := range mc.vals {
		nbToCommit += len(mc.vals[j].Limbs)
	}
	toCommit := make([]frontend.Variable, 0, nbToCommit)
	toCommit = append(toCommit, mc.r.Limbs...)
	toCommit = append(toCommit, mc.k.Limbs...)
	toCommit = append(toCommit, mc.c.Limbs...)
	toCommit = append(toCommit, mc.kNeg)
	for j := range mc.vals {
		toCommit = append(toCommit, mc.vals[j].Limbs...)
	}
	return toCommit
}

func (mc *mvCheck[T]) maxLen() int {
	maxLen := len(mc.r.Limbs)
	maxLen = max(maxLen, len(mc.k.Limbs))
	maxLen = max(maxLen, len(mc.c.Limbs))
	for j := range mc.vals {
		maxLen = max(maxLen, len(mc.vals[j].Limbs))
	}
	return maxLen
}

func (mc *mvCheck[T]) evalRound1(at []frontend.Variable) {
	mc.c = mc.f.evalWithChallenge(mc.c, at)
	mc.r = mc.f.evalWithChallenge(mc.r, at)
	mc.k = mc.f.evalWithChallenge(mc.k, at)
}

func (mc *mvCheck[T]) evalRound2(at []frontend.Variable) {
	for i := range mc.vals {
		mc.vals[i] = mc.f.evalWithChallenge(mc.vals[i], at)
	}
}

// check checks that the multivariate polynomial f(x1(ch), x2(ch), ...) = r(ch)
// + k(ch)*p(ch) + (2^t-ch) c(ch) holds. As p and (2^t-ch) are same over all
// checks then we get them as arguments to this method.
func (mc *mvCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	// we either have to perform the equality check in the native field or in
	// the extension field. It was already determined at the [Field]
	// initialization time which kind of check needs to be done.
	//
	// The hint returns |k| and a boolean kNeg ∈ {0,1} indicating whether the
	// quotient is negative. We define the sign factor s = 1 - 2·kNeg which
	// maps kNeg=0 → s=1 (positive quotient) and kNeg=1 → s=-1 (negative
	// quotient). The checked equation is then:
	//
	//   lhs(ch) = r(ch) + s·|k(ch)|·p(ch) + (2^t - ch)·c(ch)
	if mc.f.extensionApi == nil {
		ls := frontend.Variable(0)
		for i, term := range mc.mv.Terms {
			termProd := frontend.Variable(mc.mv.Coefficients[i])
			for i, pow := range term {
				for j := 0; j < pow; j++ {
					termProd = api.Mul(termProd, mc.vals[i].evaluation)
				}
			}
			ls = api.Add(ls, termProd)
		}
		kp := api.Mul(mc.k.evaluation, peval)
		s := api.Sub(1, api.Mul(2, mc.kNeg))
		rs := api.Add(mc.r.evaluation, api.Mul(s, kp), api.Mul(mc.c.evaluation, coef))
		api.AssertIsEqual(ls, rs)
	} else {
		// here we use the fact that [frontend.Variable] is defined as any, but
		// we have actually provided [ExtensionVariable]. We type assert to be
		// able to use the fieldextension API.
		//
		// the computations are same as in the previous conditional block, but
		// only in the extension.
		ls := mc.f.extensionApi.Zero()
		for i, term := range mc.mv.Terms {
			termProd := mc.f.extensionApi.AsExtensionVariable(mc.mv.Coefficients[i])
			for i, pow := range term {
				for j := 0; j < pow; j++ {
					valsexti := mc.vals[i].evaluation.(fieldextension.Element)
					termProd = mc.f.extensionApi.Mul(termProd, valsexti)
				}
			}
			ls = mc.f.extensionApi.Add(ls, termProd)
		}
		rext := mc.r.evaluation.(fieldextension.Element)
		pevalext := peval.(fieldextension.Element)
		kext := mc.k.evaluation.(fieldextension.Element)
		cext := mc.c.evaluation.(fieldextension.Element)
		coefext := coef.(fieldextension.Element)

		kpext := mc.f.extensionApi.Mul(pevalext, kext)
		sext := mc.f.extensionApi.AsExtensionVariable(api.Sub(1, api.Mul(2, mc.kNeg)))

		ccoefext := mc.f.extensionApi.Mul(coefext, cext)
		rs := mc.f.extensionApi.Add(rext, mc.f.extensionApi.Mul(sext, kpext))
		rs = mc.f.extensionApi.Add(rs, ccoefext)

		mc.f.extensionApi.AssertIsEqual(ls, rs)
	}
}

func (mc *mvCheck[T]) cleanEvaluations() {
	for i := range mc.vals {
		mc.vals[i].evaluation = 0
		mc.vals[i].isEvaluated = false
	}
	mc.r.evaluation = 0
	mc.r.isEvaluated = false
	mc.k.evaluation = 0
	mc.k.isEvaluated = false
	mc.c.evaluation = 0
	mc.c.isEvaluated = false
}

// polyMvEvalQuoSize compute the length of the quotient in bits when evaluating
// the multivariate polynomial. The method is used to compute the number of bits
// required to represent the quotient in the hint function.
//
// As it only depends on the bit-length of the inputs, then we can precompute it
// regardless of the actual values.
func (f *Field[T]) polyMvEvalQuoSize(mv *multivariate[T], at []*Element[T]) (quoSize uint) {
	if len(mv.Terms) == 0 {
		return 0
	}
	quoSizes := make([]uint, len(mv.Terms))
	for i, term := range mv.Terms {
		// for every term, the result length is the sum of the lengths of the
		// variables and the coefficient.
		var lengths []uint
		for j, pow := range term {
			for k := 0; k < pow; k++ {
				lengths = append(lengths, uint(len(at[j].Limbs))*f.fParams.BitsPerLimb()+at[j].overflow)
			}
		}
		coef := mv.Coefficients[i]
		if coef < 0 {
			coef = -coef
		}
		lengths = append(lengths, uint(bits.Len(uint(coef))))
		if lengthSum := sum(lengths...); lengthSum > 0 {
			// in edge case when inputs are zeros and coefficient is zero, we
			// would have a underflow otherwise.
			quoSizes[i] = lengthSum - 1
		}
	}
	// and for the full result, it is maximum of the inputs. We also add a bit
	// for every term for overflow.
	quoSize = slices.Max(quoSizes) + uint(len(quoSizes))
	return quoSize
}

// polyMvHint computes the multivariate evaluation as a hint. Should not be
// called directly, but rather through [Field.callPolyMvHint] method which
// handles the input packing and output unpacking.
func polyMvHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 8 {
		return errors.New("not enough inputs")
	}
	var (
		nbBits       = int(inputs[0].Int64())
		nbLimbs      = int(inputs[1].Int64())
		nbTerms      = int(inputs[2].Int64())
		nbVars       = int(inputs[3].Int64())
		nbQuoLimbs   = int(inputs[4].Int64())
		nbRemLimbs   = int(inputs[5].Int64())
		nbCarryLimbs = int(inputs[6].Int64())
	)
	// nbRemLimbs == 0 indicates that the caller asserts the evaluation to be
	// zero modulo the modulus: no remainder limbs are output and a non-zero
	// remainder is a solving error.
	if len(outputs) != nbQuoLimbs+nbRemLimbs+nbCarryLimbs+1 {
		return errors.New("output length mismatch")
	}
	outPtr := 0
	quoLimbs := outputs[outPtr : outPtr+nbQuoLimbs]
	outPtr += nbQuoLimbs
	remLimbs := outputs[outPtr : outPtr+nbRemLimbs]
	outPtr += nbRemLimbs
	carryLimbs := outputs[outPtr : outPtr+nbCarryLimbs]
	outPtr += nbCarryLimbs
	kNegOut := outputs[outPtr]
	// read per-coefficient signs: 0 = positive, 1 = negative
	ptr := 7
	signs := make([]int, nbTerms)
	for i := range signs {
		signs[i] = int(inputs[ptr].Int64())
		ptr++
	}
	terms := make([][]int, nbTerms)
	// read the terms
	for i := range terms {
		terms[i] = make([]int, nbVars)
		for j := range terms[i] {
			terms[i][j] = int(inputs[ptr].Int64())
			ptr++
		}
	}
	// read the coefficients (absolute values from hint inputs)
	coeffs := make([]*big.Int, nbTerms)
	for i := range coeffs {
		coeffs[i] = inputs[ptr]
		ptr++
	}
	// read the modulus
	plimbs := inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	p := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(p)
	if err := limbs.Recompose(plimbs, uint(nbBits), p); err != nil {
		return fmt.Errorf("recompose p: %w", err)
	}
	// read the inputs
	varsLimbs := make([][]*big.Int, nbVars)
	for i := range varsLimbs {
		varsLimbs[i] = make([]*big.Int, int(inputs[ptr].Int64()))
		ptr++
		for j := range varsLimbs[i] {
			varsLimbs[i][j] = inputs[ptr]
			ptr++
		}
	}
	if ptr != len(inputs) {
		return errors.New("inputs not exhausted")
	}
	// recompose the inputs in limb-form to *big.Int form
	vars := make([]*big.Int, nbVars)
	for i := range vars {
		vars[i] = bigIntPool.Get().(*big.Int)
		defer bigIntPool.Put(vars[i]) // recall defer is function level, not scope level
		if err := limbs.Recompose(varsLimbs[i], uint(nbBits), vars[i]); err != nil {
			return fmt.Errorf("recompose vars[%d]: %w", i, err)
		}
	}

	// compute the result on full inputs
	fullLhs := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(fullLhs)
	fullLhs.SetInt64(0)
	termRes := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(termRes)
	for i, term := range terms {
		termRes.Set(coeffs[i])
		for i, pow := range term {
			for j := 0; j < pow; j++ {
				termRes.Mul(termRes, vars[i])
			}
		}
		if signs[i] != 0 {
			fullLhs.Sub(fullLhs, termRes)
		} else {
			fullLhs.Add(fullLhs, termRes)
		}
	}

	// compute the result as r + k*p using Euclidean division (r >= 0)
	var (
		quo = bigIntPool.Get().(*big.Int)
		rem = bigIntPool.Get().(*big.Int)
	)
	defer bigIntPool.Put(rem)
	defer bigIntPool.Put(quo)
	quo.SetInt64(0)
	rem.SetInt64(0)
	if p.Sign() != 0 {
		quo.DivMod(fullLhs, p, rem)
	}
	// if quotient is negative, output |k| and set kNeg = 1
	var kNegVal int
	if quo.Sign() < 0 {
		kNegVal = 1
		quo.Neg(quo)
	}
	kNegOut.SetInt64(int64(kNegVal))
	// write the remainder and quotient to output
	if err := limbs.Decompose(quo, uint(nbBits), quoLimbs); err != nil {
		return fmt.Errorf("decompose quo: %w", err)
	}
	if nbRemLimbs == 0 {
		// the caller asserts the evaluation to be zero modulo the modulus. A
		// non-zero remainder means the assertion cannot be satisfied.
		if rem.Sign() != 0 {
			return errors.New("asserted zero evaluation has non-zero remainder")
		}
	} else if err := limbs.Decompose(rem, uint(nbBits), remLimbs); err != nil {
		return fmt.Errorf("decompose rem: %w", err)
	}

	// compute the result on limbs
	tmp := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(tmp)
	var lhs []*big.Int
	for i, term := range terms {
		// collect the variables to be multiplied together
		var termVarLimbs [][]*big.Int
		for i, pow := range term {
			for j := 0; j < pow; j++ {
				termVarLimbs = append(termVarLimbs, varsLimbs[i])
			}
		}
		termRes := []*big.Int{bigIntPool.Get().(*big.Int).Set(coeffs[i])}
		defer bigIntPool.Put(termRes[0])
		// perform limbwise multiplication
		for _, toMul := range termVarLimbs {
			termRes = limbMul(termRes, toMul)
		}
		// add current term to the result. Increase the length of necessary when
		// required.
		for j := len(lhs); j < len(termRes); j++ {
			sfx := bigIntPool.Get().(*big.Int)
			defer bigIntPool.Put(sfx)
			sfx.SetInt64(0)
			lhs = append(lhs, sfx)
		}
		if signs[i] != 0 {
			for j := range termRes {
				lhs[j].Sub(lhs[j], termRes[j])
			}
		} else {
			for j := range termRes {
				lhs[j].Add(lhs[j], termRes[j])
			}
		}
	}

	// compute k*p on limbs
	kpLimbs := make([]*big.Int, max(1, nbMultiplicationResLimbs(nbQuoLimbs, nbLimbs)))
	for i := range kpLimbs {
		kpLimbs[i] = bigIntPool.Get().(*big.Int)
		defer bigIntPool.Put(kpLimbs[i])
		kpLimbs[i].SetInt64(0)
	}
	for i := 0; i < nbLimbs; i++ {
		for j := 0; j < nbQuoLimbs; j++ {
			tmp.Mul(quoLimbs[j], plimbs[i])
			kpLimbs[i+j].Add(kpLimbs[i+j], tmp)
		}
	}

	// compute the carries
	carry := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(carry)
	carry.SetInt64(0)
	for i := range carryLimbs {
		if i < len(lhs) {
			carry.Add(carry, lhs[i])
		}
		if i < nbRemLimbs {
			carry.Sub(carry, remLimbs[i])
		}
		if i < len(kpLimbs) {
			if kNegVal == 0 {
				carry.Sub(carry, kpLimbs[i])
			} else {
				carry.Add(carry, kpLimbs[i])
			}
		}
		carry.Rsh(carry, uint(nbBits))
		carryLimbs[i].Set(carry)
	}

	return nil
}

func limbMul(lhs []*big.Int, rhs []*big.Int) []*big.Int {
	tmp := new(big.Int)
	res := make([]*big.Int, nbMultiplicationResLimbs(len(lhs), len(rhs)))
	for i := range res {
		res[i] = new(big.Int)
	}
	for i := 0; i < len(lhs); i++ {
		for j := 0; j < len(rhs); j++ {
			res[i+j].Add(res[i+j], tmp.Mul(lhs[i], rhs[j]))
		}
	}
	return res
}
