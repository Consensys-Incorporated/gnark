package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/profile"
)

// smallMulEntry represents a single multiplication entry for batched verification.
// For each multiplication a * b = q * p + r, we store:
//   - a, b: the operands (single limb each since NbLimbs == 1)
//   - r: the remainder (reduced result, single limb)
//   - q: the quotient (single limb)
type smallMulEntry struct {
	a, b frontend.Variable // operands
	r    frontend.Variable // remainder
	q    frontend.Variable // quotient
}

// smallMulCheck implements the deferredChecker interface for small field
// multiplication verification. Instead of using polynomial identity testing,
// it uses batched scalar verification:
//
//	Σ γ^i * (a_i * b_i) = Σ γ^i * r_i + (Σ γ^i * q_i) * p
//
// This approach is much cheaper for single-limb emulation because:
//   - No polynomial evaluation needed
//   - No carry polynomial needed
//   - Quotients and remainders are range-checked before the deferred check
type smallMulCheck[T FieldParams] struct {
	f       *Field[T]
	entries []smallMulEntry
	// gamma stores the random challenge received during eval rounds
	gamma frontend.Variable
}

// addEntry adds a new multiplication entry to the batch.
func (mc *smallMulCheck[T]) addEntry(a, b, r, q frontend.Variable) {
	mc.entries = append(mc.entries, smallMulEntry{a: a, b: b, r: r, q: q})
}

// toCommit returns all variables that should be committed to for the random challenge.
func (mc *smallMulCheck[T]) toCommit() []frontend.Variable {
	vars := make([]frontend.Variable, 0, len(mc.entries)*4)
	for _, e := range mc.entries {
		vars = append(vars, e.a, e.b, e.r, e.q)
	}
	return vars
}

// maxLen returns the maximum number of limbs (always 1 for small field mode).
func (mc *smallMulCheck[T]) maxLen() int {
	return 1
}

// evalRound1 stores the random challenge for later use in check.
func (mc *smallMulCheck[T]) evalRound1(at []frontend.Variable) {
	// Store the challenge (at[0] = γ) for use in check
	if len(at) > 0 {
		mc.gamma = at[0]
	}
}

// evalRound2 is a no-op for small field check since we don't use polynomial evaluation.
func (mc *smallMulCheck[T]) evalRound2(at []frontend.Variable) {
	// No polynomial evaluation needed for small field optimization
}

// check performs the batched verification:
// Σ γ^i * (a_i * b_i) = Σ γ^i * r_i + (Σ γ^i * q_i) * p
func (mc *smallMulCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	if len(mc.entries) == 0 {
		return
	}

	n := len(mc.entries)

	// Proceed with the batched verification using random challenge γ.
	gamma := mc.gamma
	if gamma == nil {
		panic("smallMulCheck: gamma not set, evalRound1 was not called")
	}

	// Compute the three sums using Horner's method for efficiency:
	// sumAB = Σ γ^i * (a_i * b_i)
	// sumR  = Σ γ^i * r_i
	// sumQ  = Σ γ^i * q_i
	//
	// Using Horner's method: a_0 + γ(a_1 + γ(a_2 + ...))
	// We iterate backwards from the last entry.

	// Start with the last entry.
	lastEntry := mc.entries[n-1]
	sumAB := api.Mul(lastEntry.a, lastEntry.b)
	sumR := lastEntry.r
	sumQ := lastEntry.q

	// Process remaining entries using Horner's method (backwards)
	for i := n - 2; i >= 0; i-- {
		e := mc.entries[i]

		// sumAB = a_i * b_i + γ * sumAB
		ab := api.Mul(e.a, e.b)
		sumAB = api.MulAcc(ab, gamma, sumAB)

		// sumR = r_i + γ * sumR
		sumR = api.MulAcc(e.r, gamma, sumR)

		// sumQ = q_i + γ * sumQ
		sumQ = api.MulAcc(e.q, gamma, sumQ)
	}

	// Verify: sumAB == sumR + sumQ * p
	p := mc.f.fParams.Modulus()
	rhs := api.MulAcc(sumR, sumQ, p)
	api.AssertIsEqual(sumAB, rhs)
}

// cleanEvaluations cleans cached evaluation values.
func (mc *smallMulCheck[T]) cleanEvaluations() {
	// Reset gamma for clean circuit recompilation
	mc.gamma = nil
}

// smallMulMod performs multiplication using the small field optimization.
// It computes a * b mod p using a hint and defers the batched verification.
func (f *Field[T]) smallMulMod(a, b *Element[T]) *Element[T] {
	// For small field mode, both a and b should have exactly 1 limb
	if len(a.Limbs) != 1 || len(b.Limbs) != 1 {
		panic("smallMulMod requires single-limb elements")
	}

	// Get or create the small mul checker
	smc := f.getOrCreateSmallMulCheck()

	// Call hint to get quotient and remainder
	q, r, err := f.callSmallMulHint(a.Limbs[0], b.Limbs[0])
	if err != nil {
		panic(fmt.Sprintf("small mul hint: %v", err))
	}

	// Range check the remainder.
	modBits := f.fParams.Modulus().BitLen()
	f.rangeCheck(r, modBits+f.smallAdditionalOverflow())

	// Compute the number of bits needed for the quotient.
	// For a*b = q*p + r:
	//   - a < 2^(bitsPerLimb + overflow_a)
	//   - b < 2^(bitsPerLimb + overflow_b)
	//   - a*b < 2^(2*bitsPerLimb + overflow_a + overflow_b)
	//   - q = floor(a*b / p) < 2^(2*bitsPerLimb + overflow_a + overflow_b - modBits + 1)
	bitsPerLimb := int(f.fParams.BitsPerLimb())
	qBits := 2*bitsPerLimb + int(a.overflow) + int(b.overflow) - modBits + 1
	// Bound each quotient individually. Range-checking only their unweighted sum
	// would allow forged quotients to cancel modulo the native field modulus.
	f.rangeCheck(q, qBits)

	// Add entry to the batch
	smc.addEntry(a.Limbs[0], b.Limbs[0], r, q)

	// Record operation for profiling
	profile.RecordOperation("emulated.SmallMulMod", 3)

	// Return result as single-limb element
	return f.newInternalElement([]frontend.Variable{r}, uint(f.smallAdditionalOverflow()))
}

// getOrCreateSmallMulCheck returns the existing smallMulCheck or creates a new one.
func (f *Field[T]) getOrCreateSmallMulCheck() *smallMulCheck[T] {
	// Look for existing smallMulCheck in deferred checks
	for _, dc := range f.deferredChecks {
		if smc, ok := dc.(*smallMulCheck[T]); ok {
			return smc
		}
	}

	// Create new smallMulCheck
	smc := &smallMulCheck[T]{f: f}
	f.deferredChecks = append(f.deferredChecks, smc)
	return smc
}

// callSmallMulHint computes q and r such that a * b = q * p + r using a hint.
func (f *Field[T]) callSmallMulHint(a, b frontend.Variable) (q, r frontend.Variable, err error) {
	p := f.fParams.Modulus()
	nbBits := f.fParams.BitsPerLimb()

	// Hint returns [q, r]
	ret, err := f.api.NewHint(smallMulHint, 2, nbBits, p, a, b)
	if err != nil {
		return nil, nil, fmt.Errorf("call hint: %w", err)
	}

	return ret[0], ret[1], nil
}

// smallMulHint computes q and r such that a * b = q * p + r.
func smallMulHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("expected 4 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(outputs))
	}

	// inputs[0] = nbBits (unused here but kept for consistency)
	// inputs[1] = p (modulus)
	// inputs[2] = a
	// inputs[3] = b
	p := inputs[1]
	a := inputs[2]
	b := inputs[3]

	// Compute a * b
	ab := new(big.Int).Mul(a, b)

	// Compute q and r such that a * b = q * p + r
	q := new(big.Int)
	r := new(big.Int)
	if p.Sign() != 0 {
		q.QuoRem(ab, p, r)
	} else {
		r.Set(ab)
	}

	outputs[0].Set(q)
	outputs[1].Set(r)
	return nil
}

// smallCheckZero creates a check that a ≡ 0 (mod p).
// This is done by verifying a = q * p + 0.
func (f *Field[T]) smallCheckZero(a *Element[T]) {
	if len(a.Limbs) != 1 {
		panic("smallCheckZero requires single-limb element")
	}

	// Call hint to get quotient only
	q, err := f.callSmallCheckZeroHint(a.Limbs[0])
	if err != nil {
		panic(fmt.Sprintf("small check zero hint: %v", err))
	}

	// Compute the number of bits needed for the quotient.
	// For a * 1 = q * p + 0:
	//   - a < 2^(bitsPerLimb + overflow_a)
	//   - q = floor(a / p) < 2^(bitsPerLimb + overflow_a - modBits + 1)
	modBits := f.fParams.Modulus().BitLen()
	bitsPerLimb := int(f.fParams.BitsPerLimb())
	qBits := bitsPerLimb + int(a.overflow) - modBits + 1

	// Individually range-check the quotient. The native equality below
	// (a == q*p mod P_native) is on its own vacuous: for any a a prover can set
	// q = a*p⁻¹ mod P_native and it holds. Binding q to qBits keeps q*p below
	// the native modulus, so a == q*p holds over the integers and proves
	// a ≡ 0 (mod p).
	f.rangeCheck(q, qBits)

	// Verify a = q * p, proving a ≡ 0 (mod p).
	f.api.AssertIsEqual(a.Limbs[0], f.api.Mul(q, f.fParams.Modulus()))

	// Record operation for profiling
	profile.RecordOperation("emulated.SmallCheckZero", 1)
}

// callSmallCheckZeroHint computes q such that a = q * p (+ remainder).
// We only need q; the remainder is not returned as we use 0 directly for soundness.
func (f *Field[T]) callSmallCheckZeroHint(a frontend.Variable) (q frontend.Variable, err error) {
	p := f.fParams.Modulus()
	nbBits := f.fParams.BitsPerLimb()

	ret, err := f.api.NewHint(smallCheckZeroHint, 1, nbBits, p, a)
	if err != nil {
		return nil, fmt.Errorf("call hint: %w", err)
	}

	return ret[0], nil
}

// smallCheckZeroHint computes q such that a = q * p + r.
// Only returns q; the remainder r is not needed as we use 0 directly for soundness.
func smallCheckZeroHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("expected 3 inputs, got %d", len(inputs))
	}
	if len(outputs) != 1 {
		return fmt.Errorf("expected 1 output, got %d", len(outputs))
	}

	// inputs[0] = nbBits (unused)
	// inputs[1] = p (modulus)
	// inputs[2] = a
	p := inputs[1]
	a := inputs[2]

	// Compute q such that a = q * p + r
	q := new(big.Int)
	if p.Sign() != 0 {
		q.Quo(a, p)
	}

	outputs[0].Set(q)
	return nil
}

// toSingleLimb converts an Element to a single-limb representation if possible.
// For elements with more limbs, it recomposes them into a single native value.
func (f *Field[T]) toSingleLimb(a *Element[T]) frontend.Variable {
	if len(a.Limbs) == 0 {
		return 0
	}
	if len(a.Limbs) == 1 {
		return a.Limbs[0]
	}

	// Recompose multiple limbs into single value
	nbBits := f.fParams.BitsPerLimb()
	result := a.Limbs[0]
	coef := new(big.Int).Lsh(big.NewInt(1), nbBits)
	for i := 1; i < len(a.Limbs); i++ {
		result = f.api.MulAcc(result, a.Limbs[i], coef)
		coef.Lsh(coef, nbBits)
	}
	return result
}

// toSingleLimbElement converts an Element to a single-limb Element.
// For small field mode, elements should be single limb, but witness
// initialization might create multi-limb elements. This function
// handles that case by recomposing the limbs.
func (f *Field[T]) toSingleLimbElement(a *Element[T]) *Element[T] {
	if len(a.Limbs) == 0 {
		return f.Zero()
	}
	if len(a.Limbs) == 1 {
		return a
	}

	// Recompose multiple limbs into a single limb
	singleLimb := f.toSingleLimb(a)
	return f.newInternalElement([]frontend.Variable{singleLimb}, a.overflow)
}

// smallAdditionalOverflow returns the additional overflow bits needed
// for small field optimization range checks.
//
// For performing range checks, we check that the element is multiple of base
// length in the range checking package. When the field modulus bit length is
// not a multiple then we still use the next multiple of the base length for
// range checking, but define that the non-native small field element can have
// some additional overflow bits to accommodate this difference.
func (f *Field[T]) smallAdditionalOverflow() int {
	// when we emulate large field, then we always construct elements with exact
	// overflow
	if !f.useSmallFieldOptimization() {
		return 0
	}
	// when we haven't performed too many range checks, then we still use exact
	// overflow
	if f.nbRangeChecks < thresholdForInexactOverflow {
		return 0
	}
	// otherwise, we use the additional overflow which reduced number of
	// decompositions during range checking
	return (rangeCheckBaseLengthForSmallField - (f.fParams.Modulus().BitLen() % rangeCheckBaseLengthForSmallField)) % rangeCheckBaseLengthForSmallField
}
