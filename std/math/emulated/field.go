package emulated

import (
	"cmp"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/compilelogger"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/internal/fieldextension"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/rs/zerolog"
)

const (
	// rangeCheckBaseLengthForSmallField is the base length used for range
	// checking when using small field optimization. We start enforcing
	// the base length only when the number of range checks exceeds
	// thresholdOptimizeOptimizedOverflow.
	rangeCheckBaseLengthForSmallField = 16
	// thresholdForInexactOverflow is the number of range checks after
	// which we start enforcing the base length for small field optimization.
	thresholdForInexactOverflow = 55000
)

// Field holds the configuration for non-native field operations. The field
// parameters (modulus, number of limbs) is given by [FieldParams] type
// parameter. If [FieldParams.IsPrime] is true, then allows inverse and division
// operations.
type Field[T FieldParams] struct {
	// api is the native API
	api frontend.API
	// extensionApi is the extension API when we need to perform multiplication checks over the extension field
	extensionApi fieldextension.Field

	// fParams carries the ring parameters
	fParams staticFieldParams[T]

	// maxOf is the maximum overflow before the element must be reduced.
	maxOf     uint
	maxOfOnce sync.Once

	// constants for often used elements n, 0 and 1. Allocated only once
	nConstOnce     sync.Once
	nConst         *Element[T]
	nprevConstOnce sync.Once
	nprevConst     *Element[T]
	zeroConstOnce  sync.Once
	zeroConst      *Element[T]
	oneConstOnce   sync.Once
	oneConst       *Element[T]

	log zerolog.Logger

	// constrainedLimbs keeps track of already range checked limbs. The map
	// value indicates the range check width.
	constrainedLimbs map[[16]byte]int
	checker          frontend.Rangechecker
	nbRangeChecks    int

	deferredChecks []deferredChecker

	// smallFieldMode indicates that the emulated field is small enough that
	// products fit in the native field and we can use scalar batched verification
	// instead of polynomial identity testing. This provides significant constraint
	// reduction for small field emulation (e.g., KoalaBear on BLS12-377).
	smallFieldMode     bool
	smallFieldModeOnce sync.Once
}

type ctxKey[T FieldParams] struct{}

// NewField returns an object to be used in-circuit to perform emulated
// arithmetic over the field defined by type parameter [FieldParams]. The
// operations on this type are defined on [Element].
func NewField[T FieldParams](native frontend.API) (*Field[T], error) {
	if storer, ok := native.Compiler().(kvstore.Store); ok {
		ff := storer.GetKeyValue(ctxKey[T]{})
		if ff, ok := ff.(*Field[T]); ok {
			return ff, nil
		}
	} else {
		panic("compiler does not implement kvstore.Store")
	}
	f := &Field[T]{
		api:              native,
		log:              logger.Logger(),
		constrainedLimbs: make(map[[16]byte]int),
		checker:          rangecheck.New(native),
		fParams:          newStaticFieldParams[T](native.Compiler().Field()),
	}
	if smallfields.IsSmallField(native.Compiler().Field()) {
		compilelogger.LogOnce(native.Compiler(), zerolog.DebugLevel,
			"emulated/isSmallField",
			"using small native field, multiplication checks will be performed in extension field")
		extapi, err := fieldextension.NewExtension(native)
		if err != nil {
			return nil, fmt.Errorf("extension field: %w", err)
		}
		f.extensionApi = extapi
	}

	// ensure prime is correctly set
	if f.fParams.IsPrime() {
		if !f.fParams.Modulus().ProbablyPrime(20) {
			return nil, errors.New("invalid parametrization: modulus is not prime")
		}
	}

	if f.fParams.BitsPerLimb() < 3 {
		// even three is way too small, but it should probably work.
		return nil, errors.New("nbBits must be at least 3")
	}

	if f.fParams.Modulus().Cmp(big.NewInt(1)) < 1 {
		return nil, errors.New("n must be at least 2")
	}

	nbLimbs := (uint(f.fParams.Modulus().BitLen()) + f.fParams.BitsPerLimb() - 1) / f.fParams.BitsPerLimb()
	if nbLimbs != f.fParams.NbLimbs() {
		return nil, fmt.Errorf("nbLimbs mismatch got %d expected %d", f.fParams.NbLimbs(), nbLimbs)
	}

	if f.api == nil {
		return f, errors.New("missing api")
	}

	// to ensure that we can perform the operations, we have to consider the
	// biggest overflow grow for elements we can have. Currently this is for
	// subtraction which can have overflow up to 2 bits. We add one more bit of
	// margin for safety.
	if uint(f.api.Compiler().FieldBitLen()) < f.fParams.BitsPerLimb()+3 {
		return nil, fmt.Errorf("elements with limb length %d does not fit into scalar field", f.fParams.BitsPerLimb())
	}

	native.Compiler().Defer(f.performDeferredChecks)
	if storer, ok := native.Compiler().(kvstore.Store); ok {
		storer.SetKeyValue(ctxKey[T]{}, f)
	} // other case is already checked above
	return f, nil
}

// NewElement builds a new Element[T] from input v.
//   - if v is a Element[T] or *Element[T] it clones it
//   - if v is a constant this is equivalent to calling emulated.ValueOf[T]
//   - if this methods interprets v as being the limbs (frontend.Variable or []frontend.Variable),
//     it constructs a new Element[T] with v as limbs and constraints the limbs to the parameters
//     of the Field[T].
func (f *Field[T]) NewElement(v any) *Element[T] {
	if e, ok := v.(Element[T]); ok {
		return e.copy()
	}
	if e, ok := v.(*Element[T]); ok {
		return e.copy()
	}
	if frontend.IsCanonical(v) {
		return f.packLimbs([]frontend.Variable{v}, true)
	}
	if e, ok := v.([]frontend.Variable); ok {
		return f.packLimbs(e, true)
	}
	// the input was not a variable, so it must be a constant. Create a new
	// element from it while setting isWitness flag to false. This ensures that
	// we use the minimal number of limbs necessary.
	c := newConstElement[T](f.api.Compiler().Field(), v, false)
	return c
}

// UnsafeFromLimbs constructs an element from the given limbs without
// enforcing any range checks on them. The caller MUST guarantee that every
// limb value is strictly less than 2^BitsPerLimb, otherwise the result is
// unsound. It is useful in gadgets where the limbs are bounded by
// construction, for example when they are convex combinations of constant
// limbs selected by a one-hot vector.
func (f *Field[T]) UnsafeFromLimbs(limbVals []frontend.Variable) *Element[T] {
	if len(limbVals) != int(f.fParams.NbLimbs()) {
		panic("limb count mismatch")
	}
	cp := make([]frontend.Variable, len(limbVals))
	copy(cp, limbVals)
	return f.newInternalElement(cp, 0)
}

// Zero returns zero as a constant.
func (f *Field[T]) Zero() *Element[T] {
	f.zeroConstOnce.Do(func() {
		f.zeroConst = f.newInternalElement([]frontend.Variable{}, 0)
	})
	return f.zeroConst
}

// One returns one as a constant.
func (f *Field[T]) One() *Element[T] {
	f.oneConstOnce.Do(func() {
		f.oneConst = f.newInternalElement([]frontend.Variable{1}, 0)
	})
	return f.oneConst
}

// Modulus returns the modulus of the emulated ring as a constant.
func (f *Field[T]) Modulus() *Element[T] {
	f.nConstOnce.Do(func() {
		f.nConst = newConstElement[T](f.api.Compiler().Field(), f.fParams.Modulus(), false)
	})
	return f.nConst
}

// modulusPrev returns modulus-1 as a constant.
func (f *Field[T]) modulusPrev() *Element[T] {
	f.nprevConstOnce.Do(func() {
		f.nprevConst = newConstElement[T](f.api.Compiler().Field(), new(big.Int).Sub(f.fParams.Modulus(), big.NewInt(1)), false)
	})
	return f.nprevConst
}

// packLimbs returns an element from the given limbs.
// If strict is true, the most significant limb will be constrained to have width of the most
// significant limb of the modulus, which may have less bits than the other limbs. In which case,
// less constraints will be generated.
// If strict is false, each limbs is constrained to have width as defined by field parameter.
func (f *Field[T]) packLimbs(limbs []frontend.Variable, strict bool) *Element[T] {
	nbBits := len(limbs) * int(f.fParams.BitsPerLimb())
	if strict {
		nbBits = f.fParams.Modulus().BitLen()
	}
	return f.packLimbsWithWidth(limbs, nbBits)
}

// packLimbsWithWidth returns an element from the given limbs with range check to nbBits.
// The number of limbs must be exactly ceil(nbBits / BitsPerLimb()), and each limb is
// range-checked accordingly.
func (f *Field[T]) packLimbsWithWidth(limbs []frontend.Variable, nbBits int) *Element[T] {
	if !f.useSmallFieldOptimization() {
		e := f.newInternalElement(limbs, 0)
		f.enforceWidth(e, nbBits)
		return e
	} else {
		e := f.newInternalElement(limbs, uint(f.smallAdditionalOverflow()))
		f.smallEnforceWidth(e, nbBits)
		return e
	}
}

func (f *Field[T]) enforceWidthConditional(a *Element[T]) (didConstrain bool) {
	if a == nil {
		// for some reason called on nil
		return false
	}
	if a.internal {
		// internal elements are already constrained in the method which returned
		// it. We return before calling [Element.Initialize] as it resets the
		// cached flags (modReduced, bit decomposition) as a safety measure
		// against stale values from a previous compilation. Internal elements
		// are always allocated during the current compilation by the method
		// which created them, so their flags cannot be stale.
		return false
	}
	// ensure that when the element is defined in-circuit with [ValueOf] method
	// (as a constant), then we decompose it into limbs. When [ValueOf] is called
	// for a witness assignment, then [Element.Initialize] is already called at
	// witness parsing time. In that case, the below operation is no-op.
	a.Initialize(f.api.Compiler().Field())
	if _, isConst := f.constantValue(a); isConst {
		// enforce constant element limbs not to be large.
		for i := range a.Limbs {
			val := utils.FromInterface(a.Limbs[i])
			if val.BitLen() > int(f.fParams.BitsPerLimb()) {
				panic("constant element limb wider than emulated parameter")
			}
		}
		// constant values are constant
		return false
	}
	for i := range a.Limbs {
		if !frontend.IsCanonical(a.Limbs[i]) {
			// this is not a canonical variable, nor a constant. This may happen
			// when some limbs are constant and some variables. Or if we are
			// running in a test engine. In either case, we must check that if
			// this limb is a [*big.Int] that its bitwidth is less than the
			// NbBits.
			val := utils.FromInterface(a.Limbs[i])
			if val.BitLen() > int(f.fParams.BitsPerLimb()) {
				panic("non-canonical integer limb wider than emulated parameter")
			}
			continue
		}
		if vv, ok := a.Limbs[i].(interface{ HashCode() [16]byte }); ok {
			// okay, this is a canonical variable and it has a hashcode. We use
			// it to see if the limb is already constrained.
			h := vv.HashCode()
			if _, ok := f.constrainedLimbs[h]; !ok {
				// we found a limb which hasn't yet been constrained. This means
				// that we should enforce width for the whole element. But we
				// still iterate over all limbs just to mark them in the table.
				didConstrain = true
				break
			}
		} else {
			// we have no way of knowing if the limb has been constrained. To be
			// on the safe side constrain the whole element again.
			didConstrain = true
		}
	}
	if didConstrain {
		if !f.useSmallFieldOptimization() {
			f.enforceWidth(a, f.fParams.Modulus().BitLen())
		} else {
			f.smallEnforceWidth(a, f.fParams.Modulus().BitLen())
		}
	}
	return
}

// ConstantValue returns the constant value of the element modulo the field
// modulus and a boolean indicating if the element is in fact a compile-time
// constant. It allows gadgets to specialize for constant inputs (for example
// scalar multiplication by a constant point can use precomputed tables).
func (f *Field[T]) ConstantValue(v *Element[T]) (*big.Int, bool) {
	c, ok := f.constantValue(v)
	if !ok {
		return nil, false
	}
	return c.Mod(c, f.fParams.Modulus()), true
}

func (f *Field[T]) constantValue(v *Element[T]) (*big.Int, bool) {
	// this case happens when we have called [ValueOf] inside a circuit as
	// [Element.Initialize] has not been called (Limbs are nil). In this case,
	// we can directly use the witness value as the constant value.
	if v.Limbs == nil && v.witnessValue != nil {
		return new(big.Int).Set(v.witnessValue), true
	}

	// otherwise - it may happen that the user has manually constructed [Element] from constant limbs.
	// In this case, we can recompose the constant value from the limbs.
	var ok bool

	constLimbs := make([]*big.Int, len(v.Limbs))
	for i, l := range v.Limbs {
		// for each limb we get it's constant value if we can, or fail.
		if constLimbs[i], ok = f.api.ConstantValue(l); !ok {
			return nil, false
		}
	}

	res := new(big.Int)
	if err := limbs.Recompose(constLimbs, f.fParams.BitsPerLimb(), res); err != nil {
		f.log.Error().Err(err).Msg("recomposing constant")
		return nil, false
	}
	return res, true
}

// maxLazyOverflow keeps lazy arithmetic and its resulting carry bounds well
// below the native field modulus. Lower values were measured to introduce
// more reduction constraints than they save in carry range checks.
const maxLazyOverflow uint = 96

// maxOverflow returns the maximal possible overflow for the element. If the
// overflow of the next operation exceeds the value returned by this method,
// then the limbs may overflow the native field.
func (f *Field[T]) maxOverflow() uint {
	f.maxOfOnce.Do(func() {
		// A lazy result must still admit a sound reduction or zero check. Those
		// operations need four carry bits in addition to the input overflow.
		if maxCarry := f.maxCarryBits(); maxCarry > 4 {
			f.maxOf = maxCarry - 4
		}
		f.maxOf = min(f.maxOf, maxLazyOverflow)
	})
	// when we perform non-reducing operations then we have to ensure that we are still
	// able to reduce the result afterwards (i.e. when doing additions/subtractions).
	return f.maxOf
}

func (f *Field[T]) maxOverflowReducedResult() uint {
	// The reduced result itself has zero overflow. This limit applies to the
	// per-call carry bound computed by mulPreCondReduced.
	return min(f.maxCarryBits(), maxLazyOverflow)
}

// maxCarryBits is the largest signed carry magnitude that keeps the
// corresponding integer coefficient strictly below the native modulus.
func (f *Field[T]) maxCarryBits() uint {
	return uint(f.api.Compiler().FieldBitLen()-2) - f.fParams.BitsPerLimb()
}

func sum[T cmp.Ordered](a ...T) T {
	if len(a) == 0 {
		var f T
		return f
	}
	m := a[0]
	for _, v := range a[1:] {
		m += v
	}
	return m
}

// useSmallFieldOptimization returns true if we can use the small field
// optimization for multiplication. The optimization is possible when:
//   - NbLimbs == 1 (emulated field fits in a single native limb)
//   - 2 * modBits + margin < nativeBits - 2 (products fit with margin for batching)
//
// When these conditions are met, we can use scalar batched verification instead
// of polynomial identity testing, which significantly reduces constraint counts.
func (f *Field[T]) useSmallFieldOptimization() bool {
	f.smallFieldModeOnce.Do(func() {
		// Small field optimization only works when NbLimbs == 1
		if f.fParams.NbLimbs() != 1 {
			f.smallFieldMode = false
			return
		}

		// Small field optimization doesn't work when we're already using extension field
		// for multiplication checks (native field is small)
		if f.extensionApi != nil {
			f.smallFieldMode = false
			return
		}

		// Check that products fit in the native field with margin for batching.
		// We need: 2 * modBits + batchingMargin < nativeBits - 2
		// The margin accounts for:
		// - γ^i scaling factors in the batched sum
		// - Multiple terms being summed together
		// We use 32 bits margin which allows for batching millions of operations.
		modBits := uint(f.fParams.Modulus().BitLen())
		nativeBits := uint(f.api.Compiler().FieldBitLen())
		const batchingMargin = 32

		f.smallFieldMode = 2*modBits+batchingMargin < nativeBits-2
		if f.smallFieldMode {
			compilelogger.LogOnce(f.api.Compiler(), zerolog.DebugLevel,
				"emulated/useSmallFieldOptimization",
				"using small field optimization for emulated multiplication (modBits = %d, nativeBits = %d)", modBits, nativeBits)
		}
	})
	return f.smallFieldMode
}

// rangeCheck performs a range check on v to ensure it fits in nbBits.
// It also keeps track of the number of range checks done, and after a certain
// threshold switches to using base length range checking for small field
// optimization.
//
// It returns a boolean indicating if the range check was actually performed (i.e. if
// the limb was not already constrained).
func (f *Field[T]) rangeCheck(v frontend.Variable, nbBits int) bool {
	if h, ok := v.(interface{ HashCode() [16]byte }); ok {
		// if the variable has a hashcode, then we can use it to see if we have
		// already range checked it.
		hc := h.HashCode()
		if existingWidth, ok := f.constrainedLimbs[hc]; ok {
			// already range checked with a certain width
			if existingWidth <= nbBits {
				return false
			}
		}
		// mark as range checked
		f.constrainedLimbs[hc] = nbBits
	}
	// update the number of range checks done. This is only to keep track if we
	// should switch to the case where instead of exact width we range check
	// multiple of base length. This reduces number of range checks when
	// emulating small field.
	f.nbRangeChecks++

	if f.nbRangeChecks == thresholdForInexactOverflow {
		// the threshold is reached, set the range checker to use base length.
		// Now we know that when constructing non-native elements, then we should
		// set overflow=f.smallAdditionalOverflow()
		if f.useSmallFieldOptimization() {
			// in case of emulated small fields we use base length 16 to reduce
			// needing to range check for [v_lo, v_hi, 2*v_hi].
			//
			// But this means that hints could output values which are bigger than
			// the emulated modulus bitwidth (for example 31 bits). This means we
			// have to set the overflow of returned elements correctly.
			f.checker = rangecheck.New(f.api, rangecheck.WithBaseLength(rangeCheckBaseLengthForSmallField))
		}
	}
	f.checker.Check(v, nbBits)
	return true
}
