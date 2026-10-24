package frontend

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend/schema"
)

// NewBuilder is a function that creates a new constraint system builder for a
// given field. It takes a field modulus and a CompileConfig as arguments and
// returns a Builder interface and an error. The Builder interface provides
// methods for building and compiling the constraint system.
//
// gnark currently implements two builder constructors:
//   - r1cs.NewBuilder
//   - plonk.NewBuilder.
//
// For a constructor optimized for small field modulus, use [NewBuilderU32] instead.
type NewBuilder = NewBuilderGeneric[constraint.U64]

// NewBuilderU32 is a function that creates a new constraint system builder
// for a given small field modulus. See [NewBuilder] for more details.
type NewBuilderU32 = NewBuilderGeneric[constraint.U32]

// NewBuilderU64W1 is a function that creates a new constraint system builder
// for a small field modulus too wide for [NewBuilderU32] but still fitting a
// single uint64, such as mamabear. See [NewBuilder] for more details.
type NewBuilderU64W1 = NewBuilderGeneric[constraint.U64W1]

// NewBuilderGeneric is a generic function that creates a new constraint system
// builder for a given field. See [NewBuilder] for more details.
type NewBuilderGeneric[E constraint.Element] func(*big.Int, CompileConfig) (Builder[E], error)

// Compiler represents a constraint system compiler
type Compiler interface {
	constraint.CustomizableSystem

	// MarkBoolean sets (but does not constrain!) v to be boolean
	// This is useful in scenarios where a variable is known to be boolean through a constraint
	// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
	MarkBoolean(v Variable)

	// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
	// Use with care; variable may not have been **constrained** to be boolean
	// This returns true if the v is a constant and v == 0 || v == 1.
	IsBoolean(v Variable) bool

	// NewHint initializes internal variables whose value will be evaluated
	// using the provided hint function at run time from the inputs. Inputs must
	// be either variables or convertible to *big.Int. The function returns an
	// error if the number of inputs is not compatible with f.
	//
	// The hint function is provided at the proof creation time and is not
	// embedded into the circuit. From the backend point of view, the variable
	// returned by the hint function is equivalent to the user-supplied witness,
	// but its actual value is assigned by the solver, not the caller.
	//
	// No new constraints are added to the newly created wire and must be added
	// manually in the circuit. Failing to do so leads to solver failure.
	//
	// If nbOutputs is specified, it must be >= 1 and <= f.NbOutputs
	NewHint(f solver.Hint, nbOutputs int, inputs ...Variable) ([]Variable, error)

	// ConstantValue returns the big.Int value of v and true if op is a success.
	// nil and false if failure. This API returns a boolean to allow for future refactoring
	// replacing *big.Int with fr.Element
	ConstantValue(v Variable) (*big.Int, bool)

	// Field returns the finite field modulus injected by the compiler
	Field() *big.Int

	// FieldBitLen returns the number of bits needed to represent an element in the scalar field
	FieldBitLen() int

	// Defer is called after circuit.Define() and before Compile(). This method
	// allows for the circuits to register callbacks which finalize batching
	// operations etc. Unlike Go defer, it is not locally scoped.
	Defer(cb func(api API) error)

	// InternalVariable returns the internal variable associated with the given wireID
	// ! Experimental: use in conjunction with constraint.CustomizableSystem
	InternalVariable(wireID uint32) Variable

	// ToCanonicalVariable converts a frontend.Variable to a constraint system specific Variable
	// ! Experimental: use in conjunction with constraint.CustomizableSystem
	ToCanonicalVariable(Variable) CanonicalVariable
}

// Builder represents a constraint system builder.
//
// Usually a builder is constructed using a function of type [NewBuilder] or
// [NewBuilderU32] (for small fields where coefficients fit into uint32). Such
// builder constructors are provided by specific frontends, e.g., R1CS or SCS
// (PLONKish).
//
// The builder interface embeds [API] which can be used to define constraints in
// the circuit ([Circuit.Define] method). It also embeds [Compiler] which
// provides accessing compiler access (e.g. finite field modulus).
//
// It is also possible to wrap an existing builder to provide additional
// functionality. However, the wrapped builders should not overwrite methods in
// [Builder] and embedded interfaces as it may lead to unexpected behavior.
// Usually, the wrapped builders would want to implement additional interfaces
// such as [Committer], [WideCommitter], or [Rangechecker].
//
// The default builders in r1cs and scs packages implement only [Committer] interface.
type Builder[E constraint.Element] interface {
	API
	Compiler

	// Compile is called after circuit.Define() to produce a final IR (ConstraintSystem)
	Compile() (constraint.ConstraintSystemGeneric[E], error)

	// PublicVariable is called by the compiler when parsing the circuit schema. It panics if
	// called inside circuit.Define()
	PublicVariable(schema.LeafInfo) Variable

	// SecretVariable is called by the compiler when parsing the circuit schema. It panics if
	// called inside circuit.Define()
	SecretVariable(schema.LeafInfo) Variable
}

// Committer allows to commit to the variables and returns the commitment. The
// commitment can be used as a challenge using Fiat-Shamir heuristic.
//
// Depending on the proof system, the commitment computation and verification may
// be expensive. Thus, this method should be used sparingly and possibly use
// nativecommit gadget to batch multiple commitment calls to a single [Commit]
// call.
//
// Custom builders can choose to implement this interface to override the default
// commitment functionality in Groth16 and PLONKish backends.
type Committer interface {
	// Commit commits to the variables and returns the commitment.
	Commit(toCommit ...Variable) (commitment Variable, err error)
}

// WideCommitter allows to commit to the variables and returns the commitment as
// an extension field element. The commitment can be used as a challenge using
// Fiat-Shamir heuristic. This method is required when the circuit is defined
// over a small field where the individual commitment would be too small to
// achieve desired soundness level.
//
// This is experimental API and may be subject to change. It is not relevant for
// pairing-based backends where the commitment is in a large field and is not
// defined for such cases. Thus, the caller should check if this or [Committer]
// interfaces is implemented and use the appropriate method.
//
// Custom builders can choose to implement this method to provide wide
// commitment functionality.
type WideCommitter interface {
	// WideCommit commits to the variables and returns the commitments.
	// This method is required when the circuit is defined over a small field
	// where the individual commitment would be too small to achieve desired
	// soundness level.
	//
	// The width parameter defines the number of elements in the commitment.
	WideCommit(width int, toCommit ...Variable) (commitment []Variable, err error)
}

// Rangechecker allows to externally range-check the variables to be of
// specified width. Not all compilers implement this interface. Users should
// instead use [github.com/consensys/gnark/std/rangecheck] package which
// automatically chooses most optimal method for range checking the variables.
//
// The default builders in gnark do not implement this interface. Custom builders
// can choose to implement this method to provide optimized range-checking
// functionality.
type Rangechecker interface {
	// Check checks that the given variable v has bit-length bits.
	Check(v Variable, bits int)
}

// CanonicalVariable represents a variable that's encoded in a constraint system specific way.
// For example:
// - a R1CS builder may represent this as a constraint.LinearExpression (linear combination of [constraint.Term]),
// - a PLONK builder as [constraint.Term]
// - and the test/Engine as *big.Int.
type CanonicalVariable interface {
	constraint.Compressible
}
