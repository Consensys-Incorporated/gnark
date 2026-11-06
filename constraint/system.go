package constraint

import (
	"io"
	"math/big"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
)

// ConstraintSystem is an interfaces that all constraint systems implement. This
// is the typed implementation using wide uint64 element representation,
// allowing to support all supported pairing based backends.
type ConstraintSystem = ConstraintSystemGeneric[U64]

// ConstraintSystemU32 is an interfaces that all constraint systems implement.
// This is typed implementation for small field implementations. Small field
// implementations are not supported by pairing based backends, but can be
// exported for external use.
type ConstraintSystemU32 = ConstraintSystemGeneric[U32]

// ConstraintSystemU64W1 is an interface that all constraint systems implement.
// This is the typed implementation for small fields which do not fit [U32] but
// still fit a single uint64, such as mamabear. Like [ConstraintSystemU32] it is
// not supported by pairing based backends.
type ConstraintSystemU64W1 = ConstraintSystemGeneric[U64W1]

// ConstraintSystemGeneric interface that all constraint systems implement. This is the
// generic interface, see the aliased specific implementations
// [ConstraintSystem], [ConstraintSystemU32] and [ConstraintSystemU64W1].
type ConstraintSystemGeneric[E Element] interface {
	io.WriterTo
	io.ReaderFrom
	Field[E]
	Resolver
	CustomizableSystem

	// IsSolved returns nil if given witness solves the constraint system and error otherwise
	// Deprecated: use _, err := Solve(...) instead
	IsSolved(witness witness.Witness, opts ...solver.Option) error

	// Solve attempts to solve the constraint system using provided witness.
	// Returns an error if the witness does not allow all the constraints to be satisfied.
	// Returns a typed solution (R1CSSolution or SparseR1CSSolution) and nil otherwise.
	Solve(witness witness.Witness, opts ...solver.Option) (any, error)

	// GetNbVariables return number of internal, secret and public Variables
	// Deprecated: use GetNbSecretVariables() instead
	GetNbVariables() (internal, secret, public int)

	GetNbInternalVariables() int
	GetNbSecretVariables() int
	GetNbPublicVariables() int

	GetNbInstructions() int
	GetNbConstraints() int
	GetNbCoefficients() int

	Field() *big.Int
	FieldBitLen() int

	AddPublicVariable(name string) int
	AddSecretVariable(name string) int
	AddInternalVariable() int

	// AddSolverHint adds a hint to the solver such that the output variables will be computed
	// using a call to output := f(input...) at solve time.
	// Providing the function f is optional. If it is provided, id will be ignored and one will be derived from f's name.
	// Otherwise, the provided id will be used to register the hint with,
	AddSolverHint(f solver.Hint, id solver.HintID, input []LinearExpression, nbOutput int) (internalVariables []int, err error)

	AddCommitment(c Commitment) error
	GetCommitments() Commitments

	AddLog(l LogEntry)

	// MakeTerm returns a new Term. The constraint system may store coefficients in a map, so
	// calls to this function will grow the memory usage of the constraint system.
	MakeTerm(coeff E, variableID int) Term

	// AddCoeff adds a coefficient to the underlying constraint system. The system will not store duplicate,
	// but is not purging for unused coeff either, so this grows memory usage.
	AddCoeff(coeff E) uint32

	NewDebugInfo(errName string, i ...interface{}) DebugInfo

	// AttachDebugInfo enables attaching debug information to multiple constraints.
	// This is more efficient than using the AddR1C(.., debugInfo) since it will store the
	// debug information only once.
	AttachDebugInfo(debugInfo DebugInfo, constraintID []int)

	// CheckUnconstrainedWires returns and error if the constraint system has wires that are not uniquely constrained.
	// This is experimental.
	CheckUnconstrainedWires() error

	GetInstruction(int) Instruction

	GetCoefficient(i int) E
}

type CustomizableSystem interface {
	// AddBlueprint registers the given blueprint and returns its id. This should be called only once per blueprint.
	AddBlueprint(b Blueprint) BlueprintID

	// AddInstruction adds an instruction to the system and returns a list of created wires
	// if the blueprint declared any outputs.
	AddInstruction(bID BlueprintID, calldata []uint32) []uint32
}
