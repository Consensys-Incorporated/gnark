package algebra

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
)

type GroupElementT any
type G1ElementT GroupElementT
type G2ElementT GroupElementT
type GtElementT GroupElementT

// Curve defines group operations on an elliptic curve.
type Curve[FR emulated.FieldParams, G1El G1ElementT] interface {
	// AddUnified adds _any_ two points and returns the sum. It does not modify the input
	// points.
	AddUnified(*G1El, *G1El) *G1El

	// Add adds two points and returns the sum. It does not modify the input
	// points.
	Add(*G1El, *G1El) *G1El

	// AssertIsEqual asserts that two points are equal.
	AssertIsEqual(*G1El, *G1El)

	// Neg negates the points and returns a negated point. It does not modify
	// the input.
	Neg(*G1El) *G1El

	// ScalarMul returns the scalar multiplication of the point by a scalar. It
	// does not modify the inputs.
	//
	// By default the scalar multiplication is complete, i.e. it handles
	// correctly zero scalar and point at infinity inputs. To opt into faster
	// incomplete formulas (when inputs are guaranteed non-degenerate), use
	// [algopts.WithIncompleteArithmetic].
	ScalarMul(*G1El, *emulated.Element[FR], ...algopts.AlgebraOption) *G1El

	// ScalarMulBase returns the scalar multiplication of the curve base point
	// by a scalar. It does not modify the scalar.
	//
	// By default the scalar multiplication is complete, i.e. it handles
	// correctly zero scalar. To opt into faster incomplete formulas (when the
	// scalar is guaranteed non-zero), use [algopts.WithIncompleteArithmetic].
	ScalarMulBase(*emulated.Element[FR], ...algopts.AlgebraOption) *G1El

	// MultiScalarMul computes the sum ∑ s_i P_i for the input
	// scalars s_i and points P_i. It returns an error if the input lengths
	// mismatch.
	//
	// By default the scalar multiplication is complete, i.e. it handles
	// correctly zero scalars and points at infinity. To opt into faster
	// incomplete formulas (when inputs are guaranteed non-degenerate), use
	// [algopts.WithIncompleteArithmetic].
	MultiScalarMul([]*G1El, []*emulated.Element[FR], ...algopts.AlgebraOption) (*G1El, error)

	// MarshalG1 returns the binary decomposition G1.X || G1.Y. It matches the
	// output of gnark-crypto's Marshal method on G1 points.
	MarshalG1(G1El, ...algopts.AlgebraOption) []frontend.Variable

	// MarshalScalar returns the binary decomposition of the argument.
	MarshalScalar(emulated.Element[FR], ...algopts.AlgebraOption) []frontend.Variable

	// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
	Select(b frontend.Variable, p1 *G1El, p2 *G1El) *G1El

	// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
	// Returns:
	//   - p1 if b0=0 and b1=0,
	//   - p2 if b0=1 and b1=0,
	//   - p3 if b0=0 and b1=1,
	//   - p4 if b0=1 and b1=1.
	Lookup2(b1 frontend.Variable, b2 frontend.Variable, p1 *G1El, p2 *G1El, p3 *G1El, p4 *G1El) *G1El

	// Mux performs a lookup from the inputs and returns inputs[sel]. It is most
	// efficient for power of two lengths of the inputs, but works for any
	// number of inputs.
	Mux(sel frontend.Variable, inputs ...*G1El) *G1El
}

// Pairing allows to compute the bi-linear pairing of G1 and G2 elements.
// Additionally, the interface provides steps used in pairing computation and a
// dedicated optimised pairing check.
//
// Security note: input validation semantics are implementation-defined and
// additionally depend on whether the G2 inputs carry precomputed line
// evaluations (e.g. G2Affine.Lines). Implementations may skip on-curve and
// subgroup checks on the pairing inputs, and precomputed lines are consumed
// without being constrained to the point coordinates. Do not rely on the
// pairing methods for input validation — use AssertIsOnG1 and AssertIsOnG2
// for explicit checks, and prefer PairingCheck over Pair followed by
// AssertIsEqual for untrusted inputs. See the concrete implementations for
// details.
type Pairing[G1El G1ElementT, G2El G2ElementT, GtEl GtElementT] interface {
	// MillerLoop computes the Miller loop of the input pairs. It returns error
	// when the inputs are of mismatching length. Implementations may cache
	// computed line evaluations into the G2 inputs.
	//
	// Precomputed line evaluations carried by the G2 inputs are used directly
	// and are trusted input: they are not constrained to correspond to the
	// point coordinates. See the concrete implementations for the input
	// validation performed.
	MillerLoop([]*G1El, []*G2El) (*GtEl, error)

	// FinalExponentiation computes the final step in the pairing. It does not
	// modify the inputs.
	FinalExponentiation(*GtEl) *GtEl

	// Pair computes the full pairing of the input pairs. It returns error when
	// the inputs are of mismatching length. It does not modify the inputs.
	//
	// See MillerLoop for the security assumptions on precomputed G2 line
	// evaluations.
	Pair([]*G1El, []*G2El) (*GtEl, error)

	// PairingCheck asserts that the pairing result is 1. It returns an error
	// when the inputs are of mismatching length. It does not modify the inputs.
	//
	// Implementations bind the asserted equation to the point coordinates of
	// the inputs even when they carry precomputed line evaluations, so this
	// method is preferred over Pair followed by AssertIsEqual for untrusted
	// inputs. Curve and subgroup validation of the inputs is
	// implementation-defined — see the interface security note.
	PairingCheck([]*G1El, []*G2El) error

	// AssertIsEqual asserts the equality of the inputs.
	AssertIsEqual(*GtEl, *GtEl)

	// AssertIsOnG1 asserts that the input is on the G1 curve and in the
	// correct subgroup.
	AssertIsOnG1(*G1El)

	// AssertIsOnG2 asserts that the input is on the G2 curve and in the
	// correct subgroup.
	AssertIsOnG2(*G2El)

	// MuxG2 performs a lookup from the G2 inputs and returns inputs[sel]. It is
	// most efficient for power of two lengths of the inputs, but works for any
	// number of inputs.
	MuxG2(sel frontend.Variable, inputs ...*G2El) *G2El

	// MuxGt performs a lookup from the Gt inputs and returns inputs[sel]. It is
	// most efficient for power of two lengths of the inputs, but works for any
	// number of inputs.
	MuxGt(sel frontend.Variable, inputs ...*GtEl) *GtEl

	// IsEqual checks if the two inputs are equal. It returns a frontend.Variable.
	IsEqual(a, b *GtEl) frontend.Variable
}
