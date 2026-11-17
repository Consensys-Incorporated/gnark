// Package debugstack allows gadgets which create their constraints in deferred
// callbacks to attribute those constraints to the place in the circuit where
// the checked operation was defined.
//
// For example, non-native arithmetic in
// [github.com/consensys/gnark/std/math/emulated] computes the results of the
// operations when they are called, but checks their correctness all at once in
// a deferred callback. Without attribution, a failing check would point to the
// deferred callback instead of the line in the circuit definition. With the
// debug build tag, the gadget records the call stack with
// [github.com/consensys/gnark/debug.Callers] when the operation is defined and
// creates the checking constraints inside [Run].
package debugstack

import "github.com/consensys/gnark/frontend"

// Attributor is implemented by the builders (and the test engine) which can
// attribute the debug information of constraints to a recorded call stack.
type Attributor interface {
	// WithDebugStack calls fn. The debug information of the constraints added
	// inside fn (or the error when an assertion fails in the test engine)
	// reports the call stack given by the program counters pcs instead of
	// the current call stack.
	WithDebugStack(pcs []uintptr, fn func())
}

// Run calls fn. If pcs is not empty and the compiler supports attribution (see
// [Attributor]), then the constraints added in fn are attributed to the call
// stack pcs. Otherwise fn is called directly.
func Run(api frontend.API, pcs []uintptr, fn func()) {
	if len(pcs) == 0 {
		fn()
		return
	}
	if a, ok := api.Compiler().(Attributor); ok {
		a.WithDebugStack(pcs, fn)
		return
	}
	fn()
}
