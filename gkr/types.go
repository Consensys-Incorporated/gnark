package gkr

import "github.com/consensys/gnark/frontend"

// Variable represents a value in a GKR circuit.
type Variable int

// GateAPI is a limited version of frontend.API,
// allowing ring arithmetic operations
type GateAPI interface {
	// ---------------------------------------------------------------------------------------------
	// Arithmetic

	// Add returns res = i1+i2+...in
	Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable

	// MulAcc sets and return a = a + (b*c).
	//
	// ! The method may mutate a without allocating a new result. If the input
	// is used elsewhere, then first initialize new variable, for example by
	// doing:
	//
	//     acopy := api.Mul(a, 1)
	//     acopy = api.MulAcc(acopy, b, c)
	//
	// ! But it may not modify a, always use MulAcc(...) result for correctness.
	MulAcc(a, b, c frontend.Variable) frontend.Variable

	// Neg returns -i
	Neg(i1 frontend.Variable) frontend.Variable

	// Sub returns res = i1 - i2 - ...in
	Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable

	// Mul returns res = i1 * i2 * ... in
	Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable

	SumExp17(a, b, c frontend.Variable) frontend.Variable
}

// GateFunction is a function that evaluates a polynomial over its inputs
// using the given GateAPI.
// It is used to define custom gates in GKR circuits.
type GateFunction func(GateAPI, ...frontend.Variable) frontend.Variable

// GateName is a string representing a (human-readable) name for a GKR gate.
//
// Deprecated: Named gates are no longer needed. Pass GateFunction directly to API.Gate().
type GateName string
