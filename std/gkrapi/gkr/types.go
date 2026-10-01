// Package gkr contains deprecated aliases of github.com/consensys/gnark/gkr.
//
// Deprecated: use github.com/consensys/gnark/gkr instead.
package gkr

import "github.com/consensys/gnark/gkr"

// Variable represents a value in a GKR circuit.
type Variable = gkr.Variable

// GateAPI is a limited version of frontend.API,
// allowing ring arithmetic operations
type GateAPI = gkr.GateAPI

// GateFunction is a function that evaluates a polynomial over its inputs
// using the given GateAPI.
// It is used to define custom gates in GKR circuits.
type GateFunction = gkr.GateFunction

// GateName is a string representing a (human-readable) name for a GKR gate.
type GateName = gkr.GateName // nolint SA1019
