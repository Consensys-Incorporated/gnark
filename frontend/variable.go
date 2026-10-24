// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package frontend

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend/internal/expr"
)

// Variable represents a variable in the circuit. Any integer type (e.g. int, *big.Int, fr.Element)
// can be assigned to it. It is also allowed to set a base-10 encoded string representing an integer value.
type Variable any

// IsCanonical returns true if the Variable has been normalized in a (internal) LinearExpression
// by one of the constraint system builders. In other words, if the Variable is a circuit input OR
// returned by the API.
func IsCanonical(v Variable) bool {
	switch v.(type) {
	case expr.LinearExpression[constraint.U32], *expr.LinearExpression[constraint.U32], expr.Term[constraint.U32], *expr.Term[constraint.U32]:
		return true
	case expr.LinearExpression[constraint.U64W1], *expr.LinearExpression[constraint.U64W1], expr.Term[constraint.U64W1], *expr.Term[constraint.U64W1]:
		return true
	case expr.LinearExpression[constraint.U64], *expr.LinearExpression[constraint.U64], expr.Term[constraint.U64], *expr.Term[constraint.U64]:
		return true
	}
	return false
}
