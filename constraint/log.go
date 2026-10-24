// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import (
	"strings"
)

// LogEntry is used as a shared data structure between the frontend and the backend
// to represent string values (in logs or debug info) where a value is not known at compile time
// (which is the case for variables that need to be resolved in the R1CS)
type LogEntry struct {
	Caller    string
	Format    string
	ToResolve []LinearExpression // TODO @gbotrel we could store here a struct with a flag that says if we expand or evaluate the expression
	Stack     []int
}

func (l *LogEntry) WriteVariable(le LinearExpression, sbb *strings.Builder) {
	// 77 correspond to the ~len(4 word modulus) in base10 string
	const elSize = 77
	sbb.Grow(len(le) * elSize)
	sbb.WriteString("%s")
	l.ToResolve = append(l.ToResolve, le)
}
