// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

type R1CS[E Element] interface {
	ConstraintSystemGeneric[E]

	// AddR1C adds a constraint to the system and returns its id
	// This does not check for validity of the constraint.
	AddR1C(r1c R1C, bID BlueprintID) int

	// GetR1Cs return the list of R1C
	// See StringBuilder for more info.
	// ! this is an experimental API.
	GetR1Cs() []R1C

	// GetR1CIterator returns an R1CIterator to iterate on the R1C constraints of the system.
	GetR1CIterator() R1CIterator
}

// R1CIterator facilitates iterating through R1C constraints.
type R1CIterator struct {
	R1C
	cs *System
	n  int
}

// Next returns the next R1C or nil if end. Caller must not store the result since the
// same memory space is re-used for subsequent calls to Next.
func (it *R1CIterator) Next() *R1C {
	if it.n >= it.cs.GetNbInstructions() {
		return nil
	}
	inst := it.cs.Instructions[it.n]
	it.n++
	blueprint := it.cs.Blueprints[inst.BlueprintID]
	if bc, ok := blueprint.(BlueprintR1C); ok {
		bc.DecompressR1C(&it.R1C, inst.Unpack(it.cs))
		return &it.R1C
	}
	return it.Next()
}

// R1C used to compute the wires
type R1C struct {
	L, R, O LinearExpression
}

// String formats a R1C as L⋅R == O
func (r1c *R1C) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteLinearExpression(r1c.L)
	sbb.WriteString(" ⋅ ")
	sbb.WriteLinearExpression(r1c.R)
	sbb.WriteString(" == ")
	sbb.WriteLinearExpression(r1c.O)
	return sbb.String()
}
