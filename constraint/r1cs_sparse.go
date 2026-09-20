// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

type SparseR1CS[E Element] interface {
	ConstraintSystemGeneric[E]

	// AddSparseR1C adds a constraint to the constraint system.
	AddSparseR1C(c SparseR1C, bID BlueprintID) int

	// GetSparseR1Cs return the list of SparseR1C
	// See StringBuilder for more info.
	// ! this is an experimental API.
	GetSparseR1Cs() []SparseR1C

	// GetSparseR1CIterator returns an SparseR1CIterator to iterate on the SparseR1C constraints of the system.
	GetSparseR1CIterator() SparseR1CIterator
}

// SparseR1CIterator facilitates iterating through SparseR1C constraints.
type SparseR1CIterator struct {
	SparseR1C
	cs *System
	n  int
}

// Next returns the next SparseR1C or nil if end. Caller must not store the result since the
// same memory space is re-used for subsequent calls to Next.
func (it *SparseR1CIterator) Next() *SparseR1C {
	if it.n >= it.cs.GetNbInstructions() {
		return nil
	}
	inst := it.cs.Instructions[it.n]
	it.n++
	blueprint := it.cs.Blueprints[inst.BlueprintID]
	if bc, ok := blueprint.(BlueprintSparseR1C); ok {
		bc.DecompressSparseR1C(&it.SparseR1C, inst.Unpack(it.cs))
		return &it.SparseR1C
	}
	return it.Next()
}

type CommitmentConstraint uint32

const (
	NOT        CommitmentConstraint = 0
	COMMITTED  CommitmentConstraint = 1
	COMMITMENT CommitmentConstraint = 2
)

// SparseR1C represent a PlonK-ish constraint
// qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC -committed?*Bsb22Commitments-commitment?*commitmentValue == 0
type SparseR1C struct {
	XA, XB, XC         uint32
	QL, QR, QO, QM, QC uint32
	Commitment         CommitmentConstraint
}

func (c *SparseR1C) Clear() {
	*c = SparseR1C{}
}

// String formats the constraint as qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
func (c *SparseR1C) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteTerm(Term{CID: c.QL, VID: c.XA})
	sbb.WriteString(" + ")
	sbb.WriteTerm(Term{CID: c.QR, VID: c.XB})
	sbb.WriteString(" + ")
	sbb.WriteTerm(Term{CID: c.QO, VID: c.XC})
	if qM := sbb.CoeffToString(int(c.QM)); qM != "0" {
		xa := sbb.VariableToString(int(c.XA))
		xb := sbb.VariableToString(int(c.XB))
		sbb.WriteString(" + ")
		sbb.WriteString(qM)
		sbb.WriteString("⋅(")
		sbb.WriteString(xa)
		sbb.WriteString("×")
		sbb.WriteString(xb)
		sbb.WriteByte(')')
	}
	sbb.WriteString(" + ")
	sbb.WriteString(r.CoeffToString(int(c.QC)))
	sbb.WriteString(" == 0")
	return sbb.String()
}
