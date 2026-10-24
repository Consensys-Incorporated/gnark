// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import (
	"math"
)

// ids of the coefficients with simple values in any cs.coeffs slice.
const (
	CoeffIdZero = iota
	CoeffIdOne
	CoeffIdTwo
	CoeffIdMinusOne
	CoeffIdMinusTwo
)

// Term represents a coeff * variable in a constraint system
type Term struct {
	CID, VID uint32
}

func (t *Term) MarkConstant() {
	t.VID = math.MaxUint32
}

func (t *Term) IsConstant() bool {
	return t.VID == math.MaxUint32
}

func (t *Term) WireID() int {
	return int(t.VID)
}

func (t *Term) CoeffID() int {
	return int(t.CID)
}

func (t Term) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteTerm(t)
	return sbb.String()
}

// implements constraint.Compressible

// Compress compresses the term into a slice of uint32 words.
// For compatibility with test engine and LinearExpression, the term is encoded as:
// 1, CID, VID (i.e a LinearExpression with a single term)
func (t Term) Compress(to *[]uint32) {
	(*to) = append((*to), 1, t.CID, t.VID)
}
