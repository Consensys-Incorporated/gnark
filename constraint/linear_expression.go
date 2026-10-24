// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

// A LinearExpression is a linear combination of Term
type LinearExpression []Term

// Clone returns a copy of the underlying slice
func (l LinearExpression) Clone() LinearExpression {
	res := make(LinearExpression, len(l))
	copy(res, l)
	return res
}

func (l LinearExpression) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteLinearExpression(l)
	return sbb.String()
}

func (l LinearExpression) Compress(to *[]uint32) {
	(*to) = append((*to), uint32(len(l)))
	for i := 0; i < len(l); i++ {
		(*to) = append((*to), l[i].CID, l[i].VID)
	}
}
