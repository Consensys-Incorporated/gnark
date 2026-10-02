// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package polynomial

import (
	"math/bits"

	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/internal/rational"
)

// MultiLin tracks the values of a (dense i.e. not sparse) multilinear polynomial
// The variables are X₁ through Xₙ where n = log(len(.))
// .[∑ᵢ 2ⁱ⁻¹ bₙ₋ᵢ] = the polynomial evaluated at (b₁, b₂, ..., bₙ)
// It is understood that any hypercube evaluation can be extrapolated to a multilinear polynomial
type MultiLin []rational.Element

// Fold is partial evaluation function k[X₁, X₂, ..., Xₙ] → k[X₂, ..., Xₙ] by setting X₁=r
func (m *MultiLin) Fold(r rational.Element) {
	mid := len(*m) / 2

	bottom, top := (*m)[:mid], (*m)[mid:]

	var t rational.Element // no need to update the top part

	// updating bookkeeping table
	// knowing that the polynomial f ∈ (k[X₂, ..., Xₙ])[X₁] is linear, we would get f(r) = f(0) + r(f(1) - f(0))
	// the following loop computes the evaluations of f(r) accordingly:
	//		f(r, b₂, ..., bₙ) = f(0, b₂, ..., bₙ) + r(f(1, b₂, ..., bₙ) - f(0, b₂, ..., bₙ))
	for i := 0; i < mid; i++ {
		// table[i] ← table[i] + r (table[i + mid] - table[i])
		t.Sub(&top[i], &bottom[i])
		t.Mul(&t, &r)
		bottom[i].Add(&bottom[i], &t)
	}

	*m = (*m)[:mid]
}

func (m *MultiLin) FoldParallel(r rational.Element) utils.Task {
	mid := len(*m) / 2
	bottom, top := (*m)[:mid], (*m)[mid:]

	*m = bottom

	return func(start, end int) {
		var t rational.Element // no need to update the top part
		for i := start; i < end; i++ {
			// table[i] ← table[i]  + r (table[i + mid] - table[i])
			t.Sub(&top[i], &bottom[i])
			t.Mul(&t, &r)
			bottom[i].Add(&bottom[i], &t)
		}
	}
}

func (m MultiLin) Sum() rational.Element {
	s := m[0]
	for i := 1; i < len(m); i++ {
		s.Add(&s, &m[i])
	}
	return s
}

func _clone(m MultiLin, p *Pool) MultiLin {
	if p == nil {
		return m.Clone()
	} else {
		return p.Clone(m)
	}
}

func _dump(m MultiLin, p *Pool) {
	if p != nil {
		p.Dump(m)
	}
}

// Evaluate extrapolate the value of the multilinear polynomial corresponding to m
// on the given coordinates
func (m MultiLin) Evaluate(coordinates []rational.Element, p *Pool) rational.Element {
	// Folding is a mutating operation
	bkCopy := _clone(m, p)

	// Evaluate step by step through repeated folding (i.e. evaluation at the first remaining variable)
	for _, r := range coordinates {
		bkCopy.Fold(r)
	}

	result := bkCopy[0]

	_dump(bkCopy, p)
	return result
}

// Clone creates a deep copy of a bookkeeping table.
// Both multilinear interpolation and sumcheck require folding an underlying
// array, but folding changes the array. To do both one requires a deep copy
// of the bookkeeping table.
func (m MultiLin) Clone() MultiLin {
	res := make(MultiLin, len(m))
	copy(res, m)
	return res
}

// Add two bookKeepingTables
func (m *MultiLin) Add(left, right MultiLin) {
	size := len(left)
	// Check that left and right have the same size
	if len(right) != size || len(*m) != size {
		panic("left, right and destination must have the right size")
	}

	// Add elementwise
	for i := 0; i < size; i++ {
		(*m)[i].Add(&left[i], &right[i])
	}
}

// EvalEq computes Eq(q₁, ... , qₙ, h₁, ... , hₙ) = Π₁ⁿ Eq(qᵢ, hᵢ)
// where Eq(x,y) = xy + (1-x)(1-y) = 1 - x - y + xy + xy interpolates
//
//	    _________________
//	    |       |       |
//	    |   0   |   1   |
//	    |_______|_______|
//	y   |       |       |
//	    |   1   |   0   |
//	    |_______|_______|
//
//	            x
//
// In other words the polynomial evaluated here is the multilinear extrapolation of
// one that evaluates to q' == h' for vectors q', h' of binary values
func EvalEq(q, h []rational.Element) rational.Element {
	var res, nxt, one, sum rational.Element
	one.SetOne()
	for i := 0; i < len(q); i++ {
		nxt.Mul(&q[i], &h[i]) // nxt <- qᵢ * hᵢ
		nxt.Double(&nxt)      // nxt <- 2 * qᵢ * hᵢ
		nxt.Add(&nxt, &one)   // nxt <- 1 + 2 * qᵢ * hᵢ
		sum.Add(&q[i], &h[i]) // sum <- qᵢ + hᵢ	TODO: Why not subtract one by one from nxt? More parallel?

		if i == 0 {
			res.Sub(&nxt, &sum) // nxt <- 1 + 2 * qᵢ * hᵢ - qᵢ - hᵢ
		} else {
			nxt.Sub(&nxt, &sum) // nxt <- 1 + 2 * qᵢ * hᵢ - qᵢ - hᵢ
			res.Mul(&res, &nxt) // res <- res * nxt
		}
	}
	return res
}

// Eq sets m to the representation of the polynomial Eq(q₁, ..., qₙ, *, ..., *) × m[0]
func (m *MultiLin) Eq(q []rational.Element) {
	n := len(q)

	if len(*m) != 1<<n {
		panic("destination must have size 2 raised to the size of source")
	}

	//At the end of each iteration, m(h₁, ..., hₙ) = Eq(q₁, ..., qᵢ₊₁, h₁, ..., hᵢ₊₁)
	for i := range q { // In the comments we use a 1-based index so q[i] = qᵢ₊₁
		// go through all assignments of (b₁, ..., bᵢ) ∈ {0,1}ⁱ
		for j := 0; j < (1 << i); j++ {
			j0 := j << (n - i)                 // bᵢ₊₁ = 0
			j1 := j0 + 1<<(n-1-i)              // bᵢ₊₁ = 1
			(*m)[j1].Mul(&q[i], &(*m)[j0])     // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) qᵢ₊₁
			(*m)[j0].Sub(&(*m)[j0], &(*m)[j1]) // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) (1-qᵢ₊₁)
		}
	}
}

func (m MultiLin) NumVars() int {
	return bits.TrailingZeros(uint(len(m)))
}
