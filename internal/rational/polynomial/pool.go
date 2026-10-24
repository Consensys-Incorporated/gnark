// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package polynomial

import (
	"github.com/consensys/gnark/internal/rational"
)

// Do as little as possible to instantiate the interface
type Pool struct {
}

func NewPool(...int) (pool Pool) {
	return Pool{}
}

func (p *Pool) Make(n int) []rational.Element {
	return make([]rational.Element, n)
}

func (p *Pool) Dump(...[]rational.Element) {
}

func (p *Pool) Clone(slice []rational.Element) []rational.Element {
	res := p.Make(len(slice))
	copy(res, slice)
	return res
}
