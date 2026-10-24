/*
	Original Copyright 2015 https://gitlab.com/NebulousLabs
*/

/*
The MIT License (MIT)

Copyright (c) 2015 Nebulous

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package merkle provides a ZKP-circuit function to verify merkle proofs.
package merkle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// MerkleProof stores the path, the root hash and an helper for the Merkle proof.
type MerkleProof struct {

	// RootHash root of the Merkle tree
	RootHash frontend.Variable

	// Path path of the Merkle proof
	Path []frontend.Variable
}

// leafSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func leafSum(api frontend.API, h hash.FieldHasher, data frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(data)
	res := h.Sum()

	return res
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(api frontend.API, h hash.FieldHasher, a, b frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(a, b)
	res := h.Sum()

	return res
}

// VerifyProof encodes constraints that verify inclusion of a leaf at the given
// index into the Merkle root stored in mp.RootHash, using the authentication
// path stored in mp.Path. The argument leaf is the leaf index (little-endian
// bit order). The actual leaf value must be provided as mp.Path[0]. This
// method does not return a value; it asserts equality of the recomputed root
// and mp.RootHash via constraints.
func (mp *MerkleProof) VerifyProof(api frontend.API, h hash.FieldHasher, leaf frontend.Variable) {

	depth := len(mp.Path) - 1
	sum := leafSum(api, h, mp.Path[0])

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(leaf, depth)

	for i := 1; i < len(mp.Path); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mp.Path[i])
		sum = nodeSum(api, h, d1, d2)
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(sum, mp.RootHash)
}
