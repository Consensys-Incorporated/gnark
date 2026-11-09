// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014)
type lineEvaluation struct {
	R0, R1 fields_bls12377.E2
}
type lineEvaluations [2][len(loopCounter) - 1]*lineEvaluation

func precomputeLines(Q bls12377.G2Affine) lineEvaluations {
	var cLines lineEvaluations
	nLines := bls12377.PrecomputeLines(Q)
	for j := range cLines[0] {
		cLines[0][j] = new(lineEvaluation)
		cLines[1][j] = new(lineEvaluation)
		cLines[0][j].R0.Assign(&nLines[0][j].R0)
		cLines[0][j].R1.Assign(&nLines[0][j].R1)
		cLines[1][j].R0.Assign(&nLines[1][j].R0)
		cLines[1][j].R1.Assign(&nLines[1][j].R1)
	}
	return cLines
}

func computeLines(api frontend.API, Q g2AffP) *lineEvaluations {

	var cLines lineEvaluations
	Qacc := Q
	n := len(loopCounter)
	for i := n - 2; i >= 1; i-- {
		if loopCounter[i] == 0 {
			Qacc, cLines[0][i] = doubleStep(api, &Qacc)
		} else {
			Qacc, cLines[0][i], cLines[1][i] = doubleAndAddStep(api, &Qacc, &Q)
		}
	}
	cLines[0][0], cLines[1][0] = linesCompute(api, &Qacc, &Q)
	return &cLines
}
