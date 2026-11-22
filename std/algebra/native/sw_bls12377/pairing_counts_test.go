// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type noCommitPairingAPI struct {
	frontend.API
}

type pairingCountCircuit struct {
	op       string
	noCommit bool
	ML       GT
	P1, P2   G1Affine
	Q1, Q2   G2Affine
	QF1, QF2 G2Affine `gnark:"-"`
}

func (c *pairingCountCircuit) Define(api frontend.API) error {
	if c.noCommit {
		api = noCommitPairingAPI{api}
	}
	switch c.op {
	case "FinalExponentiation":
		_ = FinalExponentiation(api, c.ML)
	case "MillerLoop_1":
		_, err := MillerLoop(api, []G1Affine{c.P1}, []G2Affine{c.Q1})
		return err
	case "MillerLoop_2":
		_, err := MillerLoop(api, []G1Affine{c.P1, c.P2}, []G2Affine{c.Q1, c.Q2})
		return err
	case "Pair_1":
		_, err := Pair(api, []G1Affine{c.P1}, []G2Affine{c.Q1})
		return err
	case "Pair_2":
		_, err := Pair(api, []G1Affine{c.P1, c.P2}, []G2Affine{c.Q1, c.Q2})
		return err
	case "Pair_1_FixedQ":
		_, err := Pair(api, []G1Affine{c.P1}, []G2Affine{c.QF1})
		return err
	case "Pair_2_FixedQ":
		_, err := Pair(api, []G1Affine{c.P1, c.P2}, []G2Affine{c.QF1, c.QF2})
		return err
	case "PairingCheck_2":
		return PairingCheck(api, []G1Affine{c.P1, c.P2}, []G2Affine{c.Q1, c.Q2})
	case "PairingCheck_2_FixedQ":
		return PairingCheck(api, []G1Affine{c.P1, c.P2}, []G2Affine{c.QF1, c.QF2})
	}
	return nil
}

func TestPairingConstraintCounts(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	_, _, _, qGen := bls12377.Generators()
	var q2 bls12377.G2Affine
	q2.Double(&qGen)

	cases := []struct {
		op          string
		wantR1CS    int
		wantSCSSZ   int
		wantSCSNoSZ int
	}{
		{"FinalExponentiation", 5722, 24370, 27852},
		{"MillerLoop_1", 4544, 13951, 20468},
		{"MillerLoop_2", 7766, 23310, 31563},
		{"Pair_1", 10266, 38278, 48320},
		{"Pair_2", 13488, 47637, 59415},
		{"Pair_1_FixedQ", 8381, 33855, 43570},
		{"Pair_2_FixedQ", 9718, 38802, 49933},
		{"PairingCheck_2", 8027, 24208, 33502},
		{"PairingCheck_2_FixedQ", 4257, 15368, 24002},
	}

	for _, tc := range cases {
		mk := func(nc bool) *pairingCountCircuit {
			return &pairingCountCircuit{
				op:       tc.op,
				noCommit: nc,
				QF1:      NewG2AffineFixed(qGen),
				QF2:      NewG2AffineFixed(q2),
			}
		}
		cR1CS, err := frontend.Compile(field, r1cs.NewBuilder, mk(false), frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			t.Fatalf("%s R1CS compile: %v", tc.op, err)
		}
		cSCSSZ, err := frontend.Compile(field, scs.NewBuilder, mk(false), frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			t.Fatalf("%s SCS(SZ) compile: %v", tc.op, err)
		}
		cSCSNoSZ, err := frontend.Compile(field, scs.NewBuilder, mk(true), frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			t.Fatalf("%s SCS(noCommit) compile: %v", tc.op, err)
		}

		if got := cR1CS.GetNbConstraints(); got != tc.wantR1CS {
			t.Errorf("%s R1CS constraints = %d, want %d", tc.op, got, tc.wantR1CS)
		}
		if got := cSCSSZ.GetNbConstraints(); got != tc.wantSCSSZ {
			t.Errorf("%s SCS(SZ) constraints = %d, want %d", tc.op, got, tc.wantSCSSZ)
		}
		if got := cSCSNoSZ.GetNbConstraints(); got != tc.wantSCSNoSZ {
			t.Errorf("%s SCS(noCommit) constraints = %d, want %d", tc.op, got, tc.wantSCSNoSZ)
		}
	}
}
