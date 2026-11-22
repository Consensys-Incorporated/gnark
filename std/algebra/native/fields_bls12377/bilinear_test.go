// Copyright 2020-2026 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"math/big"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/test"
)

type noCommitAPI struct {
	frontend.API
}

// --- 1. Exact rational verification over Q & prime characteristic boundaries ---

func verifyTableExactQ(t *testing.T, tbl *rationalInterpTable) {
	t.Helper()
	n := tbl.n
	m := 2*n - 2
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			// Evaluate monomial basis product X^i * X^j at {- (n-1), ..., n-2, ∞}.
			evals := make([]*big.Rat, m+1)
			for l := 0; l < m; l++ {
				x := big.NewInt(int64(l - (n - 1)))
				p := new(big.Int).Exp(x, big.NewInt(int64(i+j)), nil)
				evals[l] = new(big.Rat).SetInt(p)
			}
			if i == n-1 && j == n-1 {
				evals[m] = big.NewRat(1, 1)
			} else {
				evals[m] = big.NewRat(0, 1)
			}

			for k := 0; k < n; k++ {
				got := new(big.Rat)
				for l := 0; l <= m; l++ {
					term := new(big.Rat).Mul(tbl.exactRats[k][l], evals[l])
					got.Add(got, term)
				}
				want := big.NewRat(0, 1)
				if i+j < n && k == i+j {
					want.SetInt64(1)
				} else if i+j >= n && k == i+j-n {
					want.SetInt64(-5)
				}
				if got.Cmp(want) != 0 {
					t.Fatalf("n=%d basis (X^%d, X^%d) coeff k=%d: got %s, want %s",
						n, i, j, k, got.RatString(), want.RatString())
				}
			}
		}
	}
}

func TestRationalInterpTablesExactOverQ(t *testing.T) {
	verifyTableExactQ(t, e6BilinearTable)
	verifyTableExactQ(t, e12BilinearTable)

	for _, badP := range []int64{2, 3, 5, 7} {
		if _, ok := e6BilinearTable.weightsForField(big.NewInt(badP)); ok {
			t.Fatalf("e6BilinearTable should reject characteristic %d", badP)
		}
	}
	if _, ok := e6BilinearTable.weightsForField(big.NewInt(11)); !ok {
		t.Fatal("e6BilinearTable must accept boundary prime 11")
	}

	for _, badP := range []int64{2, 3, 5, 7, 11, 13, 17, 19} {
		if _, ok := e12BilinearTable.weightsForField(big.NewInt(badP)); ok {
			t.Fatalf("e12BilinearTable should reject characteristic %d", badP)
		}
	}
	if _, ok := e12BilinearTable.weightsForField(big.NewInt(23)); !ok {
		t.Fatal("e12BilinearTable must accept boundary prime 23")
	}
}

// --- 2. Exhaustive 36 basis pairs for E6.Mul and 144 basis pairs for E12.Mul ---

type e6MulCheckCircuit struct {
	noCommit bool
	A, B, C  E6
}

func (c *e6MulCheckCircuit) Define(api frontend.API) error {
	if c.noCommit {
		api = noCommitAPI{api}
	}
	var r E6
	r.Mul(api, c.A, c.B)
	r.AssertIsEqual(api, c.C)
	return nil
}

type e12MulCheckCircuit struct {
	noCommit bool
	A, B, C  E12
}

func (c *e12MulCheckCircuit) Define(api frontend.API) error {
	if c.noCommit {
		api = noCommitAPI{api}
	}
	var r E12
	r.Mul(api, c.A, c.B)
	r.AssertIsEqual(api, c.C)
	return nil
}

func setE6Basis(idx int) bls12377.E6 {
	var coeffs [6]*big.Int
	for i := range coeffs {
		coeffs[i] = big.NewInt(0)
	}
	coeffs[idx].SetInt64(1)
	var e bls12377.E6
	setNativeE6(&e, coeffs[:])
	return e
}

func setE12Basis(idx int) bls12377.E12 {
	var coeffs [12]*big.Int
	for i := range coeffs {
		coeffs[i] = big.NewInt(0)
	}
	coeffs[idx].SetInt64(1)
	var e bls12377.E12
	setNativeE12(&e, coeffs[:])
	return e
}

func TestE6MulExhaustiveBasisPairs(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	ccsR1CS, err := frontend.Compile(field, r1cs.NewBuilder, &e6MulCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	ccsSCS, err := frontend.Compile(field, scs.NewBuilder, &e6MulCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	ccsSCSNoCommit, err := frontend.Compile(field, scs.NewBuilder, &e6MulCheckCircuit{noCommit: true})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 6; i++ {
		a := setE6Basis(i)
		for j := 0; j < 6; j++ {
			b := setE6Basis(j)
			var c bls12377.E6
			c.Mul(&a, &b)

			wit := &e6MulCheckCircuit{}
			wit.A.Assign(&a)
			wit.B.Assign(&b)
			wit.C.Assign(&c)
			w, err := frontend.NewWitness(wit, field)
			if err != nil {
				t.Fatalf("basis (%d,%d) witness: %v", i, j, err)
			}
			if err := ccsR1CS.IsSolved(w); err != nil {
				t.Fatalf("R1CS E6.Mul basis (%d,%d) failed: %v", i, j, err)
			}
			if err := ccsSCS.IsSolved(w); err != nil {
				t.Fatalf("SCS(SZ) E6.Mul basis (%d,%d) failed: %v", i, j, err)
			}
			if err := ccsSCSNoCommit.IsSolved(w); err != nil {
				t.Fatalf("SCS(noCommit) E6.Mul basis (%d,%d) failed: %v", i, j, err)
			}
		}
	}
}

func TestE12MulExhaustiveBasisPairs(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	ccsR1CS, err := frontend.Compile(field, r1cs.NewBuilder, &e12MulCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	ccsSCS, err := frontend.Compile(field, scs.NewBuilder, &e12MulCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	ccsSCSNoCommit, err := frontend.Compile(field, scs.NewBuilder, &e12MulCheckCircuit{noCommit: true})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 12; i++ {
		a := setE12Basis(i)
		for j := 0; j < 12; j++ {
			b := setE12Basis(j)
			var c bls12377.E12
			c.Mul(&a, &b)

			wit := &e12MulCheckCircuit{}
			wit.A.Assign(&a)
			wit.B.Assign(&b)
			wit.C.Assign(&c)
			w, err := frontend.NewWitness(wit, field)
			if err != nil {
				t.Fatalf("basis (%d,%d) witness: %v", i, j, err)
			}
			if err := ccsR1CS.IsSolved(w); err != nil {
				t.Fatalf("R1CS E12.Mul basis (%d,%d) failed: %v", i, j, err)
			}
			if err := ccsSCS.IsSolved(w); err != nil {
				t.Fatalf("SCS(SZ) E12.Mul basis (%d,%d) failed: %v", i, j, err)
			}
			if err := ccsSCSNoCommit.IsSolved(w); err != nil {
				t.Fatalf("SCS(noCommit) E12.Mul basis (%d,%d) failed: %v", i, j, err)
			}
		}
	}
}

// --- 3. Random fuzzing (250+ pairs), edge cases, sparse ops & negative checks ---

type allOpsCheckCircuit struct {
	noCommit   bool
	E6A, E6B   E6
	E6MulOut   E6
	E6SqOut    E6
	C0, C1     E2
	E6By01Out  E6
	A, B       E12
	E12MulOut  E12
	E12SqOut   E12
	C3, C4     E2
	By034Out   E12
	X5         [5]E2
	By01234Out E12
	S034In     E12
	S034Out    E12
}

func (c *allOpsCheckCircuit) Define(api frontend.API) error {
	if c.noCommit {
		api = noCommitAPI{api}
	}

	var e6Mul, e6Sq E6
	e6Mul.Mul(api, c.E6A, c.E6B)
	e6Mul.AssertIsEqual(api, c.E6MulOut)

	e6Sq.Square(api, c.E6A)
	e6Sq.AssertIsEqual(api, c.E6SqOut)

	e6By01 := c.E6A
	e6By01.MulBy01(api, c.C0, c.C1)
	e6By01.AssertIsEqual(api, c.E6By01Out)

	var e12Mul, e12Sq, s034 E12
	e12Mul.Mul(api, c.A, c.B)
	e12Mul.AssertIsEqual(api, c.E12MulOut)

	e12Sq.Square(api, c.A)
	e12Sq.AssertIsEqual(api, c.E12SqOut)

	by034 := c.A
	by034.MulBy034(api, c.C3, c.C4)
	by034.AssertIsEqual(api, c.By034Out)

	by01234 := c.A
	by01234.MulBy01234(api, c.X5)
	by01234.AssertIsEqual(api, c.By01234Out)

	s034.Square034(api, c.S034In)
	s034.AssertIsEqual(api, c.S034Out)

	return nil
}

func buildAllOpsWitness(e6a, e6b bls12377.E6, c0, c1 bls12377.E2, a, b bls12377.E12, c3, c4 bls12377.E2, x5 [5]bls12377.E2, s034A0 bls12377.E2) *allOpsCheckCircuit {
	var e6Mul, e6Sq, e6By01 bls12377.E6
	e6Mul.Mul(&e6a, &e6b)
	e6Sq.Square(&e6a)
	e6By01.Set(&e6a)
	e6By01.MulBy01(&c0, &c1)

	var e12Mul, e12Sq, by034, by01234, sparse01234, s034In, s034Out bls12377.E12
	e12Mul.Mul(&a, &b)
	e12Sq.Square(&a)

	var oneE2 bls12377.E2
	oneE2.SetOne()
	by034.Set(&a)
	by034.MulBy034(&oneE2, &c3, &c4)

	sparse01234.C0.B0 = x5[0]
	sparse01234.C0.B1 = x5[1]
	sparse01234.C0.B2 = x5[2]
	sparse01234.C1.B0 = x5[3]
	sparse01234.C1.B1 = x5[4]
	by01234.Mul(&a, &sparse01234)

	s034In.C0.B0 = s034A0
	s034In.C1.B0 = c3
	s034In.C1.B1 = c4
	s034Out.Square(&s034In)

	w := &allOpsCheckCircuit{}
	w.E6A.Assign(&e6a)
	w.E6B.Assign(&e6b)
	w.E6MulOut.Assign(&e6Mul)
	w.E6SqOut.Assign(&e6Sq)
	w.C0.Assign(&c0)
	w.C1.Assign(&c1)
	w.E6By01Out.Assign(&e6By01)
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.E12MulOut.Assign(&e12Mul)
	w.E12SqOut.Assign(&e12Sq)
	w.C3.Assign(&c3)
	w.C4.Assign(&c4)
	w.By034Out.Assign(&by034)
	for i := range x5 {
		w.X5[i].Assign(&x5[i])
	}
	w.By01234Out.Assign(&by01234)
	w.S034In.Assign(&s034In)
	w.S034Out.Assign(&s034Out)
	return w
}

func TestBilinearRandomFuzzAndEdgeCases(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	ccsR1CS, err := frontend.Compile(field, r1cs.NewBuilder, &allOpsCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	ccsSCS, err := frontend.Compile(field, scs.NewBuilder, &allOpsCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	ccsSCSNoCommit, err := frontend.Compile(field, scs.NewBuilder, &allOpsCheckCircuit{noCommit: true})
	if err != nil {
		t.Fatal(err)
	}

	solveAll := func(label string, wit *allOpsCheckCircuit) {
		t.Helper()
		w, err := frontend.NewWitness(wit, field)
		if err != nil {
			t.Fatalf("%s witness: %v", label, err)
		}
		if err := ccsR1CS.IsSolved(w); err != nil {
			t.Fatalf("%s R1CS failed: %v", label, err)
		}
		if err := ccsSCS.IsSolved(w); err != nil {
			t.Fatalf("%s SCS(SZ) failed: %v", label, err)
		}
		if err := ccsSCSNoCommit.IsSolved(w); err != nil {
			t.Fatalf("%s SCS(noCommit) failed: %v", label, err)
		}
	}

	// Edge cases: (0,0), (1,1), (-1,-1), all-(p-1), (0,rand), (1,rand), (-1,rand), s034A0=1.
	var zero6, one6, negOne6, allMax6 bls12377.E6
	one6.SetOne()
	negOne6.Sub(&zero6, &one6)
	var minusOneFp fp.Element
	minusOneFp.Sub(&minusOneFp, new(fp.Element).SetOne())
	allMax6 = bls12377.E6{
		B0: bls12377.E2{A0: minusOneFp, A1: minusOneFp},
		B1: bls12377.E2{A0: minusOneFp, A1: minusOneFp},
		B2: bls12377.E2{A0: minusOneFp, A1: minusOneFp},
	}

	var zero12, one12, negOne12, allMax12 bls12377.E12
	one12.SetOne()
	negOne12.Sub(&zero12, &one12)
	allMax12 = bls12377.E12{C0: allMax6, C1: allMax6}

	var zero2, one2, negOne2, allMax2 bls12377.E2
	one2.SetOne()
	negOne2.Sub(&zero2, &one2)
	allMax2 = bls12377.E2{A0: minusOneFp, A1: minusOneFp}

	rnd6 := randomE6()
	rnd12 := randomE12()
	var rnd2a, rnd2b bls12377.E2
	rnd2a.SetRandom()
	rnd2b.SetRandom()
	var zeroX5, maxX5, rndX5 [5]bls12377.E2
	for i := range maxX5 {
		maxX5[i] = allMax2
		rndX5[i].SetRandom()
	}

	solveAll("all-zero", buildAllOpsWitness(zero6, zero6, zero2, zero2, zero12, zero12, zero2, zero2, zeroX5, zero2))
	solveAll("all-one", buildAllOpsWitness(one6, one6, one2, one2, one12, one12, one2, one2, rndX5, one2))
	solveAll("all-neg-one", buildAllOpsWitness(negOne6, negOne6, negOne2, negOne2, negOne12, negOne12, negOne2, negOne2, rndX5, negOne2))
	solveAll("all-p-minus-1", buildAllOpsWitness(allMax6, allMax6, allMax2, allMax2, allMax12, allMax12, allMax2, allMax2, maxX5, allMax2))
	solveAll("zero-left", buildAllOpsWitness(zero6, rnd6, rnd2a, rnd2b, zero12, rnd12, rnd2a, rnd2b, rndX5, one2))
	solveAll("zero-right", buildAllOpsWitness(rnd6, zero6, zero2, zero2, rnd12, zero12, zero2, zero2, zeroX5, one2))
	solveAll("one-left", buildAllOpsWitness(one6, rnd6, one2, zero2, one12, rnd12, one2, zero2, rndX5, one2))
	solveAll("neg-one-right", buildAllOpsWitness(rnd6, negOne6, negOne2, zero2, rnd12, negOne12, negOne2, zero2, rndX5, one2))

	// 256 random pairs.
	for iter := 0; iter < 256; iter++ {
		e6a, e6b := randomE6(), randomE6()
		a, b := randomE12(), randomE12()
		var c0, c1, c3, c4, s034A0 bls12377.E2
		c0.SetRandom()
		c1.SetRandom()
		c3.SetRandom()
		c4.SetRandom()
		if iter%4 == 0 {
			s034A0.SetOne()
		} else {
			s034A0.SetRandom()
		}
		var x5 [5]bls12377.E2
		for j := range x5 {
			x5[j].SetRandom()
		}
		solveAll("fuzz", buildAllOpsWitness(e6a, e6b, c0, c1, a, b, c3, c4, x5, s034A0))
	}

	// Adversarial / negative witness checks: corrupting any single output coordinate must fail R1CS.
	ccsE6, err := frontend.Compile(field, r1cs.NewBuilder, &e6MulCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	var e6Prod bls12377.E6
	e6Prod.Mul(&rnd6, &allMax6)
	for coord := 0; coord < 6; coord++ {
		bad := e6Prod
		delta := setE6Basis(coord)
		bad.Add(&bad, &delta)
		wit := &e6MulCheckCircuit{}
		wit.A.Assign(&rnd6)
		wit.B.Assign(&allMax6)
		wit.C.Assign(&bad)
		w, _ := frontend.NewWitness(wit, field)
		if err := ccsE6.IsSolved(w); err == nil {
			t.Fatalf("R1CS E6.Mul accepted corrupted output coordinate %d", coord)
		}
	}

	ccsE12, err := frontend.Compile(field, r1cs.NewBuilder, &e12MulCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	var e12Prod bls12377.E12
	e12Prod.Mul(&rnd12, &allMax12)
	for coord := 0; coord < 12; coord++ {
		bad := e12Prod
		delta := setE12Basis(coord)
		bad.Add(&bad, &delta)
		wit := &e12MulCheckCircuit{}
		wit.A.Assign(&rnd12)
		wit.B.Assign(&allMax12)
		wit.C.Assign(&bad)
		w, _ := frontend.NewWitness(wit, field)
		if err := ccsE12.IsSolved(w); err == nil {
			t.Fatalf("R1CS E12.Mul accepted corrupted output coordinate %d", coord)
		}
	}
}

// --- 4. Self-aliasing tests across Groth16 (R1CS) & PlonK (SCS) ---

type selfAliasCircuit struct {
	X6, Y6           E6
	Z6XX, X6XY, X6YX E6
	X6Sq, X6By01     E6

	X12, Y12            E12
	Z12XX, X12XY, X12YX E12
	X12Sq, X12S034      E12
	X12By034, X12By0123 E12
}

func (c *selfAliasCircuit) Define(api frontend.API) error {
	var z6 E6
	z6.Mul(api, c.X6, c.X6)
	z6.AssertIsEqual(api, c.Z6XX)

	x6a := c.X6
	x6a.Mul(api, x6a, c.Y6)
	x6a.AssertIsEqual(api, c.X6XY)

	x6b := c.X6
	x6b.Mul(api, c.Y6, x6b)
	x6b.AssertIsEqual(api, c.X6YX)

	x6c := c.X6
	x6c.Mul(api, x6c, x6c)
	x6c.AssertIsEqual(api, c.Z6XX)

	x6sq := c.X6
	x6sq.Square(api, x6sq)
	x6sq.AssertIsEqual(api, c.X6Sq)

	x6by01 := c.X6
	x6by01.MulBy01(api, x6by01.B0, x6by01.B1)
	x6by01.AssertIsEqual(api, c.X6By01)

	var z12 E12
	z12.Mul(api, c.X12, c.X12)
	z12.AssertIsEqual(api, c.Z12XX)

	x12a := c.X12
	x12a.Mul(api, x12a, c.Y12)
	x12a.AssertIsEqual(api, c.X12XY)

	x12b := c.X12
	x12b.Mul(api, c.Y12, x12b)
	x12b.AssertIsEqual(api, c.X12YX)

	x12c := c.X12
	x12c.Mul(api, x12c, x12c)
	x12c.AssertIsEqual(api, c.Z12XX)

	x12sq := c.X12
	x12sq.Square(api, x12sq)
	x12sq.AssertIsEqual(api, c.X12Sq)

	var s034 E12
	s034.C0.B0 = c.X12.C0.B0
	s034.C1.B0 = c.X12.C1.B0
	s034.C1.B1 = c.X12.C1.B1
	s034.Square034(api, s034)
	s034.AssertIsEqual(api, c.X12S034)

	x12by034 := c.X12
	x12by034.MulBy034(api, x12by034.C1.B0, x12by034.C1.B1)
	x12by034.AssertIsEqual(api, c.X12By034)

	x12by01234 := c.X12
	x12by01234.MulBy01234(api, [5]E2{
		x12by01234.C0.B0, x12by01234.C0.B1, x12by01234.C0.B2,
		x12by01234.C1.B0, x12by01234.C1.B1,
	})
	x12by01234.AssertIsEqual(api, c.X12By0123)

	return nil
}

func TestBilinearSelfAliasing(t *testing.T) {
	x6, y6 := randomE6(), randomE6()
	var z6xx, x6xy, x6yx, x6sq, x6by01 bls12377.E6
	z6xx.Mul(&x6, &x6)
	x6xy.Mul(&x6, &y6)
	x6yx.Mul(&y6, &x6)
	x6sq.Square(&x6)
	x6by01.Set(&x6)
	x6by01.MulBy01(&x6.B0, &x6.B1)

	x12, y12 := randomE12(), randomE12()
	var z12xx, x12xy, x12yx, x12sq, s034In, x12s034, x12by034, sp01234, x12by0123 bls12377.E12
	z12xx.Mul(&x12, &x12)
	x12xy.Mul(&x12, &y12)
	x12yx.Mul(&y12, &x12)
	x12sq.Square(&x12)

	s034In.C0.B0 = x12.C0.B0
	s034In.C1.B0 = x12.C1.B0
	s034In.C1.B1 = x12.C1.B1
	x12s034.Square(&s034In)

	var one2 bls12377.E2
	one2.SetOne()
	x12by034.Set(&x12)
	x12by034.MulBy034(&one2, &x12.C1.B0, &x12.C1.B1)

	sp01234.C0 = x12.C0
	sp01234.C1.B0 = x12.C1.B0
	sp01234.C1.B1 = x12.C1.B1
	x12by0123.Mul(&x12, &sp01234)

	var wit selfAliasCircuit
	wit.X6.Assign(&x6)
	wit.Y6.Assign(&y6)
	wit.Z6XX.Assign(&z6xx)
	wit.X6XY.Assign(&x6xy)
	wit.X6YX.Assign(&x6yx)
	wit.X6Sq.Assign(&x6sq)
	wit.X6By01.Assign(&x6by01)
	wit.X12.Assign(&x12)
	wit.Y12.Assign(&y12)
	wit.Z12XX.Assign(&z12xx)
	wit.X12XY.Assign(&x12xy)
	wit.X12YX.Assign(&x12yx)
	wit.X12Sq.Assign(&x12sq)
	wit.X12S034.Assign(&x12s034)
	wit.X12By034.Assign(&x12by034)
	wit.X12By0123.Assign(&x12by0123)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&selfAliasCircuit{}, test.WithValidAssignment(&wit), test.WithCurves(ecc.BW6_761))
}

// --- 5. Tiny-prime fallback & boundary prime verification ---

type directRankGadgetCircuit struct {
	A6, B6, C6, Sq6 E6
	A12, B12, C12   E12
	Sp01A, Sp01B    E2
	C6By01          E6
	Sp01234         [5]E2
	C12By01234      E12
}

func (c *directRankGadgetCircuit) Define(api frontend.API) error {
	var r6, sq6 E6
	r6.mulRank11(api, c.A6, c.B6)
	r6.AssertIsEqual(api, c.C6)

	sq6.squareToom3(api, c.A6)
	sq6.AssertIsEqual(api, c.Sq6)

	by01 := c.A6
	by01.mulBy01Rank10(api, c.Sp01A, c.Sp01B)
	by01.AssertIsEqual(api, c.C6By01)

	var r12 E12
	r12.mulRank23(api, c.A12, c.B12)
	r12.AssertIsEqual(api, c.C12)

	by01234 := c.A12
	by01234.mulBy01234Rank22(api, c.Sp01234)
	by01234.AssertIsEqual(api, c.C12By01234)
	return nil
}

func polyMulModXPlus5(a, b []*big.Int, p *big.Int) []*big.Int {
	n := len(a)
	prod := make([]*big.Int, 2*n-1)
	for i := range prod {
		prod[i] = new(big.Int)
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			prod[i+j].Add(prod[i+j], new(big.Int).Mul(a[i], b[j]))
		}
	}
	five := big.NewInt(5)
	out := make([]*big.Int, n)
	for k := 0; k < n; k++ {
		v := new(big.Int).Set(prod[k])
		if k+n < len(prod) {
			v.Sub(v, new(big.Int).Mul(five, prod[k+n]))
		}
		v.Mod(v, p)
		out[k] = v
	}
	return out
}

func TestBilinearSmallFieldFallbackAndBoundaries(t *testing.T) {
	// Primes 3, 5, 7 trigger E6 & E12 fallbacks (and p=3 triggers squareToom3 fallback).
	// Prime 11 runs E6 mulRank11 natively while triggering E12 fallback.
	// Prime 19 runs E6 mulRank11 natively while triggering E12 fallback.
	// Prime 23 is the exact threshold prime where E12 mulRank23 runs natively.
	// Prime 47 is tinyfield.Modulus() where full R1CS U32 compilation is also supported.
	for _, pInt := range []int64{3, 5, 7, 11, 19, 23, 47} {
		p := big.NewInt(pInt)
		a6Mono := make([]*big.Int, 6)
		b6Mono := make([]*big.Int, 6)
		for i := 0; i < 6; i++ {
			a6Mono[i] = new(big.Int).Mod(big.NewInt(int64(2*i+1)), p)
			b6Mono[i] = new(big.Int).Mod(big.NewInt(int64(3*i+2)), p)
		}
		c6Mono := polyMulModXPlus5(a6Mono, b6Mono, p)
		sq6Mono := polyMulModXPlus5(a6Mono, a6Mono, p)

		sp01Mono := []*big.Int{
			new(big.Int).Mod(big.NewInt(1), p),
			new(big.Int).Mod(big.NewInt(2), p),
			big.NewInt(0),
			new(big.Int).Mod(big.NewInt(3), p),
			new(big.Int).Mod(big.NewInt(4), p),
			big.NewInt(0),
		}
		c6By01Mono := polyMulModXPlus5(a6Mono, sp01Mono, p)

		a12Mono := make([]*big.Int, 12)
		b12Mono := make([]*big.Int, 12)
		sp12Mono := make([]*big.Int, 12)
		for i := 0; i < 12; i++ {
			a12Mono[i] = new(big.Int).Mod(big.NewInt(int64(i+1)), p)
			b12Mono[i] = new(big.Int).Mod(big.NewInt(int64(5*i+3)), p)
			sp12Mono[i] = new(big.Int).Mod(big.NewInt(int64(i+2)), p)
		}
		sp12Mono[5] = big.NewInt(0)
		sp12Mono[11] = big.NewInt(0)
		c12Mono := polyMulModXPlus5(a12Mono, b12Mono, p)
		c12By01234Mono := polyMulModXPlus5(a12Mono, sp12Mono, p)

		toVars := func(xs []*big.Int) []frontend.Variable {
			v := make([]frontend.Variable, len(xs))
			for i, x := range xs {
				v[i] = new(big.Int).Set(x)
			}
			return v
		}
		var wit directRankGadgetCircuit
		var d6 [6]frontend.Variable
		copy(d6[:], toVars(a6Mono))
		assignMonomialE6(&wit.A6, d6)
		copy(d6[:], toVars(b6Mono))
		assignMonomialE6(&wit.B6, d6)
		copy(d6[:], toVars(c6Mono))
		assignMonomialE6(&wit.C6, d6)
		copy(d6[:], toVars(sq6Mono))
		assignMonomialE6(&wit.Sq6, d6)
		wit.Sp01A = E2{A0: sp01Mono[0], A1: sp01Mono[3]}
		wit.Sp01B = E2{A0: sp01Mono[1], A1: sp01Mono[4]}
		copy(d6[:], toVars(c6By01Mono))
		assignMonomialE6(&wit.C6By01, d6)

		var d12 [12]frontend.Variable
		copy(d12[:], toVars(a12Mono))
		assignMonomialE12(&wit.A12, d12)
		copy(d12[:], toVars(b12Mono))
		assignMonomialE12(&wit.B12, d12)
		copy(d12[:], toVars(c12Mono))
		assignMonomialE12(&wit.C12, d12)
		var spE12 E12
		copy(d12[:], toVars(sp12Mono))
		assignMonomialE12(&spE12, d12)
		wit.Sp01234 = [5]E2{spE12.C0.B0, spE12.C0.B1, spE12.C0.B2, spE12.C1.B0, spE12.C1.B1}
		copy(d12[:], toVars(c12By01234Mono))
		assignMonomialE12(&wit.C12By01234, d12)

		if err := test.IsSolved(&directRankGadgetCircuit{}, &wit, p); err != nil {
			t.Fatalf("tiny prime p=%d failed: %v", pInt, err)
		}
	}

	// Verify R1CS compilation over tinyfield.Modulus() (p = 47 > 19) achieves exact rank 11 and 23.
	ccs6Tiny, err := frontend.CompileGeneric[constraint.U32](tinyfield.Modulus(), r1cs.NewBuilder, &pureOpCircuit{op: "E6.Mul"}, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatalf("compile E6.Mul over F_47: %v", err)
	}
	if got := ccs6Tiny.GetNbConstraints(); got != 11 {
		t.Fatalf("E6.Mul over F_47 R1CS constraints = %d, want 11", got)
	}

	ccs12Tiny, err := frontend.CompileGeneric[constraint.U32](tinyfield.Modulus(), r1cs.NewBuilder, &pureOpCircuit{op: "E12.Mul"}, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatalf("compile E12.Mul over F_47: %v", err)
	}
	if got := ccs12Tiny.GetNbConstraints(); got != 23 {
		t.Fatalf("E12.Mul over F_47 R1CS constraints = %d, want 23", got)
	}
}

// --- 6. Exact R1CS & SCS constraint count assertions ---

type pureOpCircuit struct {
	op       string
	noCommit bool
	E2A, E2B E2
	E6A, E6B E6
	A, B     E12
	X5       [5]E2
}

func (c *pureOpCircuit) Define(api frontend.API) error {
	if c.noCommit {
		api = noCommitAPI{api}
	}
	switch c.op {
	case "E6.Mul":
		var r E6
		r.Mul(api, c.E6A, c.E6B)
	case "E6.Square":
		var r E6
		r.Square(api, c.E6A)
	case "E6.MulBy01":
		r := c.E6A
		r.MulBy01(api, c.E2A, c.E2B)
	case "E12.Mul":
		var r E12
		r.Mul(api, c.A, c.B)
	case "E12.Square":
		var r E12
		r.Square(api, c.A)
	case "E12.MulBy034":
		r := c.A
		r.MulBy034(api, c.E2A, c.E2B)
	case "E12.MulBy01234":
		r := c.A
		r.MulBy01234(api, c.X5)
	case "E12.Square034":
		var r E12
		r.Square034(api, c.A)
	case "E12.ExpX0":
		var r E12
		r.ExpX0(api, c.A)
	case "E12.ExpX0Minus1Square":
		var r E12
		r.ExpX0Minus1Square(api, c.A)
	case "E12.ExpU":
		var r E12
		r.ExpU(api, c.A)
	}
	return nil
}

func TestBilinearConstraintCounts(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	cases := []struct {
		op          string
		wantR1CS    int
		wantSCSSZ   int
		wantSCSNoSZ int
	}{
		{"E6.Mul", 11, 73, 66},
		{"E6.Square", 10, 57, 43},
		{"E6.MulBy01", 10, 67, 46},
		{"E12.Mul", 23, 151, 228},
		{"E12.Square", 22, 117, 156},
		{"E12.MulBy034", 20, 129, 102},
		{"E12.MulBy01234", 22, 145, 206},
		{"E12.Square034", 14, 91, 40},
		{"E12.ExpX0", 1048, 4843, 5333},
		{"E12.ExpX0Minus1Square", 2234, 9132, 10124},
		{"E12.ExpU", 2262, 9214, 10174},
	}

	for _, tc := range cases {
		cR1CS, err := frontend.Compile(field, r1cs.NewBuilder, &pureOpCircuit{op: tc.op}, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			t.Fatalf("%s R1CS compile: %v", tc.op, err)
		}
		cSCSSZ, err := frontend.Compile(field, scs.NewBuilder, &pureOpCircuit{op: tc.op}, frontend.IgnoreUnconstrainedInputs())
		if err != nil {
			t.Fatalf("%s SCS(SZ) compile: %v", tc.op, err)
		}
		cSCSNoSZ, err := frontend.Compile(field, scs.NewBuilder, &pureOpCircuit{op: tc.op, noCommit: true}, frontend.IgnoreUnconstrainedInputs())
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

type dirtySquare034Circuit struct {
	noCommit         bool
	Dirty, S034In    E12
	WantS034         E12
}

func (c *dirtySquare034Circuit) Define(api frontend.API) error {
	if c.noCommit {
		api = noCommitAPI{api}
	}
	r := c.Dirty
	r.Square034(api, c.S034In)
	r.AssertIsEqual(api, c.WantS034)
	return nil
}

func TestBilinearConcurrentCacheU32SolveAndDirtySquare034(t *testing.T) {
	// 1. Concurrent multi-goroutine cache fill + circuit compilation stress test.
	freshTable6 := newRationalInterpTable(6)
	freshTable12 := newRationalInterpTable(12)
	primes := []*big.Int{
		big.NewInt(5),
		big.NewInt(11),
		big.NewInt(19),
		big.NewInt(23),
		big.NewInt(47),
		ecc.BW6_761.ScalarField(),
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for step := 0; step < 8; step++ {
				p := primes[(gid+step)%len(primes)]
				_, _ = freshTable6.weightsForField(p)
				_, _ = freshTable12.weightsForField(p)
			}
			_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &allOpsCheckCircuit{}, frontend.IgnoreUnconstrainedInputs())
			if err != nil {
				errCh <- err
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent compile failed: %v", err)
	}

	// 2. Actual witness solving over constraint.U32 (F_47) with non-zero W^10, W^11
	// exercising 64-bit evaluation constants (> 2^32) reduced into U32.
	pTiny := tinyfield.Modulus()
	ccs12U32, err := frontend.CompileGeneric[constraint.U32](pTiny, r1cs.NewBuilder, &e12MulCheckCircuit{})
	if err != nil {
		t.Fatalf("compile e12MulCheckCircuit over F_47 U32: %v", err)
	}
	a12 := make([]*big.Int, 12)
	b12 := make([]*big.Int, 12)
	for i := 0; i < 12; i++ {
		a12[i] = new(big.Int).Mod(big.NewInt(int64(3*i+5)), pTiny)
		b12[i] = new(big.Int).Mod(big.NewInt(int64(7*i+11)), pTiny)
	}
	c12 := polyMulModXPlus5(a12, b12, pTiny)
	var witU32 e12MulCheckCircuit
	var d12 [12]frontend.Variable
	for i := 0; i < 12; i++ {
		d12[i] = new(big.Int).Set(a12[i])
	}
	assignMonomialE12(&witU32.A, d12)
	for i := 0; i < 12; i++ {
		d12[i] = new(big.Int).Set(b12[i])
	}
	assignMonomialE12(&witU32.B, d12)
	for i := 0; i < 12; i++ {
		d12[i] = new(big.Int).Set(c12[i])
	}
	assignMonomialE12(&witU32.C, d12)

	wU32, err := frontend.NewWitness(&witU32, pTiny)
	if err != nil {
		t.Fatalf("NewWitness F_47 U32: %v", err)
	}
	if err := ccs12U32.IsSolved(wU32); err != nil {
		t.Fatalf("U32 E12.Mul IsSolved failed: %v", err)
	}
	// Corrupting C.C1.B2.A1 must fail U32 IsSolved.
	witU32.C.C1.B2.A1 = new(big.Int).Mod(new(big.Int).Add(c12[11], big.NewInt(1)), pTiny)
	wU32Bad, _ := frontend.NewWitness(&witU32, pTiny)
	if err := ccs12U32.IsSolved(wU32Bad); err == nil {
		t.Fatal("U32 E12.Mul accepted corrupted output coordinate")
	}

	// 3. Dirty receiver Square034 must explicitly zero C1.B2 across R1CS, SCS(SZ), and SCS(noCommit).
	dirty := randomE12()
	if dirty.C1.B2.IsZero() {
		dirty.C1.B2.SetOne()
	}
	var s034In, s034Out bls12377.E12
	s034In.C0.B0 = dirty.C0.B0
	s034In.C1.B0 = dirty.C1.B0
	s034In.C1.B1 = dirty.C1.B1
	s034Out.Square(&s034In)

	field := ecc.BW6_761.ScalarField()
	for _, nc := range []bool{false, true} {
		var witDirty dirtySquare034Circuit
		witDirty.Dirty.Assign(&dirty)
		witDirty.S034In.Assign(&s034In)
		witDirty.WantS034.Assign(&s034Out)
		wDirty, err := frontend.NewWitness(&witDirty, field)
		if err != nil {
			t.Fatal(err)
		}
		if !nc {
			cR1, err := frontend.Compile(field, r1cs.NewBuilder, &dirtySquare034Circuit{})
			if err != nil {
				t.Fatal(err)
			}
			if err := cR1.IsSolved(wDirty); err != nil {
				t.Fatalf("R1CS dirty Square034 failed: %v", err)
			}
		}
		cSCS, err := frontend.Compile(field, scs.NewBuilder, &dirtySquare034Circuit{noCommit: nc})
		if err != nil {
			t.Fatal(err)
		}
		if err := cSCS.IsSolved(wDirty); err != nil {
			t.Fatalf("SCS(noCommit=%v) dirty Square034 failed: %v", nc, err)
		}
	}
}
