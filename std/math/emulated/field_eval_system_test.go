package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type dedupAndEdgeEvalCircuit[T FieldParams] struct {
	A, B, OneWitness Element[T]
	Expected         Element[T]
	NegOneExpected   Element[T]
}

func (c *dedupAndEdgeEvalCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// Duplicate monomials {A, B} and {B, A} with coefficients -82 and -1476
	// should merge to -1558*A*B, cancelled monomials {A, A} (+5 and -5) drop,
	// Zero() factor drops, and One() factor simplifies.
	res := f.Eval(
		[][]*Element[T]{
			{&c.A, &c.B},
			{&c.B, &c.A},
			{&c.A, &c.A},
			{&c.A, &c.A},
			{&c.B, f.Zero()},
			{&c.A, f.One()},
			{f.One()},
		},
		[]int{-82, -1476, 5, -5, 999, 3, -1},
	)
	f.AssertIsEqual(res, &c.Expected)

	// Purely cancelled expression must evaluate to Zero with 0 witness hints.
	cancelled := f.Eval(
		[][]*Element[T]{{&c.A, &c.B}, {&c.B, &c.A}},
		[]int{42, -42},
	)
	f.AssertIsEqual(cancelled, f.Zero())
	f.AssertEvalIsZero(
		[][]*Element[T]{{&c.A, &c.B}, {&c.B, &c.A}},
		[]int{17, -17},
	)

	// Constant negative evaluation -1 mod p = p - 1, and witness-backed -1*OneWitness.
	constNegOne := f.Eval([][]*Element[T]{{f.One()}}, []int{-1})
	witNegOne := f.Eval([][]*Element[T]{{&c.OneWitness}}, []int{-1})
	f.AssertIsEqual(constNegOne, &c.NegOneExpected)
	f.AssertIsEqual(witNegOne, &c.NegOneExpected)
	return nil
}

func TestPolyMvPrepDedupAndZeroCancel(t *testing.T) {
	assert := test.NewAssert(t)
	mod := BN254Fp{}.Modulus()
	a, _ := rand.Int(rand.Reader, mod)
	b, _ := rand.Int(rand.Reader, mod)

	// Expected = -1558*a*b + 3*a - 1 mod p
	exp := new(big.Int).Mul(big.NewInt(-1558), new(big.Int).Mul(a, b))
	exp.Add(exp, new(big.Int).Mul(big.NewInt(3), a))
	exp.Sub(exp, big.NewInt(1))
	exp.Mod(exp, mod)
	negOne := new(big.Int).Sub(mod, big.NewInt(1))

	witness := &dedupAndEdgeEvalCircuit[BN254Fp]{
		A:              ValueOf[BN254Fp](a),
		B:              ValueOf[BN254Fp](b),
		OneWitness:     ValueOf[BN254Fp](1),
		Expected:       ValueOf[BN254Fp](exp),
		NegOneExpected: ValueOf[BN254Fp](negOne),
	}

	for _, builder := range []frontend.NewBuilder{r1cs.NewBuilder[constraint.U64], scs.NewBuilder[constraint.U64]} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &dedupAndEdgeEvalCircuit[BN254Fp]{})
		assert.NoError(err)
		w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
		assert.NoError(err)
		assert.NoError(ccs.IsSolved(w))
	}
}

type evalSystemOptCircuit[T FieldParams] struct {
	X0, X1, Y0, Y1 Element[T]
	UseSystem      bool `gnark:"-"`
	Out            [6]Element[T]
}

func (c *evalSystemOptCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// Build high-overflow lazy inputs to exercise the shared lazy-reduction loop.
	x0 := &c.X0
	y0 := &c.Y0
	bigFactor := new(big.Int).Lsh(big.NewInt(1), 10)
	x0Lazy := f.Add(f.MulConst(x0, bigFactor), f.MulConst(x0, bigFactor)) // 2048 * x0
	x0 = f.Sub(x0Lazy, f.MulConst(x0, new(big.Int).Sub(new(big.Int).Mul(bigFactor, big.NewInt(2)), big.NewInt(1))))

	specs := []PolySpec[T]{
		// Complex mul real & imag (triggers Karatsuba on R1CS)
		{At: [][]*Element[T]{{x0, y0}, {&c.X1, &c.Y1}}, Coefs: []int{1, -1}},
		{At: [][]*Element[T]{{x0, &c.Y1}, {&c.X1, y0}}, Coefs: []int{1, 1}},
		// Difference of squares shared across two outputs (triggers monomDiffSq)
		{At: [][]*Element[T]{{x0, x0}, {&c.X1, &c.X1}, {x0, &c.X1}}, Coefs: []int{27, -27, -6}},
		{At: [][]*Element[T]{{x0, x0}, {&c.X1, &c.X1}, {x0, &c.X1}}, Coefs: []int{3, -3, 54}},
		// Degree-3 cube real & imag (exercises shared degree-2 prefix caching)
		{At: [][]*Element[T]{{y0, y0, y0}, {y0, &c.Y1, &c.Y1}}, Coefs: []int{1, -3}},
		{At: [][]*Element[T]{{&c.Y1, y0, y0}, {&c.Y1, &c.Y1, &c.Y1}}, Coefs: []int{3, -1}},
	}

	if c.UseSystem {
		got := f.EvalSystem(specs)
		for i := range 6 {
			f.AssertIsEqual(got[i], &c.Out[i])
		}
	} else {
		for i := range 6 {
			got := f.Eval(specs[i].At, specs[i].Coefs)
			f.AssertIsEqual(got, &c.Out[i])
		}
	}
	return nil
}

func TestEvalSystemOptimizationAndLazyOverflow(t *testing.T) {
	assert := test.NewAssert(t)
	mod := BN254Fp{}.Modulus()
	x0, _ := rand.Int(rand.Reader, mod)
	x1, _ := rand.Int(rand.Reader, mod)
	y0, _ := rand.Int(rand.Reader, mod)
	y1, _ := rand.Int(rand.Reader, mod)

	modVal := func(z *big.Int) *big.Int { return new(big.Int).Mod(z, mod) }
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mul(a, b) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }
	add := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }

	dx2 := sub(mul(x0, x0), mul(x1, x1))
	x0x1 := mul(x0, x1)
	outs := [6]*big.Int{
		modVal(sub(mul(x0, y0), mul(x1, y1))),
		modVal(add(mul(x0, y1), mul(x1, y0))),
		modVal(sub(mul(big.NewInt(27), dx2), mul(big.NewInt(6), x0x1))),
		modVal(add(mul(big.NewInt(3), dx2), mul(big.NewInt(54), x0x1))),
		modVal(sub(mul(y0, mul(y0, y0)), mul(big.NewInt(3), mul(y0, mul(y1, y1))))),
		modVal(sub(mul(big.NewInt(3), mul(y1, mul(y0, y0))), mul(y1, mul(y1, y1)))),
	}

	witness := &evalSystemOptCircuit[BN254Fp]{
		X0: ValueOf[BN254Fp](x0),
		X1: ValueOf[BN254Fp](x1),
		Y0: ValueOf[BN254Fp](y0),
		Y1: ValueOf[BN254Fp](y1),
	}
	for i := range 6 {
		witness.Out[i] = ValueOf[BN254Fp](outs[i])
	}

	for _, tc := range []struct {
		name    string
		builder frontend.NewBuilder
	}{
		{"R1CS", r1cs.NewBuilder[constraint.U64]},
		{"SCS", scs.NewBuilder[constraint.U64]},
	} {
		ccsSep, err := frontend.Compile(ecc.BN254.ScalarField(), tc.builder, &evalSystemOptCircuit[BN254Fp]{UseSystem: false})
		assert.NoError(err)
		ccsSys, err := frontend.Compile(ecc.BN254.ScalarField(), tc.builder, &evalSystemOptCircuit[BN254Fp]{UseSystem: true})
		assert.NoError(err)

		w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
		assert.NoError(err)
		assert.NoError(ccsSep.IsSolved(w))
		assert.NoError(ccsSys.IsSolved(w))
		assert.True(ccsSys.GetNbConstraints() < ccsSep.GetNbConstraints(),
			"%s: EvalSystem (%d) should use fewer constraints than separate Eval (%d)",
			tc.name, ccsSys.GetNbConstraints(), ccsSep.GetNbConstraints())
	}
}

func mulPolyModTrinomial12Big(a, b [12]*big.Int, alpha, beta int64, mod *big.Int) [12]*big.Int {
	var c [23]*big.Int
	for t := range 23 {
		c[t] = new(big.Int)
	}
	tmp := new(big.Int)
	for i := range 12 {
		if a[i] == nil {
			continue
		}
		for j := range 12 {
			if b[j] == nil {
				continue
			}
			c[i+j].Add(c[i+j], tmp.Mul(a[i], b[j]))
		}
	}
	var d [12]*big.Int
	for u := range 12 {
		d[u] = new(big.Int).Set(c[u])
	}
	ab := alpha * beta
	a2b := alpha*alpha + beta
	for s := range 6 {
		d[s].Add(d[s], tmp.Mul(big.NewInt(beta), c[12+s]))
		d[6+s].Add(d[6+s], tmp.Mul(big.NewInt(alpha), c[12+s]))
	}
	for s := range 5 {
		d[s].Add(d[s], tmp.Mul(big.NewInt(ab), c[18+s]))
		d[6+s].Add(d[6+s], tmp.Mul(big.NewInt(a2b), c[18+s]))
	}
	for u := range 12 {
		d[u].Mod(d[u], mod)
	}
	return d
}

type trinomial12Circuit[T FieldParams] struct {
	A, B        [12]Element[T]
	Alpha, Beta int `gnark:"-"`
	OutMul      [12]Element[T]
	OutSq       [12]Element[T]
	OutSparse   [12]Element[T]
	OutEven     [12]Element[T]
}

func (c *trinomial12Circuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	var ap, bp [12]*Element[T]
	for i := range 12 {
		ap[i] = &c.A[i]
		bp[i] = &c.B[i]
	}

	gotMul := f.MulPolyModTrinomial12(ap, bp, c.Alpha, c.Beta)
	gotSq := f.MulPolyModTrinomial12(ap, ap, c.Alpha, c.Beta)
	sparseB := [12]*Element[T]{f.One(), bp[1], nil, bp[3], nil, nil, nil, bp[7], nil, bp[9], nil, nil}
	gotSparse := f.MulPolyModTrinomial12(ap, sparseB, c.Alpha, c.Beta)
	evenA := [12]*Element[T]{ap[0], f.Zero(), ap[2], f.Zero(), ap[4], f.Zero(), ap[6], f.Zero(), ap[8], f.Zero(), ap[10], f.Zero()}
	gotEven := f.MulPolyModTrinomial12(evenA, bp, c.Alpha, c.Beta)

	// Zero-polynomial check
	var nilB [12]*Element[T]
	gotZero := f.MulPolyModTrinomial12(ap, nilB, c.Alpha, c.Beta)

	for i := range 12 {
		f.AssertIsEqual(gotMul[i], &c.OutMul[i])
		f.AssertIsEqual(gotSq[i], &c.OutSq[i])
		f.AssertIsEqual(gotSparse[i], &c.OutSparse[i])
		f.AssertIsEqual(gotEven[i], &c.OutEven[i])
		f.AssertIsEqual(gotZero[i], f.Zero())
	}
	return nil
}

func TestMulPolyModTrinomial12R1CSAndSCS(t *testing.T) {
	assert := test.NewAssert(t)

	// Verify Vandermonde denominator invertibility boundary:
	// For K=11, denominators use primes <= 19, so p=17 falls back cleanly while p=23 succeeds.
	mats17 := getTrinomialVandermonde(big.NewInt(17), 18, -82, 11, false)
	assert.False(mats17.invertible)
	mats23 := getTrinomialVandermonde(big.NewInt(23), 18, -82, 11, false)
	assert.True(mats23.invertible)

	mod := BN254Fp{}.Modulus()
	var aBig, bBig [12]*big.Int
	for i := range 12 {
		aBig[i], _ = rand.Int(rand.Reader, mod)
		bBig[i], _ = rand.Int(rand.Reader, mod)
	}

	// Test both a Z-tower trinomial (18, -82) and a generic non-tower trinomial (3, -5).
	for _, params := range [][2]int{{18, -82}, {2, -2}, {3, -5}} {
		alpha, beta := params[0], params[1]
		sparseBig := [12]*big.Int{big.NewInt(1), bBig[1], nil, bBig[3], nil, nil, nil, bBig[7], nil, bBig[9], nil, nil}
		evenBig := [12]*big.Int{aBig[0], big.NewInt(0), aBig[2], big.NewInt(0), aBig[4], big.NewInt(0), aBig[6], big.NewInt(0), aBig[8], big.NewInt(0), aBig[10], big.NewInt(0)}

		outMul := mulPolyModTrinomial12Big(aBig, bBig, int64(alpha), int64(beta), mod)
		outSq := mulPolyModTrinomial12Big(aBig, aBig, int64(alpha), int64(beta), mod)
		outSparse := mulPolyModTrinomial12Big(aBig, sparseBig, int64(alpha), int64(beta), mod)
		outEven := mulPolyModTrinomial12Big(evenBig, bBig, int64(alpha), int64(beta), mod)

		circuit := &trinomial12Circuit[BN254Fp]{Alpha: alpha, Beta: beta}
		witness := &trinomial12Circuit[BN254Fp]{Alpha: alpha, Beta: beta}
		for i := range 12 {
			witness.A[i] = ValueOf[BN254Fp](aBig[i])
			witness.B[i] = ValueOf[BN254Fp](bBig[i])
			witness.OutMul[i] = ValueOf[BN254Fp](outMul[i])
			witness.OutSq[i] = ValueOf[BN254Fp](outSq[i])
			witness.OutSparse[i] = ValueOf[BN254Fp](outSparse[i])
			witness.OutEven[i] = ValueOf[BN254Fp](outEven[i])
		}

		for _, builder := range []frontend.NewBuilder{r1cs.NewBuilder[constraint.U64], scs.NewBuilder[constraint.U64]} {
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
			assert.NoError(err)
			w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
			assert.NoError(err)
			assert.NoError(ccs.IsSolved(w))
		}
	}
}

func TestSmallFieldExtensionEvalSystemAndTrinomial12(t *testing.T) {
	assert := test.NewAssert(t)
	mod := emparams.BN254Fp{}.Modulus()

	var aBig, bBig [12]*big.Int
	for i := range 12 {
		aBig[i], _ = rand.Int(rand.Reader, mod)
		bBig[i], _ = rand.Int(rand.Reader, mod)
	}
	sparseBig := [12]*big.Int{big.NewInt(1), bBig[1], nil, bBig[3], nil, nil, nil, bBig[7], nil, bBig[9], nil, nil}
	evenBig := [12]*big.Int{aBig[0], big.NewInt(0), aBig[2], big.NewInt(0), aBig[4], big.NewInt(0), aBig[6], big.NewInt(0), aBig[8], big.NewInt(0), aBig[10], big.NewInt(0)}

	outMul := mulPolyModTrinomial12Big(aBig, bBig, 18, -82, mod)
	outSq := mulPolyModTrinomial12Big(aBig, aBig, 18, -82, mod)
	outSparse := mulPolyModTrinomial12Big(aBig, sparseBig, 18, -82, mod)
	outEven := mulPolyModTrinomial12Big(evenBig, bBig, 18, -82, mod)

	circuit := &trinomial12Circuit[emparams.BN254Fp]{Alpha: 18, Beta: -82}
	witness := &trinomial12Circuit[emparams.BN254Fp]{Alpha: 18, Beta: -82}
	for i := range 12 {
		witness.A[i] = ValueOf[emparams.BN254Fp](aBig[i])
		witness.B[i] = ValueOf[emparams.BN254Fp](bBig[i])
		witness.OutMul[i] = ValueOf[emparams.BN254Fp](outMul[i])
		witness.OutSq[i] = ValueOf[emparams.BN254Fp](outSq[i])
		witness.OutSparse[i] = ValueOf[emparams.BN254Fp](outSparse[i])
		witness.OutEven[i] = ValueOf[emparams.BN254Fp](outEven[i])
	}

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(witness),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck(),
	)

	// Also verify EvalSystem over small fields (extensionApi != nil).
	x0, x1, y0, y1 := aBig[0], aBig[1], bBig[0], bBig[1]
	modVal := func(z *big.Int) *big.Int { return new(big.Int).Mod(z, mod) }
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mul(a, b) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }
	add := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }
	dx2 := sub(mul(x0, x0), mul(x1, x1))
	x0x1 := mul(x0, x1)

	sysWitness := &evalSystemOptCircuit[emparams.BN254Fp]{
		UseSystem: true,
		X0:        ValueOf[emparams.BN254Fp](x0),
		X1:        ValueOf[emparams.BN254Fp](x1),
		Y0:        ValueOf[emparams.BN254Fp](y0),
		Y1:        ValueOf[emparams.BN254Fp](y1),
		Out: [6]Element[emparams.BN254Fp]{
			ValueOf[emparams.BN254Fp](modVal(sub(mul(x0, y0), mul(x1, y1)))),
			ValueOf[emparams.BN254Fp](modVal(add(mul(x0, y1), mul(x1, y0)))),
			ValueOf[emparams.BN254Fp](modVal(sub(mul(big.NewInt(27), dx2), mul(big.NewInt(6), x0x1)))),
			ValueOf[emparams.BN254Fp](modVal(add(mul(big.NewInt(3), dx2), mul(big.NewInt(54), x0x1)))),
			ValueOf[emparams.BN254Fp](modVal(sub(mul(y0, mul(y0, y0)), mul(big.NewInt(3), mul(y0, mul(y1, y1)))))),
			ValueOf[emparams.BN254Fp](modVal(sub(mul(big.NewInt(3), mul(y1, mul(y0, y0))), mul(y1, mul(y1, y1))))),
		},
	}
	assert.CheckCircuit(
		&evalSystemOptCircuit[emparams.BN254Fp]{UseSystem: true},
		test.WithValidAssignment(sysWitness),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck(),
	)
}

type tamperTrinomialCircuit struct {
	A, B [12]Element[BN254Fp]
}

func (c *tamperTrinomialCircuit) Define(api frontend.API) error {
	f, err := NewField[BN254Fp](api)
	if err != nil {
		return err
	}
	var ap, bp [12]*Element[BN254Fp]
	for i := range 12 {
		ap[i] = &c.A[i]
		bp[i] = &c.B[i]
	}
	// Do NOT assert outputs against external public values so that ONLY the
	// internal deferred check + range checks catch hint tampering!
	_ = f.MulPolyModTrinomial12(ap, bp, 18, -82)
	return nil
}

func TestAdversarialPolyMvWitnessTamperingRejected(t *testing.T) {
	assert := test.NewAssert(t)
	mod := BN254Fp{}.Modulus()
	var aBig, bBig [12]*big.Int
	for i := range 12 {
		aBig[i], _ = rand.Int(rand.Reader, mod)
		bBig[i], _ = rand.Int(rand.Reader, mod)
	}
	witness := &tamperTrinomialCircuit{}
	for i := range 12 {
		witness.A[i] = ValueOf[BN254Fp](aBig[i])
		witness.B[i] = ValueOf[BN254Fp](bBig[i])
	}

	for _, tc := range []struct {
		name    string
		builder frontend.NewBuilder
	}{
		{"R1CS", r1cs.NewBuilder[constraint.U64]},
		{"SCS", scs.NewBuilder[constraint.U64]},
	} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), tc.builder, &tamperTrinomialCircuit{})
		assert.NoError(err)
		w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
		assert.NoError(err)
		assert.NoError(ccs.IsSolved(w))

		type tamperMode struct {
			name   string
			mutate func(nbQuo, nbRem, nbCarry int, hasKNeg bool, outputs []*big.Int)
		}
		modes := []tamperMode{
			{
				name: "tamper_quo_limb0",
				mutate: func(nbQuo, nbRem, nbCarry int, hasKNeg bool, outputs []*big.Int) {
					outputs[0].Xor(outputs[0], big.NewInt(1))
				},
			},
			{
				name: "tamper_rem_limb0",
				mutate: func(nbQuo, nbRem, nbCarry int, hasKNeg bool, outputs []*big.Int) {
					outputs[nbQuo].Xor(outputs[nbQuo], big.NewInt(1))
				},
			},
			{
				name: "tamper_low_carry",
				mutate: func(nbQuo, nbRem, nbCarry int, hasKNeg bool, outputs []*big.Int) {
					outputs[nbQuo+nbRem].Add(outputs[nbQuo+nbRem], big.NewInt(1))
				},
			},
			{
				name: "tamper_high_carry",
				mutate: func(nbQuo, nbRem, nbCarry int, hasKNeg bool, outputs []*big.Int) {
					outputs[nbQuo+nbRem+nbCarry-1].Add(outputs[nbQuo+nbRem+nbCarry-1], big.NewInt(1))
				},
			},
			{
				name: "tamper_kneg_nonboolean",
				mutate: func(nbQuo, nbRem, nbCarry int, hasKNeg bool, outputs []*big.Int) {
					if hasKNeg {
						outputs[len(outputs)-1].SetInt64(2)
					} else {
						outputs[0].Add(outputs[0], big.NewInt(1))
					}
				},
			},
		}

		for _, m := range modes {
			callCount := 0
			badHint := func(nativeMod *big.Int, inputs, outputs []*big.Int) error {
				if err := polyMvHint(nativeMod, inputs, outputs); err != nil {
					return err
				}
				callCount++
				if callCount == 1 {
					nbQuo := int(inputs[4].Int64())
					nbRem := int(inputs[5].Int64())
					nbCarry := int(inputs[6].Int64())
					hasKNeg := len(outputs) == nbQuo+nbRem+nbCarry+1
					m.mutate(nbQuo, nbRem, nbCarry, hasKNeg, outputs)
				}
				return nil
			}
			err := ccs.IsSolved(w, solver.OverrideHint(solver.GetHintID(polyMvHint), badHint))
			assert.Error(err, fmt.Sprintf("%s/%s should reject tampered polyMvHint output", tc.name, m.name))
		}
	}
}
