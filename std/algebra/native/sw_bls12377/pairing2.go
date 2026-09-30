package sw_bls12377

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/selector"
)

// Curve allows G1 operations in BLS12-377.
type Curve struct {
	api frontend.API
	fr  *emulated.Field[ScalarField]
}

// NewCurve initializes a new [Curve] instance.
func NewCurve(api frontend.API) (*Curve, error) {
	// this is a 2-chain curve, so the base field of BLS12-377 is the scalar
	// field of BW6-761. Error early to avoid any misuse.
	if api.Compiler().Field().Cmp(fr_bw6761.Modulus()) != 0 {
		return nil, errors.New("expected BW6-761 scalar field for BLS12-377 curve operations")
	}
	f, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, errors.New("scalar field")
	}
	return &Curve{
		api: api,
		fr:  f,
	}, nil
}

// MarshalScalar returns
func (c *Curve) MarshalScalar(s Scalar, opts ...algopts.AlgebraOption) []frontend.Variable {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	nbBits := 8 * ((ScalarField{}.Modulus().BitLen() + 7) / 8)
	var ss *emulated.Element[ScalarField]
	if cfg.ToBitsCanonical {
		ss = c.fr.ReduceStrict(&s)
	} else {
		ss = c.fr.Reduce(&s)
	}
	x := c.fr.ToBits(ss)[:nbBits]
	slices.Reverse(x)
	return x
}

// MarshalG1 returns [P.X || P.Y] in binary. Both P.X and P.Y are
// in little endian.
func (c *Curve) MarshalG1(P G1Affine, opts ...algopts.AlgebraOption) []frontend.Variable {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	nbBits := 8 * ((ecc.BLS12_377.BaseField().BitLen() + 7) / 8)
	bOpts := []bits.BaseConversionOption{bits.WithNbDigits(nbBits)}
	if !cfg.ToBitsCanonical {
		bOpts = append(bOpts, bits.OmitModulusCheck())
	}
	res := make([]frontend.Variable, 2*nbBits)
	x := bits.ToBinary(c.api, P.X, bOpts...)
	y := bits.ToBinary(c.api, P.Y, bOpts...)
	for i := 0; i < nbBits; i++ {
		res[i] = x[nbBits-1-i]
		res[i+nbBits] = y[nbBits-1-i]
	}
	xZ := c.api.IsZero(P.X)
	yZ := c.api.IsZero(P.Y)
	res[1] = c.api.Mul(xZ, yZ)
	return res
}

// Add points P and Q and return the result. Does not modify the inputs.
func (c *Curve) Add(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddAssign(c.api, *Q)
	return res
}

// AddUnified adds any two points and returns the sum. It does not modify the input
// points.
func (c *Curve) AddUnified(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddUnified(c.api, *Q)
	return res
}

// AssertIsEqual asserts the equality of P and Q.
func (c *Curve) AssertIsEqual(P, Q *G1Affine) {
	P.AssertIsEqual(c.api, *Q)
}

// Neg negates P and returns the result. Does not modify P.
func (c *Curve) Neg(P *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.Neg(c.api, *P)
	return res
}

// jointScalarMul computes s1*P+s2*P2 and returns the result. It doesn't modify the
// inputs.
func (c *Curve) jointScalarMul(P1, P2 *G1Affine, s1, s2 *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{}
	varScalar1 := c.packScalarToVar(s1)
	varScalar2 := c.packScalarToVar(s2)
	res.jointScalarMul(c.api, *P1, *P2, varScalar1, varScalar2, opts...)
	return res
}

// ScalarMul computes scalar*P and returns the result. It doesn't modify the
// inputs.
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
func (c *Curve) ScalarMul(P *G1Affine, s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	varScalar := c.packScalarToVar(s)
	res.ScalarMul(c.api, *P, varScalar, opts...)
	return res
}

// ScalarMulBase computes scalar*G where G is the standard base point of the
// curve. It doesn't modify the scalar.
//
// By default, uses complete arithmetic.
//
// [algopts.WithIncompleteArithmetic] is deprecated here and ignored.
func (c *Curve) ScalarMulBase(s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := new(G1Affine)
	varScalar := c.packScalarToVar(s)
	res.ScalarMulBase(c.api, varScalar, opts...)
	return res
}

// MultiScalarMul computes ∑scalars_i * P_i and returns it. It doesn't modify
// the inputs. It returns an error if there is a mismatch in the lengths of the
// inputs.
//
// By default, uses complete arithmetic.
//
// In incomplete mode, the non-folding path inherits the exceptional set of the
// underlying joint-scalar helper and may additionally fail on sparse partial-
// sum merge collisions. The folding path inherits the exceptional set of
// scalarBitsMul and may additionally fail on sparse prefix-sum collisions.
// Accordingly, the incomplete exceptional set is implementation-dependent and
// not fully characterized at the API level.
func (c *Curve) MultiScalarMul(P []*G1Affine, scalars []*Scalar, opts ...algopts.AlgebraOption) (*G1Affine, error) {
	if len(P) == 0 {
		return &G1Affine{
			X: 0,
			Y: 0,
		}, nil
	}
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	addFn := c.Add
	if !cfg.IncompleteArithmetic {
		addFn = c.AddUnified
	}
	if !cfg.FoldMulti {
		if len(P) != len(scalars) {
			return nil, errors.New("mismatching points and scalars slice lengths")
		}
		// points and scalars must be non-zero
		n := len(P)
		var res *G1Affine
		if n%2 == 1 {
			res = c.ScalarMul(P[n-1], scalars[n-1], opts...)
		} else {
			res = c.jointScalarMul(P[n-2], P[n-1], scalars[n-2], scalars[n-1], opts...)
		}
		for i := 1; i < n-1; i += 2 {
			q := c.jointScalarMul(P[i-1], P[i], scalars[i-1], scalars[i], opts...)
			res = addFn(res, q)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(scalars) == 0 {
			return nil, errors.New("need scalar for folding")
		}
		gamma := c.packScalarToVar(scalars[0])
		// decompose gamma in the endomorphism eigenvalue basis and bit-decompose the sub-scalars
		cc := getInnerCurveConfig(c.api.Compiler().Field())
		sd, err := c.api.Compiler().NewHint(decomposeScalarG1Simple, 2, gamma)
		if err != nil {
			panic(err)
		}
		gamma1, gamma2 := sd[0], sd[1]
		c.api.AssertIsEqual(
			c.api.Add(gamma1, c.api.Mul(gamma2, cc.lambda)),
			gamma,
		)
		nbits := cc.lambda.BitLen()
		gamma1Bits := c.api.ToBinary(gamma1, nbits)
		gamma2Bits := c.api.ToBinary(gamma2, nbits)

		// points and scalars must be non-zero
		var res G1Affine
		res.scalarBitsMul(c.api, *P[len(P)-1], gamma1Bits, gamma2Bits, opts...)
		for i := len(P) - 2; i > 0; i-- {
			res = *addFn(P[i], &res)
			res.scalarBitsMul(c.api, res, gamma1Bits, gamma2Bits, opts...)
		}
		res = *addFn(P[0], &res)
		return &res, nil
	}
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (c *Curve) Select(b frontend.Variable, p1, p2 *G1Affine) *G1Affine {
	return &G1Affine{
		X: c.api.Select(b, p1.X, p2.X),
		Y: c.api.Select(b, p1.Y, p2.Y),
	}
}

// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
// Returns:
//   - p1 if b0=0 and b1=0,
//   - p2 if b0=1 and b1=0,
//   - p3 if b0=0 and b1=1,
//   - p4 if b0=1 and b1=1.
func (c *Curve) Lookup2(b1, b2 frontend.Variable, p1, p2, p3, p4 *G1Affine) *G1Affine {
	return &G1Affine{
		X: c.api.Lookup2(b1, b2, p1.X, p2.X, p3.X, p4.X),
		Y: c.api.Lookup2(b1, b2, p1.Y, p2.Y, p3.Y, p4.Y),
	}
}

// Mux performs a lookup from the inputs and returns inputs[sel]. It is most
// efficient for power of two lengths of the inputs, but works for any number of
// inputs.
func (c *Curve) Mux(sel frontend.Variable, inputs ...*G1Affine) *G1Affine {
	xs := make([]frontend.Variable, len(inputs))
	ys := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		xs[i] = inputs[i].X
		ys[i] = inputs[i].Y
	}
	return &G1Affine{
		X: selector.Mux(c.api, sel, xs...),
		Y: selector.Mux(c.api, sel, ys...),
	}
}

// Pairing allows computing pairing-related operations in BLS12-377.
type Pairing struct {
	api frontend.API
}

// NewPairing initializes a [Pairing] instance.
func NewPairing(api frontend.API) *Pairing {
	return &Pairing{
		api: api,
	}
}

// MillerLoop computes the Miller loop between the pairs of inputs. It doesn't
// modify the inputs. It returns an error if there is a mismatch between the
// lengths of the inputs.
func (pr *Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GT, error) {
	inP := make([]G1Affine, len(P))
	for i := range P {
		inP[i] = *P[i]
	}
	inQ := make([]G2Affine, len(Q))
	for i := range Q {
		inQ[i] = *Q[i]
	}
	res, err := MillerLoop(pr.api, inP, inQ)
	return &res, err
}

// FinalExponentiation performs the final exponentiation on the target group
// element. It doesn't modify the input.
func (pr *Pairing) FinalExponentiation(e *GT) *GT {
	res := FinalExponentiation(pr.api, *e)
	return &res
}

// Pair computes a full multi-pairing on the input pairs.
func (pr *Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GT, error) {
	inP := make([]G1Affine, len(P))
	for i := range P {
		inP[i] = *P[i]
	}
	inQ := make([]G2Affine, len(Q))
	for i := range Q {
		inQ[i] = *Q[i]
	}
	res, err := Pair(pr.api, inP, inQ)
	return &res, err
}

// PairingCheck computes the multi-pairing of the input pairs and asserts that
// the result is an identity element in the target group. It returns an error if
// there is a mismatch between the lengths of the inputs.
func (pr *Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	inP := make([]G1Affine, len(P))
	for i := range P {
		inP[i] = *P[i]
	}
	inQ := make([]G2Affine, len(Q))
	for i := range Q {
		inQ[i] = *Q[i]
	}
	err := PairingCheck(pr.api, inP, inQ)
	if err != nil {
		return err
	}

	return nil
}

// AssertIsEqual asserts the equality of the target group elements.
func (pr *Pairing) AssertIsEqual(e1, e2 *GT) {
	e1.AssertIsEqual(pr.api, *e2)
}

// IsEqual returns 1 if x is equal to y, 0 otherwise.
func (pr *Pairing) IsEqual(x, y *GT) frontend.Variable {
	return x.IsEqual(pr.api, *y)
}

func (pr *Pairing) MuxG2(sel frontend.Variable, inputs ...*G2Affine) *G2Affine {
	if len(inputs) == 0 {
		return nil
	}
	if len(inputs) == 1 {
		pr.api.AssertIsEqual(sel, 0)
		return inputs[0]
	}
	for i := 1; i < len(inputs); i++ {
		if (inputs[0].Lines == nil) != (inputs[i].Lines == nil) {
			panic("muxing points with and without precomputed lines")
		}
	}
	var ret G2Affine
	XA0 := make([]frontend.Variable, len(inputs))
	XA1 := make([]frontend.Variable, len(inputs))
	YA0 := make([]frontend.Variable, len(inputs))
	YA1 := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		XA0[i] = inputs[i].P.X.A0
		XA1[i] = inputs[i].P.X.A1
		YA0[i] = inputs[i].P.Y.A0
		YA1[i] = inputs[i].P.Y.A1
	}
	ret.P.X.A0 = selector.Mux(pr.api, sel, XA0...)
	ret.P.X.A1 = selector.Mux(pr.api, sel, XA1...)
	ret.P.Y.A0 = selector.Mux(pr.api, sel, YA0...)
	ret.P.Y.A1 = selector.Mux(pr.api, sel, YA1...)

	if inputs[0].Lines == nil {
		return &ret
	}

	// switch precomputed lines
	ret.Lines = new(lineEvaluations)
	for j := range inputs[0].Lines[0] {
		lineR0A0 := make([]frontend.Variable, len(inputs))
		lineR0A1 := make([]frontend.Variable, len(inputs))
		lineR1A0 := make([]frontend.Variable, len(inputs))
		lineR1A1 := make([]frontend.Variable, len(inputs))
		for k := 0; k < 2; k++ {
			for i := range inputs {
				lineR0A0[i] = inputs[i].Lines[k][j].R0.A0
				lineR0A1[i] = inputs[i].Lines[k][j].R0.A1
				lineR1A0[i] = inputs[i].Lines[k][j].R1.A0
				lineR1A1[i] = inputs[i].Lines[k][j].R1.A1
			}
			le := &lineEvaluation{
				R0: fields_bls12377.E2{
					A0: selector.Mux(pr.api, sel, lineR0A0...),
					A1: selector.Mux(pr.api, sel, lineR0A1...),
				},
				R1: fields_bls12377.E2{
					A0: selector.Mux(pr.api, sel, lineR1A0...),
					A1: selector.Mux(pr.api, sel, lineR1A1...),
				},
			}
			ret.Lines[k][j] = le
		}
	}

	return &ret
}

func (pr *Pairing) MuxGt(sel frontend.Variable, inputs ...*GT) *GT {
	if len(inputs) == 0 {
		return nil
	}
	if len(inputs) == 1 {
		pr.api.AssertIsEqual(sel, 0)
		return inputs[0]
	}
	var ret GT
	C0B0A0s := make([]frontend.Variable, len(inputs))
	C0B0A1s := make([]frontend.Variable, len(inputs))
	C0B1A0s := make([]frontend.Variable, len(inputs))
	C0B1A1s := make([]frontend.Variable, len(inputs))
	C0B2A0s := make([]frontend.Variable, len(inputs))
	C0B2A1s := make([]frontend.Variable, len(inputs))
	C1B0A0s := make([]frontend.Variable, len(inputs))
	C1B0A1s := make([]frontend.Variable, len(inputs))
	C1B1A0s := make([]frontend.Variable, len(inputs))
	C1B1A1s := make([]frontend.Variable, len(inputs))
	C1B2A0s := make([]frontend.Variable, len(inputs))
	C1B2A1s := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		C0B0A0s[i] = inputs[i].C0.B0.A0
		C0B0A1s[i] = inputs[i].C0.B0.A1
		C0B1A0s[i] = inputs[i].C0.B1.A0
		C0B1A1s[i] = inputs[i].C0.B1.A1
		C0B2A0s[i] = inputs[i].C0.B2.A0
		C0B2A1s[i] = inputs[i].C0.B2.A1
		C1B0A0s[i] = inputs[i].C1.B0.A0
		C1B0A1s[i] = inputs[i].C1.B0.A1
		C1B1A0s[i] = inputs[i].C1.B1.A0
		C1B1A1s[i] = inputs[i].C1.B1.A1
		C1B2A0s[i] = inputs[i].C1.B2.A0
		C1B2A1s[i] = inputs[i].C1.B2.A1
	}
	ret.C0.B0.A0 = selector.Mux(pr.api, sel, C0B0A0s...)
	ret.C0.B0.A1 = selector.Mux(pr.api, sel, C0B0A1s...)
	ret.C0.B1.A0 = selector.Mux(pr.api, sel, C0B1A0s...)
	ret.C0.B1.A1 = selector.Mux(pr.api, sel, C0B1A1s...)
	ret.C0.B2.A0 = selector.Mux(pr.api, sel, C0B2A0s...)
	ret.C0.B2.A1 = selector.Mux(pr.api, sel, C0B2A1s...)
	ret.C1.B0.A0 = selector.Mux(pr.api, sel, C1B0A0s...)
	ret.C1.B0.A1 = selector.Mux(pr.api, sel, C1B0A1s...)
	ret.C1.B1.A0 = selector.Mux(pr.api, sel, C1B1A0s...)
	ret.C1.B1.A1 = selector.Mux(pr.api, sel, C1B1A1s...)
	ret.C1.B2.A0 = selector.Mux(pr.api, sel, C1B2A0s...)
	ret.C1.B2.A1 = selector.Mux(pr.api, sel, C1B2A1s...)
	return &ret
}

// AssertIsOnCurve asserts if p belongs to the curve. It doesn't modify p.
func (pr *Pairing) AssertIsOnCurve(p *G1Affine) {
	// (X,Y) ∈ {Y² == X³ + 1} U (0,0)

	// if p=(0,0) we assign b=0 and continue
	selector := pr.api.And(pr.api.IsZero(p.X), pr.api.IsZero(p.Y))
	b := pr.api.Select(selector, 0, 1)

	left := pr.api.Mul(p.Y, p.Y)
	right := pr.api.Mul(p.X, pr.api.Mul(p.X, p.X))
	right = pr.api.Add(right, b)
	pr.api.AssertIsEqual(left, right)
}

func (pr *Pairing) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)

	// 2- Check P has the right subgroup order
	// [x²]ϕ(P)
	phiP := G1Affine{
		X: pr.api.Mul(P.X, "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"),
		Y: P.Y,
	}
	var _P G1Affine
	_P.scalarMulBySeed(pr.api, &phiP)
	_P.scalarMulBySeed(pr.api, &_P)
	_P.Neg(pr.api, _P)

	// [r]Q == 0 <==>  P = -[x²]ϕ(P)
	P.AssertIsEqual(pr.api, _P)
}

// AssertIsOnTwist asserts if p belongs to the curve. It doesn't modify p.
func (pr *Pairing) AssertIsOnTwist(p *G2Affine) {
	// (X,Y) ∈ {Y² == X³ + 1/u} U (0,0)

	// if p=(0,0) we assign b=0 and continue
	selector := pr.api.And(p.P.X.IsZero(pr.api), p.P.Y.IsZero(pr.api))
	var zero fields_bls12377.E2
	zero.SetZero()
	b := fields_bls12377.E2{
		A0: 0,
		A1: "155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906",
	}
	b.Select(pr.api, selector, zero, b)

	var left, right fields_bls12377.E2
	left.Square(pr.api, p.P.Y)
	right.Cube(pr.api, p.P.X)
	right.Add(pr.api, right, b)
	left.AssertIsEqual(pr.api, right)
}

func (pr *Pairing) AssertIsOnG2(P *G2Affine) {
	// 1- Check P is on the curve
	pr.AssertIsOnTwist(P)

	// 2- Check P has the right subgroup order
	// [x₀]Q
	var xP, psiP g2AffP
	xP.scalarMulBySeed(pr.api, &P.P)
	// ψ(Q)
	psiP.psi(pr.api, &P.P)

	// [r]Q == 0 <==>  ψ(Q) == [x₀]Q
	xP.AssertIsEqual(pr.api, psiP)
}

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bls12377.G1Affine) G1Affine {
	return G1Affine{
		X: (fr_bw6761.Element)(v.X),
		Y: (fr_bw6761.Element)(v.Y),
	}
}

// newG2AffP allocates a witness from the native G2 element and returns it.
func newG2AffP(v bls12377.G2Affine) g2AffP {
	return g2AffP{
		X: fields_bls12377.E2{
			A0: (fr_bw6761.Element)(v.X.A0),
			A1: (fr_bw6761.Element)(v.X.A1),
		},
		Y: fields_bls12377.E2{
			A0: (fr_bw6761.Element)(v.Y.A0),
			A1: (fr_bw6761.Element)(v.Y.A1),
		},
	}
}

func NewG2Affine(v bls12377.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bls12377.G2Affine) G2Affine {
	lines := precomputeLines(v)
	return G2Affine{
		P:     newG2AffP(v),
		Lines: &lines,
	}
}

// NewG2AffineFixedPlaceholder returns a placeholder for the circuit compilation
// when witness will be given with line precomputations using
// [NewG2AffineFixed].
func NewG2AffineFixedPlaceholder() G2Affine {
	var lines lineEvaluations
	for i := 0; i < len(bls12377.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}

// NewGTEl allocates a witness from the native target group element and returns it.
func NewGTEl(v bls12377.GT) GT {
	return GT{
		C0: fields_bls12377.E6{
			B0: fields_bls12377.E2{
				A0: (fr_bw6761.Element)(v.C0.B0.A0),
				A1: (fr_bw6761.Element)(v.C0.B0.A1),
			},
			B1: fields_bls12377.E2{
				A0: (fr_bw6761.Element)(v.C0.B1.A0),
				A1: (fr_bw6761.Element)(v.C0.B1.A1),
			},
			B2: fields_bls12377.E2{
				A0: (fr_bw6761.Element)(v.C0.B2.A0),
				A1: (fr_bw6761.Element)(v.C0.B2.A1),
			},
		},
		C1: fields_bls12377.E6{
			B0: fields_bls12377.E2{
				A0: (fr_bw6761.Element)(v.C1.B0.A0),
				A1: (fr_bw6761.Element)(v.C1.B0.A1),
			},
			B1: fields_bls12377.E2{
				A0: (fr_bw6761.Element)(v.C1.B1.A0),
				A1: (fr_bw6761.Element)(v.C1.B1.A1),
			},
			B2: fields_bls12377.E2{
				A0: (fr_bw6761.Element)(v.C1.B2.A0),
				A1: (fr_bw6761.Element)(v.C1.B2.A1),
			},
		},
	}
}

// Scalar is a scalar in the groups. As the implementation is defined on a
// 2-chain, then this type is an alias to [frontend.Variable].
type Scalar = emulated.Element[ScalarField]

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bls12377.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// packScalarToVar packs the limbs of emulated scalar to a frontend.Variable.
//
// The method is for compatibility for existing scalar multiplication
// implementation which assumes as an input frontend.Variable.
func (c *Curve) packScalarToVar(s *Scalar) frontend.Variable {
	_, nbBits := emulated.GetEffectiveFieldParams[ScalarField](c.api.Compiler().Field())
	reduced := c.fr.Reduce(s)
	var res frontend.Variable = 0
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = c.api.Add(res, c.api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res
}

// ScalarField defines the [emulated.FieldParams] implementation on a one limb of the scalar field.
type ScalarField = emparams.BLS12377Fr
