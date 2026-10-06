package gkrcore

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/utils"
)

// GateOp represents an arithmetic operation in a compiled gate.
type GateOp uint8

const (
	OpAdd      GateOp = iota // result = src1 + src2 + ... (variadic)
	OpSub                    // result = src1 - src2 - ...
	OpMul                    // result = src1 * src2 * ...
	OpNeg                    // result = -src1
	_                        // retired: the multiply-accumulate that read its addend first
	OpSumExp17               // result = (src1 + src2 + src3)^17
	OpMulAcc                 // result = (src1 * src2) + src3
)

// GateInstruction represents a single operation in a compiled gate.
// Each instruction produces a new variable (no explicit dst field).
// Index space layout:
//   - [0, nbConsts): constant values (from GateBytecode.Constants)
//   - [nbConsts, nbConsts+nbInputs): gate inputs
//   - [nbConsts+nbInputs, ...): instruction results
type GateInstruction struct {
	Op     GateOp
	Inputs []uint16 // indices into the unified value space
}

// GateBytecode represents a gate executable compiled into a sequence of instructions.
// The compiled form is independent of curve-specific types and can be serialized.
// The index space is unified: constants (0..nbConsts-1), inputs (nbConsts..nbConsts+nbInputs-1),
// then instruction results.
type GateBytecode struct {
	Instructions []GateInstruction // sequence of operations
	Constants    []*big.Int        // constant values at indices [0, nbConsts)
}

// IdentityBytecode returns the compiled form of the identity gate (x → x).
// A GateBytecode with no instructions returns its sole input directly.
func IdentityBytecode() GateBytecode {
	return GateBytecode{}
}

// NbConstants returns the number of constants in the gate
func (g *GateBytecode) NbConstants() int {
	return len(g.Constants)
}

// EvaluatorSize returns the scratch size a gateEvaluator needs to evaluate this
// gate on nbIn inputs: one slot per constant, per input, and per instruction.
func (g GateBytecode) EvaluatorSize(nbIn int) int {
	return g.NbConstants() + nbIn + len(g.Instructions)
}

// EstimateDegree returns an upper bound on the degree of the gate
func (g *GateBytecode) EstimateDegree(nbIn int) int {
	frameSize := len(g.Constants) + nbIn
	deg := make([]int, frameSize+len(g.Instructions))
	for i := range nbIn {
		deg[i+len(g.Constants)] = 1
	}
	for i, inst := range g.Instructions {
		var curr int
		switch inst.Op {
		case OpAdd, OpSub, OpNeg, OpSumExp17:
			for _, in := range inst.Inputs {
				curr = max(curr, deg[in])
			}
		case OpMul:
			for _, in := range inst.Inputs {
				curr += deg[in]
			}
		case OpMulAcc: // a*b + c
			curr = max(deg[inst.Inputs[0]]+deg[inst.Inputs[1]], deg[inst.Inputs[2]])
		default:
			panic("unknown operation")
		}
		if inst.Op == OpSumExp17 {
			curr *= 17
		}
		deg[frameSize+i] = curr
	}
	return deg[len(deg)-1]
}

// String returns a human-readable representation of the operation
func (op GateOp) String() string {
	switch op {
	case OpAdd:
		return "add"
	case OpSub:
		return "sub"
	case OpMul:
		return "mul"
	case OpNeg:
		return "neg"
	case OpMulAcc:
		return "mulacc"
	case OpSumExp17:
		return "sumexp17"
	default:
		return "unknown"
	}
}

// gateCompiler is an implementation of gkr.GateAPI that records operations
// instead of executing them. This is used to compile gate functions into
// instruction sequences. During compilation, temporary indices are used:
//   - Constants: high indices (starting at 0x8000)
//   - Inputs: 0..nbInputs-1
//   - Results: nbInputs onwards
//
// After compilation, indices are remapped to: constants, inputs, results.
type gateCompiler struct {
	instructions  []GateInstruction // each instruction defines exactly one output variable
	constants     []*big.Int        // constant values pool
	constantIndex map[string]uint16 // map from constant value to its temp index (0x8000+)
	nbInputs      int
}

const constMarker = 0x8000

// compilationVar represents a variable during gate compilation.
type compilationVar struct {
	id uint16
}

func (gc *gateCompiler) addInstruction(op GateOp, inputs ...frontend.Variable) compilationVar {
	ins := make([]uint16, len(inputs))
	for i := range ins {
		ins[i] = gc.getVarID(inputs[i])
	}

	result := compilationVar{id: uint16(len(gc.instructions) + gc.nbInputs)}

	gc.instructions = append(gc.instructions, GateInstruction{
		Op:     op,
		Inputs: ins,
	})

	return result
}

func (gc *gateCompiler) addInstruction2Plus(op GateOp, i1, i2 frontend.Variable, in ...frontend.Variable) compilationVar {
	ins := make([]frontend.Variable, len(in)+2)
	ins[0] = i1
	ins[1] = i2
	copy(ins[2:], in)
	return gc.addInstruction(op, ins...)
}

// Add records an addition operation. Its constant operands are summed into one, placed first. An
// addition of constants alone is itself a constant.
func (gc *gateCompiler) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.recordCommutative(OpAdd, new(big.Int), (*big.Int).Add, i1, i2, in)
}

// MulAcc records a multiply-accumulate operation: a + (b * c). The instruction reads the
// multiplicands first and the addend last, with a constant multiplicand before the other.
func (gc *gateCompiler) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	if _, ok := constantValue(c); ok {
		b, c = c, b
	}
	return gc.addInstruction(OpMulAcc, b, c, a)
}

// Neg records a negation operation
func (gc *gateCompiler) Neg(i1 frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpNeg, i1)
}

// Sub records a subtraction operation. A constant minuend absorbs the constant subtrahends;
// otherwise they are summed into one, placed last. A subtraction of constants alone is itself a
// constant.
func (gc *gateCompiler) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	operands := append([]frontend.Variable{i1, i2}, in...)
	minuend, minuendIsConst := constantValue(operands[0])

	sum := new(big.Int) // of the constant subtrahends
	nbKept := 1
	for _, v := range operands[1:] {
		if c, ok := constantValue(v); ok {
			sum.Add(sum, c)
		} else {
			operands[nbKept] = v
			nbKept++
		}
	}
	hasConst := nbKept < len(operands)
	operands = operands[:nbKept]

	if minuendIsConst {
		diff := minuend.Sub(minuend, sum)
		if nbKept == 1 {
			return diff
		}
		operands[0] = diff
	} else if hasConst {
		operands = append(operands, sum)
	}
	return gc.addInstruction(OpSub, operands...)
}

// Mul records a multiplication operation. Its constant operands are multiplied into one, placed
// first. A multiplication of constants alone is itself a constant.
func (gc *gateCompiler) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.recordCommutative(OpMul, big.NewInt(1), (*big.Int).Mul, i1, i2, in)
}

// recordCommutative records op over the operands i1, i2, in, with the constants among them folded
// into one by combine, starting from identity, and placed first. If all operands are constants, it
// returns the folded constant.
func (gc *gateCompiler) recordCommutative(op GateOp, identity *big.Int, combine func(z, x, y *big.Int) *big.Int, i1, i2 frontend.Variable, in []frontend.Variable) frontend.Variable {
	folded := identity
	hasConst := false
	var vars []frontend.Variable
	for _, v := range append([]frontend.Variable{i1, i2}, in...) {
		if c, ok := constantValue(v); ok {
			folded = combine(new(big.Int), folded, c)
			hasConst = true
		} else {
			vars = append(vars, v)
		}
	}
	if len(vars) == 0 {
		return folded
	}
	if hasConst {
		vars = append(vars, vars[0])
		vars[0] = folded
	}
	return gc.addInstruction(op, vars...)
}

// SumExp17 records (a + b + c)^17 as a single instruction. If any of a, b, c is a constant, the
// first one found is read first. Constants are not merged.
func (gc *gateCompiler) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	operands := []frontend.Variable{a, b, c}
	for i, v := range operands {
		if _, ok := constantValue(v); ok {
			operands[0], operands[i] = operands[i], operands[0]
			break
		}
	}
	return gc.addInstruction(OpSumExp17, operands...)
}

// constantValue returns v's value if v is a constant, that is, not a variable of the gate.
func constantValue(v frontend.Variable) (*big.Int, bool) {
	if _, ok := v.(compilationVar); ok {
		return nil, false
	}
	val := utils.FromInterface(v)
	return &val, true
}

// getVarID extracts or creates a temporary index from a value.
// Returns a temporary index: inputs at 0..nbInputs-1, constants at 0x8000+, results at nbInputs+.
func (gc *gateCompiler) getVarID(v frontend.Variable) uint16 {
	if rv, ok := v.(compilationVar); ok {
		return rv.id
	}

	// Otherwise, it must be a constant value
	// Convert to big.Int for curve-agnostic storage
	val := utils.FromInterface(v)

	// Check if we've seen this constant before
	key := val.String()
	if idx, exists := gc.constantIndex[key]; exists {
		return idx
	}

	// Add new constant to the pool with temp index 0x8000+
	tempIdx := uint16(len(gc.constants)) | constMarker
	gc.constants = append(gc.constants, new(big.Int).Set(&val))
	gc.constantIndex[key] = tempIdx
	return tempIdx
}

// GetInstructions returns the recorded instructions
func (gc *gateCompiler) GetInstructions() []GateInstruction {
	return gc.instructions
}

// GetNbInputs returns the number of inputs
func (gc *gateCompiler) GetNbInputs() int {
	return gc.nbInputs
}

// remapIndices transforms temporary indices to final layout: constants, inputs, results.
func (gc *gateCompiler) remapIndices() {
	nbConsts := uint16(len(gc.constants))

	// Remap all instruction inputs
	for i := range gc.instructions {
		for j := range gc.instructions[i].Inputs {
			if gc.instructions[i].Inputs[j]&constMarker != 0 {
				// constant
				gc.instructions[i].Inputs[j] &= ^uint16(constMarker)
			} else {
				// variable
				gc.instructions[i].Inputs[j] += nbConsts
			}
		}
	}
}

// CompileGateFunction converts a gate function into a SerializableGate.
// This consists of compiling into bytecode as well as computing gate metadata
// such as degree and solvable var index for the given field.
func CompileGateFunction(f gkr.GateFunction, nbInputs int, field Field) (SerializableGate, error) {
	// Create compiling API
	compiler := gateCompiler{
		constantIndex: make(map[string]uint16),
		nbInputs:      nbInputs,
	}

	// Create input variables
	inputs := make([]frontend.Variable, nbInputs)
	for i := range uint16(nbInputs) {
		inputs[i] = compilationVar{i}
	}

	// Execute the gate function to record operations
	out := f(&compiler, inputs...)
	outVar, ok := out.(compilationVar)
	if !ok {
		return SerializableGate{}, errors.New("gate function must return a variable; constant values must be hard-coded into the gates that use them")
	}
	if len(compiler.instructions) == 0 {
		// No operations recorded, but not all is lost yet.
		// If the output simply mirrors the last input, we can still represent
		// it in bytecode, as the evaluator returns the last stack frame element.
		if int(outVar.id) == len(compiler.constants)+nbInputs-1 {
			// Identity-like gate: returns last input unchanged
			// Degree is 1, and the returned variable is solvable
			return SerializableGate{
				NbIn:        nbInputs,
				Degree:      1,
				SolvableVar: nbInputs - 1,
			}, nil
		}
		return SerializableGate{}, errors.New("only non-trivial or last-reflective gate functions supported")
	}

	// All instructions after the output are no-ops. Prune them and the corresponding variables.
	// Henceforth, we guarantee that the variable with the highest index is the gate output.
	lastEffectiveInstructionIndex := int(outVar.id) - compiler.nbInputs
	compiler.instructions = compiler.instructions[:lastEffectiveInstructionIndex+1]

	// Drop the constants used only by pruned instructions.
	nbUsedConstants := 0
	for _, inst := range compiler.instructions {
		for _, in := range inst.Inputs {
			if in&constMarker != 0 {
				nbUsedConstants = max(nbUsedConstants, int(in&^constMarker)+1)
			}
		}
	}
	compiler.constants = compiler.constants[:nbUsedConstants]

	// Remap indices from temporary layout to final layout
	compiler.remapIndices()

	bytecode := GateBytecode{
		Instructions: compiler.GetInstructions(),
		Constants:    compiler.constants,
	}

	// Compute degree and solvable variable
	tester := gateTester{field: field}
	tester.setGate(bytecode, nbInputs)

	degree := len(tester.fitPoly(bytecode.EstimateDegree(nbInputs))) - 1
	if degree == -1 {
		return SerializableGate{}, errors.New("cannot find degree for gate")
	}

	solvableVar := -1
	for j := range nbInputs {
		if tester.isAdditive(j) {
			solvableVar = j
			break
		}
	}

	return SerializableGate{
		Evaluate:    bytecode,
		NbIn:        nbInputs,
		Degree:      degree,
		SolvableVar: solvableVar,
	}, nil
}

// Field describes F_p[X]/(f); see gkr.Field.
type Field = gkr.Field

// gateTester evaluates gate bytecode over a field F_p[X]/(f), to discover a gate's degree and
// solvable variable. An element is a []*big.Int of length field.Degree(), coefficient i the
// coefficient of Xⁱ, each reduced mod p. For gkr.PrimeField, Degree() is 1, and every operation below
// reduces to arithmetic mod p.
type gateTester struct {
	field Field
	gate  GateBytecode
	vars  [][]*big.Int
	nbIn  int

	invExponent *big.Int // pⁿ - 2, the exponent inverse raises to; computed once, on first use
}

func (t *gateTester) setGate(g GateBytecode, nbIn int) {
	t.gate = g
	t.nbIn = nbIn
	t.vars = make([][]*big.Int, g.NbConstants()+nbIn+len(g.Instructions))
	for i, c := range g.Constants {
		t.vars[i] = t.embed(c)
	}
}

// embed returns c as the field element [c, 0, …, 0].
func (t *gateTester) embed(c *big.Int) []*big.Int {
	res := make([]*big.Int, t.field.Degree())
	res[0] = new(big.Int).Mod(c, t.field.Modulus)
	for i := 1; i < len(res); i++ {
		res[i] = new(big.Int)
	}
	return res
}

func (t *gateTester) zero() []*big.Int {
	return t.embed(new(big.Int))
}

func (t *gateTester) one() []*big.Int {
	return t.embed(big.NewInt(1))
}

func (t *gateTester) isZero(a []*big.Int) bool {
	for _, ai := range a {
		v := new(big.Int).Mod(ai, t.field.Modulus)
		if v.BitLen() != 0 {
			return false
		}
	}
	return true
}

func (t *gateTester) equal(a, b []*big.Int) bool {
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

func (t *gateTester) add(a, b []*big.Int) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := range res {
		res[i] = new(big.Int).Add(a[i], b[i])
		res[i].Mod(res[i], t.field.Modulus)
	}
	return res
}

func (t *gateTester) sub(a, b []*big.Int) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := range res {
		res[i] = new(big.Int).Sub(a[i], b[i])
		res[i].Mod(res[i], t.field.Modulus)
	}
	return res
}

func (t *gateTester) neg(a []*big.Int) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := range res {
		res[i] = new(big.Int).Neg(a[i])
		res[i].Mod(res[i], t.field.Modulus)
	}
	return res
}

// mul multiplies a and b as polynomials, then reduces the product mod f, then mod p.
func (t *gateTester) mul(a, b []*big.Int) []*big.Int {
	n := t.field.Degree()
	prod := make([]*big.Int, 2*n-1)
	for i := range prod {
		prod[i] = new(big.Int)
	}

	var term big.Int // scratch for each product term, to avoid allocating one per multiplication
	for i, ai := range a {
		for j, bj := range b {
			term.Mul(ai, bj)
			prod[i+j].Add(prod[i+j], &term)
		}
	}

	// Xⁿ ≡ -(MinPoly[n-1]Xⁿ⁻¹ + … + MinPoly[0]) (mod f); fold the coefficients at or above Xⁿ
	// down, highest first, exactly as long division would.
	for k := len(prod) - 1; k >= n; k-- {
		coeff := prod[k]
		for i := range n {
			term.Mul(coeff, t.field.MinPoly[i])
			prod[k-n+i].Sub(prod[k-n+i], &term)
		}
	}

	res := prod[:n]
	for i := range res {
		res[i].Mod(res[i], t.field.Modulus)
	}
	return res
}

// pow raises a to the eᵗʰ power by square-and-multiply, e ≥ 0.
func (t *gateTester) pow(a []*big.Int, e *big.Int) []*big.Int {
	res := t.one()
	for i := e.BitLen() - 1; i >= 0; i-- {
		res = t.mul(res, res)
		if e.Bit(i) == 1 {
			res = t.mul(res, a)
		}
	}
	return res
}

// inverse returns a⁻¹ = a^(pⁿ⁻²), which requires f irreducible.
func (t *gateTester) inverse(a []*big.Int) []*big.Int {
	if t.invExponent == nil {
		n := big.NewInt(int64(t.field.Degree()))
		t.invExponent = new(big.Int).Exp(t.field.Modulus, n, nil)
		t.invExponent.Sub(t.invExponent, big.NewInt(2))
	}
	return t.pow(a, t.invExponent)
}

func (t *gateTester) div(a, b []*big.Int) []*big.Int {
	return t.mul(a, t.inverse(b))
}

func (t *gateTester) randomElement() []*big.Int {
	res := make([]*big.Int, t.field.Degree())
	for i := range res {
		v, err := rand.Int(rand.Reader, t.field.Modulus)
		if err != nil {
			panic(err)
		}
		res[i] = v
	}
	return res
}

func (t *gateTester) randomElements(n int) [][]*big.Int {
	res := make([][]*big.Int, n)
	for i := range res {
		res[i] = t.randomElement()
	}
	return res
}

func (t *gateTester) evalPoly(p [][]*big.Int, x []*big.Int) []*big.Int {
	res := p[len(p)-1]
	for i := len(p) - 2; i >= 0; i-- {
		res = t.mul(res, x)
		res = t.add(res, p[i])
	}
	return res
}

// evaluate executes the gate bytecode with the given inputs.
func (t *gateTester) evaluate(inputs ...[]*big.Int) []*big.Int {
	frameSize := t.gate.NbConstants()

	// Copy inputs into frame
	copy(t.vars[t.gate.NbConstants():], inputs)

	frameSize += len(inputs)

	// Execute instructions
	for _, inst := range t.gate.Instructions {
		var dst []*big.Int
		switch inst.Op {
		case OpAdd:
			dst = t.vars[inst.Inputs[0]]
			for _, idx := range inst.Inputs[1:] {
				dst = t.add(dst, t.vars[idx])
			}
		case OpSub:
			dst = t.vars[inst.Inputs[0]]
			for _, idx := range inst.Inputs[1:] {
				dst = t.sub(dst, t.vars[idx])
			}
		case OpMul:
			dst = t.vars[inst.Inputs[0]]
			for _, idx := range inst.Inputs[1:] {
				dst = t.mul(dst, t.vars[idx])
			}
		case OpNeg:
			dst = t.neg(t.vars[inst.Inputs[0]])
		case OpMulAcc: // a*b + c
			dst = t.mul(t.vars[inst.Inputs[0]], t.vars[inst.Inputs[1]])
			dst = t.add(dst, t.vars[inst.Inputs[2]])
		case OpSumExp17: // (a + b + c)^17
			dst = t.add(t.vars[inst.Inputs[0]], t.vars[inst.Inputs[1]])
			dst = t.add(dst, t.vars[inst.Inputs[2]])
			dst = t.pow(dst, big.NewInt(17))
		default:
			panic("unknown operation")
		}
		t.vars[frameSize] = dst
		frameSize++
	}

	return t.vars[frameSize-1]
}

// isAdditive returns whether xᵢ occurs only in a monomial of total degree 1
func (t *gateTester) isAdditive(i int) bool {
	in := t.randomElements(t.nbIn)

	x := t.randomElement()
	in[i] = x
	y1 := t.evaluate(in...)

	zero := t.zero()
	in[i] = zero
	y0 := t.evaluate(in...)

	in[i] = t.add(x, x)
	y2 := t.evaluate(in...)

	// f(2x) - f(x) == f(x) - f(0) ?
	y2 = t.sub(y2, y1)
	y1 = t.sub(y1, y0)

	if !t.equal(y1, y2) {
		return false // not linear
	}

	if t.isZero(y1) {
		return false // zero coefficient
	}

	// check slope is independent of other variables
	in = t.randomElements(t.nbIn)
	in[i] = zero
	y0 = t.evaluate(in...)

	in[i] = x
	y1 = t.sub(t.evaluate(in...), y0)

	return t.equal(y2, y1)
}

// fitPoly tries to fit a polynomial of degree no more than degreeBound to the gate.
// It returns the polynomial if successful, nil otherwise.
func (t *gateTester) fitPoly(maxDegree int) [][]*big.Int {

	// turn f univariate by defining p(x) as f(x, rx, ..., sx)
	// where r, s, ... are random constants
	fIn := make([][]*big.Int, t.nbIn)
	consts := t.randomElements(t.nbIn - 1)

	p := make([][]*big.Int, maxDegree+1)

	x := t.randomElements(maxDegree + 1)
	for i := range x {
		fIn[0] = x[i]
		for j := range consts {
			fIn[j+1] = t.mul(x[i], consts[j])
		}
		p[i] = t.evaluate(fIn...)
	}

	// obtain p's coefficients
	p, err := t.interpolate(x, p)
	if err != nil {
		panic(err)
	}

	// check if p is equal to f. This not being the case means that f is of a degree higher than maxDegree
	fIn[0] = t.randomElement()
	for i := range consts {
		fIn[i+1] = t.mul(fIn[0], consts[i])
	}
	pAt := t.evalPoly(p, fIn[0])
	fAt := t.evaluate(fIn...)
	if !t.equal(pAt, fAt) {
		return nil
	}

	// trim p
	lastNonZero := len(p) - 1
	for lastNonZero >= 0 && t.isZero(p[lastNonZero]) {
		lastNonZero--
	}
	return p[:lastNonZero+1]
}

// interpolate fits a polynomial of degree len(X) - 1 = len(Y) - 1 to the points (X[i], Y[i])
// Note that the runtime is O(len(X)³)
func (t *gateTester) interpolate(X, Y [][]*big.Int) ([][]*big.Int, error) {
	if len(X) != len(Y) {
		return nil, errors.New("same length expected for X and Y")
	}

	one := t.one()

	// solve the system of equations by Gaussian elimination
	augmentedRows := make([][][]*big.Int, len(X)) // the last column is the Y values
	for i := range augmentedRows {
		augmentedRows[i] = make([][]*big.Int, len(X)+1)
		augmentedRows[i][0] = one
		augmentedRows[i][1] = X[i]
		for j := 2; j < len(augmentedRows[i])-1; j++ {
			augmentedRows[i][j] = t.mul(augmentedRows[i][j-1], X[i])
		}
		augmentedRows[i][len(augmentedRows[i])-1] = Y[i]
	}

	// make the upper triangle
	for i := range len(augmentedRows) - 1 {
		// use row i to eliminate the ith element in all rows below
		var negInv []*big.Int
		if t.isZero(augmentedRows[i][i]) {
			return nil, errors.New("singular matrix")
		}
		negInv = t.inverse(augmentedRows[i][i])
		negInv = t.neg(negInv)
		for j := i + 1; j < len(augmentedRows); j++ {
			c := t.mul(augmentedRows[j][i], negInv)
			// augmentedRows[j][i].SetZero() omitted
			for k := i + 1; k < len(augmentedRows[i]); k++ {
				z := t.mul(augmentedRows[i][k], c)
				augmentedRows[j][k] = t.add(augmentedRows[j][k], z)
			}
		}
	}

	// back substitution
	res := make([][]*big.Int, len(X))
	for i := len(augmentedRows) - 1; i >= 0; i-- {
		res[i] = augmentedRows[i][len(augmentedRows[i])-1]
		for j := i + 1; j < len(augmentedRows[i])-1; j++ {
			z := t.mul(res[j], augmentedRows[i][j])
			res[i] = t.sub(res[i], z)
		}
		res[i] = t.div(res[i], augmentedRows[i][i])
	}

	return res, nil
}
