package gkrcore

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

// GateOp represents an arithmetic operation in a compiled gate.
type GateOp uint8

const (
	OpAdd      GateOp = iota // result = src1 + src2 + ... (variadic)
	OpSub                    // result = src1 - src2 - ...
	OpMul                    // result = src1 * src2 * ...
	OpNeg                    // result = -src1
	OpMulAcc                 // result = src1 + (src2 * src3)
	OpSumExp17               // result = (src1 + src2 + src3)^17
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
		case OpMulAcc: // a + b*c
			curr = max(deg[inst.Inputs[0]], deg[inst.Inputs[1]]+deg[inst.Inputs[2]])
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

// Add records an addition operation.
func (gc *gateCompiler) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.addInstruction2Plus(OpAdd, i1, i2, in...)
}

// MulAcc records a multiply-accumulate operation: a + (b * c)
func (gc *gateCompiler) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpMulAcc, a, b, c)
}

// Neg records a negation operation
func (gc *gateCompiler) Neg(i1 frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpNeg, i1)
}

// Sub records a subtraction operation
func (gc *gateCompiler) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.addInstruction2Plus(OpSub, i1, i2, in...)
}

// Mul records a multiplication operation
func (gc *gateCompiler) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.addInstruction2Plus(OpMul, i1, i2, in...)
}

// SumExp17 records (a + b + c)^17 as a single instruction
func (gc *gateCompiler) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	return gc.addInstruction(OpSumExp17, a, b, c)
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
func CompileGateFunction(f gkr.GateFunction, nbInputs int, field *big.Int) (SerializableGate, error) {
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

	// Remap indices from temporary layout to final layout
	compiler.remapIndices()

	bytecode := GateBytecode{
		Instructions: compiler.GetInstructions(),
		Constants:    compiler.constants,
	}

	// Compute degree and solvable variable
	tester := gateTester{mod: field}
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

type gateTester struct {
	mod  *big.Int
	gate GateBytecode
	vars []*big.Int
	nbIn int
}

func (t *gateTester) setGate(g GateBytecode, nbIn int) {
	t.gate = g
	t.vars = make([]*big.Int, g.NbConstants()+nbIn+len(g.Instructions))
	t.nbIn = nbIn
	copy(t.vars, g.Constants)
}

func (t *gateTester) isZero(a *big.Int) bool {
	v := new(big.Int).Mod(a, t.mod)
	return v.BitLen() == 0
}

func (t *gateTester) equal(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

func (t *gateTester) add(a, b *big.Int) *big.Int {
	res := new(big.Int).Add(a, b)
	return res.Mod(res, t.mod)
}

func (t *gateTester) sub(a, b *big.Int) *big.Int {
	res := new(big.Int).Sub(a, b)
	return res.Mod(res, t.mod)
}

func (t *gateTester) mul(a, b *big.Int) *big.Int {
	res := new(big.Int).Mul(a, b)
	return res.Mod(res, t.mod)
}

func (t *gateTester) neg(a *big.Int) *big.Int {
	res := new(big.Int).Neg(a)
	return res.Mod(res, t.mod)
}

func (t *gateTester) inverse(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, t.mod)
}

func (t *gateTester) div(a, b *big.Int) *big.Int {
	res := new(big.Int).ModInverse(b, t.mod)
	return res.Mul(a, res).Mod(res, t.mod)
}

func (t *gateTester) randomElement() *big.Int {
	res, err := rand.Int(rand.Reader, t.mod)
	if err != nil {
		panic(err)
	}
	return res
}

func (t *gateTester) randomElements(n int) []*big.Int {
	res := make([]*big.Int, n)
	for i := range res {
		res[i] = t.randomElement()
	}
	return res
}

func (t *gateTester) evalPoly(p []*big.Int, x *big.Int) *big.Int {
	res := p[len(p)-1]
	for i := len(p) - 2; i >= 0; i-- {
		res = t.mul(res, x)
		res = t.add(res, p[i])
	}
	return res
}

// evaluate executes the gate bytecode with the given inputs.
func (t *gateTester) evaluate(inputs ...*big.Int) *big.Int {
	frameSize := t.gate.NbConstants()

	// Copy inputs into frame
	copy(t.vars[t.gate.NbConstants():], inputs)

	frameSize += len(inputs)

	// Execute instructions
	for _, inst := range t.gate.Instructions {
		dst := t.vars[frameSize]
		if dst == nil {
			dst = new(big.Int)
			t.vars[frameSize] = dst
		}
		switch inst.Op {
		case OpAdd:
			dst.Set(t.vars[inst.Inputs[0]])
			for _, idx := range inst.Inputs[1:] {
				dst.Add(dst, t.vars[idx])
			}
		case OpSub:
			dst.Set(t.vars[inst.Inputs[0]])
			for _, idx := range inst.Inputs[1:] {
				dst.Sub(dst, t.vars[idx])
			}
		case OpMul:
			dst.Set(t.vars[inst.Inputs[0]])
			for _, idx := range inst.Inputs[1:] {
				dst.Mul(dst, t.vars[idx])
			}
		case OpNeg:
			dst.Neg(t.vars[inst.Inputs[0]])
		case OpMulAcc: // a + b*c
			dst.Mul(t.vars[inst.Inputs[1]], t.vars[inst.Inputs[2]])
			dst.Add(dst, t.vars[inst.Inputs[0]])
		case OpSumExp17: // (a + b + c)^17
			dst.Add(t.vars[inst.Inputs[0]], t.vars[inst.Inputs[1]])
			dst.Add(dst, t.vars[inst.Inputs[2]])
			dst.Exp(dst, big.NewInt(17), t.mod)
		default:
			panic("unknown operation")
		}
		dst.Mod(dst, t.mod)
		frameSize++
	}

	return new(big.Int).Set(t.vars[frameSize-1])
}

// isAdditive returns whether xᵢ occurs only in a monomial of total degree 1
func (t *gateTester) isAdditive(i int) bool {
	in := t.randomElements(t.nbIn)

	x := t.randomElement()
	in[i] = x
	y1 := t.evaluate(in...)

	zero := new(big.Int)
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
func (t *gateTester) fitPoly(maxDegree int) []*big.Int {

	// turn f univariate by defining p(x) as f(x, rx, ..., sx)
	// where r, s, ... are random constants
	fIn := make([]*big.Int, t.nbIn)
	consts := t.randomElements(t.nbIn - 1)

	p := make([]*big.Int, maxDegree+1)

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
func (t *gateTester) interpolate(X, Y []*big.Int) ([]*big.Int, error) {
	if len(X) != len(Y) {
		return nil, errors.New("same length expected for X and Y")
	}

	one := big.NewInt(1)

	// solve the system of equations by Gaussian elimination
	augmentedRows := make([][]*big.Int, len(X)) // the last column is the Y values
	for i := range augmentedRows {
		augmentedRows[i] = make([]*big.Int, len(X)+1)
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
		var negInv *big.Int
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
	res := make([]*big.Int, len(X))
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
