package gkrcore

import (
	"crypto/rand"
	"errors"
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/utils"
)

// gateCompiler is an implementation of gkr.GateAPI that records operations
// instead of executing them. This is used to compile gate functions into
// instruction sequences. The values of a gate are numbered: the inputs 0..nbInputs-1, then the
// results of the instructions in order. Registers and constants are assigned once the instructions
// are final.
type gateCompiler struct {
	instructions []recordedInstruction // each instruction defines exactly one output variable
	nbInputs     int
	modulus      *big.Int // the modulus of the field the gate is compiled for; constants are reduced by it
}

// recordedInstruction is an operation that a gateCompiler recorded.
type recordedInstruction struct {
	op       gkr.GateOp
	operands []any
	dst      uint16 // the register of the result, set by assignRegisters
}

// compilationVar represents a variable during gate compilation.
type compilationVar struct {
	id uint16
}

func (gc *gateCompiler) addInstruction(op gkr.GateOp, inputs ...frontend.Variable) compilationVar {
	operands := make([]any, len(inputs))
	for i, in := range inputs {
		if c, ok := gc.constantValue(in); ok {
			operands[i] = c
		} else {
			operands[i] = in
		}
	}

	gc.instructions = append(gc.instructions, recordedInstruction{op: op, operands: operands})

	return compilationVar{uint16(gc.nbInputs + len(gc.instructions) - 1)}
}

// Add records an addition operation. Its constant operands are summed into one, placed first. An
// addition of constants alone is itself a constant.
func (gc *gateCompiler) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.recordCommutative(gkr.OpAdd, new(big.Int), (*big.Int).Add, i1, i2, in)
}

// MulAcc records a multiply-accumulate operation: a + (b * c). The instruction reads the
// multiplicands first and the addend last, with a constant multiplicand before the other. With two
// constant multiplicands, it records an addition of their product. With three constants, it is itself
// a constant.
func (gc *gateCompiler) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	bValue, bIsConst := gc.constantValue(b)
	cValue, cIsConst := gc.constantValue(c)
	if bIsConst && cIsConst {
		return gc.Add(bValue.Mul(bValue, cValue).Mod(bValue, gc.modulus), a)
	}
	if cIsConst {
		b, c = c, b
	}
	return gc.addInstruction(gkr.OpMulAcc, b, c, a)
}

// Neg records a negation operation. The negation of a constant is itself a constant.
func (gc *gateCompiler) Neg(i1 frontend.Variable) frontend.Variable {
	if c, ok := gc.constantValue(i1); ok {
		return c.Neg(c).Mod(c, gc.modulus)
	}
	return gc.addInstruction(gkr.OpNeg, i1)
}

// Sub records a subtraction operation. A constant minuend absorbs the constant subtrahends;
// otherwise they are summed into one, placed second. A subtraction of constants alone is itself a
// constant.
func (gc *gateCompiler) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	operands := append([]frontend.Variable{i1, i2}, in...)
	minuend, minuendIsConst := gc.constantValue(operands[0])

	subtrahends := new(big.Int)
	hasConst := false
	nbKept := 1
	for _, v := range operands[1:] {
		if c, ok := gc.constantValue(v); ok {
			subtrahends.Add(subtrahends, c)
			hasConst = true
		} else {
			operands[nbKept] = v
			nbKept++
		}
	}
	operands = operands[:nbKept]
	subtrahends.Mod(subtrahends, gc.modulus)

	if minuendIsConst {
		diff := minuend.Sub(minuend, subtrahends).Mod(minuend, gc.modulus)
		if nbKept == 1 {
			return diff
		}
		operands[0] = diff
	} else if hasConst {
		operands = slices.Insert(operands, 1, frontend.Variable(subtrahends))
	}
	return gc.addInstruction(gkr.OpSub, operands...)
}

// Mul records a multiplication operation. Its constant operands are multiplied into one, placed
// first. A multiplication of constants alone is itself a constant.
func (gc *gateCompiler) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return gc.recordCommutative(gkr.OpMul, big.NewInt(1), (*big.Int).Mul, i1, i2, in)
}

// recordCommutative records op over the operands i1, i2, in, with the constants among them folded
// into one by combine, starting from identity, and placed first. If all operands are constants, it
// returns the folded constant.
func (gc *gateCompiler) recordCommutative(op gkr.GateOp, identity *big.Int, combine func(z, x, y *big.Int) *big.Int, i1, i2 frontend.Variable, in []frontend.Variable) frontend.Variable {
	folded := identity
	hasConst := false
	var vars []frontend.Variable
	for _, v := range append([]frontend.Variable{i1, i2}, in...) {
		if c, ok := gc.constantValue(v); ok {
			folded = combine(new(big.Int), folded, c)
			folded.Mod(folded, gc.modulus)
			hasConst = true
		} else {
			vars = append(vars, v)
		}
	}
	if len(vars) == 0 {
		return folded
	}
	if hasConst {
		vars = slices.Insert(vars, 0, frontend.Variable(folded))
	}
	return gc.addInstruction(op, vars...)
}

// SumExp17 records (a + b + c)¹⁷ as a single instruction. If any of a, b, c is a constant, the
// first one found is read first. Constants are not merged. If all three are constants, it is itself a
// constant.
func (gc *gateCompiler) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	aValue, aIsConst := gc.constantValue(a)
	bValue, bIsConst := gc.constantValue(b)
	cValue, cIsConst := gc.constantValue(c)
	if aIsConst && bIsConst && cIsConst {
		sum := aValue.Add(aValue, bValue)
		return sum.Exp(sum.Add(sum, cValue), big.NewInt(17), gc.modulus)
	}
	operands := []frontend.Variable{a, b, c}
	for i, v := range operands {
		if _, ok := gc.constantValue(v); ok {
			operands[0], operands[i] = operands[i], operands[0]
			break
		}
	}
	return gc.addInstruction(gkr.OpSumExp17, operands...)
}

// constantValue returns v's value, reduced modulo the field's, if v is a constant, that is, not a
// variable of the gate.
func (gc *gateCompiler) constantValue(v frontend.Variable) (*big.Int, bool) {
	if _, ok := v.(compilationVar); ok {
		return nil, false
	}
	val := utils.FromInterface(v)
	return val.Mod(&val, gc.modulus), true
}

// removeDeadCode removes the instructions whose result does not reach the output, and renumbers the
// remaining result operands. The output is the last instruction's result afterwards.
func (gc *gateCompiler) removeDeadCode(output compilationVar) {
	live := make([]bool, len(gc.instructions))
	live[int(output.id)-gc.nbInputs] = true
	for i := len(live) - 1; i >= 0; i-- {
		if !live[i] {
			continue
		}
		for _, o := range gc.instructions[i].operands {
			if v, ok := o.(compilationVar); ok && int(v.id) >= gc.nbInputs {
				live[int(v.id)-gc.nbInputs] = true
			}
		}
	}

	var (
		instructions []recordedInstruction
		resultID     = make([]uint16, len(gc.instructions)) // the new id of the result of a live instruction
	)
	for i, inst := range gc.instructions {
		if !live[i] {
			continue
		}
		for j, o := range inst.operands {
			if v, ok := o.(compilationVar); ok && int(v.id) >= gc.nbInputs {
				inst.operands[j] = compilationVar{resultID[int(v.id)-gc.nbInputs]}
			}
		}
		resultID[i] = uint16(gc.nbInputs + len(instructions))
		instructions = append(instructions, inst)
	}
	gc.instructions = instructions
}

// register returns the register that holds the value v: v itself for an input, otherwise the
// register of the instruction that defines it.
func (gc *gateCompiler) register(v compilationVar) uint16 {
	if int(v.id) < gc.nbInputs {
		return v.id
	}
	return gc.instructions[int(v.id)-gc.nbInputs].dst
}

// assignRegisters sets the register of each instruction's result. The inputs start in registers
// 0, …, nbInputs-1, which no result takes. An instruction's register is that of its first or else its
// second operand if that operand is the result of an instruction read last by this instruction, and
// the lowest free register otherwise. The registers of the results that this instruction reads last
// are freed afterwards.
//
// The register is not that of an operand that the instruction also reads at position 2 or later.
func (gc *gateCompiler) assignRegisters() {
	nbValues := gc.nbInputs + len(gc.instructions)

	// lastUse[v] is the last instruction that reads the value v: an input, or the result of an
	// instruction, in this order. The output is read after the last instruction. It is -1 for an
	// input that the gate does not read.
	lastUse := slices.Repeat([]int{-1}, nbValues)
	for i, inst := range gc.instructions {
		for _, o := range inst.operands {
			if v, ok := o.(compilationVar); ok {
				lastUse[v.id] = i
			}
		}
	}
	lastUse[nbValues-1] = len(gc.instructions)

	// free[r] says whether r holds no value that is read later. The inputs' registers never are.
	free := make([]bool, gc.nbInputs)

	for i := range gc.instructions {
		inst := &gc.instructions[i]

		// tryInputAsDst returns the register of the operand j if it is the result of an instruction that
		// this instruction reads last, and is not also an operand at position 2 or later; otherwise -1.
		tryInputAsDst := func(j int) int {
			if j >= len(inst.operands) {
				return -1
			}
			v, ok := inst.operands[j].(compilationVar)
			if !ok || int(v.id) < gc.nbInputs || lastUse[v.id] != i || slices.Contains(inst.operands[min(2, len(inst.operands)):], inst.operands[j]) {
				return -1
			}
			return int(gc.register(v))
		}

		dst := tryInputAsDst(0)
		if dst == -1 {
			dst = tryInputAsDst(1)
		}
		if dst == -1 {
			dst = slices.Index(free, true)
			if dst == -1 {
				dst = len(free)
				free = append(free, false)
			}
		}
		inst.dst = uint16(dst)

		for _, o := range inst.operands {
			if v, ok := o.(compilationVar); ok && int(v.id) >= gc.nbInputs && lastUse[v.id] == i {
				free[gc.register(v)] = true
			}
		}
		free[inst.dst] = false
	}
}

// toBytecode returns the bytecode of the recorded instructions, once their registers are assigned.
// The constants are pooled in the order of their first use, without duplicates, and follow the
// registers in the operand space.
func (gc *gateCompiler) toBytecode() gkr.GateBytecode {
	bytecode := gkr.GateBytecode{
		Instructions: make([]gkr.GateInstruction, len(gc.instructions)),
		NbIn:         gc.nbInputs,
	}
	for i, inst := range gc.instructions {
		bytecode.Instructions[i].Op = inst.op
		bytecode.Instructions[i].Dst = inst.dst
	}
	nbRegisters := bytecode.NbRegisters()

	constantIndex := make(map[string]int) // from a constant's value to its index in the pool
	for i, inst := range gc.instructions {
		out := &bytecode.Instructions[i]
		out.Inputs = make([]uint16, len(inst.operands))
		for j, o := range inst.operands {
			switch o := o.(type) {
			case compilationVar:
				out.Inputs[j] = gc.register(o)
			case *big.Int:
				index, ok := constantIndex[o.String()]
				if !ok {
					index = len(bytecode.Constants)
					constantIndex[o.String()] = index
					bytecode.Constants = append(bytecode.Constants, o)
				}
				out.Inputs[j] = uint16(nbRegisters + index)
			}
		}
	}
	return bytecode
}

// CompileGateFunction converts a gate function into a gkr.SerializableGate.
// This consists of compiling into bytecode as well as computing gate metadata
// such as degree and solvable var index for the given field.
func CompileGateFunction(f gkr.GateFunction, nbInputs int, field Field) (gkr.SerializableGate, error) {
	compiler := gateCompiler{nbInputs: nbInputs, modulus: field.Modulus}

	inputs := make([]frontend.Variable, nbInputs)
	for i := range uint16(nbInputs) {
		inputs[i] = compilationVar{i}
	}

	out := f(&compiler, inputs...)
	outVar, ok := out.(compilationVar)
	if !ok {
		return gkr.SerializableGate{}, errors.New("gate function must return a variable; constant values must be hard-coded into the gates that use them")
	}
	if int(outVar.id) < nbInputs {
		// The output is an input. If it is the last input, we can still represent the gate in
		// bytecode, as the evaluator returns the last input's register.
		if int(outVar.id) == nbInputs-1 {
			// Identity-like gate: returns last input unchanged
			// Degree is 1, and the returned variable is solvable
			return gkr.SerializableGate{
				Evaluate:    gkr.GateBytecode{NbIn: nbInputs},
				Degree:      1,
				SolvableVar: nbInputs - 1,
			}, nil
		}
		return gkr.SerializableGate{}, errors.New("only non-trivial or last-reflective gate functions supported")
	}

	compiler.removeDeadCode(outVar)
	compiler.assignRegisters()
	bytecode := compiler.toBytecode()

	tester := gateTester{field: field}
	tester.setGate(bytecode)

	p := tester.fitPoly(bytecode.EstimateDegree())
	if p == nil {
		return gkr.SerializableGate{}, errors.New("cannot find degree for gate")
	}
	degree := max(len(p)-1, 1) // overestimating a constant gate's degree for the proof to work

	solvableVar := -1
	for j := range nbInputs {
		if tester.isAdditive(j) {
			solvableVar = j
			break
		}
	}

	return gkr.SerializableGate{
		Evaluate:    bytecode,
		Degree:      degree,
		SolvableVar: solvableVar,
	}, nil
}

// Field describes Fₚ[X]/(f); see gkr.Field.
type Field = gkr.Field

// gateTester evaluates gate bytecode over a field Fₚ[X]/(f), to discover a gate's degree and
// solvable variable. An element is a []*big.Int of length field.Degree(), coefficient i the
// coefficient of Xⁱ, each reduced mod p. For gkr.PrimeField, Degree() is 1, and every operation below
// reduces to arithmetic mod p.
type gateTester struct {
	field Field
	gate  gkr.GateBytecode
	vars  [][]*big.Int

	invExponent *big.Int // pⁿ - 2, the exponent inverse raises to; computed once, on first use
}

func (t *gateTester) setGate(g gkr.GateBytecode) {
	t.gate = g
	t.vars = make([][]*big.Int, g.EvaluatorSize())
	nbRegisters := g.NbRegisters()
	for i, c := range g.Constants {
		t.vars[nbRegisters+i] = t.embed(c)
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
	// Copy inputs into the first registers
	copy(t.vars, inputs)

	// Execute instructions
	for _, inst := range t.gate.Instructions {
		var dst []*big.Int
		switch inst.Op {
		case gkr.OpAdd:
			dst = t.vars[inst.Inputs[0]]
			for _, idx := range inst.Inputs[1:] {
				dst = t.add(dst, t.vars[idx])
			}
		case gkr.OpSub:
			dst = t.vars[inst.Inputs[0]]
			for _, idx := range inst.Inputs[1:] {
				dst = t.sub(dst, t.vars[idx])
			}
		case gkr.OpMul:
			dst = t.vars[inst.Inputs[0]]
			for _, idx := range inst.Inputs[1:] {
				dst = t.mul(dst, t.vars[idx])
			}
		case gkr.OpNeg:
			dst = t.neg(t.vars[inst.Inputs[0]])
		case gkr.OpMulAcc: // a*b + c
			dst = t.mul(t.vars[inst.Inputs[0]], t.vars[inst.Inputs[1]])
			dst = t.add(dst, t.vars[inst.Inputs[2]])
		case gkr.OpSumExp17: // (a + b + c)¹⁷
			dst = t.add(t.vars[inst.Inputs[0]], t.vars[inst.Inputs[1]])
			dst = t.add(dst, t.vars[inst.Inputs[2]])
			dst = t.pow(dst, big.NewInt(17))
		default:
			panic("unknown operation")
		}
		t.vars[inst.Dst] = dst
	}

	return t.vars[t.gate.ResultRegister()]
}

// isAdditive returns whether xᵢ occurs only in a monomial of total degree 1
func (t *gateTester) isAdditive(i int) bool {
	in := t.randomElements(t.gate.NbIn)

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
	in = t.randomElements(t.gate.NbIn)
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
	fIn := make([][]*big.Int, t.gate.NbIn)
	consts := t.randomElements(t.gate.NbIn - 1)

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
