package gkr

import "math/big"

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
