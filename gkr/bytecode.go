package gkr

import (
	"fmt"
	"math/big"
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
// Operand space layout:
//   - [0, NbRegisters()): registers
//   - [NbRegisters(), NbRegisters()+nbConsts): constant values (from GateBytecode.Constants)
//
// An operand is a constant exactly when its index is at least NbRegisters(). On entry, registers
// 0, …, NbIn-1 hold the gate's inputs. An instruction writes its result to the register Dst. Its
// first two operands are read before the result is written, so Dst may be the register of its
// first operand; later operands of an Add, Sub or Mul are read after the first write.
type GateInstruction struct {
	Op     GateOp
	Inputs []uint16 // indices into the operand space
	Dst    uint16   // register the result is written to
}

// GateBytecode represents a gate executable compiled into a sequence of instructions.
// The compiled form is independent of curve-specific types and can be serialized.
// The operand space is the registers, then the constants.
// The gate's result is the Dst of the last instruction, or the last input's register if there is no
// instruction.
type GateBytecode struct {
	Instructions []GateInstruction // sequence of operations
	Constants    []*big.Int        // constant values at indices [NbRegisters(), NbRegisters()+nbConsts)
	NbIn         int               // number of inputs
}

// IdentityBytecode returns the compiled form of the identity gate (x → x).
// A GateBytecode with no instructions returns its sole input directly.
func IdentityBytecode() GateBytecode {
	return GateBytecode{NbIn: 1}
}

// NbConstants returns the number of constants in the gate
func (g *GateBytecode) NbConstants() int {
	return len(g.Constants)
}

// NbRegisters returns the number of registers: the inputs', or one more than the largest Dst if that
// is more.
func (g *GateBytecode) NbRegisters() int {
	res := g.NbIn
	for _, inst := range g.Instructions {
		res = max(res, int(inst.Dst)+1)
	}
	return res
}

// EvaluatorSize returns the scratch size a gateEvaluator needs to evaluate this
// gate: one slot per register and per constant.
func (g *GateBytecode) EvaluatorSize() int {
	return g.NbRegisters() + g.NbConstants()
}

// CheckConstantPositions returns an error naming the first instruction whose constant operands are
// not where the evaluators read them first: an Add or Mul can only have them at index 0, and a Sub
// can only have them at index 0 or 1.
func (g *GateBytecode) CheckConstantPositions() error {
	nbRegisters := g.NbRegisters()
	for i, inst := range g.Instructions {
		var lastPosition int // the last position a constant may take
		switch inst.Op {
		case OpAdd, OpMul:
			lastPosition = 0
		case OpSub:
			lastPosition = 1
		default:
			continue
		}
		for j := lastPosition + 1; j < len(inst.Inputs); j++ {
			if int(inst.Inputs[j]) >= nbRegisters {
				return fmt.Errorf("instruction %d (%s): constant operand at position %d", i, inst.Op, j)
			}
		}
	}
	return nil
}

// ResultRegister returns the register of the value the gate returns.
func (g *GateBytecode) ResultRegister() uint16 {
	if len(g.Instructions) == 0 {
		return uint16(g.NbIn - 1)
	}
	return g.Instructions[len(g.Instructions)-1].Dst
}

// EstimateDegree returns an upper bound on the degree of the gate
func (g *GateBytecode) EstimateDegree() int {
	deg := make([]int, g.EvaluatorSize())
	for i := range g.NbIn {
		deg[i] = 1
	}
	for _, inst := range g.Instructions {
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
		deg[inst.Dst] = curr
	}
	return deg[g.ResultRegister()]
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
