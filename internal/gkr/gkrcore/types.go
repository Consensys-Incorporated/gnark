package gkrcore

import (
	"errors"
	"slices"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/utils"
)

type (
	InputDependency struct {
		OutputWire     int
		OutputInstance int
		InputInstance  int
	}

	// RawWire is a minimal wire representation with only inputs and gate function.
	RawWire struct {
		Gate     gkr.GateFunction
		Inputs   []int
		Exported bool
	}

	// RawCircuit is a minimal circuit representation for API-level circuit construction.
	// It contains only the essential topology (inputs) and gate functions.
	RawCircuit []RawWire
)

// MemoryRequirements returns the strictly increasing vector of memory
// allocation sizes required for proving a GKR statement on this circuit.
func MemoryRequirements(c gkr.SerializableCircuit, nbInstances int) []int {
	largest := gkr.IdentityBytecode().EvaluatorSize(1)
	for i := range c {
		if !c[i].IsInput() {
			largest = max(largest, c[i].Gate.Evaluate.EvaluatorSize(len(c[i].Inputs)))
		}
	}

	res := []int{nbInstances, largest}
	slices.Sort(res)
	return slices.Compact(res)
}

// some sample gates

// Identity gate: x -> x
func Identity(_ gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return in[0]
}

// Add2 gate: (x, y) -> x + y
func Add2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Add(in[0], in[1])
}

// Sub2 gate: (x, y) -> x - y
func Sub2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Sub(in[0], in[1])
}

// Neg gate: x -> -x
func Neg(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Neg(in[0])
}

// Mul2 gate: (x, y) -> x * y
func Mul2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Mul(in[0], in[1])
}

// BlueprintSolve is the interface for GKR solve blueprints
type BlueprintSolve interface {
	constraint.BlueprintStateful[constraint.U64]
	SetNbInstances(nbInstances uint32)
}

// Blueprints holds all GKR-related blueprint IDs and references
type Blueprints struct {
	SolveID         constraint.BlueprintID
	Solve           BlueprintSolve
	ProveID         constraint.BlueprintID
	GetAssignmentID constraint.BlueprintID
}

// Compile compiles a raw circuit into both a gadget circuit and a serializable circuit.
// It computes all wire and gate metadata (Degree, SolvableVar).
func (c RawCircuit) Compile(field Field) (gkr.GadgetCircuit, gkr.SerializableCircuit, error) {
	gadget := make(gkr.GadgetCircuit, len(c))
	serializable := make(gkr.SerializableCircuit, len(c))

	for i := range c {
		gadget[i].Inputs = c[i].Inputs
		gadget[i].Exported = c[i].Exported
		serializable[i].Inputs = c[i].Inputs
		serializable[i].Exported = c[i].Exported

		if gadget[i].IsInput() {
			continue
		}

		if c[i].Gate == nil {
			return nil, nil, errors.New("gate function required for non-input wire")
		}

		nbIn := len(c[i].Inputs)
		compiledGate, err := CompileGateFunction(c[i].Gate, nbIn, field)
		if err != nil {
			return nil, nil, err
		}

		gadget[i].Gate = gkr.GadgetGate{
			Evaluate:    c[i].Gate,
			NbIn:        nbIn,
			Degree:      compiledGate.Degree,
			SolvableVar: compiledGate.SolvableVar,
		}
		serializable[i].Gate = compiledGate
	}

	return gadget, serializable, nil
}

func varToInt(a gkr.Variable) int {
	return int(a)
}

// NewInput creates a new input variable.
func (c *RawCircuit) NewInput() gkr.Variable {
	i := len(*c)
	*c = append(*c, RawWire{})
	return gkr.Variable(i)
}

// Gate adds the given gate with the given inputs and returns its output wire.
func (c *RawCircuit) Gate(gate gkr.GateFunction, inputs ...gkr.Variable) gkr.Variable {
	*c = append(*c, RawWire{
		Gate:   gate,
		Inputs: utils.Map(inputs, varToInt),
	})
	return gkr.Variable(len(*c) - 1)
}

func (c *RawCircuit) gate2PlusIn(gate gkr.GateFunction, in1, in2 gkr.Variable, in ...gkr.Variable) gkr.Variable {
	inCombined := make([]gkr.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return c.Gate(gate, inCombined...)
}

func (c *RawCircuit) Add(i1, i2 gkr.Variable) gkr.Variable {
	return c.gate2PlusIn(Add2, i1, i2)
}

func (c *RawCircuit) Neg(i1 gkr.Variable) gkr.Variable {
	return c.Gate(Neg, i1)
}

func (c *RawCircuit) Sub(i1, i2 gkr.Variable) gkr.Variable {
	return c.gate2PlusIn(Sub2, i1, i2)
}

func (c *RawCircuit) Mul(i1, i2 gkr.Variable) gkr.Variable {
	return c.gate2PlusIn(Mul2, i1, i2)
}

// Export explicitly designates a wire as output.
// Wires that are not used as input to another are considered output by default.
func (c *RawCircuit) Export(in ...gkr.Variable) {
	for _, v := range in {
		(*c)[v].Exported = true
	}
}
