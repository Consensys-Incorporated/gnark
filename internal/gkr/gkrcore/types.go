package gkrcore

import (
	"errors"
	"math/big"
	"slices"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkrapi/gkr"
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

	// A Gate is a low-degree multivariate polynomial
	Gate[GateExecutable any] struct {
		Evaluate    GateExecutable
		NbIn        int // number of inputs
		Degree      int // total Degree of the polynomial
		SolvableVar int // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
	}

	Wire[GateExecutable any] struct {
		Gate     Gate[GateExecutable]
		Inputs   []int
		Exported bool
	}

	Circuit[GateExecutable any] []Wire[GateExecutable]

	// Type aliases for different circuit instantiations

	// Serializable types (bytecode only, for native proving)

	SerializableGate    = Gate[GateBytecode]
	SerializableCircuit = Circuit[GateBytecode]
	SerializableWire    = Wire[GateBytecode]

	// Gadget types (gate functions only, for in-circuit verification)

	GadgetGate    = Gate[gkr.GateFunction]
	GadgetCircuit = Circuit[gkr.GateFunction]
	GadgetWire    = Wire[gkr.GateFunction]
)

// IsInput returns whether the wire is an input wire.
func (w Wire[GateExecutable]) IsInput() bool {
	return len(w.Inputs) == 0
}

func (c Circuit[GateExecutable]) IsInput(wireIndex int) bool {
	return c[wireIndex].IsInput()
}

// ClaimPropagationInfo returns sets of indices describing the pruning of claim propagation.
// At the end of sumcheck for wire #wireIndex, we end up with sequences "uniqueEvaluations" and "evaluations",
// the former a subsequence of the latter.
// injection consists of the indices of the unique evaluations in the original evaluation list.
// injectionRightInverse are the indices of the original evaluations in the unique evaluations list.
// There are no guarantees on the non-unique choice of the semi-inverse map.
func (c Circuit[GateExecutable]) ClaimPropagationInfo(wireIndex int) (injection, injectionLeftInverse []int) {
	w := c[wireIndex]
	indexInProof := makeNeg1Slice(len(c)) // O(n); use a map instead if it caused performance issues
	injection = make([]int, 0, len(w.Inputs))
	injectionLeftInverse = make([]int, len(w.Inputs))

	for inI, in := range w.Inputs {
		if indexInProof[in] == -1 { // not found
			indexInProof[in] = len(injection)
			injection = append(injection, inI)
		}
		injectionLeftInverse[inI] = indexInProof[in]
	}

	return
}

// MemoryRequirements returns the strictly increasing vector of memory
// allocation sizes required for proving a GKR statement on this circuit.
func MemoryRequirements(c SerializableCircuit, nbInstances int) []int {
	largest := IdentityBytecode().EvaluatorSize(1)
	for i := range c {
		if !c[i].IsInput() {
			largest = max(largest, c[i].Gate.Evaluate.EvaluatorSize(len(c[i].Inputs)))
		}
	}

	res := []int{nbInstances, largest}
	slices.Sort(res)
	return slices.Compact(res)
}

// Inputs returns the list of input wire indices.
func (c Circuit[GateExecutable]) Inputs() []int {
	res := make([]int, 0, len(c))
	for i := range c {
		if c[i].IsInput() {
			res = append(res, i)
		}
	}
	return res
}

// Outputs returns the list of output wire indices.
func (c Circuit[GateExecutable]) Outputs() []int {
	isOutputTo := make([]bool, len(c))
	for i := range c {
		for _, in := range c[i].Inputs {
			isOutputTo[in] = true
		}
	}
	res := make([]int, 0, len(c))
	for i := range c {
		if !isOutputTo[i] || c[i].Exported {
			res = append(res, i)
		}
	}
	return res
}

// MaxGateNbIn returns the maximum number of inputs of any gate in the circuit.
func (c Circuit[GateExecutable]) MaxGateNbIn() int {
	res := 0
	for i := range c {
		res = max(res, len(c[i].Inputs))
	}
	return res
}

// makeNeg1Slice returns a slice of size n with all elements set to -1.
func makeNeg1Slice(n int) []int {
	res := make([]int, n)
	for i := range res {
		res[i] = -1
	}
	return res
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
func (c RawCircuit) Compile(mod *big.Int) (GadgetCircuit, SerializableCircuit, error) {
	gadget := make(GadgetCircuit, len(c))
	serializable := make(SerializableCircuit, len(c))

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
		compiledGate, err := CompileGateFunction(c[i].Gate, nbIn, mod)
		if err != nil {
			return nil, nil, err
		}

		gadget[i].Gate = GadgetGate{
			Evaluate:    c[i].Gate,
			NbIn:        nbIn,
			Degree:      compiledGate.Degree,
			SolvableVar: compiledGate.SolvableVar,
		}
		serializable[i].Gate = compiledGate
	}

	return gadget, serializable, nil
}
