package gkr

type (
	// A Gate is a low-degree multivariate polynomial
	Gate[GateExecutable any] struct {
		Evaluate    GateExecutable
		NbIn        int // number of inputs
		Degree      int // total Degree of the polynomial
		SolvableVar int // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
	}

	// Wire is a wire of a circuit: the gate that computes it, the indices of the wires its gate
	// reads, and whether it is an output even if another wire reads it.
	Wire[GateExecutable any] struct {
		Gate     Gate[GateExecutable]
		Inputs   []int
		Exported bool
	}

	// Circuit is a list of wires, in topological order: each wire's inputs precede it.
	Circuit[GateExecutable any] []Wire[GateExecutable]

	// Type aliases for different circuit instantiations

	// Serializable types (bytecode only, for native proving)

	SerializableGate    = Gate[GateBytecode]
	SerializableCircuit = Circuit[GateBytecode]
	SerializableWire    = Wire[GateBytecode]

	// Gadget types (gate functions only, for in-circuit verification)

	GadgetGate    = Gate[GateFunction]
	GadgetCircuit = Circuit[GateFunction]
	GadgetWire    = Wire[GateFunction]
)

// IsInput returns whether the wire is an input wire.
func (w Wire[GateExecutable]) IsInput() bool {
	return len(w.Inputs) == 0
}

// IsInput returns whether wire wireIndex is an input wire.
func (c Circuit[GateExecutable]) IsInput(wireIndex int) bool {
	return c[wireIndex].IsInput()
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
