package gkrapi

import (
	"github.com/consensys/gnark/constraint/solver/gkrgates" // nolint SA1019
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/internal/utils"
)

type (
	API struct {
		circuit     gkrcore.RawCircuit
		assignments gadget.WireAssignment
		parentApi   frontend.API
	}
)

func frontendVarToInt(a gkr.Variable) int {
	return int(a)
}

// Gate adds the given gate with the given inputs and returns its output wire.
func (api *API) Gate(gate gkr.GateFunction, inputs ...gkr.Variable) gkr.Variable {
	api.circuit = append(api.circuit, gkrcore.RawWire{
		Gate:   gate,
		Inputs: utils.Map(inputs, frontendVarToInt),
	})
	api.assignments = append(api.assignments, nil)
	return gkr.Variable(len(api.circuit) - 1)
}

// NamedGate adds a gate looked up by name from the registry.
//
// Deprecated: Named gates are no longer needed. Pass GateFunction directly to API.Gate().
func (api *API) NamedGate(gate gkr.GateName, inputs ...gkr.Variable) gkr.Variable {
	return api.Gate(gkrgates.Get(gate), inputs...)
}

func (api *API) gate2PlusIn(gate gkr.GateFunction, in1, in2 gkr.Variable, in ...gkr.Variable) gkr.Variable {
	inCombined := make([]gkr.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return api.Gate(gate, inCombined...)
}

func (api *API) Add(i1, i2 gkr.Variable) gkr.Variable {
	return api.gate2PlusIn(gkrcore.Add2, i1, i2)
}

func (api *API) Neg(i1 gkr.Variable) gkr.Variable {
	return api.Gate(gkrcore.Neg, i1)
}

func (api *API) Sub(i1, i2 gkr.Variable) gkr.Variable {
	return api.gate2PlusIn(gkrcore.Sub2, i1, i2)
}

func (api *API) Mul(i1, i2 gkr.Variable) gkr.Variable {
	return api.gate2PlusIn(gkrcore.Mul2, i1, i2)
}

// Export explicitly designates a wire as output.
// Wires that are not used as input to another are considered output by default.
func (api *API) Export(in ...gkr.Variable) {
	for _, v := range in {
		api.circuit[v].Exported = true
	}
}
