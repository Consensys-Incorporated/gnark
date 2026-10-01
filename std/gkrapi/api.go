package gkrapi

import (
	"github.com/consensys/gnark/constraint/solver/gkrgates" // nolint SA1019
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
)

type (
	API struct {
		circuit   gkrcore.RawCircuit
		parentApi frontend.API
	}
)

// Gate adds the given gate with the given inputs and returns its output wire.
func (api *API) Gate(gate gkr.GateFunction, inputs ...gkr.Variable) gkr.Variable {
	return api.circuit.Gate(gate, inputs...)
}

// NamedGate adds a gate looked up by name from the registry.
//
// Deprecated: Named gates are no longer needed. Pass GateFunction directly to API.Gate().
func (api *API) NamedGate(gate gkr.GateName, inputs ...gkr.Variable) gkr.Variable {
	return api.Gate(gkrgates.Get(gate), inputs...)
}

func (api *API) Add(i1, i2 gkr.Variable) gkr.Variable {
	return api.circuit.Add(i1, i2)
}

func (api *API) Neg(i1 gkr.Variable) gkr.Variable {
	return api.circuit.Neg(i1)
}

func (api *API) Sub(i1, i2 gkr.Variable) gkr.Variable {
	return api.circuit.Sub(i1, i2)
}

func (api *API) Mul(i1, i2 gkr.Variable) gkr.Variable {
	return api.circuit.Mul(i1, i2)
}

// Export explicitly designates a wire as output.
// Wires that are not used as input to another are considered output by default.
func (api *API) Export(in ...gkr.Variable) {
	api.circuit.Export(in...)
}
