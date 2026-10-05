// Package gkrapi builds and compiles a GKR circuit, for proving and verifying with gkr/<curve>.
package gkrapi

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
)

// Circuit is a circuit compiled by API.Compile, ready to prove and verify with gkr/<curve>.
type Circuit = gkrcore.SerializableCircuit

// ConsolidationMode selects which wires DefaultProvingSchedule consolidates into level 0.
type ConsolidationMode = gkrcore.ConsolidationMode

// The consolidation modes Compile accepts.
const (
	ConsolidateAll                  = gkrcore.ConsolidateAll
	ConsolidateMultiClaimInputsOnly = gkrcore.ConsolidateMultiClaimInputsOnly
	ConsolidateNone                 = gkrcore.ConsolidateNone
)

// API builds a GKR circuit, gate by gate.
type API struct {
	circuit gkrcore.RawCircuit
}

// New creates a new GKR API.
func New() *API {
	return &API{}
}

// NewInput creates a new input variable.
func (api *API) NewInput() gkr.Variable {
	return api.circuit.NewInput()
}

// Gate adds the given gate with the given inputs and returns its output wire.
func (api *API) Gate(gate gkr.GateFunction, inputs ...gkr.Variable) gkr.Variable {
	return api.circuit.Gate(gate, inputs...)
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

// Compile compiles the circuit for field, and builds its default proving schedule under mode.
func (api *API) Compile(field *big.Int, mode ConsolidationMode) (Circuit, constraint.GkrProvingSchedule, error) {
	_, circuit, err := api.circuit.Compile(field)
	if err != nil {
		return nil, nil, err
	}
	schedule, err := gkrcore.DefaultProvingSchedule(circuit, mode)
	if err != nil {
		return nil, nil, err
	}
	return circuit, schedule, nil
}
