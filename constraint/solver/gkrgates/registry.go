// Package gkrgates contains the registry of GKR gates.
//
// Deprecated: Named gates are no longer needed. Pass GateFunction directly to API.Gate().
package gkrgates

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
)

type registerSettings struct {
	solvableVar int
	degree      int
	name        gkr.GateName // nolint SA1019
	curves      []ecc.ID
}

const unset = -2

func newRegisterSettings() registerSettings {
	return registerSettings{
		solvableVar: unset,
		degree:      unset,
	}
}

// RegisterOption is a functional option for Register.
type RegisterOption func(*registerSettings) error

// WithSolvableVar gives the index of a variable whose value can be uniquely determined
// from that of the other variables along with the gate's output.
func WithSolvableVar(solvableVar int) RegisterOption {
	return func(s *registerSettings) error {
		if s.solvableVar != unset {
			return fmt.Errorf("solvable variable already set to %d", s.solvableVar)
		}
		s.solvableVar = solvableVar
		return nil
	}
}

// WithUnverifiedSolvableVar sets the index of a variable whose value can be uniquely determined
// from that of the other variables along with the gate's output.
// This now functions identically to WithSolvableVar.
func WithUnverifiedSolvableVar(solvableVar int) RegisterOption {
	return WithSolvableVar(solvableVar)
}

// WithNoSolvableVar sets the gate as having no variable whose value can be uniquely determined
// from that of the other variables along with the gate's output.
func WithNoSolvableVar() RegisterOption {
	return WithSolvableVar(-1)
}

// WithUnverifiedDegree sets the degree of the gate.
// This now functions identically to WithDegree.
func WithUnverifiedDegree(degree int) RegisterOption {
	return WithDegree(degree)
}

// WithDegree sets the degree of the gate.
func WithDegree(degree int) RegisterOption {
	return func(s *registerSettings) error {
		if s.degree != unset {
			return fmt.Errorf("gate degree already set to %d", s.degree)
		}
		s.degree = degree
		return nil
	}
}

// WithName can be used to set a human-readable name for the gate.
func WithName(name gkr.GateName) RegisterOption { // nolint SA1019
	return func(s *registerSettings) error {
		if name == "" {
			return errors.New("gate name must not be empty")
		}
		if s.name != "" {
			return fmt.Errorf("gate name already set to %q", s.name)
		}
		s.name = name
		return nil
	}
}

// WithCurves determines on which curves the gate is validated and allowed to be used.
func WithCurves(curves ...ecc.ID) RegisterOption {
	return func(s *registerSettings) error {
		if s.curves != nil {
			return errors.New("gate curves already set")
		}
		s.curves = curves
		return nil
	}
}

var gates = make(map[gkr.GateName]gkr.GateFunction) // nolint SA1019

// Register creates a gate object and stores it in the gates registry.
func Register(f gkr.GateFunction, nbIn int, options ...RegisterOption) error {
	s := newRegisterSettings()
	for _, opt := range options {
		if err := opt(&s); err != nil {
			return err
		}
	}
	if s.name == "" {
		s.name = GetDefaultGateName(f)
	}

	if s.curves == nil {
		s.curves = []ecc.ID{ecc.BN254}
	}

	for _, curve := range s.curves {
		compiled, err := gkrcore.CompileGateFunction(f, nbIn, curve.ScalarField())
		if err != nil {
			return err
		}

		if s.degree == unset {
			s.degree = compiled.Degree
		}
		if s.degree != compiled.Degree {
			return fmt.Errorf("gate degree mismatch: expected %d, got %d on %s", s.degree, compiled.Degree, curve)
		}

		if s.solvableVar == unset {
			s.solvableVar = compiled.SolvableVar
		}
		if s.solvableVar != compiled.SolvableVar {
			return fmt.Errorf("solvable variable mismatch: expected %d, got %d on %s", s.solvableVar, compiled.SolvableVar, curve)
		}
	}

	gates[s.name] = f
	return nil
}

// Get returns a registered gate function by name.
// If not found, it panics.
func Get(name gkr.GateName) gkr.GateFunction { // nolint SA1019
	if f, ok := gates[name]; ok {
		return f
	}
	panic("gate not found: " + string(name))
}

// GetDefaultGateName provides a standardized name for a gate function, depending on its package and name.
// NB: For anonymous functions, the name is the same no matter the implicit arguments provided.
func GetDefaultGateName(fn gkr.GateFunction) gkr.GateName { // nolint SA1019
	fnptr := reflect.ValueOf(fn).Pointer()
	return gkr.GateName(runtime.FuncForPC(fnptr).Name()) // nolint SA1019
}
