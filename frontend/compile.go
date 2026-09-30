package frontend

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/circuitdefer"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/logger"
)

// Compile will generate a ConstraintSystem from the given circuit
//
// 1. it will first allocate the user inputs (see [schema.TagOpt] and [Circuit] for more info)
// example:
//
//	type MyCircuit struct {
//		Y frontend.Variable `gnark:"exponent,public"`
//	}
//
// in that case, Compile() will allocate one public variable with id "exponent"
//
// 2. it then calls circuit.Define(curveID, R1CS) to build the internal constraint system
// from the declarative code
//
//  3. finally, it converts that to a ConstraintSystem.
//     if zkpID == backend.GROTH16	→ R1CS
//     if zkpID == backend.PLONK 	→ SparseR1CS
//
// For implementation which compiles the circuit optimized for a small-field modulus, see [CompileU32].
func Compile(field *big.Int, newBuilder NewBuilder, circuit Circuit, opts ...CompileOption) (constraint.ConstraintSystem, error) {
	if !constraint.FitsElement[constraint.U64](field) {
		var supported []string
		for _, c := range gnark.Curves() {
			supported = append(supported, c.String())
		}
		return nil, fmt.Errorf("can not compile over field %s. This method supports compiling over scalar fields of supported curves: %s. For compiling over small fields use frontend.CompileU32", field, strings.Join(supported, ", "))
	}
	return CompileGeneric(field, newBuilder, circuit, opts...)
}

// CompileU32 is a variant of [Compile] which is optimized for small field
// modulus.
//
// NB! When compiling for a small field modulus, then the resulting [constraint.ConstraintSystem] is not
// compatible with pairing based backends.
func CompileU32(field *big.Int, newBuilder NewBuilderU32, circuit Circuit, opts ...CompileOption) (constraint.ConstraintSystemU32, error) {
	if !constraint.FitsElement[constraint.U32](field) {
		var supported []string
		for _, c := range smallfields.Supported() {
			supported = append(supported, c.String())
		}
		return nil, fmt.Errorf("can not compile over field %s. This method only supports the following moduli: %s. For compiling over scalar fields of supported elliptic curves use frontend.Compile", field, strings.Join(supported, ", "))
	}
	return CompileGeneric(field, newBuilder, circuit, opts...)
}

// CompileGeneric is a generic version of [Compile] and [CompileU32]. It is
// mainly for allowing for type switching, for users the methods [Compile] and
// [CompileU32] are more convenient as are explicitly constrained to specific
// types.
func CompileGeneric[E constraint.Element](field *big.Int, newBuilder NewBuilderGeneric[E], circuit Circuit, opts ...CompileOption) (constraint.ConstraintSystemGeneric[E], error) {
	log := logger.Logger()
	log.Info().Msg("compiling circuit")
	// parse options
	opt := defaultCompileConfig()
	for _, o := range opts {
		if err := o(&opt); err != nil {
			log.Err(err).Msg("applying compile option")
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}

	// instantiate new builder
	builder, err := newBuilder(field, opt)
	if err != nil {
		log.Err(err).Msg("instantiating builder")
		return nil, fmt.Errorf("new compiler: %w", err)
	}

	// parse the circuit builds a schema of the circuit
	// and call circuit.Define() method to initialize a list of constraints in the compiler
	if err = parseCircuit(builder, circuit); err != nil {
		log.Err(err).Msg("parsing circuit")
		return nil, fmt.Errorf("parse circuit: %w", err)

	}

	// compile the circuit into its final form
	return builder.Compile()
}

func parseCircuit[E constraint.Element](builder Builder[E], circuit Circuit) (err error) {
	// ensure circuit.Define has pointer receiver
	if reflect.ValueOf(circuit).Kind() != reflect.Pointer {
		return errors.New("frontend.Circuit methods must be defined on pointer receiver")
	}

	s, err := schema.Walk(builder.Field(), circuit, tVariable, nil)
	if err != nil {
		return err
	}

	log := logger.Logger()
	log.Info().Int("nbSecret", s.Secret).Int("nbPublic", s.Public).Msg("parsed circuit inputs")

	// leaf handlers are called when encountering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	variableAdder := func(targetVisibility schema.Visibility) func(f schema.LeafInfo, tInput reflect.Value) error {
		return func(f schema.LeafInfo, tInput reflect.Value) error {
			if tInput.CanSet() {
				if f.Visibility == schema.Unset {
					return errors.New("can't set val " + f.FullName() + " visibility is unset")
				}
				if f.Visibility == targetVisibility {
					if f.Visibility == schema.Public {
						tInput.Set(reflect.ValueOf(builder.PublicVariable(f)))
					} else if f.Visibility == schema.Secret {
						tInput.Set(reflect.ValueOf(builder.SecretVariable(f)))
					}
				}

				return nil
			}
			return errors.New("can't set val " + f.FullName())
		}
	}

	// add public inputs first to compute correct offsets
	_, err = schema.Walk(builder.Field(), circuit, tVariable, variableAdder(schema.Public))
	if err != nil {
		return err
	}

	// add secret inputs
	_, err = schema.Walk(builder.Field(), circuit, tVariable, variableAdder(schema.Secret))
	if err != nil {
		return err
	}

	// recover from panics to print user-friendlier messages
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, debug.Stack())
		}
	}()

	// call Define() to fill in the Constraints
	if err = circuit.Define(builder); err != nil {
		return fmt.Errorf("define circuit: %w", err)
	}
	if err = callDeferred(builder); err != nil {
		return fmt.Errorf("deferred: %w", err)
	}

	return
}

func callDeferred[E constraint.Element](builder Builder[E]) error {
	// we get the compiler from the builder in case builder is already wrapped
	// and overwrites methods required in kvstore.Store (SetKeyValue and
	// GetKeyValue).
	//
	// However, as an API to the callbacks we still pass in the initial builder
	// as deferred methods may use wrapped methods (Commit, WideCommit).
	compiler := builder.Compiler()
	for i := 0; i < len(circuitdefer.GetAll[func(API) error](compiler)); i++ {
		if err := circuitdefer.GetAll[func(API) error](compiler)[i](builder); err != nil {
			return fmt.Errorf("defer fn %d: %w", i, err)
		}
	}
	return nil
}

// CompileOption defines option for altering the behaviour of the Compile
// method. See the descriptions of the functions returning instances of this
// type for available options.
type CompileOption func(opt *CompileConfig) error

func defaultCompileConfig() CompileConfig {
	return CompileConfig{
		CompressThreshold: 300,
	}
}

type CompileConfig struct {
	Capacity                  int
	IgnoreUnconstrainedInputs bool
	CompressThreshold         int
}

// WithCapacity is a compile option that specifies the estimated capacity needed
// for internal variables and constraints. If not set, then the initial capacity
// is 0 and is dynamically allocated as needed.
func WithCapacity(capacity int) CompileOption {
	return func(opt *CompileConfig) error {
		opt.Capacity = capacity
		return nil
	}
}

// IgnoreUnconstrainedInputs is a compile option which allow compiling input
// circuits where not all inputs are not constrained. If not set, then the
// compiler returns an error if there exists an unconstrained input.
//
// This option is useful for debugging circuits, but should not be used in
// production settings as it means that there is a potential error in the
// circuit definition or that it is possible to optimize witness size.
func IgnoreUnconstrainedInputs() CompileOption {
	return func(opt *CompileConfig) error {
		opt.IgnoreUnconstrainedInputs = true
		return nil
	}
}

// WithCompressThreshold is a compile option which enforces automatic variable
// compression if the length of the linear expression in the variable exceeds
// given threshold.
//
// This option is usable in arithmetisations where the variable is a linear
// combination, as for example in R1CS. If variable is not a linear combination,
// then this option does not change the compile behaviour.
//
// This compile option should be used in cases when it is known that there are
// long addition chains and the compile time and memory usage start are growing
// fast. The compression adds some overhead in the number of constraints. The
// overhead and compile performance depends on threshold value, and it should be
// chosen carefully.
//
// If this option is not given then by default we use the compress threshold of
// 300.
func WithCompressThreshold(threshold int) CompileOption {
	return func(opt *CompileConfig) error {
		opt.CompressThreshold = threshold
		return nil
	}
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A Variable }{}).FieldByName("A").Type()
}
