package test

import (
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/internal/utils"
)

// ignore witness size larger than this bound
const permutterBound = 3

// r1cs + sparser1cs
const nbSystems = 2

var builders [2]frontend.NewBuilderU32

func TestSolverConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping R1CS solver test with testing.Short() flag set")
		return
	}

	// idea is test circuits, we are going to test all possible values of the witness.
	// (hence the choice of a small modulus for the field size)
	//
	// we generate witnesses and compare with the output of big.Int test engine against
	// R1CS and SparseR1CS solvers

	for name := range circuits.Circuits {
		t.Run(name, func(t *testing.T) {
			tc := circuits.Circuits[name]
			if tc.U64Only {
				t.Skip("circuit only supports U64 fields")
			}
			if name == "commit" {
				// we skip the commit circuit for consistency check because small field circuits
				// should use [frontend.WideCommitter] interface, but in this test we want to
				// use the given builder not, the one wrapped using [widecommitter.From].
				return
			}
			t.Parallel()
			err := consistentSolver(tc.Circuit, tc.HintFunctions)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// witness used for the permutter. It implements the Witness interface
// using mock methods (only the underlying vector is required).
type permutterWitness struct {
	vector any
}

func (pw *permutterWitness) WriteTo(w io.Writer) (int64, error) {
	return 0, nil
}

func (pw *permutterWitness) ReadFrom(r io.Reader) (int64, error) {
	return 0, nil
}

func (pw *permutterWitness) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (pw *permutterWitness) UnmarshalBinary([]byte) error {
	return nil
}

func (pw *permutterWitness) Public() (witness.Witness, error) {
	return pw, nil
}

func (pw *permutterWitness) Vector() any {
	return pw.vector
}

func (pw *permutterWitness) ToJSON(s *schema.Schema) ([]byte, error) {
	return nil, nil
}

func (pw *permutterWitness) FromJSON(s *schema.Schema, data []byte) error {
	return nil
}

func (pw *permutterWitness) Fill(nbPublic, nbSecret int, values <-chan any) error {
	return nil
}

func newPermutterWitness(pv tinyfield.Vector) witness.Witness {
	return &permutterWitness{
		vector: pv,
	}
}

type permutter struct {
	circuit           frontend.Circuit
	constraintSystems [2]constraint.ConstraintSystemU32
	witness           []tinyfield.Element
	hints             []solver.Hint
}

// note that circuit will be mutated and this is not thread safe
func (p *permutter) permuteAndTest(index int) error {

	for i := 0; i < len(tinyfieldElements); i++ {
		p.witness[index].SetUint64(uint64(tinyfieldElements[i]))
		if index == len(p.witness)-1 {

			// we have a unique permutation
			var errorSystems [2]error
			var errorEngines [2]error

			// 2 constraints systems
			for k := 0; k < nbSystems; k++ {

				errorSystems[k] = p.solve(k)

				// solve the cs using test engine
				// first copy the witness in the circuit
				copyWitnessFromVector(tinyfield.Modulus(), p.circuit, p.witness)
				errorEngines[0] = isSolvedEngine(p.circuit, tinyfield.Modulus())

				copyWitnessFromVector(tinyfield.Modulus(), p.circuit, p.witness)
				errorEngines[1] = isSolvedEngine(p.circuit, tinyfield.Modulus(), SetAllVariablesAsConstants())

			}
			if (errorSystems[0] == nil) != (errorEngines[0] == nil) ||
				(errorSystems[1] == nil) != (errorEngines[0] == nil) ||
				(errorEngines[0] == nil) != (errorEngines[1] == nil) {
				return fmt.Errorf("errSCS :%s\nerrR1CS :%s\nerrEngine(const=false): %s\nerrEngine(const=true): %s\nwitness: %s",
					formatError(errorSystems[0]),
					formatError(errorSystems[1]),
					formatError(errorEngines[0]),
					formatError(errorEngines[1]),
					formatWitness(p.witness))
			}

		} else {
			// recurse
			if err := p.permuteAndTest(index + 1); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func formatWitness(witness []tinyfield.Element) string {
	var sbb strings.Builder
	sbb.WriteByte('[')

	for i := 0; i < len(witness); i++ {
		sbb.WriteString(strconv.Itoa(int(witness[i].Uint64())))
		if i != len(witness)-1 {
			sbb.WriteString(", ")
		}
	}

	sbb.WriteByte(']')

	return sbb.String()
}

func (p *permutter) solve(i int) error {
	pw := newPermutterWitness(p.witness)
	_, err := p.constraintSystems[i].Solve(pw, solver.WithHints(p.hints...))
	return err
}

// isSolvedEngine behaves like test.IsSolved except it doesn't clone the circuit
func isSolvedEngine(c frontend.Circuit, field *big.Int, opts ...TestEngineOption) (err error) {
	e := &engine{
		curveID:   utils.FieldToCurve(field),
		q:         new(big.Int).Set(field),
		constVars: false,
		Store:     kvstore.New(),
	}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return fmt.Errorf("apply option: %w", err)
		}
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, string(debug.Stack()))
		}
	}()

	if err = c.Define(e); err != nil {
		return fmt.Errorf("define: %w", err)
	}
	if err = callDeferred(e); err != nil {
		return fmt.Errorf("")
	}

	return
}

// fill the "to" frontend.Circuit with values from the provided vector
// values are assumed to be ordered [public | secret]
func copyWitnessFromVector(field *big.Int, to frontend.Circuit, from []tinyfield.Element) {
	i := 0
	schema.Walk(field, to, tVariable, func(f schema.LeafInfo, tInput reflect.Value) error {
		if f.Visibility == schema.Public {
			tInput.Set(reflect.ValueOf(from[i]))
			i++
		}
		return nil
	})

	schema.Walk(field, to, tVariable, func(f schema.LeafInfo, tInput reflect.Value) error {
		if f.Visibility == schema.Secret {
			tInput.Set(reflect.ValueOf(from[i]))
			i++
		}
		return nil
	})
}

// ConsistentSolver solves given circuit with all possible witness combinations using internal/tinyfield
//
// Since the goal of this method is to flag potential solver issues, it is not exposed as an API for now
func consistentSolver(circuit frontend.Circuit, hintFunctions []solver.Hint) error {

	p := permutter{
		circuit: circuit,
		hints:   hintFunctions,
	}

	// compile the systems
	for i := 0; i < nbSystems; i++ {

		ccs, err := frontend.CompileU32(tinyfield.Modulus(), builders[i], circuit)
		if err != nil {
			return err
		}
		p.constraintSystems[i] = ccs

		if i == 0 { // the -1 is only for r1cs...
			n := ccs.GetNbPublicVariables() - 1 + ccs.GetNbSecretVariables()
			if n > permutterBound {
				return nil
			}
			p.witness = make([]tinyfield.Element, n)
		}

	}

	return p.permuteAndTest(0)
}

// [0, 1, ..., q - 1], with q == tinyfield.Modulus()
var tinyfieldElements []uint64

func init() {
	n := tinyfield.Modulus().Uint64()
	tinyfieldElements = make([]uint64, n)
	for i := uint64(0); i < n; i++ {
		tinyfieldElements[i] = i
	}

	builders[0] = r1cs.NewBuilder
	builders[1] = scs.NewBuilder
}
