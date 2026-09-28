package gkr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func TestGkrVectors(t *testing.T) {

	testDirPath := "./test_vectors"
	dirEntries, err := os.ReadDir(testDirPath)
	if err != nil {
		t.Error(err)
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() && filepath.Ext(dirEntry.Name()) == ".json" {
			path := filepath.Join(testDirPath, dirEntry.Name())
			noExt := dirEntry.Name()[:len(dirEntry.Name())-len(".json")]

			t.Run(noExt, generateTestVerifier(path))
		}
	}
}

type _options struct {
	noSuccess bool
	noFail    bool
}

type option func(*_options)

func noSuccess(o *_options) {
	o.noSuccess = true
}

func generateTestVerifier(path string, options ...option) func(t *testing.T) {
	var opts _options
	for _, opt := range options {
		opt(&opts)
	}

	return func(t *testing.T) {

		testCase, err := getTestCase(path)
		assert := test.NewAssert(t)
		assert.NoError(err)

		assignment := &GkrVerifierCircuit{
			Input:           testCase.Input,
			Output:          testCase.Output,
			SerializedProof: testCase.Proof.Serialize(),
			ToFail:          false,
			TestCaseName:    path,
		}

		validCircuit := &GkrVerifierCircuit{
			Input:           make([][]frontend.Variable, len(testCase.Input)),
			Output:          make([][]frontend.Variable, len(testCase.Output)),
			SerializedProof: make([]frontend.Variable, len(assignment.SerializedProof)),
			ToFail:          false,
			TestCaseName:    path,
		}

		invalidCircuit := &GkrVerifierCircuit{
			Input:           make([][]frontend.Variable, len(testCase.Input)),
			Output:          make([][]frontend.Variable, len(testCase.Output)),
			SerializedProof: make([]frontend.Variable, len(assignment.SerializedProof)),
			ToFail:          true,
			TestCaseName:    path,
		}

		fillWithBlanks(validCircuit.Input, len(testCase.Input[0]))
		fillWithBlanks(validCircuit.Output, len(testCase.Input[0]))
		fillWithBlanks(invalidCircuit.Input, len(testCase.Input[0]))
		fillWithBlanks(invalidCircuit.Output, len(testCase.Input[0]))

		if !opts.noSuccess {
			assert.CheckCircuit(validCircuit, test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
		}

		if !opts.noFail {
			assert.CheckCircuit(invalidCircuit, test.WithBackends(backend.GROTH16), test.WithInvalidAssignment(assignment))
		}
	}
}

type GkrVerifierCircuit struct {
	Input           [][]frontend.Variable
	Output          [][]frontend.Variable `gnark:",public"`
	SerializedProof []frontend.Variable
	ToFail          bool
	TestCaseName    string
}

func (c *GkrVerifierCircuit) Define(api frontend.API) error {
	var testCase *testCase
	var proof Proof
	var err error
	if testCase, err = getTestCase(c.TestCaseName); err != nil {
		return err
	}

	if proof, err = DeserializeProof(testCase.Circuit, testCase.Schedule, c.SerializedProof); err != nil {
		return err
	}
	assignment := makeInOutAssignment(testCase.Circuit, c.Input, c.Output)

	var hsh hash.FieldHasher
	if c.ToFail {
		hsh = newMessageCounter(api, 1, 1)
	} else {
		if hsh, err = hashFromDescription(api, testCase.Hash); err != nil {
			return err
		}
	}

	claims, err := Verify(api, testCase.Circuit, testCase.Schedule, assignment.NbVars(), proof, hsh)
	if err != nil {
		return err
	}
	claims.Check(api, assignment)
	return nil
}

func makeInOutAssignment(c Circuit, inputValues [][]frontend.Variable, outputValues [][]frontend.Variable) WireAssignment {
	res := make(WireAssignment, len(c))
	inputs := c.Inputs()
	outputs := c.Outputs()
	for i, wI := range inputs {
		res[wI] = inputValues[i]
	}
	for i, wI := range outputs {
		res[wI] = outputValues[i]
	}
	return res
}

func fillWithBlanks(slice [][]frontend.Variable, size int) {
	for i := range slice {
		slice[i] = make([]frontend.Variable, size)
	}
}

type testCase struct {
	Circuit  Circuit
	Schedule constraint.GkrProvingSchedule
	Hash     hashDescription
	Proof    Proof
	Input    [][]frontend.Variable
	Output   [][]frontend.Variable
	Name     string
}
type testCaseInfo struct {
	Hash    hashDescription `json:"hash"`
	Circuit string          `json:"circuit"`
	Input   [][]interface{} `json:"input"`
	Output  [][]interface{} `json:"output"`
	Proof   printableProof  `json:"proof"`
}

var testCases = make(map[string]*testCase)

func getTestCase(path string) (*testCase, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)

	cse, ok := testCases[path]
	if !ok {
		var bytes []byte
		cse = &testCase{}
		if bytes, err = os.ReadFile(path); err == nil {
			var info testCaseInfo
			err = json.Unmarshal(bytes, &info)
			if err != nil {
				return nil, err
			}

			serializableCircuit, gadgetCircuit := cache.GetCircuit(filepath.Join(dir, info.Circuit))
			cse.Circuit = gadgetCircuit

			schedule, schedErr := gkrcore.DefaultProvingSchedule(serializableCircuit, gkrcore.SNARKConsolidationMode)
			if schedErr != nil {
				return nil, schedErr
			}
			cse.Schedule = schedule

			cse.Proof = unmarshalProof(info.Proof)

			cse.Input = toVariableSliceSlice(info.Input)
			cse.Output = toVariableSliceSlice(info.Output)
			cse.Hash = info.Hash
			cse.Name = path
			testCases[path] = cse
		} else {
			return nil, err
		}
	}

	return cse, nil
}

type printableProof []printableSumcheckProof

type printableSumcheckProof struct {
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
}

func unmarshalProof(printable printableProof) (proof Proof) {
	proof = make(Proof, len(printable))
	for i := range printable {

		if printable[i].FinalEvalProof != nil {
			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
			finalEvalProof := make([]frontend.Variable, finalEvalSlice.Len())
			for k := range finalEvalProof {
				finalEvalProof[k] = toVariable(finalEvalSlice.Index(k).Interface())
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].PartialSumPolys = make([]polynomial.Polynomial, len(printable[i].PartialSumPolys))
		for k := range printable[i].PartialSumPolys {
			proof[i].PartialSumPolys[k] = toVariableSlice(printable[i].PartialSumPolys[k])
		}
	}
	return
}

func hasSumcheck(s constraint.GkrProvingSchedule) bool {
	for _, l := range s {
		if _, ok := l.(*constraint.GkrSumcheckLevel); ok {
			return true
		}
	}
	return false
}

func TestLogNbInstances(t *testing.T) {
	testLogNbInstances := func(path string) func(t *testing.T) {
		return func(t *testing.T) {
			testCase, err := getTestCase(path)
			assert.NoError(t, err)
			serializedProof := testCase.Proof.Serialize()
			logNbInstances := ComputeLogNbInstances(testCase.Circuit, testCase.Schedule, len(serializedProof))
			if hasSumcheck(testCase.Schedule) {
				assert.Equal(t, 1, logNbInstances)
			} else {
				assert.Equal(t, -1, logNbInstances, "no-sumcheck schedule should have logNbInstances=-1, got %d instead", logNbInstances)
			}
		}
	}

	cases := []string{"two_inputs_select-input-3_gate_two_instances", "two_identity_gates_composed_single_input_two_instances"}

	for _, caseName := range cases {
		t.Run("log_nb_instances:"+caseName, testLogNbInstances("test_vectors/"+caseName+".json"))
	}
}

type hashDescription map[string]interface{}

// hashFromDescription returns the hash a test vector names. The only type is "const": a
// messageCounter with step 0, so every challenge equals the given value regardless of what was
// bound to the transcript. Test vectors therefore pin down the GKR and sumcheck arithmetic only.
// Transcript handling is exercised end to end by the std/gkrapi tests, which use real hashes.
func hashFromDescription(api frontend.API, d hashDescription) (hash.FieldHasher, error) {
	if _type, ok := d["type"]; ok {
		switch _type {
		case "const":
			startState := int(d["val"].(float64))
			return newMessageCounter(api, startState, 0), nil
		default:
			return nil, fmt.Errorf("unknown fake hash type \"%s\"", _type)
		}
	}
	return nil, fmt.Errorf("hash description missing type")
}

// messageCounter is a stand-in hash whose state depends only on the number of variables written
// to it, not on their values.
type messageCounter struct {
	startState int64
	state      int64
	step       int64

	// cheap trick to avoid unconstrained input errors
	api  frontend.API
	zero frontend.Variable
}

func (m *messageCounter) Write(data ...frontend.Variable) {

	for i := range data {
		sq1, sq2 := m.api.Mul(data[i], data[i]), m.api.Mul(data[i], data[i])
		m.zero = m.api.Sub(sq1, sq2, m.zero)
	}

	m.state += int64(len(data)) * m.step
}

func (m *messageCounter) Sum() frontend.Variable {
	return m.api.Add(m.state, m.zero)
}

func (m *messageCounter) Reset() {
	m.zero = 0
	m.state = m.startState
}

func newMessageCounter(api frontend.API, startState, step int) hash.FieldHasher {
	return &messageCounter{startState: int64(startState), state: int64(startState), step: int64(step), zero: 0, api: api}
}

type constHashCircuit struct {
	X frontend.Variable
}

func (c *constHashCircuit) Define(api frontend.API) error {
	hsh := newMessageCounter(api, 0, 0)
	hsh.Reset()
	hsh.Write(c.X)
	sum := hsh.Sum()
	api.AssertIsEqual(sum, 0)
	api.AssertIsEqual(api.Mul(c.X, c.X), 1) // ensure we have at least 2 constraints
	return nil
}

func TestConstHash(t *testing.T) {
	test.NewAssert(t).CheckCircuit(
		&constHashCircuit{},

		test.WithValidAssignment(&constHashCircuit{X: 1}),
	)
}

var cache = gkrtesting.NewCache(ecc.BN254.ScalarField())
