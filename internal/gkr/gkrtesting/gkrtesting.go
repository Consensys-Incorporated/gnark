package gkrtesting

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/stretchr/testify/require"
)

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	field    *big.Int
	circuits map[string]circuits
	gates    map[string]gkr.GateFunction
	lock     sync.Mutex
}

type circuits struct {
	serializable gkrcore.SerializableCircuit
	gadget       gkrcore.GadgetCircuit
}

func mimcGate(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	sum := api.Add(input[0], input[1]) //.Add(&sum, &m.ark)  TODO: add ark
	res := api.Mul(sum, sum)           // sum^2
	res = api.Mul(res, sum)            // sum^3
	res = api.Mul(res, res)            // sum^6
	res = api.Mul(res, sum)            // sum^7

	return res
}

// mimcLastGate is the final-round gate, which also takes the initial state input (input[2]).
// This mirrors std/permutation/gkr-mimc, where the state input feeds both the first round and the
// final gate — making it a multi-source input.
func mimcLastGate(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	sum := api.Add(input[0], input[1])
	sum = api.Add(sum, input[2])
	res := api.Mul(sum, sum)
	res = api.Mul(res, sum)
	return res
}

func selectInput3Gate(_ gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return in[2]
}

func NewCache(field *big.Int) *Cache {
	gates := make(map[string]gkr.GateFunction, 7)
	gates[""] = nil
	gates["identity"] = gkrcore.Identity
	gates["add2"] = gkrcore.Add2
	gates["sub2"] = gkrcore.Sub2
	gates["neg"] = gkrcore.Neg
	gates["mul2"] = gkrcore.Mul2
	gates["mimc"] = mimcGate
	gates["select-input-3"] = selectInput3Gate

	return &Cache{
		field:    field,
		circuits: make(map[string]circuits),
		gates:    gates,
	}
}

// JSONWire is the JSON serialization format for circuit wires (gate name + inputs)
type JSONWire struct {
	Gate   string `json:"gate"`   // gate name, empty for input wires
	Inputs []int  `json:"inputs"` // indices of input wires
}

// JSONCircuit is the JSON serialization format for circuits
type JSONCircuit []JSONWire

// Compile compiles a RawCircuit into a SerializableCircuit.
func (c *Cache) Compile(t require.TestingT, circuit gkrcore.RawCircuit) (gkrcore.GadgetCircuit, gkrcore.SerializableCircuit) {
	gadget, serializable, err := circuit.Compile(c.field)
	require.NoError(t, err)
	return gadget, serializable
}

func (c *Cache) GetCircuit(path string) (gkrcore.SerializableCircuit, gkrcore.GadgetCircuit) {
	c.lock.Lock()
	defer c.lock.Unlock()

	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	if circuit, ok := c.circuits[path]; ok {
		return circuit.serializable, circuit.gadget
	}

	var bytes []byte
	if bytes, err = os.ReadFile(path); err != nil {
		panic(err)
	}

	// Unmarshal from JSON format (gate names as strings)
	var jsonCircuit JSONCircuit
	if err = json.Unmarshal(bytes, &jsonCircuit); err != nil {
		panic(err)
	}

	// Convert JSON format to RawCircuit
	rawCircuit := make(gkrcore.RawCircuit, len(jsonCircuit))
	for i, wJSON := range jsonCircuit {
		rawCircuit[i] = gkrcore.RawWire{
			Gate:   c.GetGate(wJSON.Gate),
			Inputs: wJSON.Inputs,
		}
	}
	gCircuit, sCircuit, err := rawCircuit.Compile(c.field)
	if err != nil {
		panic(err)
	}

	c.circuits[path] = circuits{
		serializable: sCircuit,
		gadget:       gCircuit,
	}

	return sCircuit, gCircuit
}

func (c *Cache) RegisterGate(name string, gate gkr.GateFunction) {
	if _, ok := c.gates[name]; ok {
		panic("gate already registered")
	}
	c.gates[name] = gate
}

func (c *Cache) GetGate(name string) gkr.GateFunction {
	if gate, ok := c.gates[name]; ok {
		return gate
	}
	panic("gate not found: " + name)
}

// MiMCCircuit returns a circuit faithful to the topology of std/permutation/gkr-mimc:
// the key input (wire 0) is fed to every round and the final gate, while the state input (wire 1)
// seeds the chain and is also fed to the final gate. Both inputs are thus multi-source.
// numRounds is the total number of rounds, matching the real gadget's len(constants): the first
// numRounds-1 rounds use mimcGate, and the final round uses mimcLastGate (which additionally takes
// the state input). Rounds are chained: wire i = mimcGate(0, i-1); the final wire is
// mimcLastGate(0, last, 1).
func MiMCCircuit(numRounds int) gkrcore.RawCircuit {
	c := make(gkrcore.RawCircuit, numRounds+2)
	// wires 0 (key) and 1 (state): inputs
	for i := range numRounds - 1 {
		c[i+2] = gkrcore.RawWire{Gate: mimcGate, Inputs: []int{0, i + 1}}
	}
	c[numRounds+1] = gkrcore.RawWire{Gate: mimcLastGate, Inputs: []int{0, numRounds, 1}}
	return c
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
}

type HashDescription map[string]interface{}

// TestCaseInfo is the serializable form of a GKR test case, matching the JSON file format.
// Schedule is nil when absent from JSON, which means DefaultProvingSchedule.
type TestCaseInfo struct {
	Hash     HashDescription `json:"hash"`
	Circuit  string          `json:"circuit"`
	Input    [][]interface{} `json:"input"`
	Output   [][]interface{} `json:"output"`
	Proof    PrintableProof  `json:"proof"`
	Schedule ScheduleInfo    `json:"schedule,omitempty"`
}

// ScheduleStepInfo is the JSON representation of a single proving level.
// Type is "sumcheck", "skip", or "singleSourceZeroCheck".
type ScheduleStepInfo struct {
	Type        string                     `json:"type"`
	ClaimGroups []constraint.GkrClaimGroup `json:"claimGroups,omitempty"` // for "sumcheck"
	ClaimGroup  *constraint.GkrClaimGroup  `json:"claimGroup,omitempty"`  // for "skip"
}

// ScheduleInfo is the JSON-serializable form of a ProvingSchedule.
type ScheduleInfo []ScheduleStepInfo

// ToProvingSchedule converts a ScheduleInfo to a constraint.GkrProvingSchedule.
// A nil ScheduleInfo returns nil, which callers should interpret as DefaultProvingSchedule.
func (p ScheduleInfo) ToProvingSchedule() (constraint.GkrProvingSchedule, error) {
	if p == nil {
		return nil, nil
	}
	s := make(constraint.GkrProvingSchedule, len(p))
	for i, step := range p {
		switch step.Type {
		case "sumcheck":
			groups := step.ClaimGroups
			if groups == nil {
				groups = []constraint.GkrClaimGroup{}
			}
			lvl := constraint.GkrSumcheckLevel(groups)
			s[i] = &lvl
		case "skip":
			if step.ClaimGroup == nil {
				return nil, fmt.Errorf("level %d: type=skip but claimGroup is absent", i)
			}
			lvl := constraint.GkrSkipLevel(*step.ClaimGroup)
			s[i] = &lvl
		case "singleSourceZeroCheck":
			if step.ClaimGroup == nil {
				return nil, fmt.Errorf("level %d: type=singleSourceZeroCheck but claimGroup is absent", i)
			}
			lvl := constraint.GkrSingleSourceZeroCheckLevel(*step.ClaimGroup)
			s[i] = &lvl
		default:
			return nil, errors.New("unknown ProvingLevel type: " + step.Type)
		}
	}
	return s, nil
}

func (c *Cache) ReadTestCaseInfo(filePath string) (info TestCaseInfo, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	err = json.NewDecoder(f).Decode(&info)
	return
}

func NoGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
	}
}

func SingleAddGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{},
		{Gate: gkrcore.Add2, Inputs: []int{0, 1}},
	}
}

func SingleMulGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{},
		{Gate: gkrcore.Mul2, Inputs: []int{0, 1}},
	}
}

func SingleInputTwoIdentityGatesCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{Gate: gkrcore.Identity, Inputs: []int{0}},
		{Gate: gkrcore.Identity, Inputs: []int{0}},
	}
}

func SingleInputTwoIdentityGatesComposedCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{Gate: gkrcore.Identity, Inputs: []int{0}},
		{Gate: gkrcore.Identity, Inputs: []int{1}},
	}
}

func APowNTimesBCircuit(n int) gkrcore.RawCircuit {
	c := make(gkrcore.RawCircuit, n+2)
	for i := 2; i < len(c); i++ {
		c[i] = gkrcore.RawWire{Gate: gkrcore.Mul2, Inputs: []int{i - 1, 0}}
	}
	return c
}

func SingleMimcCipherGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{},
		{Gate: mimcGate, Inputs: []int{0, 1}},
	}
}

// poseidon2ExtLinear0 computes 2*x[0] + x[1] (external matrix, state[0] row).
func poseidon2ExtLinear0(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[0], x[1])
}

// poseidon2ExtLinear1 computes x[0] + 2*x[1] (external matrix, state[1] row).
func poseidon2ExtLinear1(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[1], x[1])
}

// poseidon2IntLinear1 computes x[0] + 3*x[1] (internal matrix, state[1] row; state[0] row = external).
func poseidon2IntLinear1(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[1], x[1], x[1])
}

// poseidon2SBox computes x[0]^2 (simplified s-box).
func poseidon2SBox(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Mul(x[0], x[0])
}

// poseidon2FeedForward computes 2*x[0] + x[1] + x[2] (external matrix row with feed-forward).
func poseidon2FeedForward(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[0], x[1], x[2])
}

// Poseidon2Circuit returns a 2-state Poseidon2-like GKR circuit with the given number of
// full and partial rounds, followed by a feed-forward output wire.
// Each full round applies the external linear layer (degree 1, skip) to both state elements
// followed by the s-box x^2 (degree 2, sumcheck) to both.
// Each partial round applies the external linear layer to state[0] and the internal linear
// layer to state[1] (both skip), then the s-box to state[0] only (sumcheck).
// The final output wire is 2*s0 + s1 + in1 (external matrix row with the second input fed forward).
//
// Wire layout per full round (wires s0, s1 are the current state):
//
//	+0 = 2*s0 + s1   external linear, state[0]  (skip)
//	+1 = s0 + 2*s1   external linear, state[1]  (skip)
//	+2 = lin0^2      s-box, state[0]             (sumcheck)
//	+3 = lin1^2      s-box, state[1]             (sumcheck)
//
// Wire layout per partial round:
//
//	+0 = 2*s0 + s1   external linear, state[0]  (skip)
//	+1 = s0 + 3*s1   internal linear, state[1]  (skip)
//	+2 = lin0^2      s-box, state[0] only        (sumcheck)
//
// Final wire: 2*s0 + s1 + in1 (feed-forward, sumcheck output)
func Poseidon2Circuit(nbFullRounds, nbPartialRounds int) gkrcore.RawCircuit {
	// 2 inputs + 4 wires per full round + 3 wires per partial round + 1 feed-forward output
	nbWires := 2 + 4*nbFullRounds + 3*nbPartialRounds + 1
	c := make(gkrcore.RawCircuit, nbWires)
	// wires 0, 1 are inputs
	s0, s1 := 0, 1

	w := 2
	appendFullRound := func() {
		c[w] = gkrcore.RawWire{Gate: poseidon2ExtLinear0, Inputs: []int{s0, s1}}
		c[w+1] = gkrcore.RawWire{Gate: poseidon2ExtLinear1, Inputs: []int{s0, s1}}
		c[w+2] = gkrcore.RawWire{Gate: poseidon2SBox, Inputs: []int{w}}
		c[w+3] = gkrcore.RawWire{Gate: poseidon2SBox, Inputs: []int{w + 1}}
		s0, s1 = w+2, w+3
		w += 4
	}
	appendPartialRound := func() {
		c[w] = gkrcore.RawWire{Gate: poseidon2ExtLinear0, Inputs: []int{s0, s1}}
		c[w+1] = gkrcore.RawWire{Gate: poseidon2IntLinear1, Inputs: []int{s0, s1}}
		c[w+2] = gkrcore.RawWire{Gate: poseidon2SBox, Inputs: []int{w}}
		s0, s1 = w+2, w+1
		w += 3
	}

	for range nbFullRounds / 2 {
		appendFullRound()
	}
	for range nbPartialRounds {
		appendPartialRound()
	}
	for range nbFullRounds - nbFullRounds/2 {
		appendFullRound()
	}

	// feed-forward: 2*s0 + s1 + in1
	c[w] = gkrcore.RawWire{Gate: poseidon2FeedForward, Inputs: []int{s0, s1, 1}}

	return c
}

func GetLogMaxInstances(t *testing.T) int {
	s := os.Getenv("GKR_LOG_INSTANCES")
	if s == "" {
		return 5
	}
	res, err := strconv.Atoi(s)
	if err != nil {
		t.Error(err)
	}
	return res
}
