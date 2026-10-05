package gkrapi

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	gadget "github.com/consensys/gnark/internal/gkr"
	gkrbls12377 "github.com/consensys/gnark/internal/gkr/bls12-377/blueprints"
	gkrbls12381 "github.com/consensys/gnark/internal/gkr/bls12-381/blueprints"
	gkrbn254 "github.com/consensys/gnark/internal/gkr/bn254/blueprints"
	gkrbw6761 "github.com/consensys/gnark/internal/gkr/bw6-761/blueprints"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/hash"
	_ "github.com/consensys/gnark/std/hash/all"
	"github.com/consensys/gnark/std/multicommit"
)

// The InitialChallengeGetter provides a one-time initial Fiat-Shamir challenge for the GKR prover.
// Normally, these should include a unique circuit identifier and all input-output pairs.
type InitialChallengeGetter func() []frontend.Variable

// Circuit represents a GKR circuit.
type Circuit struct {
	circuit     gkrcore.GadgetCircuit
	schedule    constraint.GkrProvingSchedule
	gates       []gkrcore.GateBytecode
	assignments gadget.WireAssignment
	ins         []gkr.Variable
	outs        []gkr.Variable
	api         frontend.API // the parent API

	// Fiat-Shamir bootstrapping
	getInitialChallenges InitialChallengeGetter // optional getter for the I/O related portion of the initial Fiat-Shamir challenge
	statementHash        []byte                 // hash of the circuit and schedule

	// Blueprint-based fields
	blueprints gkrcore.Blueprints

	// Metadata
	hashName    string
	nbInstances int
}

// New creates a new GKR API
func New(api frontend.API) (*API, error) {
	return &API{
		parentApi: api,
	}, nil
}

// NewInput creates a new input variable.
func (api *API) NewInput() gkr.Variable {
	return api.circuit.NewInput()
}

type CompileOption func(*Circuit)

// WithInitialChallenge provides a getter for the I/O portion of the initial Fiat-Shamir challenge.
// If not provided, the I/O initial challenge will be a commitment to all the input and output values of the circuit.
func WithInitialChallenge(getInitialChallenge InitialChallengeGetter) CompileOption {
	return func(c *Circuit) {
		c.getInitialChallenges = getInitialChallenge
	}
}

// Compile finalizes the GKR circuit.
// From this point on, the circuit cannot be modified,
// but instances can be added to it.
func (api *API) Compile(fiatshamirHashName string, options ...CompileOption) (*Circuit, error) {
	// Dispatch to a curve-specific factory
	compiler := api.parentApi.Compiler()
	field := compiler.Field()
	curveID := utils.FieldToCurve(field)

	gadgetCircuit, serializableCircuit, err := api.circuit.Compile(field)
	if err != nil {
		return nil, err
	}

	schedule, err := gkrcore.DefaultProvingSchedule(serializableCircuit, gkrcore.SNARKConsolidationMode)
	if err != nil {
		return nil, fmt.Errorf("failed to compute proving schedule: %w", err)
	}

	hsh := sha256.New()
	if err = gkrcore.SerializeCircuit(hsh, serializableCircuit); err != nil {
		return nil, fmt.Errorf("failed to serialize circuit: %w", err)
	}
	if err = gkrcore.SerializeSchedule(hsh, schedule); err != nil {
		return nil, fmt.Errorf("failed to serialize schedule: %w", err)
	}

	res := Circuit{
		circuit:       gadgetCircuit,
		schedule:      schedule,
		assignments:   make(gadget.WireAssignment, len(serializableCircuit)),
		api:           api.parentApi,
		hashName:      fiatshamirHashName,
		statementHash: hsh.Sum(nil),
	}

	switch curveID {
	case ecc.BN254:
		res.blueprints = gkrbn254.NewBlueprints(serializableCircuit, schedule, fiatshamirHashName, compiler)
	case ecc.BLS12_377:
		res.blueprints = gkrbls12377.NewBlueprints(serializableCircuit, schedule, fiatshamirHashName, compiler)
	case ecc.BLS12_381:
		res.blueprints = gkrbls12381.NewBlueprints(serializableCircuit, schedule, fiatshamirHashName, compiler)
	case ecc.BW6_761:
		res.blueprints = gkrbw6761.NewBlueprints(serializableCircuit, schedule, fiatshamirHashName, compiler)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveID)
	}

	for _, opt := range options {
		opt(&res)
	}

	// Use circuit helper methods for inputs and outputs
	inputIndices := res.circuit.Inputs()
	outputIndices := res.circuit.Outputs()

	if len(inputIndices) == len(res.circuit) {
		return nil, errors.New("circuit has no non-input wires")
	}

	res.ins = make([]gkr.Variable, len(inputIndices))
	for i, inI := range inputIndices {
		res.ins[i] = gkr.Variable(inI)
	}

	res.outs = make([]gkr.Variable, len(outputIndices))
	for i, outI := range outputIndices {
		res.outs[i] = gkr.Variable(outI)
	}

	res.api.Compiler().Defer(res.finalize)

	return &res, nil
}

// AddInstance adds a new instance to the GKR circuit, returning the values of output variables for the instance.
func (c *Circuit) AddInstance(input map[gkr.Variable]frontend.Variable) (map[gkr.Variable]frontend.Variable, error) {
	if len(input) != len(c.ins) {
		for k := range input {
			if k >= gkr.Variable(len(c.circuit)) {
				return nil, fmt.Errorf("variable %d is out of bounds (max %d)", k, len(c.circuit)-1)
			}
			if !c.circuit[k].IsInput() {
				return nil, fmt.Errorf("value provided for non-input variable %d", k)
			}
		}
	}

	// Build instruction calldata for solveBlueprint
	// Format: [0]=totalSize, [1]=instanceIndex, [2...]=input values as linear expressions
	compiler := c.api.Compiler()
	calldata := make([]uint32, 2, 2+len(c.ins)*3) // pre-allocate: size + instanceIndex + linear expressions
	calldata[1] = uint32(c.nbInstances)

	// Encode input variables
	for _, wI := range c.ins {
		inV, ok := input[wI]
		if !ok {
			return nil, fmt.Errorf("missing entry for input variable %d", wI)
		}
		// Store in assignment for later use
		c.assignments[wI] = append(c.assignments[wI], inV)

		// Encode as linear expression in calldata
		v := compiler.ToCanonicalVariable(inV)
		v.Compress(&calldata)
	}

	// Update total size
	calldata[0] = uint32(len(calldata))

	// Execute solve blueprint instruction
	outputs := compiler.AddInstruction(c.blueprints.SolveID, calldata)

	// Track instance count
	c.nbInstances++

	// Convert outputs to map
	res := make(map[gkr.Variable]frontend.Variable, len(c.outs))
	for i, v := range c.outs {
		outVar := compiler.InternalVariable(outputs[i])
		res[v] = outVar
		c.assignments[v] = append(c.assignments[v], outVar)
	}

	return res, nil
}

// finalize encodes the verification circuitry for the GKR circuit.
func (c *Circuit) finalize(api frontend.API) error {

	// if the circuit is empty or with no instances, there is nothing to do.
	if len(c.outs) == 0 || len(c.assignments[0]) == 0 { // wire 0 is always an input wire
		return nil
	}

	// pad instances to the next power of 2
	nbPaddedInstances := int(ecc.NextPowerOfTwo(uint64(c.nbInstances)))
	// pad instances to the next power of 2 by repeating the last instance
	if c.nbInstances < nbPaddedInstances && c.nbInstances > 0 {
		for _, wI := range c.ins {
			c.assignments[wI] = utils.ExtendRepeatLast(c.assignments[wI], nbPaddedInstances)
		}
		for _, wI := range c.outs {
			c.assignments[wI] = utils.ExtendRepeatLast(c.assignments[wI], nbPaddedInstances)
		}
	}

	c.blueprints.Solve.SetNbInstances(uint32(c.nbInstances))

	// if the circuit consists of only one instance, directly solve the circuit
	if len(c.assignments[c.ins[0]]) == 1 {
		outputSet := make(map[int]bool, len(c.outs))
		for _, wI := range c.outs {
			outputSet[int(wI)] = true
		}
		gateIn := make([]frontend.Variable, c.circuit.MaxGateNbIn())
		for wI, w := range c.circuit {
			if w.IsInput() {
				continue
			}
			for inI, inWI := range w.Inputs {
				gateIn[inI] = c.assignments[inWI][0] // take the first (only) instance
			}
			res := w.Gate.Evaluate(gadget.FrontendAPIWrapper{API: api}, gateIn[:len(w.Inputs)]...)
			if outputSet[wI] {
				api.AssertIsEqual(res, c.assignments[wI][0])
			} else {
				c.assignments[wI] = append(c.assignments[wI], res)
			}
		}
		return nil
	}

	if c.getInitialChallenges != nil {
		return c.verify(api, c.circuit, append([]frontend.Variable{c.statementHash}, c.getInitialChallenges()...))
	}

	// The default initial challenge is a commitment to the circuit, solving schedule, and all input and output values.
	challenges := make([]frontend.Variable, 1, (len(c.ins)+len(c.outs))*len(c.assignments[c.ins[0]])+1)
	challenges[0] = c.statementHash
	for _, in := range c.ins {
		challenges = append(challenges, c.assignments[in]...)
	}
	for _, out := range c.outs {
		challenges = append(challenges, c.assignments[out]...)
	}

	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		return c.verify(api, c.circuit, []frontend.Variable{commitment})
	}, challenges...)

	return nil
}

func (c *Circuit) verify(api frontend.API, circuit gkrcore.GadgetCircuit, initialChallenges []frontend.Variable) error {

	compiler := api.Compiler()

	// Build calldata for prove instruction
	// Format: [0]=totalSize, [1...]=challenge linear expressions
	calldata := make([]uint32, 1, 1+len(initialChallenges)*3)

	// Encode initial challenges
	for _, challenge := range initialChallenges {
		v := compiler.ToCanonicalVariable(challenge)
		v.Compress(&calldata)
	}

	// Update total size
	calldata[0] = uint32(len(calldata))

	// Execute prove solveBlueprint instruction
	proofOutputs := compiler.AddInstruction(c.blueprints.ProveID, calldata)

	// Convert outputs to proof
	proofSerialized := make([]frontend.Variable, len(proofOutputs))
	for i, wireID := range proofOutputs {
		proofSerialized[i] = compiler.InternalVariable(wireID)
	}

	var (
		proof gadget.Proof
		err   error
	)

	if proof, err = gadget.DeserializeProof(circuit, c.schedule, proofSerialized); err != nil {
		return err
	}

	var hsh hash.FieldHasher
	if hsh, err = hash.GetFieldHasher(c.hashName, api); err != nil {
		return err
	}

	hsh.Write(initialChallenges...)
	logNbInstances := c.assignments[c.ins[0]].NumVars()
	claims, err := gadget.Verify(api, circuit, c.schedule, logNbInstances, proof, hsh)
	if err != nil {
		return err
	}
	claims.Check(api, c.assignments)
	return nil
}

// GetValue is a debugging utility returning the value of variable v at instance i.
// While v can be an input or output variable, GetValue is most useful for querying intermediate values in the circuit.
func (c *Circuit) GetValue(v gkr.Variable, i int) frontend.Variable {
	// Create an instruction that will retrieve the assignment at solving time
	compiler := c.api.Compiler()

	// Build calldata: [0]=totalSize, [1]=wireI, [2]=instanceI, [3...]=dependency_wire_as_linear_expression
	// The dependency ensures this instruction runs after the solving instruction for instance i
	calldata := make([]uint32, 3, 6) // pre-allocate: size + wireI + instanceI + dependency linear expression (typically 3)
	calldata[1] = uint32(v)
	calldata[2] = uint32(i)

	// Use the first output variable from instance i as a dependency
	// This ensures the solving instruction for this instance has completed
	if len(c.outs) == 0 || i >= len(c.assignments[c.outs[0]]) {
		panic("GetValue called with invalid instance or before instance was added")
	}
	dependencyWire := c.assignments[c.outs[0]][i]
	depVar := compiler.ToCanonicalVariable(dependencyWire)
	depVar.Compress(&calldata)

	// Update total size
	calldata[0] = uint32(len(calldata))

	outputs := compiler.AddInstruction(c.blueprints.GetAssignmentID, calldata)
	return compiler.InternalVariable(outputs[0])
}
