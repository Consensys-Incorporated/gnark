package gkrapi

import (
	"fmt"
	"hash"
	"math/big"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	gcHash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// compressThreshold → if linear expressions are larger than this, the frontend will introduce
// intermediate constraints. The lower this number is, the faster compile time should be (to a point).
// However, the resulting circuit will have more constraints (slower proving time).
const compressThreshold = 1000

type doubleNoDependencyCircuit struct {
	X        []frontend.Variable
	hashName string
}

func (c *doubleNoDependencyCircuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	z := gkrApi.Add(x, x)

	gkrCircuit, err := gkrApi.Compile(c.hashName)
	if err != nil {
		return err
	}

	instanceIn := make(map[gkr.Variable]frontend.Variable)
	for i := range c.X {
		instanceIn[x] = c.X[i]
		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}
		api.AssertIsEqual(instanceOut[z], api.Mul(2, c.X[i]))
	}
	return nil
}

func TestDoubleNoDependencyCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	xValuess := [][]frontend.Variable{
		{1, 1},
		{1, 2},
	}

	hashes := []string{"-1", "-20"}

	for i, xValues := range xValuess {
		for _, hashName := range hashes {
			assignment := doubleNoDependencyCircuit{X: xValues}
			circuit := doubleNoDependencyCircuit{X: make([]frontend.Variable, len(xValues)), hashName: hashName}
			assert.Run(func(assert *test.Assert) {
				assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
			}, fmt.Sprintf("xValue=%d/hash=%s", i, hashName))

		}
	}
}

type sqNoDependencyCircuit struct {
	X        []frontend.Variable
	hashName string
}

func (c *sqNoDependencyCircuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	z := gkrApi.Mul(x, x)

	gkrCircuit, err := gkrApi.Compile(c.hashName)
	if err != nil {
		return err
	}

	instanceIn := make(map[gkr.Variable]frontend.Variable)
	for i := range c.X {
		instanceIn[x] = c.X[i]
		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}
		api.AssertIsEqual(instanceOut[z], api.Mul(c.X[i], c.X[i]))
	}
	return nil
}

func TestSqNoDependencyCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	xValuess := [][]frontend.Variable{
		{1, 1},
		{1, 2},
	}

	hashes := []string{"-1", "-20"}

	for i, xValues := range xValuess {
		for _, hashName := range hashes {
			assignment := sqNoDependencyCircuit{X: xValues}
			circuit := sqNoDependencyCircuit{X: make([]frontend.Variable, len(xValues)), hashName: hashName}
			assert.Run(func(assert *test.Assert) {
				assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
			}, fmt.Sprintf("xValues=%d/hash=%s", i, hashName))
		}
	}
}

type mulNoDependencyCircuit struct {
	X, Y     []frontend.Variable
	hashName string
}

func (c *mulNoDependencyCircuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	y := gkrApi.NewInput()
	z := gkrApi.Mul(x, y)

	gkrCircuit, err := gkrApi.Compile(c.hashName)
	if err != nil {
		return err
	}

	instanceIn := make(map[gkr.Variable]frontend.Variable)
	for i := range c.X {
		instanceIn[x] = c.X[i]
		instanceIn[y] = c.Y[i]
		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}
		api.AssertIsEqual(instanceOut[z], api.Mul(c.Y[i], c.X[i]))
	}
	return nil
}

func TestMulNoDependency(t *testing.T) {
	assert := test.NewAssert(t)
	xValuess := [][]frontend.Variable{
		{1, 2},
	}
	yValuess := [][]frontend.Variable{
		{0, 3},
	}

	hashes := []string{"-1", "-20"}

	for i := range xValuess {
		for _, hashName := range hashes {

			assignment := mulNoDependencyCircuit{
				X: xValuess[i],
				Y: yValuess[i],
			}
			circuit := mulNoDependencyCircuit{
				X:        make([]frontend.Variable, len(xValuess[i])),
				Y:        make([]frontend.Variable, len(yValuess[i])),
				hashName: hashName,
			}
			assert.Run(func(assert *test.Assert) {
				assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
			}, fmt.Sprintf("xValues=%d/hash=%s", i, hashName))
		}
	}
}

type mulWithDependencyCircuit struct {
	XFirst   frontend.Variable
	Y        []frontend.Variable
	hashName string
}

func (c *mulWithDependencyCircuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}

	x := gkrApi.NewInput() // x is the state variable
	y := gkrApi.NewInput()
	z := gkrApi.Mul(x, y)

	gkrCircuit, err := gkrApi.Compile(c.hashName)
	if err != nil {
		return err
	}

	state := c.XFirst
	instanceIn := make(map[gkr.Variable]frontend.Variable)

	for i := range c.Y {
		instanceIn[x] = state
		instanceIn[y] = c.Y[i]

		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}

		api.AssertIsEqual(instanceOut[z], api.Mul(state, c.Y[i]))
		state = instanceOut[z] // update state for the next iteration
	}
	return nil
}

func TestSolveMulWithDependency(t *testing.T) {
	assert := test.NewAssert(t)
	assignment := mulWithDependencyCircuit{
		XFirst: 1,
		Y:      []frontend.Variable{3, 2},
	}
	circuit := mulWithDependencyCircuit{Y: make([]frontend.Variable, len(assignment.Y)), hashName: "-20"}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

func BenchmarkMiMCMerkleTree(b *testing.B) {
	circuit := benchMiMCMerkleTreeCircuit{
		depth: 14,
	}
	circuit.X = make([]frontend.Variable, 1<<circuit.depth)

	assignment := benchMiMCMerkleTreeCircuit{
		X: make([]frontend.Variable, len(circuit.X)),
	}

	for i := range assignment.X {
		assignment.X[i] = i
	}

	benchProof(b, &circuit, &assignment)
}

func benchCompile(b *testing.B, circuit frontend.Circuit) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
		require.NoError(b, err)
	}
}

func benchProof(b *testing.B, circuit, assignment frontend.Circuit) {
	fmt.Println("compiling...")
	start := time.Now().UnixMicro()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
	require.NoError(b, err)
	fmt.Println("compiled in", time.Now().UnixMicro()-start, "μs")
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(b, err)
	fmt.Println("setting up...")
	pk, _, err := groth16.Setup(cs)
	require.NoError(b, err)

	fmt.Println("solving and proving...")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		id := rand.Uint32() % 256 //#nosec G404 -- This is a false positive
		start = time.Now().UnixMicro()
		fmt.Println("groth16 proving", id)
		_, err = groth16.Prove(cs, pk, fullWitness)
		require.NoError(b, err)
		fmt.Println("groth16 proved", id, "in", time.Now().UnixMicro()-start, "μs")
	}
}

type benchMiMCMerkleTreeCircuit struct {
	depth int
	X     []frontend.Variable
}

// hard-coded bn254
func (c *benchMiMCMerkleTreeCircuit) Define(api frontend.API) error {

	// define the circuit
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	y := gkrApi.NewInput()
	z := gkrApi.Gate(mimcGate, x, y)

	gkrCircuit, err := gkrApi.Compile("-20")
	if err != nil {
		return err
	}

	// prepare input
	curLayer := make([]frontend.Variable, 1<<c.depth)
	if len(curLayer) < len(c.X) {
		return fmt.Errorf("%d values not fitting in tree of depth %d", len(c.X), c.depth)
	}

	copy(curLayer, c.X)
	for i := len(c.X); i < len(curLayer); i++ {
		curLayer[i] = 0 // fill the rest with zeros
	}

	// create instances
	instanceIn := make(map[gkr.Variable]frontend.Variable)

	// first, dummy hash the leaves
	for i := range curLayer {
		instanceIn[x] = curLayer[i]
		instanceIn[y] = i

		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}
		curLayer[i] = instanceOut
	}

	// fill the tree layer by layer
	for len(curLayer) > 1 {
		nextLayer := curLayer[:len(curLayer)/2]

		for i := range nextLayer {
			instanceIn[x] = curLayer[2*i]
			instanceIn[y] = curLayer[2*i+1]

			instanceOut, err := gkrCircuit.AddInstance(instanceIn)
			if err != nil {
				return fmt.Errorf("failed to add instance: %w", err)
			}
			nextLayer[i] = instanceOut[z] // store the result of the hash
		}

		curLayer = nextLayer
	}
	return nil
}

func mimcGate(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	mimcSnarkTotalCalls++

	if len(input) != 2 {
		panic("mimc has fan-in 2")
	}
	sum := api.Add(input[0], input[1] /*, m.Ark*/)

	sumCubed := api.Mul(sum, sum, sum) // sum³
	return api.Mul(sumCubed, sumCubed, sum)
}

type constPseudoHash int

func (c constPseudoHash) Sum() frontend.Variable {
	return int(c)
}

func (c constPseudoHash) Write(...frontend.Variable) {}

func (c constPseudoHash) Reset() {}

type mimcNoGkrCircuit struct {
	X         []frontend.Variable
	Y         []frontend.Variable
	mimcDepth int
}

func (c *mimcNoGkrCircuit) Define(api frontend.API) error {
	Z := make([]frontend.Variable, len(c.X))
	zSum := frontend.Variable(0)
	for i := range Z {
		Z[i] = c.Y[i]
		for j := 0; j < c.mimcDepth; j++ {
			Z[i] = MiMCCipherGate{Ark: 0}.Evaluate(api, c.X[i], Z[i])
		}
		zSum = api.Add(zSum, Z[i])
	}
	api.AssertIsDifferent(zSum, 0)
	return nil
}

func BenchmarkMiMCMerkleTreeNoGkrNoDep(b *testing.B) {
	nbInstances := 1 << 18
	X := make([]frontend.Variable, nbInstances)
	Y := make([]frontend.Variable, nbInstances)
	for i := range X {
		X[i] = i
		Y[i] = -2*i + 1
	}
	assignment := mimcNoGkrCircuit{
		X: X,
		Y: Y,
	}
	circuit := mimcNoGkrCircuit{
		X: make([]frontend.Variable, nbInstances),
		Y: make([]frontend.Variable, nbInstances),
	}

	benchProof(b, &circuit, &assignment)
}

type mimcNoDepCircuit struct {
	X         []frontend.Variable
	Y         []frontend.Variable
	mimcDepth int
	hashName  string
}

func (c *mimcNoDepCircuit) Define(api frontend.API) error {
	// define the circuit
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	y := gkrApi.NewInput()

	if c.mimcDepth < 1 {
		return fmt.Errorf("mimcDepth must be at least 1, got %d", c.mimcDepth)
	}

	z := y
	for range c.mimcDepth {
		z = gkrApi.Gate(mimcGate, x, z)
	}

	gkrCircuit, err := gkrApi.Compile(c.hashName)
	if err != nil {
		return err
	}

	instanceIn := make(map[gkr.Variable]frontend.Variable)
	for i := range c.X {
		instanceIn[x] = c.X[i]
		instanceIn[y] = c.Y[i]

		_, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}
	}
	return nil
}

func mimcNoDepCircuits(mimcDepth, nbInstances int, hashName string) (circuit, assignment frontend.Circuit) {
	X := make([]frontend.Variable, nbInstances)
	Y := make([]frontend.Variable, nbInstances)
	for i := range X {
		X[i] = i
		Y[i] = -2*i + 1
	}
	assignment = &mimcNoDepCircuit{
		X: X,
		Y: Y,
	}
	circuit = &mimcNoDepCircuit{
		X:         make([]frontend.Variable, nbInstances),
		Y:         make([]frontend.Variable, nbInstances),
		mimcDepth: mimcDepth,
		hashName:  hashName,
	}
	return
}

func BenchmarkMiMCNoDepSolve(b *testing.B) {
	//defer profile.Start().Stop()
	circuit, assignment := mimcNoDepCircuits(1, 1<<9, "-20")
	benchProof(b, circuit, assignment)
}

func BenchmarkMiMCFullDepthNoDepSolve(b *testing.B) {
	circuit, assignment := mimcNoDepCircuits(91, 1<<19, "-20")
	benchProof(b, circuit, assignment)
}

func BenchmarkMiMCFullDepthNoDepCompile(b *testing.B) {
	circuit, _ := mimcNoDepCircuits(91, 1<<17, "-20")
	benchCompile(b, circuit)
}

func BenchmarkMiMCNoGkrFullDepthSolve(b *testing.B) {
	circuit, assignment := mimcNoGkrCircuits(91, 1<<19)
	benchProof(b, circuit, assignment)
}

func TestMiMCNoDepSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for _, depth := range []int{1, 2, 100} {
		for _, nbInstances := range []int{1 << 1, 1 << 2, 1 << 5} {
			circuit, assignment := mimcNoDepCircuits(depth, nbInstances, "-20")
			assert.Run(func(assert *test.Assert) {
				assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254))
			}, fmt.Sprintf("depth=%d, nbInstances=%d", depth, nbInstances))
		}
	}
}

func TestMiMCShallowNoDepSolveWithMiMCHash(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := mimcNoDepCircuits(5, 1<<3, "MIMC")
	assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254))
}

func mimcNoGkrCircuits(mimcDepth, nbInstances int) (circuit, assignment frontend.Circuit) {
	X := make([]frontend.Variable, nbInstances)
	Y := make([]frontend.Variable, nbInstances)
	for i := range X {
		X[i] = i
		Y[i] = -2*i + 1
	}
	assignment = &mimcNoGkrCircuit{
		X: X,
		Y: Y,
	}
	circuit = &mimcNoGkrCircuit{
		X:         make([]frontend.Variable, nbInstances),
		Y:         make([]frontend.Variable, nbInstances),
		mimcDepth: mimcDepth,
	}
	return
}

var mimcSnarkTotalCalls = 0

type MiMCCipherGate struct {
	Ark frontend.Variable
}

func (m MiMCCipherGate) Evaluate(api frontend.API, input ...frontend.Variable) frontend.Variable {
	mimcSnarkTotalCalls++

	if len(input) != 2 {
		panic("mimc has fan-in 2")
	}
	sum := api.Add(input[0], input[1], m.Ark)

	sumCubed := api.Mul(sum, sum, sum) // sum³
	return api.Mul(sumCubed, sumCubed, sum)
}

func (m MiMCCipherGate) Degree() int {
	return 7
}

type constBytesPseudoHash []byte

func (c constBytesPseudoHash) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (c constBytesPseudoHash) Sum([]byte) []byte {
	return slices.Clone(c)
}

func (c constBytesPseudoHash) Reset() {
}

func (c constBytesPseudoHash) Size() int {
	return len(c)
}

func (c constBytesPseudoHash) BlockSize() int {
	return len(c)
}

func newConstBytesPseudoHash(c int64, mod *big.Int) constBytesPseudoHash {
	i := big.NewInt(c)
	i.Mod(i, mod)
	b := make([]byte, len(mod.Bytes()))
	i.FillBytes(b)
	return b
}

func init() {
	// Register custom (constant) "hash" functions
	for _, v := range []int64{-1, -20} {
		name := strconv.Itoa(int(v))
		stdHash.RegisterCustomHash(name, func(api frontend.API) (stdHash.FieldHasher, error) {
			return constPseudoHash(v), nil
		})
		for _, curve := range gnark.Curves() {
			h := newConstBytesPseudoHash(v, curve.ScalarField())
			gcHash.RegisterCustomHash(name+"_"+strings.ToUpper(curve.String()), func() hash.Hash {
				return h
			})
		}
	}
}

// pow3Circuit computes x⁴ and also checks the correctness of intermediate value x².
// This is to demonstrate the use of [Circuit.GetValue] and should not be done
// in production code, as it negates the performance benefits of using GKR in the first place.
type pow4Circuit struct {
	X []frontend.Variable
}

func (c *pow4Circuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	x2 := gkrApi.Mul(x, x)   // x²
	x4 := gkrApi.Mul(x2, x2) // x⁴

	gkrCircuit, err := gkrApi.Compile("MIMC")
	if err != nil {
		return err
	}

	for i := range c.X {
		instanceIn := make(map[gkr.Variable]frontend.Variable)
		instanceIn[x] = c.X[i]

		instanceOut, err := gkrCircuit.AddInstance(instanceIn)
		if err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}

		api.AssertIsEqual(gkrCircuit.GetValue(x, i), c.X[i]) // x

		v := api.Mul(c.X[i], c.X[i])                     // x²
		api.AssertIsEqual(gkrCircuit.GetValue(x2, i), v) // x²

		v = api.Mul(v, v)                                // x⁴
		api.AssertIsEqual(gkrCircuit.GetValue(x4, i), v) // x⁴
		api.AssertIsEqual(instanceOut[x4], v)            // x⁴
	}

	return nil
}

func TestPow4Circuit_GetValue(t *testing.T) {
	assignment := pow4Circuit{
		X: []frontend.Variable{1, 2, 3, 4, 5},
	}

	circuit := pow4Circuit{
		X: make([]frontend.Variable, len(assignment.X)),
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

func TestWitnessExtend(t *testing.T) {
	circuit := doubleNoDependencyCircuit{X: make([]frontend.Variable, 3), hashName: "-1"}
	assignment := doubleNoDependencyCircuit{X: []frontend.Variable{0, 0, 1}}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(t, err)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	_, err = cs.Solve(witness)
	require.NoError(t, err)
}

func TestSingleInstance(t *testing.T) {
	circuit := mimcNoDepCircuit{
		X:         make([]frontend.Variable, 1),
		Y:         make([]frontend.Variable, 1),
		mimcDepth: 2,
		hashName:  "MIMC",
	}
	assignment := mimcNoDepCircuit{
		X: []frontend.Variable{10},
		Y: []frontend.Variable{2},
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

func TestNoInstance(t *testing.T) {
	var circuit testNoInstanceCircuit
	assignment := testNoInstanceCircuit{0}

	// Dummy exists only so that the witness is not empty; nothing reads it.
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

type testNoInstanceCircuit struct {
	Dummy frontend.Variable // Plonk prover would fail on an empty witness
}

func (c *testNoInstanceCircuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	y := gkrApi.Mul(x, x)
	gkrApi.Mul(x, y)

	_, err = gkrApi.Compile("MIMC")
	return err
}

type testMultiCircuit struct {
	X [2]frontend.Variable
	Y [2]frontend.Variable
}

func (c *testMultiCircuit) Define(api frontend.API) error {
	api1, err := New(api)
	if err != nil {
		return err
	}
	api2, err := New(api)
	if err != nil {
		return err
	}

	x1 := api1.NewInput()
	y1 := api1.NewInput()
	z1 := api1.Add(x1, y1)

	x2 := api2.NewInput()
	y2 := api2.NewInput()
	z2 := api2.Mul(x2, y2)

	circuit2, err := api2.Compile("MIMC")
	if err != nil {
		return err
	}

	circuit1, err := api1.Compile("-1")
	if err != nil {
		return err
	}

	for i := range c.X {
		out, err := circuit1.AddInstance(map[gkr.Variable]frontend.Variable{x1: c.X[i], y1: c.Y[i]})
		if err != nil {
			return err
		}
		api.AssertIsEqual(out[z1], api.Add(c.X[i], c.Y[i]))

		out, err = circuit2.AddInstance(map[gkr.Variable]frontend.Variable{x2: c.X[i], y2: c.Y[i]})
		if err != nil {
			return err
		}
		api.AssertIsEqual(out[z2], api.Mul(c.X[i], c.Y[i]))
	}

	return nil
}

func TestMulti(t *testing.T) {
	assignment := testMultiCircuit{
		X: [2]frontend.Variable{2, 3},
		Y: [2]frontend.Variable{4, 5},
	}

	test.NewAssert(t).CheckCircuit(new(testMultiCircuit), test.WithValidAssignment(&assignment))
}

// Poseidon2 gate functions — match gkrtesting.Poseidon2Circuit(4, 2) exactly.

func p2ExtLinear0(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[0], x[1]) // 2*x[0] + x[1]
}

func p2ExtLinear1(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[1], x[1]) // x[0] + 2*x[1]
}

func p2IntLinear1(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[1], x[1], x[1]) // x[0] + 3*x[1]
}

func p2SBox(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Mul(x[0], x[0]) // x^2
}

func p2FeedForward(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Add(x[0], x[0], x[1], x[2]) // 2*x[0] + x[1] + x[2]
}

type poseidon2GadgetCircuit struct {
	In0      []frontend.Variable
	In1      []frontend.Variable
	hashName string
}

func (c *poseidon2GadgetCircuit) Define(api frontend.API) error {
	gkrApi, err := New(api)
	if err != nil {
		return err
	}
	in0 := gkrApi.NewInput()
	in1 := gkrApi.NewInput()
	s0, s1 := in0, in1

	appendFullRound := func() {
		lin0 := gkrApi.Gate(p2ExtLinear0, s0, s1)
		lin1 := gkrApi.Gate(p2ExtLinear1, s0, s1)
		s0 = gkrApi.Gate(p2SBox, lin0)
		s1 = gkrApi.Gate(p2SBox, lin1)
	}
	appendPartialRound := func() {
		lin0 := gkrApi.Gate(p2ExtLinear0, s0, s1)
		lin1 := gkrApi.Gate(p2IntLinear1, s0, s1)
		s0 = gkrApi.Gate(p2SBox, lin0)
		s1 = lin1
	}

	// 4 full rounds, 2 partial rounds: 2 + 2 structure
	appendFullRound()
	appendFullRound()
	appendPartialRound()
	appendPartialRound()
	appendFullRound()
	appendFullRound()

	_ = gkrApi.Gate(p2FeedForward, s0, s1, in1)

	gkrCircuit, err := gkrApi.Compile(c.hashName)
	if err != nil {
		return err
	}

	instanceIn := make(map[gkr.Variable]frontend.Variable)
	for i := range c.In0 {
		instanceIn[in0] = c.In0[i]
		instanceIn[in1] = c.In1[i]
		if _, err := gkrCircuit.AddInstance(instanceIn); err != nil {
			return fmt.Errorf("failed to add instance: %w", err)
		}
	}
	return nil
}

func TestPoseidon2Gadget(t *testing.T) {
	assert := test.NewAssert(t)
	nbInstances := 2
	In0 := make([]frontend.Variable, nbInstances)
	In1 := make([]frontend.Variable, nbInstances)
	for i := range In0 {
		In0[i] = i + 1
		In1[i] = 2 * (i + 1)
	}
	assignment := &poseidon2GadgetCircuit{In0: In0, In1: In1}
	circuit := &poseidon2GadgetCircuit{
		In0:      make([]frontend.Variable, nbInstances),
		In1:      make([]frontend.Variable, nbInstances),
		hashName: "-1",
	}
	assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254))
}
