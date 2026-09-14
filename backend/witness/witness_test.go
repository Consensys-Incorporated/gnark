package witness_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/io"
	"github.com/stretchr/testify/require"
)

type circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

func (c *circuit) Define(frontend.API) error {
	return nil
}

func ExampleWitness() {
	// Witnesses can be created directly by "walking" through an assignment (circuit structure)
	// simple assignment
	assignment := &circuit{
		X: 42,
		Y: 8000,
		E: 1,
	}

	w, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	// Binary [de]serialization
	data, _ := w.MarshalBinary()

	reconstructed, _ := witness.New(ecc.BN254.ScalarField())
	reconstructed.UnmarshalBinary(data)

	// For pretty printing, we can do JSON conversions; they are not efficient and don't handle
	// complex circuit structures well.

	// first get the circuit expected schema
	schema, _ := frontend.NewSchema(ecc.BN254.ScalarField(), assignment)
	ret, _ := reconstructed.ToJSON(schema)

	var b bytes.Buffer
	json.Indent(&b, ret, "", "\t")
	fmt.Println(b.String())
	// Output:
	// {
	//	"X": 42,
	//	"Y": 8000,
	//	"E": 1
	// }

}

func TestMarshalPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)

	roundTripMarshal(assert, assignment, true)
	roundTripMarshalJSON(assert, assignment, true)
}

func TestMarshal(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)
	assignment.E = new(fr.Element).SetInt64(1)

	roundTripMarshal(assert, assignment, false)
	roundTripMarshalJSON(assert, assignment, false)
}

func TestPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)
	assignment.E = new(fr.Element).SetInt64(1)

	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	publicW, err := w.Public()
	assert.NoError(err)

	wt := publicW.Vector().(fr.Vector)

	assert.Equal(3, len(w.Vector().(fr.Vector)))
	assert.Equal(2, len(wt))

	assert.Equal("42", wt[0].String())
	assert.Equal("8000", wt[1].String())
}

func roundTripMarshal(assert *require.Assertions, assignment circuit, publicOnly bool) {
	var opts []frontend.WitnessOption
	if publicOnly {
		opts = append(opts, frontend.PublicOnly())
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), opts...)
	assert.NoError(err)

	assert.NoError(io.RoundTripCheck(w, func() interface{} {
		rw, err := witness.New(ecc.BN254.ScalarField())
		assert.NoError(err)
		return rw
	}))
}

func roundTripMarshalJSON(assert *require.Assertions, assignment circuit, publicOnly bool) {
	// build the vector
	var opts []frontend.WitnessOption
	if publicOnly {
		opts = append(opts, frontend.PublicOnly())
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), opts...)
	assert.NoError(err)

	s, err := frontend.NewSchema(ecc.BN254.ScalarField(), &assignment)
	assert.NoError(err)

	// serialize the vector to JSON
	data, err := w.ToJSON(s)
	assert.NoError(err)
	nbSecret := s.NbSecret

	// re-read
	rw, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	err = rw.FromJSON(s, data)
	assert.NoError(err)
	assert.Equal(nbSecret, s.NbSecret)

	assert.True(reflect.DeepEqual(rw, w), "witness json round trip serialization")

}

func TestFromJSONReusesSchema(t *testing.T) {
	assert := require.New(t)

	assignment := &circuit{
		X: new(fr.Element).SetInt64(42),
		Y: new(fr.Element).SetInt64(8000),
		E: new(fr.Element).SetInt64(1),
	}
	s, err := frontend.NewSchema(ecc.BN254.ScalarField(), assignment)
	assert.NoError(err)
	nbSecret := s.NbSecret

	publicW, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	assert.NoError(err)
	publicJSON, err := publicW.ToJSON(s)
	assert.NoError(err)
	publicRoundTrip, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	assert.NoError(publicRoundTrip.FromJSON(s, publicJSON))
	assert.Equal(nbSecret, s.NbSecret)

	fullW, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	fullJSON, err := fullW.ToJSON(s)
	assert.NoError(err)
	fullRoundTrip, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	assert.NoError(fullRoundTrip.FromJSON(s, fullJSON))
	assert.True(reflect.DeepEqual(fullRoundTrip, fullW), "witness json round trip serialization")
	assert.Equal(nbSecret, s.NbSecret)
}

type initableVariable struct {
	Val []frontend.Variable
}

func (iv *initableVariable) Initialize(field *big.Int) {
	if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		iv.Val = []frontend.Variable{1, 2} // need to init value as are assigning to witness
	} else {
		iv.Val = []frontend.Variable{1, 2, 3}
	}
}

type initableCircuit struct {
	X [2]initableVariable
	Y []initableVariable
	Z initableVariable
}

func (c *initableCircuit) Define(api frontend.API) error {
	panic("not called")
}

func TestVariableInitHook(t *testing.T) {
	assert := require.New(t)

	assignment := &initableCircuit{Y: make([]initableVariable, 2)}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	fw, ok := w.Vector().(fr.Vector)
	assert.True(ok)
	assert.Len(fw, 10, "invalid length")

	// check that we call field-specific init
	w2, err := frontend.NewWitness(assignment, tinyfield.Modulus())
	assert.NoError(err)
	fw2, ok := w2.Vector().(tinyfield.Vector)
	assert.True(ok)
	assert.Len(fw2, 15, "invalid length")
}
