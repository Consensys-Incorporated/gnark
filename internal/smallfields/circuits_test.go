package smallfields_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

var testSmallField = koalabear.Modulus()

type NativeCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",secret"`
}

func (circuit *NativeCircuit) Define(api frontend.API) error {
	res := api.Mul(circuit.A, circuit.A)
	api.AssertIsEqual(res, circuit.B)
	return nil
}

var testCases = []struct {
	name            string
	modulus         *big.Int
	supportsCompile bool
	// u64 marks a small field whose constraint system uses the U64 element
	// type. mamabear is 49 bits, so it does not fit the U32 element the 31-bit
	// fields use, even though it is just as much a small field.
	u64 bool
}{
	{"tinyfield", tinyfield.Modulus(), true, false},
	{"babybear", babybear.Modulus(), true, false},
	{"koalabear", koalabear.Modulus(), true, false},
	{"mamabear", mamabear.Modulus(), true, true},
}

// solvable is the part of a constraint system this test needs. The U32 and U64
// constraint systems share no common interface, so we narrow to what is used.
type solvable interface {
	IsSolved(witness witness.Witness, opts ...solver.Option) error
}

// compileSmallField compiles with the element type matching the field's
// constraint system.
func compileSmallField(u64 bool, modulus *big.Int, newBuilderU32 frontend.NewBuilderU32, newBuilderU64 frontend.NewBuilder, circuit frontend.Circuit) (solvable, error) {
	if u64 {
		return frontend.Compile(modulus, newBuilderU64, circuit)
	}
	return frontend.CompileU32(modulus, newBuilderU32, circuit)
}

func TestNativeCircuitTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			err := test.IsSolved(&NativeCircuit{}, &NativeCircuit{A: 2, B: 4}, tc.modulus)
			assert.NoError(err)
		}, tc.name)
	}
}

func TestNativeCircuitCompileAndSolve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range testCases {
		if !tc.supportsCompile {
			continue
		}
		assert.Run(func(assert *test.Assert) {
			ccs, err := compileSmallField(tc.u64, tc.modulus, r1cs.NewBuilder, r1cs.NewBuilder, &NativeCircuit{})
			assert.NoError(err)
			assignment := &NativeCircuit{A: 2, B: 4}
			wit, err := frontend.NewWitness(assignment, tc.modulus)
			assert.NoError(err)
			err = ccs.IsSolved(wit)
			assert.NoError(err)

		}, fmt.Sprintf("ccs=r1cs/field=%s", tc.name))
		assert.Run(func(assert *test.Assert) {
			ccs, err := compileSmallField(tc.u64, tc.modulus, scs.NewBuilder, scs.NewBuilder, &NativeCircuit{})
			assert.NoError(err)
			assignment := &NativeCircuit{A: 2, B: 4}
			wit, err := frontend.NewWitness(assignment, tc.modulus)
			assert.NoError(err)
			err = ccs.IsSolved(wit)
			assert.NoError(err)
		}, fmt.Sprintf("ccs=scs/field=%s", tc.name))
	}
}

type EmulatedCircuit[T emulated.FieldParams] struct {
	A emulated.Element[T] `gnark:",public"`
	B emulated.Element[T] `gnark:",secret"`
}

func (c *EmulatedCircuit[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&c.A, &c.A)
	f.AssertIsEqual(res, &c.B)
	return nil
}

func TestEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	a, err := rand.Int(rand.Reader, emparams.BN254Fp{}.Modulus())
	assert.NoError(err)
	b := new(big.Int).Mul(a, a)
	b.Mod(b, emparams.BN254Fp{}.Modulus())

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, ecc.BN254.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, testSmallField)
	assert.NoError(err)

	// assert that when the compiled doesn't have specific support for small fields (rangechecker and widecommit), then it would fail
	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, testSmallField, test.WithNoSmallFieldCompatibility())
	assert.Error(err)
}

func TestCompileEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	f := testSmallField

	assignment := &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](2), B: emulated.ValueOf[emparams.BN254Fp](4)}

	ccs, err := frontend.CompileU32(f, widecommitter.From[constraint.U32](scs.NewBuilder), &EmulatedCircuit[emparams.BN254Fp]{})
	assert.NoError(err)

	w, err := frontend.NewWitness(assignment, f)
	assert.NoError(err)

	err = ccs.IsSolved(w)
	assert.NoError(err)

	ccs2, err := frontend.CompileU32(f, widecommitter.From[constraint.U32](r1cs.NewBuilder), &EmulatedCircuit[emparams.BN254Fp]{})
	assert.NoError(err)

	err = ccs2.IsSolved(w)
	assert.NoError(err)

	// ensure the compilation fails in case we compile over a small field but we don't have rangechecker and widecommit support
	_, err = frontend.CompileU32(f, scs.NewBuilder, &EmulatedCircuit[emparams.BN254Fp]{})
	assert.Error(err)
	_, err = frontend.CompileU32(f, r1cs.NewBuilder, &EmulatedCircuit[emparams.BN254Fp]{})
	assert.Error(err)
}

type PairCircuit struct {
	InG1 sw_bn254.G1Affine
	InG2 sw_bn254.G2Affine
	Res  sw_bn254.GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	res, err := pairing.Pair([]*sw_bn254.G1Affine{&c.InG1}, []*sw_bn254.G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: sw_bn254.NewG1Affine(p),
		InG2: sw_bn254.NewG2Affine(q),
		Res:  sw_bn254.NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, testSmallField)
	assert.NoError(err)

	ccs, err := frontend.CompileU32(testSmallField, widecommitter.From[constraint.U32](scs.NewBuilder), &PairCircuit{})
	assert.NoError(err)

	w, err := frontend.NewWitness(&witness, testSmallField)
	assert.NoError(err)

	err = ccs.IsSolved(w)
	assert.NoError(err)

	ccs2, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &PairCircuit{})
	assert.NoError(err)
	// we define it again as the field is different
	witness = PairCircuit{
		InG1: sw_bn254.NewG1Affine(p),
		InG2: sw_bn254.NewG2Affine(q),
		Res:  sw_bn254.NewGTEl(res),
	}
	w2, err := frontend.NewWitness(&witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	err = ccs2.IsSolved(w2)
	assert.NoError(err)
}

func randomG1G2Affines() (bn254.G1Affine, bn254.G2Affine) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}
