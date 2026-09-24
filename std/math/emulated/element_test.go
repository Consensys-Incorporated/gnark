package emulated

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

const testCurve = ecc.BN254

func testName[T FieldParams]() string {
	var fp T
	return fmt.Sprintf("%s/limb=%d", reflect.TypeOf(fp).Name(), fp.BitsPerLimb())
}

// TODO: add also cases which should fail

type AssertIsLessEqualThanCircuit[T FieldParams] struct {
	L, R Element[T]
}

func (c *AssertIsLessEqualThanCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	f.AssertIsLessOrEqual(&c.L, &c.R)
	return nil
}

func TestAssertIsLessEqualThan(t *testing.T) {
	testAssertIsLessEqualThan[Goldilocks](t)
	testAssertIsLessEqualThan[Secp256k1Fp](t)
	testAssertIsLessEqualThan[BN254Fp](t)
}

func testAssertIsLessEqualThan[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanCircuit[T]
		R, _ := rand.Int(rand.Reader, fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		witness.R = ValueOf[T](R)
		witness.L = ValueOf[T](L)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type AssertIsLessEqualThanConstantCiruit[T FieldParams] struct {
	L Element[T]
	R *big.Int
}

func (c *AssertIsLessEqualThanConstantCiruit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	R := f.NewElement(c.R)
	f.AssertIsLessOrEqual(&c.L, R)
	return nil
}

func testAssertIsLessEqualThanConstant[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanConstantCiruit[T]
		R, _ := rand.Int(rand.Reader, fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		circuit.R = R
		witness.R = R
		witness.L = ValueOf[T](L)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanConstantCiruit[T]
		R := new(big.Int).Set(fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		circuit.R = R
		witness.R = R
		witness.L = ValueOf[T](L)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, fmt.Sprintf("overflow/%s", testName[T]()))
}

func TestAssertIsLessEqualThanConstant(t *testing.T) {
	testAssertIsLessEqualThanConstant[Goldilocks](t)
	testAssertIsLessEqualThanConstant[Secp256k1Fp](t)
	testAssertIsLessEqualThanConstant[BN254Fp](t)
}

type AddCircuit[T FieldParams] struct {
	A, B, C Element[T]
}

func (c *AddCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Add(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestAddCircuitNoOverflow(t *testing.T) {
	testAddCircuitNoOverflow[Goldilocks](t)
	testAddCircuitNoOverflow[Secp256k1Fp](t)
	testAddCircuitNoOverflow[BN254Fp](t)
}

func testAddCircuitNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AddCircuit[T]
		bound := new(big.Int).Rsh(fp.Modulus(), 1)
		val1, _ := rand.Int(rand.Reader, bound)
		val2, _ := rand.Int(rand.Reader, bound)
		res := new(big.Int).Add(val1, val2)
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type MulNoOverflowCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *MulNoOverflowCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestMulCircuitNoOverflow(t *testing.T) {
	testMulCircuitNoOverflow[Goldilocks](t)
	testMulCircuitNoOverflow[Secp256k1Fp](t)
	testMulCircuitNoOverflow[BN254Fp](t)
}

func testMulCircuitNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MulNoOverflowCircuit[T]
		val1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(fp.Modulus().BitLen())/2))
		val2, _ := rand.Int(rand.Reader, new(big.Int).Div(fp.Modulus(), val1))
		res := new(big.Int).Mul(val1, val2)
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16))
	}, testName[T]())
}

type MulCircuitOverflow[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *MulCircuitOverflow[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestMulCircuitOverflow(t *testing.T) {
	testMulCircuitOverflow[Goldilocks](t)
	testMulCircuitOverflow[Secp256k1Fp](t)
	testMulCircuitOverflow[BN254Fp](t)
}

func testMulCircuitOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MulCircuitOverflow[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).Mul(val1, val2)
		res.Mod(res, fp.Modulus())
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type ReduceAfterAddCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *ReduceAfterAddCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Add(&c.A, &c.B)
	res = f.Reduce(res)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestReduceAfterAdd(t *testing.T) {
	testReduceAfterAdd[Goldilocks](t)
	testReduceAfterAdd[Secp256k1Fp](t)
	testReduceAfterAdd[BN254Fp](t)
}

func testReduceAfterAdd[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness ReduceAfterAddCircuit[T]
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val1, _ := rand.Int(rand.Reader, val2)
		val3 := new(big.Int).Add(val1, fp.Modulus())
		val3.Sub(val3, val2)
		witness.A = ValueOf[T](val3)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](val1)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type SubtractCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *SubtractCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Sub(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestSubtractNoOverflow(t *testing.T) {
	testSubtractNoOverflow[Goldilocks](t)
	testSubtractNoOverflow[Secp256k1Fp](t)
	testSubtractNoOverflow[BN254Fp](t)

	testSubtractOverflow[Goldilocks](t)
	testSubtractOverflow[Secp256k1Fp](t)
	testSubtractOverflow[BN254Fp](t)
}

func testSubtractNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness SubtractCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, val1)
		res := new(big.Int).Sub(val1, val2)
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

func testSubtractOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness SubtractCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, new(big.Int).Sub(fp.Modulus(), val1))
		val2.Add(val2, val1)
		res := new(big.Int).Sub(val1, val2)
		res.Mod(res, fp.Modulus())
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type NegationCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
}

func (c *NegationCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Neg(&c.A)
	f.AssertIsEqual(res, &c.B)
	return nil
}

func TestNegation(t *testing.T) {
	testNegation[Goldilocks](t)
	testNegation[Secp256k1Fp](t)
	testNegation[BN254Fp](t)
}

func testNegation[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness NegationCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).Sub(fp.Modulus(), val1)
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type InverseCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
}

func (c *InverseCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Inverse(&c.A)
	f.AssertIsEqual(res, &c.B)
	return nil
}

func TestInverse(t *testing.T) {
	testInverse[Goldilocks](t)
	testInverse[Secp256k1Fp](t)
	testInverse[BN254Fp](t)
}

func testInverse[T FieldParams](t *testing.T) {
	var fp T
	if !fp.IsPrime() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness InverseCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).ModInverse(val1, fp.Modulus())
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type DivisionCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *DivisionCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Div(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestDivision(t *testing.T) {
	testDivision[Goldilocks](t)
	testDivision[Secp256k1Fp](t)
	testDivision[BN254Fp](t)
}

func testDivision[T FieldParams](t *testing.T) {
	var fp T
	if !fp.IsPrime() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness DivisionCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int)
		res.ModInverse(val2, fp.Modulus())
		res.Mul(val1, res)
		res.Mod(res, fp.Modulus())
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type ToBinaryCircuit[T FieldParams] struct {
	Value Element[T]
	Bits  []frontend.Variable
}

func (c *ToBinaryCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	bits := f.ToBits(&c.Value)
	if len(bits) != len(c.Bits) {
		return fmt.Errorf("got %d bits, expected %d", len(bits), len(c.Bits))
	}
	// check that the cached bits match the bits we get from ToBits. This is important as AssertIsInRange relies on the cached bits to be correct.
	newBits := f.ToBits(&c.Value)
	if len(newBits) != len(bits) {
		return fmt.Errorf("got %d bits, expected %d", len(newBits), len(bits))
	}
	for i := range bits {
		api.AssertIsEqual(bits[i], newBits[i])
		api.AssertIsEqual(bits[i], c.Bits[i])
	}
	return nil
}

func TestToBinary(t *testing.T) {
	testToBinary[Goldilocks](t)
	testToBinary[Secp256k1Fp](t)
	testToBinary[BN254Fp](t)
}

func testToBinary[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness ToBinaryCircuit[T]
		bitLen := fp.BitsPerLimb() * fp.NbLimbs()
		circuit.Bits = make([]frontend.Variable, bitLen)
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		bits := make([]frontend.Variable, bitLen)
		for i := 0; i < len(bits); i++ {
			bits[i] = val1.Bit(i)
		}
		witness.Value = ValueOf[T](val1)
		witness.Bits = bits
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type FromBinaryCircuit[T FieldParams] struct {
	Bits []frontend.Variable
	Res  Element[T]
}

func (c *FromBinaryCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.FromBits(c.Bits...)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestFromBinary(t *testing.T) {
	testFromBinary[Goldilocks](t)
	testFromBinary[Secp256k1Fp](t)
	testFromBinary[BN254Fp](t)
}

func testFromBinary[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness FromBinaryCircuit[T]
		bitLen := fp.Modulus().BitLen()
		circuit.Bits = make([]frontend.Variable, bitLen)

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		bits := make([]frontend.Variable, bitLen)
		for i := 0; i < len(bits); i++ {
			bits[i] = val1.Bit(i)
		}

		witness.Res = ValueOf[T](val1)
		witness.Bits = bits
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type EqualityCheckCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
}

func (c *EqualityCheckCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// res := c.A //f.Set(c.A) TODO @gbotrel fixme
	f.AssertIsEqual(&c.A, &c.B)
	return nil
}

func TestConstantEqual(t *testing.T) {
	testConstantEqual[Goldilocks](t)
	testConstantEqual[BN254Fp](t)
	testConstantEqual[Secp256k1Fp](t)
}

func testConstantEqual[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness EqualityCheckCircuit[T]
		val, _ := rand.Int(rand.Reader, fp.Modulus())
		witness.A = ValueOf[T](val)
		witness.B = ValueOf[T](val)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type SelectCircuit[T FieldParams] struct {
	Selector frontend.Variable
	A        Element[T]
	B        Element[T]
	C        Element[T]
	D        Element[T]
}

func (c *SelectCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	l := f.Mul(&c.A, &c.B)
	res := f.Select(c.Selector, l, &c.C)
	f.AssertIsEqual(res, &c.D)
	return nil
}

func TestSelect(t *testing.T) {
	testSelect[Goldilocks](t)
	testSelect[Secp256k1Fp](t)
	testSelect[BN254Fp](t)
}

func testSelect[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness SelectCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val3, _ := rand.Int(rand.Reader, fp.Modulus())
		l := new(big.Int).Mul(val1, val2)
		l.Mod(l, fp.Modulus())
		randbit, _ := rand.Int(rand.Reader, big.NewInt(2))
		b := randbit.Uint64()

		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](val3)
		witness.D = ValueOf[T]([]*big.Int{l, val3}[1-b])
		witness.Selector = b

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type Lookup2Circuit[T FieldParams] struct {
	Bit0 frontend.Variable
	Bit1 frontend.Variable
	A    Element[T]
	B    Element[T]
	C    Element[T]
	D    Element[T]
	E    Element[T]
}

func (c *Lookup2Circuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Lookup2(c.Bit0, c.Bit1, &c.A, &c.B, &c.C, &c.D)
	f.AssertIsEqual(res, &c.E)
	return nil
}

func TestLookup2(t *testing.T) {
	testLookup2[Goldilocks](t)
	testLookup2[Secp256k1Fp](t)
	testLookup2[BN254Fp](t)
}

func testLookup2[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness Lookup2Circuit[T]

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val3, _ := rand.Int(rand.Reader, fp.Modulus())
		val4, _ := rand.Int(rand.Reader, fp.Modulus())
		randbit, _ := rand.Int(rand.Reader, big.NewInt(4))

		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](val3)
		witness.D = ValueOf[T](val4)
		witness.E = ValueOf[T]([]*big.Int{val1, val2, val3, val4}[randbit.Uint64()])
		witness.Bit0 = randbit.Bit(0)
		witness.Bit1 = randbit.Bit(1)

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type MuxCircuit[T FieldParams] struct {
	Selector frontend.Variable
	Inputs   [8]Element[T]
	Expected Element[T]
}

func (c *MuxCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	inputs := make([]*Element[T], len(c.Inputs))
	for i := range inputs {
		inputs[i] = &c.Inputs[i]
	}
	res := f.Mux(c.Selector, inputs...)
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMux(t *testing.T) {
	testMux[Goldilocks](t)
	testMux[Secp256k1Fp](t)
	testMux[BN254Fp](t)
}

func testMux[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MuxCircuit[T]
		vals := make([]*big.Int, len(witness.Inputs))
		for i := range witness.Inputs {
			vals[i], _ = rand.Int(rand.Reader, fp.Modulus())
			witness.Inputs[i] = ValueOf[T](vals[i])
		}
		selector, _ := rand.Int(rand.Reader, big.NewInt(int64(len(witness.Inputs))))
		expected := vals[selector.Int64()]
		witness.Expected = ValueOf[T](expected)
		witness.Selector = selector

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	})
}

type ComputationCircuit[T FieldParams] struct {
	noReduce bool

	X1, X2, X3, X4, X5, X6 Element[T]
	Res                    Element[T]
}

func (c *ComputationCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := f.Mul(&c.X1, &c.X1)
	if !c.noReduce {
		x13 = f.Reduce(x13)
	}
	x13 = f.Mul(x13, &c.X1)
	if !c.noReduce {
		x13 = f.Reduce(x13)
	}

	fx2 := f.Mul(f.NewElement(5), &c.X2)
	fx2 = f.Reduce(fx2)

	nom := f.Sub(&c.X3, &c.X4)

	denom := f.Add(&c.X5, &c.X6)

	free := f.Div(nom, denom)

	// res := f.Add(x13, fx2, free)
	res := f.Add(x13, fx2)
	res = f.Add(res, free)

	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestComputation(t *testing.T) {
	testComputation[Goldilocks](t)
	testComputation[Secp256k1Fp](t)
	testComputation[BN254Fp](t)
}

func testComputation[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness ComputationCircuit[T]

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val3, _ := rand.Int(rand.Reader, fp.Modulus())
		val4, _ := rand.Int(rand.Reader, fp.Modulus())
		val5, _ := rand.Int(rand.Reader, fp.Modulus())
		val6, _ := rand.Int(rand.Reader, fp.Modulus())

		tmp := new(big.Int)
		res := new(big.Int)
		// res = x1^3
		tmp.Exp(val1, big.NewInt(3), fp.Modulus())
		res.Set(tmp)
		// res = x1^3 + 5*x2
		tmp.Mul(val2, big.NewInt(5))
		res.Add(res, tmp)
		// tmp = (x3-x4)
		tmp.Sub(val3, val4)
		tmp.Mod(tmp, fp.Modulus())
		// tmp2 = (x5+x6)
		tmp2 := new(big.Int)
		tmp2.Add(val5, val6)
		// tmp = (x3-x4)/(x5+x6)
		tmp2.ModInverse(tmp2, fp.Modulus())
		tmp.Mul(tmp, tmp2)
		tmp.Mod(tmp, fp.Modulus())
		// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
		res.Add(res, tmp)
		res.Mod(res, fp.Modulus())

		witness.X1 = ValueOf[T](val1)
		witness.X2 = ValueOf[T](val2)
		witness.X3 = ValueOf[T](val3)
		witness.X4 = ValueOf[T](val4)
		witness.X5 = ValueOf[T](val5)
		witness.X6 = ValueOf[T](val6)
		witness.Res = ValueOf[T](res)

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

func TestOptimisation(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := ComputationCircuit[BN254Fp]{
		noReduce: true,
	}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs.GetNbConstraints(), 5945)
	ccs2, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs2.GetNbConstraints(), 14859)
}

type FourMulsCircuit[T FieldParams] struct {
	A   Element[T]
	Res Element[T]
}

func (c *FourMulsCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&c.A, &c.A)
	res = f.Mul(res, &c.A)
	res = f.Mul(res, &c.A)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestFourMuls(t *testing.T) {
	testFourMuls[Goldilocks](t)
	testFourMuls[Secp256k1Fp](t)
	testFourMuls[BN254Fp](t)
}

func testFourMuls[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness FourMulsCircuit[T]

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int)
		res.Mul(val1, val1)
		res.Mul(res, val1)
		res.Mul(res, val1)
		res.Mod(res, fp.Modulus())

		witness.A = ValueOf[T](val1)
		witness.Res = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

func TestIssue348UnconstrainedLimbs(t *testing.T) {
	t.Skip("regression #348")
	// The inputs were found by the fuzzer. These inputs represent a case where
	// addition overflows due to unconstrained limbs. Usually for random inputs
	// this should lead to some failed assertion, but here the overflow is
	// exactly a multiple of non-native modulus and the equality assertion
	// succeeds.
	//
	// Usually, the widths of non-native element limbs should be bounded, but
	// for freshly initialised elements (using NewElement, or directly by
	// constructing the structure), we do not automatically enforce the widths.
	//
	// The bug is tracked in https://github.com/Consensys/gnark/issues/348
	a := big.NewInt(5)
	b, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495612", 10)
	assert := test.NewAssert(t)
	witness := NegationCircuit[Goldilocks]{
		A: Element[Goldilocks]{overflow: 0, Limbs: []frontend.Variable{a}},
		B: Element[Goldilocks]{overflow: 0, Limbs: []frontend.Variable{b}}}
	err := test.IsSolved(&NegationCircuit[Goldilocks]{}, &witness, testCurve.ScalarField())
	// this should err but does not.
	assert.Error(err)
	err = test.IsSolved(&NegationCircuit[Goldilocks]{}, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	// this should err and does. It errs because we consider all inputs as
	// constants and the field emulation package has a short path for constant
	// inputs.
	assert.Error(err)
}

type AssertInRangeCircuit[T FieldParams] struct {
	X Element[T]
}

func (c *AssertInRangeCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	f.AssertIsInRange(&c.X)
	return nil
}

func TestAssertInRange(t *testing.T) {
	testAssertIsInRange[Goldilocks](t)
	testAssertIsInRange[Secp256k1Fp](t)
	testAssertIsInRange[BN254Fp](t)
}

func testAssertIsInRange[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		X, _ := rand.Int(rand.Reader, fp.Modulus())
		circuit := AssertInRangeCircuit[T]{}
		witness := AssertInRangeCircuit[T]{X: ValueOf[T](X)}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
		witness2 := AssertInRangeCircuit[T]{X: ValueOf[T](0)}
		witness2.X.Limbs = make([]frontend.Variable, fp.NbLimbs())
		t := 0
		for i := 0; i < int(fp.NbLimbs())-1; i++ {
			L := new(big.Int).Lsh(big.NewInt(1), fp.BitsPerLimb())
			L.Sub(L, big.NewInt(1))
			witness2.X.Limbs[i] = L
			t += int(fp.BitsPerLimb())
		}
		highlimb := fp.Modulus().BitLen() - t
		L := new(big.Int).Lsh(big.NewInt(1), uint(highlimb))
		L.Sub(L, big.NewInt(1))
		witness2.X.Limbs[fp.NbLimbs()-1] = L
		assert.ProverFailed(&circuit, &witness2, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type IsZeroCircuit[T FieldParams] struct {
	X, Y Element[T]
	Zero frontend.Variable
}

func (c *IsZeroCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	R := f.Add(&c.X, &c.Y)
	api.AssertIsEqual(c.Zero, f.IsZero(R))

	isZero := f.IsZero(f.Zero())
	api.AssertIsEqual(isZero, 1)
	return nil
}

func TestIsZero(t *testing.T) {
	testIsZero[Goldilocks](t)
	testIsZero[Secp256k1Fp](t)
	testIsZero[BN254Fp](t)
}

func testIsZero[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		X, _ := rand.Int(rand.Reader, fp.Modulus())
		Y := new(big.Int).Sub(fp.Modulus(), X)
		circuit := IsZeroCircuit[T]{}
		assert.ProverSucceeded(&circuit, &IsZeroCircuit[T]{X: ValueOf[T](X), Y: ValueOf[T](Y), Zero: 1}, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
		assert.ProverSucceeded(&circuit, &IsZeroCircuit[T]{X: ValueOf[T](X), Y: ValueOf[T](0), Zero: 0}, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type SqrtCircuit[T FieldParams] struct {
	X, Expected Element[T]
}

func (c *SqrtCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Sqrt(&c.X)
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestSqrt(t *testing.T) {
	testSqrt[Goldilocks](t)
	testSqrt[Secp256k1Fp](t)
	testSqrt[BN254Fp](t)
}

func testSqrt[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var X *big.Int
		exp := new(big.Int)
		for {
			X, _ = rand.Int(rand.Reader, fp.Modulus())
			if exp.ModSqrt(X, fp.Modulus()) != nil {
				break
			}
		}
		assert.ProverSucceeded(&SqrtCircuit[T]{}, &SqrtCircuit[T]{X: ValueOf[T](X), Expected: ValueOf[T](exp)}, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type MulNoReduceCircuit[T FieldParams] struct {
	A, B, C          Element[T]
	expectedOverflow uint
	expectedNbLimbs  int
}

func (c *MulNoReduceCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.MulNoReduce(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	if res.overflow != c.expectedOverflow {
		return fmt.Errorf("unexpected overflow: got %d, expected %d", res.overflow, c.expectedOverflow)
	}
	if len(res.Limbs) != c.expectedNbLimbs {
		return fmt.Errorf("unexpected number of limbs: got %d, expected %d", len(res.Limbs), c.expectedNbLimbs)
	}
	return nil
}

func TestMulNoReduce(t *testing.T) {
	testMulNoReduce[Goldilocks](t)
	testMulNoReduce[Secp256k1Fp](t)
	testMulNoReduce[BN254Fp](t)
}

func testMulNoReduce[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		A, _ := rand.Int(rand.Reader, fp.Modulus())
		B, _ := rand.Int(rand.Reader, fp.Modulus())
		C := new(big.Int).Mul(A, B)
		C.Mod(C, fp.Modulus())
		expectedLimbs := 2*fp.NbLimbs() - 1
		expectedOverFlow := math.Ceil(math.Log2(float64(expectedLimbs+1))) + float64(fp.BitsPerLimb())
		circuit := &MulNoReduceCircuit[T]{expectedOverflow: uint(expectedOverFlow), expectedNbLimbs: int(expectedLimbs)}
		assignment := &MulNoReduceCircuit[T]{A: ValueOf[T](A), B: ValueOf[T](B), C: ValueOf[T](C)}
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment))
	}, testName[T]())
}

type SumCircuit[T FieldParams] struct {
	Inputs   []Element[T]
	Expected Element[T]
}

func (c *SumCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	inputs := make([]*Element[T], len(c.Inputs))
	for i := range inputs {
		inputs[i] = &c.Inputs[i]
	}
	res := f.Sum(inputs...)
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestSum(t *testing.T) {
	testSum[Goldilocks](t)
	testSum[Secp256k1Fp](t)
	testSum[BN254Fp](t)
}

func testSum[T FieldParams](t *testing.T) {
	var fp T
	nbInputs := 1024
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		circuit := &SumCircuit[T]{Inputs: make([]Element[T], nbInputs)}
		inputs := make([]Element[T], nbInputs)
		result := new(big.Int)
		for i := range inputs {
			val, _ := rand.Int(rand.Reader, fp.Modulus())
			result.Add(result, val)
			inputs[i] = ValueOf[T](val)
		}
		result.Mod(result, fp.Modulus())
		witness := &SumCircuit[T]{Inputs: inputs, Expected: ValueOf[T](result)}
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
	}, testName[T]())
}

type expCircuit[T FieldParams] struct {
	Base     Element[T]
	Exp      Element[T]
	Expected Element[T]
}

func (c *expCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.Exp(&c.Base, &c.Exp)
	f.AssertIsEqual(&c.Expected, res)
	return nil
}

func testExp[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit expCircuit[T]
		base, _ := rand.Int(rand.Reader, fp.Modulus())
		exp, _ := rand.Int(rand.Reader, fp.Modulus())
		expected := new(big.Int).Exp(base, exp, fp.Modulus())
		assignment := &expCircuit[T]{
			Base:     ValueOf[T](base),
			Exp:      ValueOf[T](exp),
			Expected: ValueOf[T](expected),
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(assignment))
	}, testName[T]())
}
func TestExp(t *testing.T) {
	testExp[Goldilocks](t)
	testExp[BN254Fr](t)
	testExp[emparams.Mod1e512](t)
}

type ReduceStrictCircuit[T FieldParams] struct {
	Limbs        []frontend.Variable
	Expected     []frontend.Variable
	strictReduce bool
}

func (c *ReduceStrictCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	el := f.newInternalElement(c.Limbs, 0)
	var elR *Element[T]
	if c.strictReduce {
		elR = f.ReduceStrict(el)
	} else {
		elR = f.Reduce(el)
	}
	for i := range elR.Limbs {
		api.AssertIsEqual(elR.Limbs[i], c.Expected[i])
	}

	// TODO: dummy constraint to have at least two constraints in the circuit.
	// Otherwise PLONK setup phase fails.
	api.AssertIsEqual(c.Expected[0], elR.Limbs[0])
	return nil
}

func testReduceStrict[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		p := fp.Modulus()
		plimbs := make([]*big.Int, int(fp.NbLimbs()))
		for i := range plimbs {
			plimbs[i] = new(big.Int)
		}
		err := limbs.Decompose(p, fp.BitsPerLimb(), plimbs)
		assert.NoError(err)
		plimbs[0].Add(plimbs[0], big.NewInt(1))
		exp := make([]*big.Int, int(fp.NbLimbs()))
		exp[0] = big.NewInt(1)
		for i := 1; i < int(fp.NbLimbs()); i++ {
			exp[i] = big.NewInt(0)
		}
		circuitStrict := &ReduceStrictCircuit[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: make([]frontend.Variable, int(fp.NbLimbs())), strictReduce: true}
		circuitLax := &ReduceStrictCircuit[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: make([]frontend.Variable, int(fp.NbLimbs()))}
		witness := &ReduceStrictCircuit[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: make([]frontend.Variable, int(fp.NbLimbs()))}
		for i := range plimbs {
			witness.Limbs[i] = plimbs[i]
			witness.Expected[i] = exp[i]
		}
		assert.CheckCircuit(circuitStrict, test.WithValidAssignment(witness))
		assert.CheckCircuit(circuitLax, test.WithInvalidAssignment(witness))

	}, testName[T]())
}

func TestReduceStrict(t *testing.T) {
	testReduceStrict[Goldilocks](t)
	testReduceStrict[BN254Fr](t)
	testReduceStrict[emparams.Mod1e512](t)
}

type ToBitsCanonicalCircuit[T FieldParams] struct {
	Limbs    []frontend.Variable
	Expected []frontend.Variable
}

func (c *ToBitsCanonicalCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	el := f.newInternalElement(c.Limbs, 0)
	bts := f.ToBitsCanonical(el)
	// ensure that the bit caching is working correctly by calling ToBitsCanonical twice and comparing the results.
	newBts := f.ToBitsCanonical(el)
	if len(newBts) != len(bts) {
		return fmt.Errorf("got %d bits, expected %d", len(bts), len(c.Expected))
	}
	for i := range bts {
		api.AssertIsEqual(bts[i], newBts[i])
		api.AssertIsEqual(bts[i], c.Expected[i])
	}
	return nil
}

func testToBitsCanonical[T FieldParams](t *testing.T) {
	var fp T
	nbBits := fp.Modulus().BitLen()
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		p := fp.Modulus()
		plimbs := make([]*big.Int, int(fp.NbLimbs()))
		for i := range plimbs {
			plimbs[i] = new(big.Int)
		}
		err := limbs.Decompose(p, fp.BitsPerLimb(), plimbs)
		assert.NoError(err)
		plimbs[0].Add(plimbs[0], big.NewInt(1))
		exp := make([]*big.Int, int(nbBits))
		exp[0] = big.NewInt(1)
		for i := 1; i < len(exp); i++ {
			exp[i] = big.NewInt(0)
		}
		circuit := &ToBitsCanonicalCircuit[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: make([]frontend.Variable, nbBits)}
		witness := &ToBitsCanonicalCircuit[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: make([]frontend.Variable, nbBits)}
		for i := range plimbs {
			witness.Limbs[i] = plimbs[i]
		}
		for i := range exp {
			witness.Expected[i] = exp[i]
		}
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
	}, testName[T]())
}

func TestToBitsCanonical(t *testing.T) {
	testToBitsCanonical[Goldilocks](t)
	testToBitsCanonical[BN254Fr](t)
	testToBitsCanonical[emparams.Mod1e512](t)
}

type IsZeroEdgeCase[T FieldParams] struct {
	Limbs    []frontend.Variable
	Expected frontend.Variable
}

func (c *IsZeroEdgeCase[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	el := f.newInternalElement(c.Limbs, 0)
	res := f.IsZero(el)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func testIsZeroEdgeCases[T FieldParams](t *testing.T) {
	var fp T
	p := fp.Modulus()
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		plimbs := make([]*big.Int, int(fp.NbLimbs()))
		for i := range plimbs {
			plimbs[i] = new(big.Int)
		}
		err := limbs.Decompose(p, fp.BitsPerLimb(), plimbs)
		assert.NoError(err)
		// limbs are for zero
		witness1 := &IsZeroEdgeCase[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: 1}
		for i := range plimbs {
			witness1.Limbs[i] = big.NewInt(0)
		}
		// limbs are for p
		witness2 := &IsZeroEdgeCase[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: 1}
		for i := range plimbs {
			witness2.Limbs[i] = plimbs[i]
		}
		// limbs are for not zero
		witness3 := &IsZeroEdgeCase[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: 0}
		witness3.Limbs[0] = big.NewInt(1)
		for i := 1; i < len(witness3.Limbs); i++ {
			witness3.Limbs[i] = big.NewInt(0)
		}
		// limbs are for not zero bigger than p
		witness4 := &IsZeroEdgeCase[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs())), Expected: 0}
		witness4.Limbs[0] = new(big.Int).Add(plimbs[0], big.NewInt(1))
		for i := 1; i < len(witness4.Limbs); i++ {
			witness4.Limbs[i] = plimbs[i]
		}
		assert.CheckCircuit(&IsZeroEdgeCase[T]{Limbs: make([]frontend.Variable, int(fp.NbLimbs()))}, test.WithValidAssignment(witness1), test.WithValidAssignment(witness2), test.WithValidAssignment(witness3), test.WithValidAssignment(witness4))

	}, testName[T]())
}

func TestIsZeroEdgeCases(t *testing.T) {
	testIsZeroEdgeCases[Goldilocks](t)
	testIsZeroEdgeCases[BN254Fr](t)
	testIsZeroEdgeCases[emparams.Mod1e512](t)
}

type PolyEvalCircuit[T FieldParams] struct {
	Inputs         []Element[T]
	TermsByIndices [][]int
	Coeffs         []int
	Expected       Element[T]
}

func (c *PolyEvalCircuit[T]) Define(api frontend.API) error {
	// withEval
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// reconstruct the terms from the inputs and the indices
	terms := make([][]*Element[T], len(c.TermsByIndices))
	for i := range terms {
		terms[i] = make([]*Element[T], len(c.TermsByIndices[i]))
		for j := range terms[i] {
			terms[i][j] = &c.Inputs[c.TermsByIndices[i][j]]
		}
	}
	resEval := f.Eval(terms, c.Coeffs)

	// withSum
	addTerms := make([]*Element[T], len(c.TermsByIndices))
	for i, term := range c.TermsByIndices {
		termVal := f.One()
		for j := range term {
			termVal = f.Mul(termVal, &c.Inputs[term[j]])
		}
		addTerms[i] = f.MulConst(termVal, big.NewInt(int64(c.Coeffs[i])))
	}
	resSum := f.Sum(addTerms...)

	// mul no reduce
	addTerms2 := make([]*Element[T], len(c.TermsByIndices))
	for i, term := range c.TermsByIndices {
		termVal := f.One()
		for j := range term {
			termVal = f.MulNoReduce(termVal, &c.Inputs[term[j]])
		}
		addTerms2[i] = f.MulConst(termVal, big.NewInt(int64(c.Coeffs[i])))
	}
	resNoReduce := f.Sum(addTerms2...)
	resReduced := f.Reduce(resNoReduce)

	// assertions
	f.AssertIsEqual(resEval, &c.Expected)
	f.AssertIsEqual(resSum, &c.Expected)
	f.AssertIsEqual(resNoReduce, &c.Expected)
	f.AssertIsEqual(resReduced, &c.Expected)

	return nil
}

func TestPolyEval(t *testing.T) {
	testPolyEval[Goldilocks](t)
	testPolyEval[BN254Fr](t)
	testPolyEval[emparams.Mod1e512](t)
}

func testPolyEval[T FieldParams](t *testing.T) {
	const nbInputs = 2
	assert := test.NewAssert(t)
	var fp T
	var err error
	// 2*x^3 + 3*x^2 y + 4*x y^2 + 5*y^3 assuming we have inputs w=[x, y], then
	// we can represent by the indices of the inputs:
	//    2*x^3 + 3*x^2 y + 4*x y^2 + 5*y^3 -> 2*x*x*x + 3*x*x*y + 4*x*y*y + 5*y*y*y -> 2*w[0]*w[0]*w[0] + 3*w[0]*w[0]*w[1] + 4*w[0]*w[1]*w[1] + 5*w[1]*w[1]*w[1]
	// the following variable gives the indices of the inputs. For givin the
	// circuit this is better as then we can easily reference to the inputs by
	// index.
	toMulByIndex := [][]int{{0, 0, 0}, {0, 0, 1}, {0, 1, 1}, {1, 1, 1}}
	coefficients := []int{2, 3, 4, 5}
	inputs := make([]*big.Int, nbInputs)
	assignmentInput := make([]Element[T], nbInputs)
	for i := range inputs {
		inputs[i], err = rand.Int(rand.Reader, fp.Modulus())
		assert.NoError(err)
	}
	for i := range inputs {
		assignmentInput[i] = ValueOf[T](inputs[i])
	}
	expected := new(big.Int)
	for i, term := range toMulByIndex {
		termVal := new(big.Int).SetInt64(int64(coefficients[i]))
		for j := range term {
			termVal.Mul(termVal, inputs[term[j]])
		}
		expected.Add(expected, termVal)
	}
	expected.Mod(expected, fp.Modulus())

	assignment := &PolyEvalCircuit[T]{
		Inputs:   assignmentInput,
		Expected: ValueOf[T](expected),
	}
	assert.CheckCircuit(&PolyEvalCircuit[T]{Inputs: make([]Element[T], nbInputs), TermsByIndices: toMulByIndex, Coeffs: coefficients}, test.WithValidAssignment(assignment))
}

type PolyEvalNegativeCoefficient[T FieldParams] struct {
	Inputs []Element[T]
	Res    Element[T]
}

func (c *PolyEvalNegativeCoefficient[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// x - y
	coefficients := []int{1, -1}
	res := f.Eval([][]*Element[T]{{&c.Inputs[0]}, {&c.Inputs[1]}}, coefficients)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPolyEvalNegativeCoefficient(t *testing.T) {
	testPolyEvalNegativeCoefficient[Goldilocks](t)
	testPolyEvalNegativeCoefficient[BN254Fr](t)
	testPolyEvalNegativeCoefficient[emparams.Mod1e512](t)
}

func testPolyEvalNegativeCoefficient[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	var fp T
	var err error
	const nbInputs = 2
	inputs := make([]*big.Int, nbInputs)
	assignmentInput := make([]Element[T], nbInputs)
	for i := range inputs {
		inputs[i], err = rand.Int(rand.Reader, fp.Modulus())
		assert.NoError(err)
	}
	for i := range inputs {
		assignmentInput[i] = ValueOf[T](inputs[i])
	}
	expected := new(big.Int).Sub(inputs[0], inputs[1])
	expected.Mod(expected, fp.Modulus())
	assignment := &PolyEvalNegativeCoefficient[T]{Inputs: assignmentInput, Res: ValueOf[T](expected)}
	err = test.IsSolved(&PolyEvalNegativeCoefficient[T]{Inputs: make([]Element[T], nbInputs)}, assignment, testCurve.ScalarField())
	assert.NoError(err)
}

type PolyEvalNegCoeffDiffSquares[T FieldParams] struct {
	Inputs []Element[T]
	Res    Element[T]
}

func (c *PolyEvalNegCoeffDiffSquares[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// x² - y²
	coefficients := []int{1, -1}
	res := f.Eval([][]*Element[T]{{&c.Inputs[0], &c.Inputs[0]}, {&c.Inputs[1], &c.Inputs[1]}}, coefficients)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPolyEvalNegCoeffDiffSquares(t *testing.T) {
	testPolyEvalNegCoeffDiffSquares[Goldilocks](t)
	testPolyEvalNegCoeffDiffSquares[BN254Fr](t)
	testPolyEvalNegCoeffDiffSquares[emparams.Mod1e512](t)
}

func testPolyEvalNegCoeffDiffSquares[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	var fp T
	var err error
	const nbInputs = 2
	inputs := make([]*big.Int, nbInputs)
	assignmentInput := make([]Element[T], nbInputs)
	for i := range inputs {
		inputs[i], err = rand.Int(rand.Reader, fp.Modulus())
		assert.NoError(err)
	}
	for i := range inputs {
		assignmentInput[i] = ValueOf[T](inputs[i])
	}
	// x² - y²
	expected := new(big.Int).Mul(inputs[0], inputs[0])
	expected.Sub(expected, new(big.Int).Mul(inputs[1], inputs[1]))
	expected.Mod(expected, fp.Modulus())
	assignment := &PolyEvalNegCoeffDiffSquares[T]{Inputs: assignmentInput, Res: ValueOf[T](expected)}
	err = test.IsSolved(&PolyEvalNegCoeffDiffSquares[T]{Inputs: make([]Element[T], nbInputs)}, assignment, testCurve.ScalarField())
	assert.NoError(err)
}

// PolyEvalNegCoeffLarge tests Eval with larger negative coefficients (-2, -3).
// Computes 3*x*y - 2*z² + x.
type PolyEvalNegCoeffLarge[T FieldParams] struct {
	Inputs []Element[T]
	Res    Element[T]
}

func (c *PolyEvalNegCoeffLarge[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// 3*x*y - 2*z² + x
	coefficients := []int{3, -2, 1}
	res := f.Eval([][]*Element[T]{{&c.Inputs[0], &c.Inputs[1]}, {&c.Inputs[2], &c.Inputs[2]}, {&c.Inputs[0]}}, coefficients)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPolyEvalNegCoeffLarge(t *testing.T) {
	testPolyEvalNegCoeffLarge[Goldilocks](t)
	testPolyEvalNegCoeffLarge[BN254Fr](t)
	testPolyEvalNegCoeffLarge[emparams.Mod1e512](t)
}

func testPolyEvalNegCoeffLarge[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	var fp T
	var err error
	const nbInputs = 3
	inputs := make([]*big.Int, nbInputs)
	assignmentInput := make([]Element[T], nbInputs)
	for i := range inputs {
		inputs[i], err = rand.Int(rand.Reader, fp.Modulus())
		assert.NoError(err)
	}
	for i := range inputs {
		assignmentInput[i] = ValueOf[T](inputs[i])
	}
	// 3*x*y - 2*z² + x
	expected := new(big.Int).Mul(inputs[0], inputs[1])
	expected.Mul(expected, big.NewInt(3))
	z2 := new(big.Int).Mul(inputs[2], inputs[2])
	z2.Mul(z2, big.NewInt(2))
	expected.Sub(expected, z2)
	expected.Add(expected, inputs[0])
	expected.Mod(expected, fp.Modulus())
	assignment := &PolyEvalNegCoeffLarge[T]{Inputs: assignmentInput, Res: ValueOf[T](expected)}
	err = test.IsSolved(&PolyEvalNegCoeffLarge[T]{Inputs: make([]Element[T], nbInputs)}, assignment, testCurve.ScalarField())
	assert.NoError(err)
}

// PolyEvalNegCoeffMixed tests Eval with a mix of positive and negative coefficients
// including larger values. Computes 82*a*b - 82*c*d + 18*a*d - 242*b*c.
type PolyEvalNegCoeffMixed[T FieldParams] struct {
	Inputs []Element[T]
	Res    Element[T]
}

func (c *PolyEvalNegCoeffMixed[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	coefficients := []int{82, -82, 18, -242}
	res := f.Eval([][]*Element[T]{
		{&c.Inputs[0], &c.Inputs[1]},
		{&c.Inputs[2], &c.Inputs[3]},
		{&c.Inputs[0], &c.Inputs[3]},
		{&c.Inputs[1], &c.Inputs[2]},
	}, coefficients)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPolyEvalNegCoeffMixed(t *testing.T) {
	testPolyEvalNegCoeffMixed[Goldilocks](t)
	testPolyEvalNegCoeffMixed[BN254Fr](t)
	testPolyEvalNegCoeffMixed[emparams.Mod1e512](t)
}

func testPolyEvalNegCoeffMixed[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	var fp T
	var err error
	const nbInputs = 4
	inputs := make([]*big.Int, nbInputs)
	assignmentInput := make([]Element[T], nbInputs)
	for i := range inputs {
		inputs[i], err = rand.Int(rand.Reader, fp.Modulus())
		assert.NoError(err)
	}
	for i := range inputs {
		assignmentInput[i] = ValueOf[T](inputs[i])
	}
	// 82*a*b - 82*c*d + 18*a*d - 242*b*c
	mod := fp.Modulus()
	expected := new(big.Int).Mul(inputs[0], inputs[1])
	expected.Mul(expected, big.NewInt(82))
	t2 := new(big.Int).Mul(inputs[2], inputs[3])
	t2.Mul(t2, big.NewInt(82))
	expected.Sub(expected, t2)
	t3 := new(big.Int).Mul(inputs[0], inputs[3])
	t3.Mul(t3, big.NewInt(18))
	expected.Add(expected, t3)
	t4 := new(big.Int).Mul(inputs[1], inputs[2])
	t4.Mul(t4, big.NewInt(242))
	expected.Sub(expected, t4)
	expected.Mod(expected, mod)
	assignment := &PolyEvalNegCoeffMixed[T]{Inputs: assignmentInput, Res: ValueOf[T](expected)}
	err = test.IsSolved(&PolyEvalNegCoeffMixed[T]{Inputs: make([]Element[T], nbInputs)}, assignment, testCurve.ScalarField())
	assert.NoError(err)
}

type FastPathsCircuit[T FieldParams] struct {
	Rand Element[T]
	Zero Element[T]
}

func (c *FastPathsCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// instead of using witness values, we need to create the elements
	// in-circuit. In witness creation we always create elements with full
	// number of limbs.

	zero := f.Zero()

	// mul
	res := f.Mul(zero, &c.Rand)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)
	res = f.Mul(&c.Rand, zero)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)

	res = f.MulMod(zero, &c.Rand)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)
	res = f.MulMod(&c.Rand, zero)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)

	res = f.MulNoReduce(zero, &c.Rand)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)
	res = f.MulNoReduce(&c.Rand, zero)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)

	// div
	res = f.Div(zero, &c.Rand)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)

	// square root
	res = f.Sqrt(zero)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)

	// exp
	res = f.Exp(zero, &c.Rand)
	f.AssertIsEqual(res, &c.Zero)
	f.AssertIsEqual(res, zero)

	return nil
}

func TestFastPaths(t *testing.T) {
	testFastPaths[Goldilocks](t)
	testFastPaths[BN254Fr](t)
	testFastPaths[emparams.Mod1e512](t)
}

func testFastPaths[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	var fp T
	randVal, _ := rand.Int(rand.Reader, fp.Modulus())
	circuit := &FastPathsCircuit[T]{}
	assignment := &FastPathsCircuit[T]{Rand: ValueOf[T](randVal), Zero: ValueOf[T](0)}

	// every operation short-circuits on the constant zero, so Rand is never
	// read by a constraint.
	assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

type TestAssertIsDifferentCircuit[T FieldParams] struct {
	A, B   Element[T]
	addMod bool
}

func (c *TestAssertIsDifferentCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	b := &c.B
	if c.addMod {
		b = f.Add(b, f.Modulus())
	}
	f.AssertIsDifferent(&c.A, b)
	return nil
}

func TestAssertIsDifferent(t *testing.T) {
	testAssertIsDifferent[Goldilocks](t)
	testAssertIsDifferent[Secp256k1Fp](t)
	testAssertIsDifferent[BN254Fp](t)
}

func testAssertIsDifferent[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	circuitNoMod := &TestAssertIsDifferentCircuit[T]{addMod: false}
	var fp T
	a, _ := rand.Int(rand.Reader, fp.Modulus())
	assignment1 := &TestAssertIsDifferentCircuit[T]{A: ValueOf[T](a), B: ValueOf[T](a)}
	var b *big.Int
	for {
		b, _ = rand.Int(rand.Reader, fp.Modulus())
		if b.Cmp(a) == 0 {
			continue
		}
		break
	}
	assignment2 := &TestAssertIsDifferentCircuit[T]{A: ValueOf[T](a), B: ValueOf[T](b)}
	assert.CheckCircuit(circuitNoMod, test.WithInvalidAssignment(assignment1), test.WithValidAssignment(assignment2))

	circuitWithMod := &TestAssertIsDifferentCircuit[T]{addMod: true}
	assignment3 := &TestAssertIsDifferentCircuit[T]{A: ValueOf[T](a), B: ValueOf[T](a)}
	assignment4 := &TestAssertIsDifferentCircuit[T]{A: ValueOf[T](a), B: ValueOf[T](b)}
	assert.CheckCircuit(circuitWithMod, test.WithInvalidAssignment(assignment3), test.WithValidAssignment(assignment4))
}

type TestLookup2AndMuxOnAllLimbsCircuit[T FieldParams] struct {
	A Element[T] `gnark:",public"`
}

func (c *TestLookup2AndMuxOnAllLimbsCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}

	one := f.One()
	res := f.Lookup2(1, 0, one, &c.A, &c.A, &c.A)
	if len(res.Limbs) != len(c.A.Limbs) {
		return fmt.Errorf("unexpected number of limbs: got %d, expected %d", len(res.Limbs), len(c.A.Limbs))
	}
	for i := range res.Limbs {
		api.AssertIsEqual(res.Limbs[i], c.A.Limbs[i])
	}

	res2 := f.Mux(1, one, &c.A, &c.A, &c.A)
	if len(res2.Limbs) != len(c.A.Limbs) {
		return fmt.Errorf("unexpected number of limbs: got %d, expected %d", len(res2.Limbs), len(c.A.Limbs))
	}
	for i := range res2.Limbs {
		api.AssertIsEqual(res2.Limbs[i], c.A.Limbs[i])
	}
	return nil
}

// TestLookup2AndMuxOnAllLimbs tests the Lookup2 and Mux switch all limbs.
func TestLookup2AndMuxOnAllLimbs(t *testing.T) {
	testLookup2AndMuxOnAllLimbs[Goldilocks](t)
	testLookup2AndMuxOnAllLimbs[Secp256k1Fp](t)
	testLookup2AndMuxOnAllLimbs[BN254Fp](t)
}

func testLookup2AndMuxOnAllLimbs[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	var fp T
	a, _ := rand.Int(rand.Reader, fp.Modulus())
	assignment := &TestLookup2AndMuxOnAllLimbsCircuit[T]{A: ValueOf[T](a)}
	assert.CheckCircuit(&TestLookup2AndMuxOnAllLimbsCircuit[T]{}, test.WithValidAssignment(assignment))
}
