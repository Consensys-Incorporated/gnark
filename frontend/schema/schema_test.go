// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package schema

import (
	"bytes"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/stretchr/testify/require"
)

type variable interface{}

type Circuit struct {
	X variable `gnark:"x"`
	Y variable `gnark:",public"`
	Z []variable
	G circuitChild
	H circuitGrandChild `gnark:",secret"`
	I [2]circuitGrandChild
}

type circuitChild struct {
	A variable          `gnark:",public"`
	B circuitGrandChild `gnark:",public"`
	C [2]variable       `gnark:"super"`
}

type circuitGrandChild struct {
	E variable
	F [2]variable
	N circuitGrandGrandChildWithoutVariables
	O circuitGrandGrandChildWithVariables
	P [1]circuitGrandGrandChildWithVariables
}

type circuitGrandGrandChildWithoutVariables struct {
	L int
}

type circuitGrandGrandChildWithVariables struct {
	M variable
}

type expected struct {
	X int `gnark:"x,secret" json:"x"`
	Y int `gnark:",public"`
	Z [3]int
	G struct {
		A int `gnark:",public"`
		B struct {
			E int
			F [2]int
			O struct {
				M int
			}
			P [1]struct {
				M int
			}
		} `gnark:",public"`
		C [2]int `gnark:"super" json:"super"`
	}
	H struct {
		E int
		F [2]int
		O struct {
			M int
		}
		P [1]struct {
			M int
		}
	} `gnark:",secret"`
	I [2]struct {
		E int
		F [2]int
		O struct {
			M int
		}
		P [1]struct {
			M int
		}
	}
}

func TestSchemaCorrectness(t *testing.T) {
	assert := require.New(t)

	// build schema
	witness := &Circuit{Z: make([]variable, 3)}
	s, err := New(ecc.BN254.ScalarField(), witness, tVariable)
	assert.NoError(err)

	// instantiate a concrete object
	var a int
	instance := s.Instantiate(reflect.TypeOf(a), false)

	// encode it to json
	var instanceBuf, expectedBuf bytes.Buffer
	err = json.NewEncoder(&instanceBuf).Encode(instance)
	assert.NoError(err)
	err = json.NewEncoder(&expectedBuf).Encode(expected{})
	assert.NoError(err)

	// ensure it matches what we expect
	assert.Equal(expectedBuf.String(), instanceBuf.String())
}

type pointerInner struct {
	A variable
	B [2]variable
}

type circuitPointerField struct {
	P  *pointerInner `gnark:",public"`
	S  []*pointerInner
	X  variable
	NP *pointerInner
}

// TestSchemaPointerFields checks that the schema contains the leaves behind
// pointer fields, in the same number as Walk (used to build the witness) finds.
func TestSchemaPointerFields(t *testing.T) {
	assert := require.New(t)

	circuit := &circuitPointerField{
		P: &pointerInner{},
		S: []*pointerInner{{}, {}},
	}
	s, err := New(ecc.BN254.ScalarField(), circuit, tVariable)
	assert.NoError(err)
	count, err := Walk(ecc.BN254.ScalarField(), circuit, tVariable, nil)
	assert.NoError(err)

	assert.Equal(3, s.NbPublic)
	assert.Equal(7, s.NbSecret)
	assert.Equal(count.Public, s.NbPublic)
	assert.Equal(count.Secret, s.NbSecret)
}

type circuitInherit1 struct {
	X variable `gnark:"x"`
	Y struct {
		U, V variable
	} `gnark:",public"`
}

type circuitInherit2 struct {
	X struct {
		A variable `gnark:"x,secret"`
	}
	Y struct {
		U variable `gnark:",public"`
		V struct {
			Z variable
			W variable
		}
	} `gnark:",public"`
}

func TestSchemaInherit(t *testing.T) {
	assert := require.New(t)

	{
		var c circuitInherit1

		s, err := Walk(ecc.BN254.ScalarField(), &c, tVariable, nil)
		assert.NoError(err)

		assert.Equal(2, s.Public)
		assert.Equal(1, s.Secret)
	}

	{
		var c circuitInherit2

		s, err := Walk(ecc.BN254.ScalarField(), &c, tVariable, nil)
		assert.NoError(err)

		assert.Equal(3, s.Public)
		assert.Equal(1, s.Secret)
	}
}

type initableVariable struct {
	Val []variable
}

func (iv *initableVariable) Initialize(field *big.Int) {
	if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		iv.Val = make([]variable, 2)
	} else {
		iv.Val = make([]variable, 3)
	}
}

type initableCircuit struct {
	X [2]initableVariable
	Y []initableVariable
	Z initableVariable
}

func TestVariableInitHook(t *testing.T) {
	assert := require.New(t)

	witness := &initableCircuit{Y: make([]initableVariable, 2)}
	s, err := New(ecc.BN254.ScalarField(), witness, tVariable)
	assert.NoError(err)
	assert.Equal(s.NbSecret, 10) // X: 2*2, Y: 2*2, Z: 2

	s2, err := New(tinyfield.Modulus(), witness, tVariable)
	assert.NoError(err)
	assert.Equal(s2.NbSecret, 15) // X: 2*3, Y: 2*3, Z: 3
}

func BenchmarkLargeSchema(b *testing.B) {
	const n1 = 1 << 12
	const n2 = 1 << 12

	t1 := struct {
		A [][n2]variable
	}{
		make([][n2]variable, n1),
	}

	b.Run("walk", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := Walk(ecc.BN254.ScalarField(), &t1, tVariable, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("parse", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := New(ecc.BN254.ScalarField(), &t1, tVariable)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkArrayOfSliceOfStructSchema(b *testing.B) {
	const n1 = 1 << 12
	const n2 = 1 << 12

	type point struct {
		x, y variable
		z    string
	}
	type circuit struct {
		A [n1][]point
	}

	var t1 circuit
	for i := 0; i < len(t1.A); i++ {
		t1.A[i] = make([]point, n2<<(i%2))
	}
	b.Run("walk", func(b *testing.B) {

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := Walk(ecc.BN254.ScalarField(), &t1, tVariable, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("parse", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := New(ecc.BN254.ScalarField(), &t1, tVariable)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A variable }{}).FieldByName("A").Type()
}
