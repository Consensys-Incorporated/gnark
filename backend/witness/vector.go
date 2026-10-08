package witness

import (
	"errors"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	fr_grumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/internal/utils"
)

func newVector(field *big.Int, size int) (any, error) {
	curveID := utils.FieldToCurve(field)
	switch curveID {
	case ecc.BN254:
		return make(fr_bn254.Vector, size), nil
	case ecc.BLS12_377:
		return make(fr_bls12377.Vector, size), nil
	case ecc.BLS12_381:
		return make(fr_bls12381.Vector, size), nil
	case ecc.BW6_761:
		return make(fr_bw6761.Vector, size), nil
	default:
		if field.Cmp(ecc.GRUMPKIN.ScalarField()) == 0 {
			return make(fr_grumpkin.Vector, size), nil
		}
		if field.Cmp(tinyfield.Modulus()) == 0 {
			return make(tinyfield.Vector, size), nil
		}
		if field.Cmp(babybear.Modulus()) == 0 {
			return make(babybear.Vector, size), nil
		}
		if field.Cmp(koalabear.Modulus()) == 0 {
			return make(koalabear.Vector, size), nil
		}
		if field.Cmp(mamabear.Modulus()) == 0 {
			return make(mamabear.Vector, size), nil
		}
		return nil, errors.New("unsupported modulus")
	}
}

func newFrom(from any, n int) (any, error) {
	switch wt := from.(type) {
	case fr_bn254.Vector:
		a := make(fr_bn254.Vector, n)
		copy(a, wt)
		return a, nil
	case fr_bls12377.Vector:
		a := make(fr_bls12377.Vector, n)
		copy(a, wt)
		return a, nil
	case fr_bls12381.Vector:
		a := make(fr_bls12381.Vector, n)
		copy(a, wt)
		return a, nil
	case fr_bw6761.Vector:
		a := make(fr_bw6761.Vector, n)
		copy(a, wt)
		return a, nil
	case fr_grumpkin.Vector:
		a := make(fr_grumpkin.Vector, n)
		copy(a, wt)
		return a, nil
	case tinyfield.Vector:
		a := make(tinyfield.Vector, n)
		copy(a, wt)
		return a, nil
	case babybear.Vector:
		a := make(babybear.Vector, n)
		copy(a, wt)
		return a, nil
	case koalabear.Vector:
		a := make(koalabear.Vector, n)
		copy(a, wt)
		return a, nil
	case mamabear.Vector:
		a := make(mamabear.Vector, n)
		copy(a, wt)
		return a, nil
	default:
		return nil, errors.New("unsupported modulus")
	}
}

func leafType(v any) reflect.Type {
	switch v.(type) {
	case fr_bn254.Vector:
		return reflect.TypeOf(fr_bn254.Element{})
	case fr_bls12377.Vector:
		return reflect.TypeOf(fr_bls12377.Element{})
	case fr_bls12381.Vector:
		return reflect.TypeOf(fr_bls12381.Element{})
	case fr_bw6761.Vector:
		return reflect.TypeOf(fr_bw6761.Element{})
	case fr_grumpkin.Vector:
		return reflect.TypeOf(fr_grumpkin.Element{})
	case tinyfield.Vector:
		return reflect.TypeOf(tinyfield.Element{})
	case babybear.Vector:
		return reflect.TypeOf(babybear.Element{})
	case koalabear.Vector:
		return reflect.TypeOf(koalabear.Element{})
	case mamabear.Vector:
		return reflect.TypeOf(mamabear.Element{})
	default:
		panic("invalid input")
	}
}

func set(v any, index int, value any) error {
	switch pv := v.(type) {
	case fr_bn254.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case fr_bls12377.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case fr_bls12381.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case fr_bw6761.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case fr_grumpkin.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case tinyfield.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case babybear.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case koalabear.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	case mamabear.Vector:
		if index >= len(pv) {
			return errors.New("out of bounds")
		}
		_, err := pv[index].SetInterface(value)
		return err
	default:
		panic("invalid input")
	}
}

func iterate(v any) chan any {
	chValues := make(chan any)
	switch pv := v.(type) {
	case fr_bn254.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case fr_bls12377.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case fr_bls12381.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case fr_bw6761.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case fr_grumpkin.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case tinyfield.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case babybear.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case koalabear.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	case mamabear.Vector:
		go func() {
			for i := 0; i < len(pv); i++ {
				chValues <- &(pv)[i]
			}
			close(chValues)
		}()
	default:
		panic("invalid input")
	}
	return chValues
}

func resize(v any, n int) any {
	switch v.(type) {
	case fr_bn254.Vector:
		return make(fr_bn254.Vector, n)
	case fr_bls12377.Vector:
		return make(fr_bls12377.Vector, n)
	case fr_bls12381.Vector:
		return make(fr_bls12381.Vector, n)
	case fr_bw6761.Vector:
		return make(fr_bw6761.Vector, n)
	case fr_grumpkin.Vector:
		return make(fr_grumpkin.Vector, n)
	case tinyfield.Vector:
		return make(tinyfield.Vector, n)
	case babybear.Vector:
		return make(babybear.Vector, n)
	case koalabear.Vector:
		return make(koalabear.Vector, n)
	case mamabear.Vector:
		return make(mamabear.Vector, n)
	default:
		panic("invalid input")
	}
}
