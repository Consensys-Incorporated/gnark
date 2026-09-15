// Package keccakf implements the KeccakF-1600 permutation function.
//
// This package exposes only the permutation primitive. For SHA3, SHAKE3 etc.
// functions it is necessary to apply the sponge construction. The constructions
// will be implemented in future in [github.com/consensys/gnark/std/hash/sha3]
// package.
//
// The cost for a single application of permutation is:
//   - 94160 constraints in Groth16
//   - 158486 constraints in Plonk
package keccakf

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/frontendtype"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/math/uints"
)

func init() {
	solver.RegisterHint(xor3Hint, chiHint)
}

var rc = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}
var rotc = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}
var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

// Permute applies Keccak-F permutation on the input and returns the permuted vector.
// Original input is not modified.
func Permute(uapi *uints.BinaryField[uints.U64], input [25]uints.U64) [25]uints.U64 {
	var state [25][64]frontend.Variable
	for i := range input {
		bits := uapi.ToBits(input[i])
		copy(state[i][:], bits)
	}
	state = permuteBits(uapi.API(), state)

	var ret [25]uints.U64
	for i := range ret {
		ret[i] = uapi.FromBits(state[i][:]...)
	}
	return ret
}

func permuteBits(api frontend.API, st [25][64]frontend.Variable) [25][64]frontend.Variable {
	if isR1CS(api) {
		return permuteBitsR1CS(api, st)
	}
	return permuteBitsGeneric(api, st)
}

func isR1CS(api frontend.API) bool {
	// The custom one-row gadgets below rely on the characteristic being
	// larger than their constant coefficients (they would divide by zero on
	// F2/F3); those fields use the generic path.
	if api.Compiler().Field().Cmp(big.NewInt(3)) <= 0 {
		return false
	}
	ft, ok := api.Compiler().(frontendtype.FrontendTyper)
	return ok && ft.FrontendType() == frontendtype.R1CS
}

func permuteBitsGeneric(api frontend.API, st [25][64]frontend.Variable) [25][64]frontend.Variable {
	var bc [5][64]frontend.Variable
	for r := 0; r < 24; r++ {
		// theta
		for i := 0; i < 5; i++ {
			for z := 0; z < 64; z++ {
				bc[i][z] = xor(api, st[i][z], st[i+5][z], st[i+10][z], st[i+15][z], st[i+20][z])
			}
		}
		for i := 0; i < 5; i++ {
			rot := lrot(bc[(i+1)%5], 1)
			for z := 0; z < 64; z++ {
				d := api.Xor(bc[(i+4)%5][z], rot[z])
				for j := 0; j < 25; j += 5 {
					st[j+i][z] = api.Xor(st[j+i][z], d)
				}
			}
		}
		// rho pi
		t := st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc0 := st[j]
			st[j] = lrot(t, rotc[i])
			t = bc0
		}

		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				for z := 0; z < 64; z++ {
					st[j+i][z] = api.Xor(st[j+i][z], andNot(api, bc[(i+1)%5][z], bc[(i+2)%5][z]))
				}
			}
		}
		// iota
		for z := 0; z < 64; z++ {
			if (rc[r]>>z)&1 == 1 {
				st[0][z] = api.Xor(st[0][z], 1)
			}
		}
	}
	return st
}

func permuteBitsR1CS(api frontend.API, st [25][64]frontend.Variable) [25][64]frontend.Variable {
	var bc [5][64]frontend.Variable
	for r := 0; r < 24; r++ {
		// theta: C[x] is a five-bit parity using two one-row XOR3s. D[x] is
		// folded into A[x,y] as XOR3(A[x,y], C[x-1], ROT(C[x+1], 1)).
		for i := 0; i < 5; i++ {
			for z := 0; z < 64; z++ {
				t := xor3R1CS(api, st[i][z], st[i+5][z], st[i+10][z])
				bc[i][z] = xor3R1CS(api, t, st[i+15][z], st[i+20][z])
			}
		}
		for i := 0; i < 5; i++ {
			rot := lrot(bc[(i+1)%5], 1)
			for z := 0; z < 64; z++ {
				for j := 0; j < 25; j += 5 {
					st[j+i][z] = xor3R1CS(api, st[j+i][z], bc[(i+4)%5][z], rot[z])
				}
			}
		}

		// rho pi
		t := st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc0 := st[j]
			st[j] = lrot(t, rotc[i])
			t = bc0
		}

		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				for z := 0; z < 64; z++ {
					st[j+i][z] = chiR1CS(api, bc[i][z], bc[(i+1)%5][z], bc[(i+2)%5][z])
				}
			}
		}

		// iota
		for z := 0; z < 64; z++ {
			if (rc[r]>>z)&1 == 1 {
				st[0][z] = api.Sub(1, st[0][z])
				api.Compiler().MarkBoolean(st[0][z])
			}
		}
	}
	return st
}

func xor(api frontend.API, xs ...frontend.Variable) frontend.Variable {
	ret := xs[0]
	for _, x := range xs[1:] {
		ret = api.Xor(ret, x)
	}
	return ret
}

func andNot(api frontend.API, b, c frontend.Variable) frontend.Variable {
	plonkAPI, ok := api.Compiler().(frontend.PlonkAPI)
	if !ok {
		return api.And(api.Xor(b, 1), c)
	}
	// z = (NOT b) AND c = c - bc, with b and c already boolean.
	z := plonkAPI.EvaluatePlonkExpression(b, c, 0, 1, -1, 0)
	api.Compiler().MarkBoolean(z)
	return z
}

func lrot(a [64]frontend.Variable, c int) [64]frontend.Variable {
	var ret [64]frontend.Variable
	for i := range a {
		ret[(i+c)%64] = a[i]
	}
	return ret
}

type r1cBlueprintKey struct{}

func r1cBlueprintID(api frontend.API) constraint.BlueprintID {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("compiler does not implement kvstore.Store")
	}
	if id := kv.GetKeyValue(r1cBlueprintKey{}); id != nil {
		return id.(constraint.BlueprintID)
	}
	id := api.Compiler().AddBlueprint(&constraint.BlueprintGenericR1C{})
	kv.SetKeyValue(r1cBlueprintKey{}, id)
	return id
}

func addR1C(api frontend.API, left, right, output frontend.Variable) {
	l, ok := api.Compiler().ToCanonicalVariable(left).(constraint.LinearExpression)
	if !ok {
		panic("expected R1CS linear expression")
	}
	r, ok := api.Compiler().ToCanonicalVariable(right).(constraint.LinearExpression)
	if !ok {
		panic("expected R1CS linear expression")
	}
	o, ok := api.Compiler().ToCanonicalVariable(output).(constraint.LinearExpression)
	if !ok {
		panic("expected R1CS linear expression")
	}

	r1c := constraint.R1C{L: l, R: r, O: o}
	var blueprint constraint.BlueprintGenericR1C
	calldata := make([]uint32, 0)
	blueprint.CompressR1C(&r1c, &calldata)
	api.Compiler().AddInstruction(r1cBlueprintID(api), calldata)
}

func xor3R1CS(api frontend.API, a, b, c frontend.Variable) frontend.Variable {
	out, err := api.Compiler().NewHint(xor3Hint, 1, a, b, c)
	if err != nil {
		panic(err)
	}
	z := out[0]
	// For boolean a,b,c and char > 3, the multiplier is never zero and this
	// row uniquely pins z = a XOR b XOR c.
	left := api.Add(z, api.Mul(2, a), api.Mul(2, b), api.Mul(7, c))
	right := api.Add(a, b, api.Mul(-4, c), 1)
	output := api.Add(api.Mul(6, a), api.Mul(6, b), api.Mul(-24, c))
	addR1C(api, left, right, output)
	api.Compiler().MarkBoolean(z)
	return z
}

func chiR1CS(api frontend.API, a, b, c frontend.Variable) frontend.Variable {
	out, err := api.Compiler().NewHint(chiHint, 1, a, b, c)
	if err != nil {
		panic(err)
	}
	z := out[0]
	// For boolean a,b,c and char > 3, the multiplier is never zero and this
	// row uniquely pins z = a XOR ((NOT b) AND c).
	left := api.Add(z, api.Mul(3, a), api.Neg(b), api.Neg(c))
	right := api.Add(api.Mul(4, a), b, c, -3)
	output := api.Add(api.Mul(4, a), api.Mul(2, b))
	addR1C(api, left, right, output)
	api.Compiler().MarkBoolean(z)
	return z
}

func xor3Hint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || len(outputs) != 1 {
		return errors.New("expecting three inputs and one output")
	}
	outputs[0].SetUint64(uint64(inputs[0].Bit(0) ^ inputs[1].Bit(0) ^ inputs[2].Bit(0)))
	return nil
}

func chiHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || len(outputs) != 1 {
		return errors.New("expecting three inputs and one output")
	}
	a := inputs[0].Bit(0)
	b := inputs[1].Bit(0)
	c := inputs[2].Bit(0)
	outputs[0].SetUint64(uint64(a ^ ((1 ^ b) & c)))
	return nil
}
