package gkr_mimc

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi"
	"github.com/consensys/gnark/std/hash"
)

// compressor implements a compression function by applying
// the Miyaguchi–Preneel transformation to the MiMC encryption function.
type compressor struct {
	gkrCircuit    *gkrapi.Circuit
	in0, in1, out gkr.Variable
}

func (c *compressor) Compress(x frontend.Variable, y frontend.Variable) frontend.Variable {
	res, err := c.gkrCircuit.AddInstance(map[gkr.Variable]frontend.Variable{c.in0: x, c.in1: y})
	if err != nil {
		panic(err)
	}
	return res[c.out]
}

func NewCompressor(api frontend.API) (hash.Compressor, error) {

	store, ok := api.Compiler().(kvstore.Store)
	if !ok {
		return nil, fmt.Errorf("api of type %T does not implement kvstore.Store", api)
	}

	cached := store.GetKeyValue(gkrMiMCKey{})
	if cached != nil {
		if compressor, ok := cached.(*compressor); ok {
			return compressor, nil
		}
		return nil, fmt.Errorf("cached value is of type %T, not a compressor", cached)
	}

	gkrApi, err := gkrapi.New(api)
	if err != nil {
		return nil, err
	}

	in0 := gkrApi.NewInput()
	in1 := gkrApi.NewInput()

	y := in1

	curve := utils.FieldToCurve(api.Compiler().Field())
	constants, deg, err := getConstants(curve)
	if err != nil {
		return nil, err
	}

	// Select sBox functions based on degree
	var lastLayerSBox, nonLastLayerSBox func(*big.Int) gkr.GateFunction
	switch deg {
	case 5:
		lastLayerSBox = addPow5Add
		nonLastLayerSBox = addPow5
	case 7:
		lastLayerSBox = addPow7Add
		nonLastLayerSBox = addPow7
	case 17:
		lastLayerSBox = addPow17Add
		nonLastLayerSBox = addPow17
	default:
		return nil, fmt.Errorf("s-Box of degree %d not supported", deg)
	}

	for i := range len(constants) - 1 {
		y = gkrApi.Gate(nonLastLayerSBox(&constants[i]), in0, y)
	}

	y = gkrApi.Gate(lastLayerSBox(&constants[len(constants)-1]), in0, y, in1)

	gkrCircuit, err := gkrApi.Compile("POSEIDON2")
	if err != nil {
		return nil, err
	}

	res :=
		&compressor{
			gkrCircuit: gkrCircuit,
			in0:        in0,
			in1:        in1,
			out:        y,
		}

	store.SetKeyValue(gkrMiMCKey{}, res)
	return res, nil
}

// Deprecated: Gate registration now happens automatically via api.Gate().
func RegisterGates(curves ...ecc.ID) error {
	return nil
}

// getConstants returns the parameters for the MiMC encryption function for the given curve.
// It also returns the degree of the s-Box
func getConstants(curve ecc.ID) ([]big.Int, int, error) {
	switch curve {
	case ecc.BN254:
		return bn254.GetConstants(), 5, nil
	case ecc.BLS12_381:
		return bls12381.GetConstants(), 5, nil
	case ecc.BLS12_377:
		return bls12377.GetConstants(), 17, nil
	case ecc.BW6_761:
		return bw6761.GetConstants(), 5, nil
	default:
		return nil, -1, fmt.Errorf("unsupported curve ID: %s", curve)
	}
}

func addPow5(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 2 {
			panic("expected two input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		return api.Mul(t, t, s)
	}
}

// addPow5Add: (in[0]+in[1]+key)⁵ + 2*in[0] + in[2]
func addPow5Add(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 3 {
			panic("expected three input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		t = api.Mul(t, t, s)

		return api.Add(t, in[0], in[0], in[2])
	}
}

func addPow7(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 2 {
			panic("expected two input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		return api.Mul(t, t, t, s) // s⁶ × s
	}
}

// addPow7Add: (in[0]+in[1]+key)⁷ + 2*in[0] + in[2]
func addPow7Add(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 3 {
			panic("expected three input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		return api.Add(api.Mul(t, t, t, s), in[0], in[0], in[2]) // s⁶ × s + 2*in[0] + in[2]
	}
}

// addPow17: (in[0]+in[1]+key)¹⁷
func addPow17(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 2 {
			panic("expected two input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)   // s²
		t = api.Mul(t, t)    // s⁴
		t = api.Mul(t, t)    // s⁸
		t = api.Mul(t, t)    // s¹⁶
		return api.Mul(t, s) // s¹⁶ × s
	}
}

// addPow17Add: (in[0]+in[1]+key)¹⁷ + in[0] + in[2]
func addPow17Add(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 3 {
			panic("expected three input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)                                 // s²
		t = api.Mul(t, t)                                  // s⁴
		t = api.Mul(t, t)                                  // s⁸
		t = api.Mul(t, t)                                  // s¹⁶
		return api.Add(api.Mul(t, s), in[0], in[0], in[2]) // s¹⁶ × s + 2*in[0] + in[2]
	}
}

type gkrMiMCKey struct{}
