package gkr_poseidon2

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// extKeyGate applies the external matrix mul, then adds the round key.
// Because of its symmetry, we don't need to define distinct x1 and x2 versions of it
func extKeyGate(roundKey frontend.Variable) gkr.GateFunction {
	return func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		if len(x) != 2 {
			panic("expected 2 inputs")
		}
		return api.Add(api.Mul(x[0], 2), x[1], roundKey)
	}
}

// pow4Gate computes a -> a⁴
func pow4Gate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	y := api.Mul(x[0], x[0])
	y = api.Mul(y, y)

	return y
}

// pow4TimesGate computes a, b -> a⁴ * b
func pow4TimesGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 input")
	}
	y := api.Mul(x[0], x[0])
	y = api.Mul(y, y)

	return api.Mul(y, x[1])
}

// pow3Gate computes a -> a³
func pow3Gate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	return api.Mul(x[0], x[0], x[0])
}

// pow2Gate computes a -> a²
func pow2Gate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	return api.Mul(x[0], x[0])
}

// pow2TimesGate computes a, b -> a² * b
func pow2TimesGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Mul(x[0], x[0], x[1])
}

// for x1, the partial round gates are identical to full round gates
// for x2, the partial round gates are just a linear combination
// TODO @Tabaie try eliminating the x2 partial round gates and have the x1 gates depend on i - rf/2 or so previous x1's

// extGate2 applies the external matrix mul, outputting the second element of the result
func extGate2(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 2), x[0])
}

// intKeyGate2 applies the internal matrix mul, then adds the round key
func intKeyGate2(roundKey frontend.Variable) gkr.GateFunction {
	return func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		if len(x) != 2 {
			panic("expected 2 inputs")
		}
		return api.Add(api.Mul(x[1], 3), x[0], roundKey)
	}
}

// intGate2 applies the internal matrix mul. The round key is zero
func intGate2(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 3), x[0])
}

// extAddGate applies the first row of the external matrix to the first two elements and adds the third
func extAddGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 3 {
		panic("expected 3 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1], x[2])
}

type compressor struct {
	api           frontend.API
	gkrCircuit    *gkrapi.Circuit
	in1, in2, out gkr.Variable
}

// NewCompressor returns an object that can compute the Poseidon2 compression function
// which consists of a permutation along with the input fed forward.
// The correctness of the compression functions is proved using GKR.
func NewCompressor(api frontend.API) (hash.Compressor, error) {
	store, ok := api.Compiler().(kvstore.Store)
	if !ok {
		return nil, fmt.Errorf("api of type %T does not implement kvstore.Store", api)
	}

	cached := store.GetKeyValue(gkrPoseidon2Key{})
	if cached != nil {
		if compressor, ok := cached.(*compressor); ok {
			return compressor, nil
		}
		return nil, fmt.Errorf("cached value is of type %T, not a gkr-poseidon2.Compressor", cached)
	}

	gkrCircuit, in1, in2, out, err := defineCircuit(api)
	if err != nil {
		return nil, fmt.Errorf("failed to define GKR circuit: %w", err)
	}
	res := &compressor{
		api:        api,
		gkrCircuit: gkrCircuit,
		in1:        in1,
		in2:        in2,
		out:        out,
	}
	store.SetKeyValue(gkrPoseidon2Key{}, res)
	return res, nil
}

func (p *compressor) Compress(a, b frontend.Variable) frontend.Variable {
	outs, err := p.gkrCircuit.AddInstance(map[gkr.Variable]frontend.Variable{p.in1: a, p.in2: b})
	if err != nil {
		panic(err)
	}

	return outs[p.out]
}

// defineCircuit defines the GKR circuit for the Poseidon2 permutation over BLS12-377.
// insLeft and insRight are the inputs to the permutation.
// They must be padded to a power of 2
func defineCircuit(api frontend.API) (gkrCircuit *gkrapi.Circuit, in1, in2, out gkr.Variable, err error) {
	// variable indexes
	const (
		xI = iota
		yI
	)

	curve := utils.FieldToCurve(api.Compiler().Field())
	p, err := poseidon2.GetDefaultParameters(curve)
	if err != nil {
		return
	}

	gkrApi, err := gkrapi.New(api)
	if err != nil {
		return
	}

	x := gkrApi.NewInput()
	y := gkrApi.NewInput()

	in1, in2 = x, y // save to feed forward at the end

	// *** shorthands for gate functions ***

	// Poseidon2 is a sequence of additions, exponentiations (s-Box), and linear operations.
	// But here we group the operations so that every round consists of a degree-1 operation followed by the s-Box.
	// This allows for more efficient result sharing among the gates.
	// But also breaks the uniformity of the circuit a bit, in that the matrix operation.
	// In every round comes from the previous (canonical) round.

	// Apply the s-Box to u

	var sBox func(gkr.Variable) gkr.Variable
	switch p.DegreeSBox {
	case 5:
		sBox = func(u gkr.Variable) gkr.Variable {
			v := gkrApi.Gate(pow2Gate, u)           // u²
			return gkrApi.Gate(pow2TimesGate, v, u) // u⁵
		}
	case 7:
		sBox = func(u gkr.Variable) gkr.Variable {
			v := gkrApi.Gate(pow3Gate, u)           // u³
			return gkrApi.Gate(pow2TimesGate, v, u) // u⁷
		}
	case 17:
		sBox = func(u gkr.Variable) gkr.Variable {
			v := gkrApi.Gate(pow4Gate, u)           // u⁴
			return gkrApi.Gate(pow4TimesGate, v, u) // u¹⁷
		}
	default:
		err = fmt.Errorf("unsupported s-Box degree %d", p.DegreeSBox)
		return
	}

	// Apply external matrix multiplication and round key addition.
	// Round-dependent due to the round key
	extKeySBox := func(round, varI int, a, b gkr.Variable) gkr.Variable {
		return sBox(gkrApi.Gate(extKeyGate(&p.RoundKeys[round][varI]), a, b))
	}

	// Apply internal matrix multiplication and round key addition,
	// then apply the s-Box for the second variable
	intKeySBox2 := func(round int, a, b gkr.Variable) gkr.Variable {
		return sBox(gkrApi.Gate(intKeyGate2(&p.RoundKeys[round][1]), a, b))
	}

	// apply a full round
	fullRound := func(i int) {
		x1 := extKeySBox(i, xI, x, y)
		x, y = x1, extKeySBox(i, yI, y, x) // the external matrix is symmetric so we can use the same gate with inputs swapped
	}

	// *** construct the circuit ***

	for i := range p.NbFullRounds / 2 {
		fullRound(i)
	}

	{
		// i = halfRf: first partial round
		// still using the external matrix, since the linear operation still belongs to a full (canonical) round
		x1 := extKeySBox(p.NbFullRounds/2, xI, x, y)

		x, y = x1, gkrApi.Gate(extGate2, x, y)
	}

	for i := p.NbFullRounds/2 + 1; i < p.NbFullRounds/2+p.NbPartialRounds; i++ {
		x1 := extKeySBox(i, xI, x, y) // the first row of the internal matrix is the same as that of the external matrix
		x, y = x1, gkrApi.Gate(intGate2, x, y)
	}

	{
		i := p.NbFullRounds/2 + p.NbPartialRounds
		// The first iteration of the final batch of full rounds.
		// Still using the internal matrix, since the linear operation still belongs to a partial (canonical) round
		x1 := extKeySBox(i, xI, x, y)
		x, y = x1, intKeySBox2(i, x, y)
	}

	for i := p.NbFullRounds/2 + p.NbPartialRounds + 1; i < p.NbPartialRounds+p.NbFullRounds; i++ {
		fullRound(i)
	}

	// apply the external matrix one last time to obtain the final value of y
	out = gkrApi.Gate(extAddGate, y, x, in2)

	gkrCircuit, err = gkrApi.Compile("MIMC")

	return
}

// Deprecated: Gate registration now happens automatically via api.Gate().
func RegisterGates(curves ...ecc.ID) error {
	return nil
}

type gkrPoseidon2Key struct{}
