// Package gkr_poseidon2 builds the GKR circuit of the Poseidon2 compression function over
// KoalaBear, for proving many instances of it at once with gkr/koalabear.
//
// An instance maps (left, right) to the right half of P(left, right), plus right, where P is
// gnark-crypto's Poseidon2 permutation over KoalaBear.
//
// Every linear layer is a level of affine wires, which the prover handles with skip levels, no
// sumcheck being needed; the round constants are folded into these wires. The S-boxes are cube
// gates of one input. The partial rounds keep one wire each, their other coordinates being carried
// symbolically as affine combinations of the wires that precede them. The circuit is compiled for
// KoalaBear's E6 with gkrapi.ConsolidateAll, and Compressor.Schedule is the default schedule that
// gkrapi.Compile produces.
package gkr_poseidon2

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/gkr/gkrapi"
	gkrkoalabear "github.com/consensys/gnark/gkr/koalabear"
)

// Compressor is the GKR circuit of the Poseidon2 compression function over KoalaBear: each
// instance maps (left, right) to the right half of P(left, right), plus right.
type Compressor struct {
	Circuit  gkrapi.Circuit
	Schedule constraint.GkrProvingSchedule
	Left     []gkr.Variable // the first Width/2 input wires
	Right    []gkr.Variable // the last Width/2 input wires
	Out      []gkr.Variable // the Width/2 output wires, exported
}

// NewCompressor builds the circuit for params, e.g. poseidon2.GetDefaultParameters(), compiled for
// KoalaBear's E6 with gkrapi.ConsolidateAll.
func NewCompressor(params *poseidon2.Parameters) (*Compressor, error) {
	if poseidon2.DegreeSBox() != 3 {
		return nil, fmt.Errorf("the S-box has degree %d, only 3 is supported", poseidon2.DegreeSBox())
	}
	if params.Width%4 != 0 {
		return nil, fmt.Errorf("the width %d is not a multiple of 4", params.Width)
	}

	b := builder{
		api:      gkrapi.New(),
		width:    params.Width,
		external: params.ExternalMatrix(),
		internal: params.InternalMatrix(),
	}
	b.build(params)

	circuit, schedule, err := b.api.Compile(gkrapi.KoalaBearE6(), gkrapi.ConsolidateAll)
	if err != nil {
		return nil, err
	}
	return &Compressor{
		Circuit:  circuit,
		Schedule: schedule,
		Left:     b.input[:params.Width/2],
		Right:    b.input[params.Width/2:],
		Out:      b.out,
	}, nil
}

// Assignment returns a WireAssignment with the input columns set, left[i] and right[i] holding
// the i-th element of every instance's left and right halves; Prove computes the rest.
// It panics if the slices' shapes do not match the circuit.
func (c *Compressor) Assignment(left, right [][]koalabear.Element) gkrkoalabear.WireAssignment {
	if len(left) != len(c.Left) || len(right) != len(c.Right) {
		panic(fmt.Sprintf("expected %d columns for each half, got %d and %d", len(c.Left), len(left), len(right)))
	}
	nbInstances := len(left[0])
	assignment := make(gkrkoalabear.WireAssignment, len(c.Circuit))
	for i := range c.Left {
		if len(left[i]) != nbInstances || len(right[i]) != nbInstances {
			panic("the columns do not all have the same length")
		}
		assignment[c.Left[i]] = left[i]
		assignment[c.Right[i]] = right[i]
	}
	return assignment
}

// builder holds the state of the circuit's construction.
type builder struct {
	api      *gkrapi.API
	width    int
	external [][]koalabear.Element
	internal [][]koalabear.Element
	input    []gkr.Variable
	out      []gkr.Variable
}

func (b *builder) build(params *poseidon2.Parameters) {
	t := b.width
	halfFull := params.NbFullRounds / 2
	nbRounds := params.NbFullRounds + params.NbPartialRounds

	for range t {
		b.input = append(b.input, b.api.NewInput())
	}

	// The first full rounds.
	y := b.input
	for r := range halfFull {
		y = b.fullRound(params.RoundKeys[r], b.external, y)
	}

	// The partial rounds. The state is held symbolically: each of its coordinates is an affine
	// combination of the basis, which starts as the wires entering them.
	basis := y
	state := make([][]koalabear.Element, t)
	for i := range state {
		state[i] = make([]koalabear.Element, t)
		state[i][i].SetOne()
	}
	for k := range params.NbPartialRounds {
		matrix := b.internal
		if k == 0 {
			matrix = b.external
		}
		state = apply(matrix, state)

		r := halfFull + k
		linear := b.api.Gate(affineGate(&params.RoundKeys[r][0], state[0]), basis...)
		cube := b.api.Gate(cubeGate, linear)

		basis = append(basis[:len(basis):len(basis)], cube)
		for i := range state {
			state[i] = append(state[i], koalabear.Element{})
		}
		state[0] = make([]koalabear.Element, len(basis))
		state[0][len(basis)-1].SetOne()
	}

	// The first full round after them reads the whole basis.
	state = apply(b.internal, state)
	r := halfFull + params.NbPartialRounds
	linear := make([]gkr.Variable, t)
	for i := range linear {
		linear[i] = b.api.Gate(affineGate(&params.RoundKeys[r][i], state[i]), basis...)
	}
	y = b.cubes(linear)

	// The remaining full rounds.
	for r++; r < nbRounds; r++ {
		y = b.fullRound(params.RoundKeys[r], b.external, y)
	}

	// The outputs: the last external matrix and the feed-forward together.
	for i := range t / 2 {
		row := append(append([]koalabear.Element(nil), b.external[t/2+i]...), koalabear.Element{})
		row[t].SetOne()
		b.out = append(b.out, b.api.Gate(affineGate(nil, row), append(y[:t:t], b.input[t/2+i])...))
	}
	b.api.Export(b.out...)
}

// fullRound returns the cube wires of a full round with the given round keys, whose linear layer
// applies matrix to the wires y.
func (b *builder) fullRound(keys []koalabear.Element, matrix [][]koalabear.Element, y []gkr.Variable) []gkr.Variable {
	linear := make([]gkr.Variable, b.width)
	for i := range linear {
		linear[i] = b.api.Gate(affineGate(&keys[i], matrix[i]), y...)
	}
	return b.cubes(linear)
}

// cubes returns the cubes of the wires. The scheduler batches wires of consecutive indices only,
// so a level's wires are created together.
func (b *builder) cubes(wires []gkr.Variable) []gkr.Variable {
	res := make([]gkr.Variable, len(wires))
	for i := range wires {
		res[i] = b.api.Gate(cubeGate, wires[i])
	}
	return res
}

// apply returns matrix · state, each coordinate of state being a vector of coefficients.
func apply(matrix, state [][]koalabear.Element) [][]koalabear.Element {
	res := make([][]koalabear.Element, len(matrix))
	for i := range res {
		res[i] = make([]koalabear.Element, len(state[0]))
		for j := range state {
			var term koalabear.Element
			for k := range res[i] {
				term.Mul(&matrix[i][j], &state[j][k])
				res[i][k].Add(&res[i][k], &term)
			}
		}
	}
	return res
}

// cubeGate computes x ↦ x³.
func cubeGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	return api.Mul(x[0], x[0], x[0])
}

// affineGate returns the gate function of constant + Σⱼ coefficients[j]·x[j], the constant being
// omitted if nil. Zero coefficients are omitted from the sum, and the sum is padded with zeros up
// to two terms.
func affineGate(constant *koalabear.Element, coefficients []koalabear.Element) gkr.GateFunction {
	coefficients = append([]koalabear.Element(nil), coefficients...)
	var one koalabear.Element
	one.SetOne()
	return func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		var terms []frontend.Variable
		if constant != nil {
			terms = append(terms, constant)
		}
		for j := range coefficients {
			switch {
			case coefficients[j].IsZero():
			case coefficients[j].Equal(&one):
				terms = append(terms, x[j])
			default:
				terms = append(terms, api.Mul(&coefficients[j], x[j]))
			}
		}
		for len(terms) < 2 { // Add takes at least two operands
			terms = append(terms, 0)
		}
		return api.Add(terms[0], terms[1], terms[2:]...)
	}
}
