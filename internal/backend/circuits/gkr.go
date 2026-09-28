package circuits

import (
	"github.com/consensys/gnark"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gkr"
	"github.com/consensys/gnark/std/gkrapi"
	_ "github.com/consensys/gnark/std/hash/all" // register hash functions for GKR
)

type gkrCubeCircuit struct {
	X      []frontend.Variable
	Square []frontend.Variable `gnark:",public"`
	Cube   []frontend.Variable `gnark:",public"`
}

func (c *gkrCubeCircuit) Define(api frontend.API) error {
	gkrApi, err := gkrapi.New(api)
	if err != nil {
		return err
	}
	x := gkrApi.NewInput()
	y := gkrApi.Mul(x, x)
	z := gkrApi.Mul(x, y)

	gkrApi.Export(y)

	gkrCircuit, err := gkrApi.Compile("MIMC")
	if err != nil {
		return err
	}

	for i := range c.X {
		out, err := gkrCircuit.AddInstance(map[gkr.Variable]frontend.Variable{x: c.X[i]})
		if err != nil {
			return err
		}
		api.AssertIsEqual(out[y], c.Square[i])
		api.AssertIsEqual(out[z], c.Cube[i])
	}
	return nil
}

func init() {
	circuit := &gkrCubeCircuit{
		X:      make([]frontend.Variable, 2),
		Square: make([]frontend.Variable, 2),
		Cube:   make([]frontend.Variable, 2),
	}
	good := &gkrCubeCircuit{X: []frontend.Variable{3, 5}, Square: []frontend.Variable{9, 25}, Cube: []frontend.Variable{27, 125}}
	bad := &gkrCubeCircuit{X: []frontend.Variable{3, 5}, Square: []frontend.Variable{9, 25}, Cube: []frontend.Variable{27, 126}}

	addEntry("gkr_cube", circuit, good, bad, gnark.Curves(), withU64Only())
}
