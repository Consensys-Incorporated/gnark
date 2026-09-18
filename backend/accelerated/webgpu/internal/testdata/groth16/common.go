package groth16

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type MulAddChainCircuit struct {
	X           frontend.Variable
	Y           frontend.Variable
	Out         frontend.Variable `gnark:",public"`
	Steps       int               `gnark:"-"`
	Commitments int               `gnark:"-"`
}

func (c *MulAddChainCircuit) Define(api frontend.API) error {
	acc := c.X
	quarter := c.Steps / 4
	var commit0, commit1 []frontend.Variable
	if c.Commitments >= 1 {
		commit0 = make([]frontend.Variable, 0, quarter)
	}
	if c.Commitments >= 2 {
		commit1 = make([]frontend.Variable, 0, quarter)
	}
	for i := 0; i < c.Steps; i++ {
		acc = api.Add(api.Mul(acc, c.Y), 1)
		switch {
		case c.Commitments >= 1 && i < quarter:
			commit0 = append(commit0, acc)
		case c.Commitments >= 2 && i >= quarter && i < 2*quarter:
			commit1 = append(commit1, acc)
		}
	}
	switch c.Commitments {
	case 0:
	case 1:
		if err := commitValues(api, commit0); err != nil {
			return err
		}
	case 2:
		if err := commitValues(api, commit0); err != nil {
			return err
		}
		if err := commitValues(api, commit1); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported commitment count %d", c.Commitments)
	}
	api.AssertIsEqual(acc, c.Out)
	return nil
}

func commitValues(api frontend.API, values []frontend.Variable) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("frontend does not support commitments")
	}
	commitment, err := committer.Commit(values...)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

func ComputeOutput(field *big.Int, x uint64, y uint64, depth int) *big.Int {
	acc := new(big.Int).SetUint64(x)
	mul := new(big.Int).SetUint64(y)
	one := big.NewInt(1)

	for i := 0; i < depth; i++ {
		acc.Mul(acc, mul)
		acc.Mod(acc, field)
		acc.Add(acc, one)
		acc.Mod(acc, field)
	}

	return acc
}
