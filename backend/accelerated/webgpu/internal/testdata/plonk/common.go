package plonk

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

func TargetConstraints(sizeLog int) int {
	return 1 << sizeLog
}

func ChainStepsForTarget(sizeLog, commitments int) int {
	limit := TargetConstraints(sizeLog) - 4
	if limit <= 0 {
		return 1
	}
	if commitments < 0 {
		commitments = 0
	}
	if commitments > 2 {
		commitments = 2
	}

	steps := 4
	for {
		next := steps + 4
		if estimatedConstraints(next, commitments) > limit {
			return steps
		}
		steps = next
	}
}

func estimatedConstraints(steps, commitments int) int {
	// Each chain step is four PLONK operations: mul, add, add, add-constant.
	// Each commitment adds one commitment operation over a quarter of the chain,
	// plus the small verifier challenge plumbing emitted by gnark.
	return 4*steps + commitments*(steps/4+2)
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
		product := api.Mul(acc, c.Y)
		sum := api.Add(product, acc)
		sum = api.Add(sum, c.X)
		acc = api.Add(sum, 1)
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
	xValue := new(big.Int).SetUint64(x)
	one := big.NewInt(1)

	for i := 0; i < depth; i++ {
		product := new(big.Int).Mul(acc, mul)
		acc.Add(product, acc)
		acc.Add(acc, xValue)
		acc.Add(acc, one)
		acc.Mod(acc, field)
	}

	return acc
}
