// package widecommitter provides mocked implementation of the widecommitter interface
package widecommitter

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"golang.org/x/crypto/sha3"
)

// wrappedBuilder mimics the behaviour of the backend which has wide commitment
// and rangechecker capabilities. We don't have these in gnark yet, but we
// in principle allow other backends to implement them.
type wrappedBuilder[E constraint.Element] struct {
	frontend.Builder[E]
}

// From creates a new builder that implements [frontend.WideCommitter] and [frontend.Rangechecker].
// It wraps the given builder and implements the required methods. This is useful for testing
// circuit solvability and compilation without needing to implement the full functionality of the backend.
//
// NB! The [Check] method is a no-op and does not perform any checks. The [WideCommit] method does not
// perform any checks in the proof system, returning pseudo-random values instead.
func From[E constraint.Element](newBuilder frontend.NewBuilderGeneric[E]) frontend.NewBuilderGeneric[E] {
	return func(field *big.Int, config frontend.CompileConfig) (frontend.Builder[E], error) {
		b, err := newBuilder(field, config)
		if err != nil {
			return nil, err
		}
		log := logger.Logger()
		log.Warn().Msg("using fake wide committer, no checks will be performed. Use only for testing")
		return &wrappedBuilder[E]{b}, nil
	}
}

func (w *wrappedBuilder[E]) WideCommit(width int, toCommit ...frontend.Variable) (commitment []frontend.Variable, err error) {
	res, err := w.NewHint(mockedWideCommitHint, width, toCommit...)
	return res, err
}

func (w *wrappedBuilder[E]) Check(in frontend.Variable, width int) {
	_, err := w.NewHint(mockedRangecheckHint, 1, width, in)
	if err != nil {
		panic(fmt.Sprintf("failed to check range: %v", err))
	}
}

func mockedWideCommitHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nb := (m.BitLen() + 7) / 8
	buf := make([]byte, nb)
	hasher := sha3.NewCShake128(nil, []byte("gnark test engine"))
	for _, in := range inputs {
		bs := in.FillBytes(buf)
		hasher.Write(bs)
	}
	for i := range len(outputs) {
		hasher.Read(buf)
		outputs[i].SetBytes(buf)
		outputs[i].Mod(outputs[i], m)
	}
	return nil
}

func mockedRangecheckHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// this mocked range check hint errors in case the input is not in the range.
	// it doesn't enforce in the proof system, but it is useful for testing and checking
	// consistency with the test engine
	if len(inputs) != 2 {
		return fmt.Errorf("expected 2 inputs, got %d", len(inputs))
	}
	width := inputs[0].Int64()
	val := inputs[1]
	if val.BitLen() > int(width) {
		return fmt.Errorf("value %s is not less than %d bits", val, width)
	}
	return nil
}

func init() {
	solver.RegisterHint(mockedWideCommitHint, mockedRangecheckHint)
}
