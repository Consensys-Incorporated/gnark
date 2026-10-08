package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/mamabear"
	poseidonmamabear "github.com/consensys/gnark-crypto/field/mamabear/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

type mamabearPermutationCircuit struct {
	In  []frontend.Variable
	Out []frontend.Variable
}

func (c *mamabearPermutationCircuit) Define(api frontend.API) error {
	p, err := NewPoseidon2(api)
	if err != nil {
		return err
	}
	if err := p.Permutation(c.In); err != nil {
		return err
	}
	for i := range c.In {
		api.AssertIsEqual(c.In[i], c.Out[i])
	}
	return nil
}

// TestMamabearMatchesNative is what pins the in-circuit parameters: the
// diagonal is derived from its definition here rather than shared with
// gnark-crypto, so the only thing establishing that the two agree is running
// the whole permutation both ways on the same input.
func TestMamabearMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)

	params := poseidonmamabear.GetDefaultParameters()
	width := params.Width
	perm := poseidonmamabear.NewPermutation(width, params.NbFullRounds, params.NbPartialRounds)

	state := make([]mamabear.Element, width)
	for i := range state {
		state[i].SetUint64(uint64(i*7 + 1))
	}
	expected := make([]mamabear.Element, width)
	copy(expected, state)
	require.NoError(t, perm.Permutation(expected))

	in := make([]frontend.Variable, width)
	out := make([]frontend.Variable, width)
	for i := range state {
		in[i] = state[i]
		out[i] = expected[i]
	}

	err := test.IsSolved(
		&mamabearPermutationCircuit{In: make([]frontend.Variable, width), Out: make([]frontend.Variable, width)},
		&mamabearPermutationCircuit{In: in, Out: out},
		mamabear.Modulus())
	assert.NoError(err)
}

// TestMamabearParameters checks the shape of what we hand the gadget.
func TestMamabearParameters(t *testing.T) {
	p, err := mamabearParameters()
	require.NoError(t, err)
	require.Equal(t, 16, p.Width)
	require.Equal(t, 3, p.DegreeSBox)
	// Round numbers follow Eq. (1) of the Poseidon2 paper for n = 49, t = 16,
	// d = 3 at kappa = 128: R_F = 8, R_P = ceil(1.075 * 29) = 32. They are NOT
	// koalabear's 6/21 -- the bound grows with min{kappa, log2(p)}, so a wider
	// field needs more rounds. See the gnark-crypto parameters this reads.
	require.Equal(t, 8, p.NbFullRounds)
	require.Equal(t, 32, p.NbPartialRounds)
	require.Len(t, p.DiagM1, p.Width)
	require.Len(t, p.RoundKeys, p.NbFullRounds+p.NbPartialRounds)

	// every diagonal entry must be a non-zero residue: a zero would collapse a
	// state element onto the row sum
	for i, d := range p.DiagM1 {
		require.NotEqual(t, 0, d.Sign(), "DiagM1[%d] is zero", i)
		require.Less(t, d.Cmp(mamabear.Modulus()), 0, "DiagM1[%d] is not reduced", i)
	}
}

// TestGetDefaultParametersForFieldUnsupported checks the error path rather than
// a panic for a field we do not have parameters for.
func TestGetDefaultParametersForFieldUnsupported(t *testing.T) {
	_, err := GetDefaultParametersForField(mamabear.Modulus())
	require.NoError(t, err, "mamabear should be supported")

	// tinyfield has no poseidon2 parameters
	_, err = GetDefaultParametersForField(mamabear.Modulus().Add(mamabear.Modulus(), mamabear.Modulus()))
	require.Error(t, err)
}

type mamabearPermOnlyCircuit struct {
	In []frontend.Variable
}

func (c *mamabearPermOnlyCircuit) Define(api frontend.API) error {
	p, err := NewPoseidon2(api)
	if err != nil {
		return err
	}
	return p.Permutation(c.In)
}

// TestMamabearConstraintCount pins the in-circuit cost. Every R1CS constraint is
// an S-box multiplication -- the external and internal layers are linear, and
// multiplication by the diagonal constants folds into linear combinations -- so
// the count is exactly 2 muls per S-box (degree 3) times the number of S-boxes:
// width per full round, one per partial round.
func TestMamabearConstraintCount(t *testing.T) {
	p, err := mamabearParameters()
	require.NoError(t, err)

	ccs, err := frontend.Compile(mamabear.Modulus(), r1cs.NewBuilder,
		&mamabearPermOnlyCircuit{In: make([]frontend.Variable, p.Width)})
	require.NoError(t, err)

	nbSBoxes := p.NbFullRounds*p.Width + p.NbPartialRounds
	require.Equal(t, 2*nbSBoxes, ccs.GetNbConstraints(),
		"expected one constraint per S-box multiplication")
}
