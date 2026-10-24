package gkrcore

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	extensionsHash "github.com/consensys/gnark-crypto/field/koalabear/extensions/hash"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/stretchr/testify/assert"
)

// TestHashTranscriptBindsWholeElement checks that every coordinate of an absorbed extension
// element affects the next challenge.
func TestHashTranscriptBindsWholeElement(t *testing.T) {
	var element extensions.E6
	element.MustSetRandom()

	var one koalabear.Element
	one.SetOne()

	coordinates := func(e *extensions.E6) []*koalabear.Element {
		return []*koalabear.Element{&e.B0.A0, &e.B0.A1, &e.B1.A0, &e.B1.A1, &e.B2.A0, &e.B2.A1}
	}

	challenge := func(e extensions.E6) extensions.E6 {
		transcript := NewHashTranscript[extensions.E6](extensionsHash.NewBaseFieldHashAdapterE6(poseidon2.NewMerkleDamgardHasher()))
		transcript.Absorb(e)
		return transcript.Squeeze()
	}

	reference := challenge(element)
	for i := range coordinates(&element) {
		modified := element
		c := coordinates(&modified)[i]
		c.Add(c, &one)
		assert.NotEqual(t, reference, challenge(modified), "coordinate %d does not affect the challenge", i)
	}
}
