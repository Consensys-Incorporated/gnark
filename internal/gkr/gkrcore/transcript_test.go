package gkrcore

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	gcHash "github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/hash/all" // registers POSEIDON2_KOALABEAR
	"github.com/stretchr/testify/assert"
)

// TestHashTranscriptBindsWholeElement checks that every coordinate of a bound extension element
// affects the next challenge.
func TestHashTranscriptBindsWholeElement(t *testing.T) {
	var element extensions.E6
	element.MustSetRandom()

	var one koalabear.Element
	one.SetOne()

	coordinates := func(e *extensions.E6) []*koalabear.Element {
		return []*koalabear.Element{&e.B0.A0, &e.B0.A1, &e.B1.A0, &e.B1.A1, &e.B2.A0, &e.B2.A1}
	}

	challenge := func(e extensions.E6) extensions.E6 {
		transcript := NewHashTranscript[extensions.E6](gcHash.POSEIDON2_KOALABEAR.New())
		transcript.Bind(e)
		return transcript.Challenge()
	}

	reference := challenge(element)
	for i := range coordinates(&element) {
		modified := element
		c := coordinates(&modified)[i]
		c.Add(c, &one)
		assert.NotEqual(t, reference, challenge(modified), "coordinate %d does not affect the challenge", i)
	}
}
