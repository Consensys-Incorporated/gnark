package gkrcore_test

import (
	"bytes"
	"hash"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	gcHash "github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/hash/all" // registers POSEIDON2_KOALABEAR
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/stretchr/testify/assert"
)

// recordingHash is a hash.Hash that records its writes.
type recordingHash struct {
	hash.Hash
	writes [][]byte
}

func (h *recordingHash) Write(p []byte) (int, error) {
	h.writes = append(h.writes, bytes.Clone(p))
	return h.Hash.Write(p)
}

// TestHashTranscriptWritesOncePerSqueeze checks that the elements absorbed between two challenges
// reach the hash in a single write, at the squeeze, holding their Marshal() in order.
func TestHashTranscriptWritesOncePerSqueeze(t *testing.T) {
	elements := make([]extensions.E6, 3)
	var expected []byte
	for i := range elements {
		elements[i].MustSetRandom()
		expected = append(expected, elements[i].Marshal()...)
	}

	h := &recordingHash{Hash: gcHash.POSEIDON2_KOALABEAR.New()}
	transcript := gkrcore.NewHashTranscript[extensions.E6](h)

	transcript.Absorb(elements[:2]...)
	transcript.Absorb()
	transcript.Absorb(elements[2:]...)
	assert.Empty(t, h.writes, "Absorb does not write to the hash")

	transcript.Squeeze()
	assert.Equal(t, [][]byte{expected}, h.writes)

	transcript.Squeeze()
	assert.Equal(t, [][]byte{expected, {0}}, h.writes, "a squeeze with nothing absorbed writes the separator")
}

// TestHashTranscriptBindsWholeElement checks that every coordinate of an absorbed extension element
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
		transcript := gkrcore.NewHashTranscript[extensions.E6](gcHash.POSEIDON2_KOALABEAR.New())
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
