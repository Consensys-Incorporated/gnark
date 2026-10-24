package gkrcore

import "github.com/consensys/gnark-crypto/hash"

// HashTranscript is a Fiat-Shamir transcript backed by a running field hasher. Absorb writes field
// elements; Squeeze derives challenges from them. The hasher is never reset — all previous data is
// implicitly part of future challenges.
type HashTranscript[E any] struct {
	h        hash.FieldHasher[E, E]
	absorbed bool // whether Absorb was called since the last Squeeze
}

// NewHashTranscript returns a transcript backed by h.
func NewHashTranscript[E any](h hash.FieldHasher[E, E]) *HashTranscript[E] {
	return &HashTranscript[E]{h: h}
}

// Absorb writes field elements to the transcript, to be part of the next squeeze.
func (t *HashTranscript[E]) Absorb(elements ...E) {
	if len(elements) == 0 {
		return
	}
	t.h.WriteField(elements...)
	t.absorbed = true
}

// Squeeze absorbs elements as Absorb would, then derives a challenge from the hasher's state.
// If nothing was absorbed since the last squeeze, the zero element is written first to advance
// the state and prevent repeated values.
func (t *HashTranscript[E]) Squeeze(elements ...E) E {
	t.Absorb(elements...)
	if !t.absorbed {
		var zero E
		t.h.WriteField(zero)
	}
	t.absorbed = false
	t.h.PadBlock()
	return t.h.SumField()
}
