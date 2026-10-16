package gkrcore

import "hash"

// HashTranscript is a Fiat-Shamir transcript backed by a running hash. Field elements are written
// via Bind; challenges are derived via Challenge. The hash is never reset — all previous data is
// implicitly part of future challenges.
type HashTranscript[E any, PE interface {
	*E
	SetBytesCanonical([]byte) error
	Marshal() []byte
}] struct {
	h     hash.Hash
	size  int  // length of an element's Marshal(), computed once from the zero element
	bound bool // whether Bind was called since the last Challenge
}

// NewHashTranscript returns a transcript backed by h. Bind writes each element's Marshal().
// Challenge writes a separator byte if nothing was bound since the last challenge, then returns
// the element set by SetBytesCanonical from the first len(Marshal()) bytes of h.Sum(nil).
// h.Size() must be at least len(Marshal()).
func NewHashTranscript[E any, PE interface {
	*E
	SetBytesCanonical([]byte) error
	Marshal() []byte
}](h hash.Hash) *HashTranscript[E, PE] {
	var zero E
	return &HashTranscript[E, PE]{h: h, size: len(PE(&zero).Marshal())}
}

// Bind writes field elements to the transcript as bindings for the next challenge.
func (t *HashTranscript[E, PE]) Bind(elements ...E) {
	if len(elements) == 0 {
		return
	}
	for i := range elements {
		t.h.Write(PE(&elements[i]).Marshal())
	}
	t.bound = true
}

// Challenge binds elements as Bind would, then squeezes a challenge from the current hash state.
// If no bindings were added since the last challenge, a separator byte is written first to
// advance the state and prevent repeated values. It panics if the digest prefix is not a canonical
// encoding of an element, which a hash producing field elements never yields.
func (t *HashTranscript[E, PE]) Challenge(elements ...E) E {
	t.Bind(elements...)
	if !t.bound {
		t.h.Write([]byte{0})
	}
	t.bound = false
	var res E
	if err := PE(&res).SetBytesCanonical(t.h.Sum(nil)[:t.size]); err != nil {
		panic(err)
	}
	return res
}
