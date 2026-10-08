package gkrcore

import "hash"

// HashTranscript is a Fiat-Shamir transcript backed by a running hash. Field elements are written
// via Absorb; challenges are derived via Squeeze. The hash is never reset — all previous data is
// implicitly part of future challenges. Absorb only buffers the elements; Squeeze writes everything
// absorbed since the last challenge to the hash in a single write.
type HashTranscript[E any, PE interface {
	*E
	SetBytesCanonical([]byte) error
	Marshal() []byte
}] struct {
	h      hash.Hash
	size   int    // length of an element's Marshal(), computed once from the zero element
	buffer []byte // the elements absorbed since the last Squeeze, as their Marshal() concatenated
}

// NewHashTranscript returns a transcript backed by h. Absorb buffers its elements' Marshal().
// Squeeze writes the buffer to h in a single write, or a separator byte if nothing was absorbed
// since the last challenge, then returns the element set by SetBytesCanonical from the first
// len(Marshal()) bytes of h.Sum(nil).
// h.Size() must be at least len(Marshal()).
func NewHashTranscript[E any, PE interface {
	*E
	SetBytesCanonical([]byte) error
	Marshal() []byte
}](h hash.Hash) *HashTranscript[E, PE] {
	var zero E
	return &HashTranscript[E, PE]{h: h, size: len(PE(&zero).Marshal())}
}

// Absorb adds field elements to the transcript, for the next challenge to depend on.
func (t *HashTranscript[E, PE]) Absorb(elements ...E) {
	for i := range elements {
		t.buffer = append(t.buffer, PE(&elements[i]).Marshal()...)
	}
}

// Squeeze absorbs elements as Absorb would, then squeezes a challenge from the current hash state.
// If nothing was absorbed since the last challenge, a separator byte is written to
// advance the state and prevent repeated values. It panics if the digest prefix is not a canonical
// encoding of an element, which a hash producing field elements never yields.
func (t *HashTranscript[E, PE]) Squeeze(elements ...E) E {
	t.Absorb(elements...)
	if len(t.buffer) == 0 {
		t.buffer = append(t.buffer, 0) // separator
	}
	t.h.Write(t.buffer)
	t.buffer = t.buffer[:0]
	var res E
	if err := PE(&res).SetBytesCanonical(t.h.Sum(nil)[:t.size]); err != nil {
		panic(err)
	}
	return res
}
