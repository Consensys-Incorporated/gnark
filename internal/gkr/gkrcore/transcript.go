package gkrcore

import "github.com/consensys/gnark-crypto/hash"

// Transcript is a Fiat-Shamir transcript over the elements of E. Absorb writes field elements;
// Squeeze derives challenges from them.
type Transcript[E any] interface {
	Absorb(elements ...E)
	Squeeze(elements ...E) E
}

// NativeTranscript is a Fiat-Shamir transcript backed by a running hasher of the field's elements.
// The hasher is never reset — all previous data is implicitly part of future challenges.
type NativeTranscript[E any] struct {
	h        hash.FieldHasher[E, E]
	absorbed bool // whether Absorb was called since the last Squeeze
}

// NewNativeTranscript returns a transcript backed by h.
func NewNativeTranscript[E any](h hash.FieldHasher[E, E]) *NativeTranscript[E] {
	return &NativeTranscript[E]{h: h}
}

// Absorb writes field elements to the transcript, to be part of the next squeeze.
func (t *NativeTranscript[E]) Absorb(elements ...E) {
	if len(elements) == 0 {
		return
	}
	t.h.WriteElements(elements...)
	t.absorbed = true
}

// Squeeze absorbs elements as Absorb would, then derives a challenge from the hasher's state.
// If nothing was absorbed since the last squeeze, the zero element is written first to advance
// the state and prevent repeated values.
func (t *NativeTranscript[E]) Squeeze(elements ...E) E {
	t.Absorb(elements...)
	if !t.absorbed {
		var zero E
		t.h.WriteElements(zero)
	}
	t.absorbed = false
	t.h.PadBlock()
	return t.h.SumDigest()
}

// ExtensionTranscript is a Fiat-Shamir transcript over an extension E of a field F, backed by a
// running hasher of F. An element is written as its coordinates, and a challenge is made of the
// first coordinates of the hasher's digest. Absorb and Squeeze are otherwise those of
// NativeTranscript.
type ExtensionTranscript[E interface{ AppendBase([]F) []F }, PE interface {
	*E
	SetBase([]F) *E
}, F any, D hash.ArrayBlock[F]] struct {
	h        hash.FieldHasher[F, D]
	degree   int  // the number of coordinates of an element of E
	buf      []F  // the coordinates being written or read
	absorbed bool // whether Absorb was called since the last Squeeze
}

// NewExtensionTranscript returns a transcript backed by h. It panics if a digest of h has fewer
// elements than E has coordinates.
func NewExtensionTranscript[E interface{ AppendBase([]F) []F }, PE interface {
	*E
	SetBase([]F) *E
}, F any, D hash.ArrayBlock[F]](h hash.FieldHasher[F, D]) *ExtensionTranscript[E, PE, F, D] {
	var zero E
	var d D
	degree := len(zero.AppendBase(nil))
	if len(d) < degree {
		panic("the digest is shorter than an element")
	}
	return &ExtensionTranscript[E, PE, F, D]{h: h, degree: degree, buf: make([]F, 0, degree)}
}

func (t *ExtensionTranscript[E, PE, F, D]) write(e E) {
	t.buf = e.AppendBase(t.buf[:0])
	t.h.WriteElements(t.buf...)
}

// Absorb writes field elements to the transcript, to be part of the next squeeze.
func (t *ExtensionTranscript[E, PE, F, D]) Absorb(elements ...E) {
	if len(elements) == 0 {
		return
	}
	for _, e := range elements {
		t.write(e)
	}
	t.absorbed = true
}

// Squeeze absorbs elements as Absorb would, then derives a challenge from the hasher's state.
// If nothing was absorbed since the last squeeze, the zero element is written first to advance
// the state and prevent repeated values.
func (t *ExtensionTranscript[E, PE, F, D]) Squeeze(elements ...E) E {
	t.Absorb(elements...)
	if !t.absorbed {
		var zero E
		t.write(zero)
	}
	t.absorbed = false
	t.h.PadBlock()
	d := t.h.SumDigest()
	t.buf = t.buf[:t.degree]
	for i := range t.buf {
		t.buf[i] = d[i]
	}
	var res E
	return *PE(&res).SetBase(t.buf)
}
