package expand

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// ExpandMsgXmd implements the expand_message_xmd function from [RFC9380 Section
// 5.3.1]. It is hardcoded to use SHA2-256 as the hash function (but can be made
// optionally configurable in the future).
//
// It expand a message `msg` with a fixed domain separation tag `dst` to a slice
// of length `lenInBytes`.
//
// For gnark-crypto implementation see [gnark-crypto].
//
// [RFC9380 Section 5.3.1]: https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd
// [gnark-crypto]: https://github.com/consensys/gnark-crypto/blob/master/field/hash/hashutils.go#L11
func ExpandMsgXmd(api frontend.API, msg []uints.U8, dst []byte, lenInBytes int) ([]uints.U8, error) {
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("new uints.Bytes: %w", err)
	}
	h, err := sha2.New(api)
	if err != nil {
		return nil, fmt.Errorf("new hasher: %w", err)
	}

	ell := (lenInBytes + h.Size() - 1) / h.Size() // ceil(len_in_bytes / b_in_bytes)
	if ell > 255 {
		return nil, errors.New("invalid lenInBytes")
	}
	if len(dst) > 255 {
		return nil, errors.New("invalid domain size (>255 bytes)")
	}
	sizeDomain := uint8(len(dst))

	// Z_pad = I2OSP(0, r_in_bytes)
	Z_pad := uints.NewU8Array(make([]uint8, h.BlockSize()))
	// l_i_b_str = I2OSP(len_in_bytes, 2)
	l_i_b_str := uints.NewU8Array([]uint8{
		uint8(lenInBytes >> 8),
		uint8(lenInBytes),
	})
	// DST_prime = DST ∥ I2OSP(len(DST), 1)
	DST_prime := uints.NewU8Array(append(dst, sizeDomain))
	// b₀ = H(Z_pad ∥ msg ∥ l_i_b_str ∥ I2OSP(0, 1) ∥ DST_prime)
	h.Write(Z_pad)
	h.Write(msg)
	h.Write(l_i_b_str)
	h.Write([]uints.U8{uints.NewU8(0)})
	h.Write(DST_prime)
	b0 := h.Sum()

	h, err = sha2.New(api)
	if err != nil {
		return nil, fmt.Errorf("new hasher for b1: %w", err)
	}
	// b₁ = H(b₀ ∥ I2OSP(1, 1) ∥ DST_prime)
	h.Write(b0)
	h.Write([]uints.U8{uints.NewU8(1)})
	h.Write(DST_prime)
	b1 := h.Sum()

	res := make([]uints.U8, lenInBytes)
	copy(res, b1)

	for i := 2; i <= ell; i++ {
		h, err = sha2.New(api)
		if err != nil {
			return nil, fmt.Errorf("new hasher for b%d: %w", i, err)
		}

		// b_i = H(strxor(b₀, b_(i - 1)) ∥ I2OSP(i, 1) ∥ DST_prime)
		strxor := make([]uints.U8, h.Size())
		for j := 0; j < h.Size(); j++ {
			strxor[j] = uapi.Xor(b0[j], b1[j])
		}
		h.Write(strxor)
		h.Write([]uints.U8{uints.NewU8(uint8(i))})
		h.Write(DST_prime)
		b1 = h.Sum()
		copy(res[h.Size()*(i-1):min(h.Size()*i, len(res))], b1)
	}

	return res, nil
}
