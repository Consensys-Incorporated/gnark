//go:build js && wasm

package bridge

import (
	"errors"
	"math/big"
)

// Key is a proving key prepared on the GPU: the runtime handle of its uploaded
// base vectors and the registry that maps sub-slices of those vectors back to
// their name and offset.
type Key struct {
	Client Client
	Handle string
	bases  BasisRegistry
	g1, g2 map[string][]byte
}

// AddBases records s as the base vector name of group ("g1" or "g2") for the
// next Upload. The bytes of s are sent as is (affine points, Montgomery limbs).
func AddBases[T any](k *Key, group, name string, s []T) {
	m := &k.g1
	if group == "g2" {
		m = &k.g2
	}
	if *m == nil {
		*m = map[string][]byte{}
	}
	(*m)[name] = Bytes(s)
	RegisterSlice(&k.bases, name, s)
}

// Upload initializes the runtime for curve and uploads the recorded bases.
func (k *Key) Upload(curve string) error {
	if k.Handle != "" {
		return nil
	}
	if err := k.Client.Init(curve); err != nil {
		return err
	}
	handle, err := k.Client.PrepareKey(curve, k.g1, k.g2)
	if err != nil {
		return err
	}
	k.Handle, k.g1, k.g2 = handle, nil, nil
	return nil
}

// Release frees the GPU buffers of the key.
func (k *Key) Release() error {
	if k.Handle == "" {
		return nil
	}
	err := k.Client.ReleaseKey(k.Handle)
	k.Handle = ""
	return err
}

// MSM runs Σ scalars[i]·bases[i] on the GPU for a sub-slice of one of the
// key's vectors and returns the packed affine result. scalars are regular
// little-endian and there must be exactly one per base.
func MSM[T any](k *Key, group string, bases []T, scalarsRegularLE []byte) ([]byte, error) {
	if len(bases) == 0 {
		return nil, nil
	}
	name, start, ok := ResolveSlice(&k.bases, bases)
	if !ok {
		return nil, errors.New(k.Client.ErrorPrefix + ": bases are not part of the proving key")
	}
	if group == "g2" {
		return k.Client.MSMG2(k.Handle, name, start, scalarsRegularLE)
	}
	return k.Client.MSMG1(k.Handle, name, start, scalarsRegularLE)
}

// ModulusLimbs returns the little-endian 64-bit limbs of m, padded to n.
func ModulusLimbs(m *big.Int, n int) []uint64 {
	out := make([]uint64, n)
	for i, w := range new(big.Int).Set(m).Bits() {
		out[i] = uint64(w)
	}
	return out
}

// DecodeLimbs copies a little-endian Montgomery-form element into z and checks
// that it is reduced modulo the field whose limbs are given.
func DecodeLimbs(z []uint64, b []byte, modulus []uint64) error {
	copy(Bytes(z), b)
	for i := len(z) - 1; i >= 0; i-- {
		if z[i] < modulus[i] {
			return nil
		}
		if z[i] > modulus[i] {
			break
		}
	}
	return errors.New("GPU returned a non reduced field element")
}
