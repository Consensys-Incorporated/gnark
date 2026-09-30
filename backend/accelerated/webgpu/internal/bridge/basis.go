//go:build js && wasm

package bridge

import "unsafe"

// BasisRegistry maps the base vectors uploaded to the GPU back to their name,
// so that an accelerator receiving a sub-slice of a proving key vector can
// resolve which GPU buffer, and which offset in it, the MSM refers to.
type BasisRegistry struct {
	entries []basisEntry
}

type basisEntry struct {
	name       string
	start, end uintptr
	elemSize   uintptr
}

// RegisterSlice records s under name.
func RegisterSlice[T any](r *BasisRegistry, name string, s []T) {
	if len(s) == 0 {
		return
	}
	var zero T
	start := uintptr(unsafe.Pointer(&s[0]))
	size := unsafe.Sizeof(zero)
	r.entries = append(r.entries, basisEntry{name: name, start: start, end: start + uintptr(len(s))*size, elemSize: size})
}

// ResolveSlice returns the name of the registered vector containing s and the
// index of s[0] in it.
func ResolveSlice[T any](r *BasisRegistry, s []T) (name string, start int, ok bool) {
	if len(s) == 0 {
		return "", 0, false
	}
	var zero T
	ptr := uintptr(unsafe.Pointer(&s[0]))
	end := ptr + uintptr(len(s))*unsafe.Sizeof(zero)
	for _, e := range r.entries {
		if e.elemSize == unsafe.Sizeof(zero) && ptr >= e.start && end <= e.end {
			return e.name, int((ptr - e.start) / e.elemSize), true
		}
	}
	return "", 0, false
}
