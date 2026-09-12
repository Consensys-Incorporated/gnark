//go:build js && wasm

// Package bridge is the Go side of the protocol between the wasm prover and the
// TypeScript WebGPU runtime. The runtime installs one bridge object per proof
// system on globalThis (gnarkGroth16WebGPU, gnarkPlonkWebGPU) whose methods
// return promises; Client invokes them and blocks the calling goroutine until
// the promise settles. Byte formats:
//
//   - Points are affine, one coordinate after the other, each coordinate being
//     the Montgomery-form limbs of the base field in little-endian order, which
//     is exactly the in-memory layout of gnark-crypto elements on wasm. The
//     point at infinity has all-zero coordinates.
//   - Field element vectors are Montgomery-form limbs, little-endian, unless a
//     method says "regular", in which case the elements are in canonical (non
//     Montgomery) form, little-endian.
//   - MSM scalars are regular little-endian.
package bridge

import (
	"fmt"
	"syscall/js"
	"unsafe"
)

// Client invokes the methods of a bridge object installed on globalThis.
type Client struct {
	GlobalName  string
	ErrorPrefix string
}

// Bytes returns the memory backing s as a byte slice. The result aliases s and
// is valid as long as s is.
func Bytes[T any](s []T) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), len(s)*int(unsafe.Sizeof(s[0])))
}

// Uint8Array copies b into a new JavaScript Uint8Array.
func Uint8Array(b []byte) js.Value {
	out := js.Global().Get("Uint8Array").New(len(b))
	if len(b) > 0 {
		js.CopyBytesToJS(out, b)
	}
	return out
}

// object builds a JavaScript object from key/value pairs.
func object(kv ...any) js.Value {
	obj := js.Global().Get("Object").New()
	for i := 0; i < len(kv); i += 2 {
		obj.Set(kv[i].(string), kv[i+1])
	}
	return obj
}

func (c Client) call(method string, args ...any) (js.Value, error) {
	bridge := js.Global().Get(c.GlobalName)
	if bridge.IsUndefined() || bridge.IsNull() {
		return js.Undefined(), fmt.Errorf("%s: %s bridge not found on global object", c.ErrorPrefix, c.GlobalName)
	}
	fn := bridge.Get(method)
	if fn.Type() != js.TypeFunction {
		return js.Undefined(), fmt.Errorf("%s: bridge method %q is not available", c.ErrorPrefix, method)
	}
	return c.await(fn.Invoke(args...))
}

func (c Client) await(promise js.Value) (js.Value, error) {
	if promise.IsUndefined() || promise.IsNull() {
		return js.Undefined(), fmt.Errorf("%s: bridge returned empty promise", c.ErrorPrefix)
	}
	type result struct {
		value js.Value
		err   error
	}
	ch := make(chan result, 1)
	resolve := js.FuncOf(func(_ js.Value, args []js.Value) any {
		value := js.Undefined()
		if len(args) > 0 {
			value = args[0]
		}
		ch <- result{value: value}
		return nil
	})
	reject := js.FuncOf(func(_ js.Value, args []js.Value) any {
		err := fmt.Errorf("%s: bridge promise rejected", c.ErrorPrefix)
		if len(args) > 0 {
			err = c.jsError(args[0])
		}
		ch <- result{err: err}
		return nil
	})
	defer resolve.Release()
	defer reject.Release()
	promise.Call("then", resolve, reject)
	out := <-ch
	return out.value, out.err
}

func (c Client) jsError(v js.Value) error {
	if v.IsUndefined() || v.IsNull() {
		return fmt.Errorf("%s: unknown JS error", c.ErrorPrefix)
	}
	if message := v.Get("message"); message.Type() == js.TypeString {
		return fmt.Errorf("%s: %s", c.ErrorPrefix, message.String())
	}
	return fmt.Errorf("%s: %s", c.ErrorPrefix, v.String())
}

// callBytes invokes method and copies its Uint8Array result into a new slice.
func (c Client) callBytes(method string, args ...any) ([]byte, error) {
	value, err := c.call(method, args...)
	if err != nil {
		return nil, err
	}
	n, err := c.byteLength(value)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if n > 0 {
		js.CopyBytesToGo(out, value)
	}
	return out, nil
}

// callBytesInto invokes method and copies its Uint8Array result into dst, which
// must have exactly the result's length.
func (c Client) callBytesInto(dst []byte, method string, args ...any) error {
	value, err := c.call(method, args...)
	if err != nil {
		return err
	}
	n, err := c.byteLength(value)
	if err != nil {
		return err
	}
	if n != len(dst) {
		return fmt.Errorf("%s: %s returned %d bytes, expected %d", c.ErrorPrefix, method, n, len(dst))
	}
	if n > 0 {
		js.CopyBytesToGo(dst, value)
	}
	return nil
}

func (c Client) byteLength(v js.Value) (int, error) {
	if v.IsUndefined() || v.IsNull() {
		return 0, fmt.Errorf("%s: expected Uint8Array result, got empty value", c.ErrorPrefix)
	}
	n := v.Get("byteLength")
	if n.Type() != js.TypeNumber {
		return 0, fmt.Errorf("%s: JS result does not expose byteLength", c.ErrorPrefix)
	}
	return n.Int(), nil
}

// Init initializes the WebGPU runtime for curve.
func (c Client) Init(curve string) error {
	_, err := c.call("init", curve)
	return err
}

// PrepareKey uploads the named G1 and G2 base vectors (affine, see package doc)
// to the GPU and returns the key handle.
func (c Client) PrepareKey(curve string, g1, g2 map[string][]byte) (string, error) {
	g1Obj, g2Obj := object(), object()
	for name, b := range g1 {
		g1Obj.Set(name, Uint8Array(b))
	}
	for name, b := range g2 {
		g2Obj.Set(name, Uint8Array(b))
	}
	value, err := c.call("prepareKey", curve, object("g1", g1Obj, "g2", g2Obj))
	if err != nil {
		return "", err
	}
	handle := value.Get("handle")
	if handle.Type() != js.TypeString || handle.String() == "" {
		return "", fmt.Errorf("%s: bridge returned invalid key handle", c.ErrorPrefix)
	}
	return handle.String(), nil
}

// ReleaseKey frees the GPU buffers of a prepared key.
func (c Client) ReleaseKey(handle string) error {
	_, err := c.call("releaseKey", handle)
	return err
}

// MSMG1 returns Σ scalars[i]·bases[start+i] over the named G1 vector of the
// key, as an affine point.
func (c Client) MSMG1(handle, name string, start int, scalarsRegularLE []byte) ([]byte, error) {
	return c.callBytes("msmG1", handle, name, start, Uint8Array(scalarsRegularLE))
}

// MSMG2 is MSMG1 for the named G2 vector.
func (c Client) MSMG2(handle, name string, start int, scalarsRegularLE []byte) ([]byte, error) {
	return c.callBytes("msmG2", handle, name, start, Uint8Array(scalarsRegularLE))
}

// ComputeH computes the Groth16 quotient polynomial from the evaluations a, b, c
// (Montgomery, zero padded to n by the runtime) and copies the n resulting
// Montgomery-form coefficients into dst.
func (c Client) ComputeH(curve string, a, b, cc []byte, n int, dst []byte) error {
	return c.callBytesInto(dst, "computeH", curve, Uint8Array(a), Uint8Array(b), Uint8Array(cc), n)
}

// PrewarmQuotientDomain precomputes the Groth16 quotient FFT tables for size n.
func (c Client) PrewarmQuotientDomain(curve string, n int) error {
	_, err := c.call("prewarmQuotientDomain", curve, n)
	return err
}

// CanonicalizeVectors converts, in place semantics, vectorCount vectors of n
// Montgomery elements from Lagrange (or Lagrange-coset, inverseCoset) basis in
// Regular (or BitReverse, inputBitReversed) layout to canonical basis, Regular
// layout, copying the result into dst.
func (c Client) CanonicalizeVectors(curve string, values []byte, vectorCount, n int, inputBitReversed, inverseCoset bool, dst []byte) error {
	return c.callBytesInto(dst, "canonicalizeVectors", curve, Uint8Array(values), vectorCount, n, inputBitReversed, inverseCoset)
}

// PreloadQuotientStatics uploads, under key, the circuit polynomials of a PLONK
// proving key in canonical form (staticVectorCount vectors of n Montgomery
// elements) together with the per-coset tables the numerator kernel needs:
// scaling (cosetCount vectors: the coset shift powers), twiddles (one vector:
// the powers of the small domain generator) and denominators (cosetCount
// vectors: 1/(s·ωⁱ−1)). They stay resident on the GPU until ReleaseQuotientStatics.
func (c Client) PreloadQuotientStatics(curve string, key uint32, statics, scaling, twiddles, denominators []byte, n, staticVectorCount, cosetCount int) error {
	_, err := c.call("preloadQuotientStatics", curve, key,
		Uint8Array(statics), Uint8Array(scaling), Uint8Array(twiddles), Uint8Array(denominators),
		n, staticVectorCount, cosetCount)
	return err
}

// ReleaseQuotientStatics frees the buffers uploaded by PreloadQuotientStatics.
func (c Client) ReleaseQuotientStatics(curve string, key uint32) error {
	_, err := c.call("releaseQuotientStatics", curve, key)
	return err
}

// EvaluateQuotient evaluates the PLONK numerator on the cosetCount cosets of
// the large domain. dynamic holds the witness vectors (L, R, O, Z, Qk, then the
// committed values) in Lagrange basis, blinds the blinding coefficients scaled
// per coset and scalars the per-coset challenges, all Montgomery. The numerator
// (cosetCount·n elements, already in the bit-reversed layout of the large
// domain) is copied into numerator and the canonical form of the dynamic
// vectors into canonical.
func (c Client) EvaluateQuotient(curve string, key uint32, dynamic, blinds, scalars []byte, n, blindCoeffCount, commitmentCount, cosetCount int, numerator, canonical []byte) error {
	value, err := c.call("evaluateQuotient", curve, key,
		Uint8Array(dynamic), Uint8Array(blinds), Uint8Array(scalars),
		n, blindCoeffCount, commitmentCount, cosetCount)
	if err != nil {
		return err
	}
	if err := c.copyField(value, "numerator", numerator); err != nil {
		return err
	}
	return c.copyField(value, "canonical", canonical)
}

func (c Client) copyField(obj js.Value, field string, dst []byte) error {
	v := obj.Get(field)
	n, err := c.byteLength(v)
	if err != nil {
		return err
	}
	if n != len(dst) {
		return fmt.Errorf("%s: %s has %d bytes, expected %d", c.ErrorPrefix, field, n, len(dst))
	}
	if n > 0 {
		js.CopyBytesToGo(dst, v)
	}
	return nil
}

// PrewarmQuotient compiles the PLONK kernels and FFT tables for a small domain
// of size n, cosetCount cosets and commitmentCount BSB22 commitments.
func (c Client) PrewarmQuotient(curve string, n, cosetCount, commitmentCount int) error {
	_, err := c.call("prewarmQuotient", curve, n, cosetCount, commitmentCount)
	return err
}
