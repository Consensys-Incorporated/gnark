//go:build js && wasm

package wasmruntime

import (
	"bytes"
	"syscall/js"
	"testing"
)

func uint8Array(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	if len(b) > 0 {
		js.CopyBytesToJS(v, b)
	}
	return v
}

// bytesArg runs in the goroutine backing a JavaScript promise, where a panic
// tears down the whole wasm instance and leaves the promise unsettled, so
// every argument that is not a byte array must come back as an error.
func TestBytesArgRejectsNonByteArrays(t *testing.T) {
	arrayBuffer := js.Global().Get("ArrayBuffer").New(8)
	for _, tc := range []struct {
		name string
		args []js.Value
	}{
		{"missing", nil},
		{"undefined", []js.Value{js.Undefined()}},
		{"null", []js.Value{js.Null()}},
		{"number", []js.Value{js.ValueOf(123)}},
		{"string", []js.Value{js.ValueOf("bn254")}},
		{"boolean", []js.Value{js.ValueOf(true)}},
		{"function", []js.Value{js.Global().Get("Object")}},
		{"plain object", []js.Value{js.Global().Get("Object").New()}},
		{"byteLength impostor", []js.Value{object("byteLength", 8)}},
		{"ArrayBuffer", []js.Value{arrayBuffer}},
		{"DataView", []js.Value{js.Global().Get("DataView").New(arrayBuffer)}},
		{"Uint32Array", []js.Value{js.Global().Get("Uint32Array").New(2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := bytesArg(tc.args, 0); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestBytesArgAcceptsByteArrays(t *testing.T) {
	want := []byte{0, 1, 2, 3}
	for _, tc := range []struct {
		name string
		arg  js.Value
	}{
		{"Uint8Array", uint8Array(want)},
		{"Uint8ClampedArray", js.Global().Get("Uint8ClampedArray").New(uint8Array(want))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bytesArg([]js.Value{js.Undefined(), tc.arg}, 1)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestBytesArgAcceptsEmptyUint8Array(t *testing.T) {
	got, err := bytesArg([]js.Value{uint8Array(nil)}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want an empty slice", got)
	}
}

// readConstraintSystem("bn254", 123) and friends must reject their second
// argument rather than panic on it.
func TestCurveAndBytesRejectsNonByteArrays(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked instead of returning an error: %v", r)
		}
	}()
	if _, _, err := curveAndBytes([]js.Value{js.ValueOf("bn254"), js.ValueOf(123)}); err == nil {
		t.Fatal("expected an error")
	}
}
