//go:build js && wasm

package bridge

import (
	"syscall/js"
	"testing"
)

// Every result the bridge cannot copy bytes out of must come back as an error:
// js.CopyBytesToGo and Value.Get panic, and the callers run on the prover
// goroutine where a panic tears down the wasm instance.
func TestByteLengthRejectsNonByteArrays(t *testing.T) {
	c := Client{ErrorPrefix: "test"}
	arrayBuffer := js.Global().Get("ArrayBuffer").New(8)
	for _, tc := range []struct {
		name  string
		value js.Value
	}{
		{"undefined", js.Undefined()},
		{"null", js.Null()},
		{"number", js.ValueOf(123)},
		{"string", js.ValueOf("bn254")},
		{"boolean", js.ValueOf(true)},
		{"plain object", object()},
		{"byteLength impostor", object("byteLength", 8)},
		{"ArrayBuffer", arrayBuffer},
		{"DataView", js.Global().Get("DataView").New(arrayBuffer)},
		{"Uint32Array", js.Global().Get("Uint32Array").New(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := c.byteLength(tc.value); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestByteLengthAcceptsByteArrays(t *testing.T) {
	c := Client{ErrorPrefix: "test"}
	for _, tc := range []struct {
		name  string
		value js.Value
		want  int
	}{
		{"Uint8Array", Uint8Array([]byte{0, 1, 2}), 3},
		{"empty Uint8Array", Uint8Array(nil), 0},
		{"Uint8ClampedArray", js.Global().Get("Uint8ClampedArray").New(2), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.byteLength(tc.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
