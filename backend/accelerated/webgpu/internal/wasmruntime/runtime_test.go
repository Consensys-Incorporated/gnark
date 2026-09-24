//go:build js && wasm

package wasmruntime

import (
	"bytes"
	"syscall/js"
	"testing"
)

func TestBytesArgRejectsNonUint8Array(t *testing.T) {
	objectWithByteLength := js.Global().Get("Object").New()
	objectWithByteLength.Set("byteLength", 3)

	tests := []struct {
		name  string
		value js.Value
	}{
		{name: "number", value: js.ValueOf(123)},
		{name: "string", value: js.ValueOf("bytes")},
		{name: "boolean", value: js.ValueOf(true)},
		{name: "null", value: js.Null()},
		{name: "undefined", value: js.Undefined()},
		{name: "object with byteLength", value: objectWithByteLength},
		{name: "ArrayBuffer", value: js.Global().Get("ArrayBuffer").New(3)},
		{name: "Uint8ClampedArray", value: js.Global().Get("Uint8ClampedArray").New(3)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bytesArg([]js.Value{tt.value}, 0)
			if err == nil || err.Error() != "expected Uint8Array" {
				t.Fatalf("bytesArg() = (%v, %v), want (nil, expected Uint8Array error)", got, err)
			}
			if got != nil {
				t.Fatalf("bytesArg() returned %v, want nil", got)
			}
		})
	}
}

func TestBytesArgCopiesUint8Array(t *testing.T) {
	want := []byte{0, 1, 127, 255}
	value := js.Global().Get("Uint8Array").New(len(want))
	js.CopyBytesToJS(value, want)

	got, err := bytesArg([]js.Value{value}, 0)
	if err != nil {
		t.Fatalf("bytesArg() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("bytesArg() = %v, want %v", got, want)
	}
}

func TestBytesArgAcceptsEmptyUint8Array(t *testing.T) {
	got, err := bytesArg([]js.Value{js.Global().Get("Uint8Array").New(0)}, 0)
	if err != nil {
		t.Fatalf("bytesArg() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("bytesArg() = %v, want empty bytes", got)
	}
}

func TestBytesArgRequiresArgument(t *testing.T) {
	got, err := bytesArg(nil, 0)
	if err == nil || err.Error() != "missing bytes argument" {
		t.Fatalf("bytesArg() = (%v, %v), want (nil, missing bytes argument error)", got, err)
	}
}
