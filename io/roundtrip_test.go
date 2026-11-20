package io

import (
	"bytes"
	stdio "io"
	"testing"
)

type roundTripValue struct{ Data []byte }

func (v *roundTripValue) WriteTo(w stdio.Writer) (int64, error) {
	n, err := w.Write(v.Data)
	return int64(n), err
}

func (v *roundTripValue) ReadFrom(r stdio.Reader) (int64, error) {
	data, err := stdio.ReadAll(r)
	v.Data = data
	return int64(len(data)), err
}

func TestRoundTripCheckRequiresSerializationInterfaces(t *testing.T) {
	if err := RoundTripCheck(struct{}{}, func() any { return &roundTripValue{} }); err == nil {
		t.Fatal("a source without a serialization interface must not pass the check")
	}
	if err := RoundTripCheck(&roundTripValue{Data: []byte("data")}, func() any { return struct{}{} }); err == nil {
		t.Fatal("a destination without a deserialization interface must not pass the check")
	}
	value := &roundTripValue{Data: []byte("round-trip data")}
	if err := RoundTripCheck(value, func() any { return &roundTripValue{} }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value.Data, []byte("round-trip data")) {
		t.Fatal("round trip modified the source")
	}
}
