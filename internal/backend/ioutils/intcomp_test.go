package ioutils

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadAndDecompressRejectsMalformedLength(t *testing.T) {
	input := make([]byte, 8)
	binary.LittleEndian.PutUint64(input, ^uint64(0))

	if _, _, _, err := ReadAndDecompressUints32(input, nil); err == nil {
		t.Fatal("expected ReadAndDecompressUints32 error")
	}
	if _, _, err := ReadAndDecompressUints64(input); err == nil {
		t.Fatal("expected ReadAndDecompressUints64 error")
	}
}

func FuzzIntcomp32(f *testing.F) {
	f.Fuzz(func(t *testing.T, in []byte) {
		// convert in into a []uint32 ref slice; we just parse by multiple of 4 bytes
		// and convert to uint32
		data := make([]uint32, len(in)/4)
		for i := 0; i < len(data); i++ {
			data[i] = uint32(in[i*4]) | uint32(in[i*4+1])<<8 | uint32(in[i*4+2])<<16 | uint32(in[i*4+3])<<24
		}

		var buf bytes.Buffer
		if _, err := CompressAndWriteUints32(&buf, data, nil); err != nil {
			t.Fatalf("CompressAndWriteUints32: %v", err)
		}
		_, n, out, err := ReadAndDecompressUints32(buf.Bytes(), nil)
		if err != nil {
			t.Fatalf("ReadAndDecompressUints32: %v", err)
		}
		if n != len(buf.Bytes()) {
			t.Fatalf("ReadAndDecompressUints32: n=%d, want %d", n, len(buf.Bytes()))
		}
		if len(out) != len(data) {
			t.Fatalf("ReadAndDecompressUints32: len(out)=%d, want %d", len(out), len(data))
		}
		for i := 0; i < len(data); i++ {
			if out[i] != data[i] {
				t.Fatalf("ReadAndDecompressUints32: out[%d]=%d, want %d", i, out[i], data[i])
			}
		}
	})

}
