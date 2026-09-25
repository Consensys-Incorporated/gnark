package cs

import (
	"encoding/binary"
	"testing"
)

func TestCoeffTableFromBytesRejectsMalformedLength(t *testing.T) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, ^uint64(0))

	var ct CoeffTable
	if err := ct.fromBytes(buf); err == nil {
		t.Fatal("expected error")
	}
}
