package constraint

import (
	"encoding/binary"
	"testing"
)

func TestSystemFromBytesRejectsMalformedSectionLengths(t *testing.T) {
	testCases := []struct {
		name     string
		lengths  [4]uint64
		payloads [][]byte
	}{
		{
			name:    "all sections empty",
			lengths: [4]uint64{},
		},
		{
			name:    "oversized levels section",
			lengths: [4]uint64{^uint64(0), 0, 0, 0},
		},
		{
			name:    "truncated levels section header",
			lengths: [4]uint64{1, 0, 0, 0},
			payloads: [][]byte{
				{0},
			},
		},
		{
			name:    "oversized levels count",
			lengths: [4]uint64{8, 0, 0, 0},
			payloads: [][]byte{
				uint64Bytes(^uint64(0)),
			},
		},
		{
			name:    "oversized instructions compressed count",
			lengths: [4]uint64{8, 8, 0, 0},
			payloads: [][]byte{
				uint64Bytes(0),
				uint64Bytes(^uint64(0)),
			},
		},
		{
			name:    "truncated calldata section header",
			lengths: [4]uint64{8, 32, 1, 0},
			payloads: [][]byte{
				make([]byte, 8),
				make([]byte, 32),
				{0},
			},
		},
		{
			name:    "oversized calldata count",
			lengths: [4]uint64{8, 32, 8, 0},
			payloads: [][]byte{
				uint64Bytes(0),
				make([]byte, 32),
				uint64Bytes(^uint64(0)),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var system System
			_, err := system.FromBytes(serializedSystemPayload(tc.lengths, tc.payloads...))
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func serializedSystemPayload(lengths [4]uint64, payloads ...[]byte) []byte {
	data := make([]byte, headerLen)
	for i, length := range lengths {
		binary.LittleEndian.PutUint64(data[i*8:(i+1)*8], length)
	}
	for _, payload := range payloads {
		data = append(data, payload...)
	}
	return data
}

func uint64Bytes(v uint64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, v)
	return data
}
