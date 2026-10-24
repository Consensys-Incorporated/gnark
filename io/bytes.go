package io

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// WriteBytesShort writes a short byte slice (maximum length of 255) to a writer.
func WriteBytesShort(challenge []byte, writer io.Writer) (int64, error) {
	if len(challenge) > 255 {
		return 0, fmt.Errorf("challenge too long %d > 255", len(challenge))
	}
	if err := binary.Write(writer, binary.BigEndian, uint8(len(challenge))); err != nil {
		return math.MinInt, err // in this case we're not sure how many bytes were written
	}
	n, err := writer.Write(challenge)
	return int64(n) + 1, err
}

// ReadBytesShort reads a short byte slice (maximum length of 255) from a reader.
func ReadBytesShort(reader io.Reader) ([]byte, int64, error) {
	var length uint8
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, math.MinInt, err // in this case we're not sure how many bytes were read
	}
	if length == 0 {
		return nil, 1, nil
	}
	challenge := make([]byte, length)
	// a single Read may return fewer bytes without an error (e.g. bufio.Reader
	// at a buffer boundary), so read until the slice is full.
	dn, err := io.ReadFull(reader, challenge)
	return challenge, 1 + int64(dn), err
}
