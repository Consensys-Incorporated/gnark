package io

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadBytesShortPartialReads(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xab, 0xcd}, 20)
	var buf bytes.Buffer
	if _, err := WriteBytesShort(challenge, &buf); err != nil {
		t.Fatal(err)
	}
	// the reader returns one byte per Read call
	got, n, err := ReadBytesShort(iotest.OneByteReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("read %d bytes, expected %d", n, buf.Len())
	}
	if !bytes.Equal(got, challenge) {
		t.Fatalf("got %x, expected %x", got, challenge)
	}
}

func TestReadBytesShortTruncated(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xab}, 32)
	var buf bytes.Buffer
	if _, err := WriteBytesShort(challenge, &buf); err != nil {
		t.Fatal(err)
	}
	truncated := buf.Bytes()[:buf.Len()-1]
	if _, _, err := ReadBytesShort(bytes.NewReader(truncated)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}
