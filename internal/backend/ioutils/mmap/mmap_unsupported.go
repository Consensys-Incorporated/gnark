// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

//go:build !unix

package mmap

import "errors"

// Mapping is a read-only memory mapping.
type Mapping struct {
	Data []byte
}

// Supported reports whether this build supports memory-mapped files.
func Supported() bool {
	return false
}

// Open returns an error on platforms without mmap support.
func Open(string) (*Mapping, error) {
	return nil, errors.New("mmap is unsupported on this platform")
}

// Close releases the mapping.
func (m *Mapping) Close() error {
	if m != nil {
		m.Data = nil
	}
	return nil
}
