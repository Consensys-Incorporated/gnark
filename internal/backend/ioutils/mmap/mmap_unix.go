// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

//go:build unix

package mmap

import (
	"fmt"
	"os"
	"syscall"
)

// Mapping is a read-only memory mapping.
type Mapping struct {
	Data []byte
}

// Supported reports whether this build supports memory-mapped files.
func Supported() bool {
	return true
}

// Open maps path into memory using a private read-only mapping.
func Open(path string) (*Mapping, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() == 0 {
		return nil, fmt.Errorf("mmap %s: empty file", path)
	}
	if stat.Size() > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("mmap %s: file too large for platform", path)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(stat.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	return &Mapping{Data: data}, nil
}

// Close releases the mapping.
func (m *Mapping) Close() error {
	if m == nil || m.Data == nil {
		return nil
	}
	err := syscall.Munmap(m.Data)
	m.Data = nil
	return err
}
