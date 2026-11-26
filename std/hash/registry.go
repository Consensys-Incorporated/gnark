package hash

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark/frontend"
)

var (
	defaultHashes = make([]func(api frontend.API) (FieldHasher, error), maxHash)
	namedHashes   = make(map[string]func(api frontend.API) (FieldHasher, error), maxHash)
	lock          sync.RWMutex
)

// Hash represents a registered hash function.
type Hash uint

const (
	// MIMC is the MiMC hash function over the native field of the curve.
	MIMC Hash = iota
	// POSEIDON2 is the Poseidon2 hash function over the native field of the curve.
	POSEIDON2

	maxHash // the number of registered hash functions
)

// New initializes the hash function. This is a convenience function which does
// not allow setting hash-specific options.
func (m Hash) New(api frontend.API) (FieldHasher, error) {
	if m < maxHash {
		lock.RLock()
		defer lock.RUnlock()
		builder := defaultHashes[m]
		if builder != nil {
			return builder(api)
		}
	}
	return nil, fmt.Errorf("hash function \"%s\" not registered. Import the corresponding hash function package", m)
}

// Returns the unique identifier of the hash function as a string.
func (m Hash) String() string {
	switch m {
	case MIMC:
		return "MIMC"
	case POSEIDON2:
		return "POSEIDON2"
	default:
		return fmt.Sprintf("unknown hash function %d", m)
	}
}

// Available returns true if the hash function is available.
func (m Hash) Available() bool {
	return m < maxHash && defaultHashes[m] != nil
}

// Register registers a new hash function by its constant index. To ensure that
// the hash function is registered, import the corresponding hash gadget package
// so that it would call this method.
//
// Alternatively, you can import the [github.com/consensys/gnark/std/hash/all]
// package which automatically registers all hash functions.
func Register(m Hash, builder func(api frontend.API) (FieldHasher, error)) {
	if m >= maxHash {
		panic(fmt.Sprintf("cannot register a hash function with index %d, maximum is %d", m, maxHash-1))
	}
	lock.Lock()
	defer lock.Unlock()
	defaultHashes[m] = builder
}

// RegisterCustomHash registers a new hash function by a name. To ensure that
// the hash function is registered, import the corresponding hash gadget package
// so that it would call this method.
//
// Alternatively, you can import the [github.com/consensys/gnark/std/hash/all]
// package which automatically registers all hash functions.
func RegisterCustomHash(name string, builder func(api frontend.API) (FieldHasher, error)) {
	for i := Hash(0); i < maxHash; i++ {
		if i.String() == name {
			panic("cannot register a named hash overriding a default hash function: " + name)
		}
	}
	lock.Lock()
	defer lock.Unlock()
	namedHashes[name] = builder
}

// GetFieldHasher retrieves a hash function by name and returns an error if the
// name is not registered. The name should match the output of [Hash.String] or
// a name used with [RegisterCustomHash]. To register the hash function, import
// the corresponding hash gadget package so it calls [Register] or
// [RegisterCustomHash].
//
// Alternatively, you can import the [github.com/consensys/gnark/std/hash/all]
// package which automatically registers all hash functions.
func GetFieldHasher(name string, api frontend.API) (FieldHasher, error) {
	lock.RLock()
	defer lock.RUnlock()
	for i := Hash(0); i < maxHash; i++ {
		if i.String() == name {
			builder := defaultHashes[i]
			if builder != nil {
				return builder(api)
			}
		}
	}
	if f, ok := namedHashes[name]; ok {
		return f(api)
	}
	return nil, fmt.Errorf("hash function \"%s\" not registered. Import the corresponding package to register it", name)
}
