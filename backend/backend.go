// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package backend implements Zero Knowledge Proof systems: it consumes circuit compiled with gnark/frontend.
package backend

import (
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/consensys/gnark/constraint/solver"
)

// ID represent a unique ID for a proving scheme
type ID uint16

const (
	UNKNOWN ID = iota
	GROTH16
	PLONK
)

// Implemented return the list of proof systems implemented in gnark
func Implemented() []ID {
	return []ID{GROTH16, PLONK}
}

// String returns the string representation of a proof system
func (id ID) String() string {
	switch id {
	case GROTH16:
		return "groth16"
	case PLONK:
		return "plonk"
	default:
		return "unknown"
	}
}

// IDFromString returns the ID of a proof system from its string representation
func IDFromString(s string) ID {
	switch s {
	case "groth16":
		return GROTH16
	case "plonk":
		return PLONK
	default:
		return UNKNOWN
	}
}

// ProverOption defines option for altering the behavior of the prover in
// Prove, ReadAndProve and IsSolved methods. See the descriptions of functions
// returning instances of this type for implemented options.
type ProverOption func(*ProverConfig) error

// ProverConfig is the configuration for the prover with the options applied.
type ProverConfig struct {
	SolverOpts        []solver.Option
	HashToFieldFn     hash.Hash
	ChallengeHash     hash.Hash
	KZGFoldingHash    hash.Hash
	StatisticalZK     bool
	SolutionCachePath string // if non-empty, path to cache/load solver solution
}

// NewProverConfig returns a default ProverConfig with given prover options opts
// applied.
func NewProverConfig(opts ...ProverOption) (ProverConfig, error) {
	opt := ProverConfig{
		// we cannot initialize HashToFieldFn here as we use different domain
		// separation tags for PLONK and Groth16
		ChallengeHash:  sha256.New(),
		KZGFoldingHash: sha256.New(),
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return ProverConfig{}, err
		}
	}
	return opt, nil
}

// WithSolverOptions specifies the constraint system solver options.
func WithSolverOptions(solverOpts ...solver.Option) ProverOption {
	return func(opt *ProverConfig) error {
		opt.SolverOpts = solverOpts
		return nil
	}
}

// WithProverHashToFieldFunction changes the hash function used for hashing
// bytes to field. If not set then the default hash function based on RFC 9380
// is used. Used mainly for compatibility between different systems and
// efficient recursion.
func WithProverHashToFieldFunction(hFunc hash.Hash) ProverOption {
	return func(cfg *ProverConfig) error {
		cfg.HashToFieldFn = hFunc
		return nil
	}
}

// WithProverChallengeHashFunction sets the hash function used for computing
// non-interactive challenges in Fiat-Shamir heuristic. If not set then by
// default SHA2-256 is used. Used mainly for compatibility between different
// systems and efficient recursion.
func WithProverChallengeHashFunction(hFunc hash.Hash) ProverOption {
	return func(pc *ProverConfig) error {
		pc.ChallengeHash = hFunc
		return nil
	}
}

// WithProverKZGFoldingHashFunction sets the hash function used for computing
// the challenge when folding the KZG opening proofs. If not set then by default
// SHA2-256 is used. Used mainly for compatibility between different systems and
// efficient recursion.
func WithProverKZGFoldingHashFunction(hFunc hash.Hash) ProverOption {
	return func(pc *ProverConfig) error {
		pc.KZGFoldingHash = hFunc
		return nil
	}
}

// WithIcicleAcceleration requests to use [ICICLE] GPU proving backend.
//
// DEPRECATED: we don't switch to ICICLE automatically anymore, the user has to
// explicitly use methods in the [github.com/consensys/gnark/backend/accelerated/icicle]
// package to use ICICLE acceleration. This option will be removed in a future release,
// but kept for now for API backward compatibility. It will error at runtime instead.
//
// [ICICLE]: https://github.com/ingonyama-zk/icicle-gnark
func WithIcicleAcceleration() ProverOption {
	return func(pc *ProverConfig) error {
		return fmt.Errorf("WithIcicleAcceleration for switching is deprecated, please use the ICICLE backend directly. " +
			"Import \"github.com/consensys/gnark/backend/accelerated/icicle\" and use the Prove method there")
	}
}

// WithSolutionCachePath sets a file path used to cache the solver solution.
// It is currently honored only by the ICICLE-accelerated Groth16 backend
// (backend/accelerated/icicle/groth16). On the first prove call the solver
// runs normally and the result is written to the file. Subsequent calls with
// the same path load the cached solution (validated against the circuit's
// wire count) and skip the solver entirely. The caller is responsible for
// deleting the cache when the witness or circuit changes.
// Caching is automatically disabled when BSB22 commitments are present (the
// solver has side effects that cannot be replayed from cache).
func WithSolutionCachePath(path string) ProverOption {
	return func(pc *ProverConfig) error {
		pc.SolutionCachePath = path
		return nil
	}
}

// WithStatisticalZeroKnowledge ensures that statistical zero knowledgeness is achieved.
// This option makes the prover more memory costly, as there are 3 more size n (size of the circuit)
// allocations.
func WithStatisticalZeroKnowledge() ProverOption {
	return func(pc *ProverConfig) error {
		pc.StatisticalZK = true
		return nil
	}
}

// VerifierOption defines option for altering the behavior of the verifier. See
// the descriptions of functions returning instances of this type for
// implemented options.
type VerifierOption func(*VerifierConfig) error

// VerifierConfig is the configuration for the verifier with the options applied.
type VerifierConfig struct {
	HashToFieldFn  hash.Hash
	ChallengeHash  hash.Hash
	KZGFoldingHash hash.Hash
}

// NewVerifierConfig returns a default [VerifierConfig] with given verifier
// options applied.
func NewVerifierConfig(opts ...VerifierOption) (VerifierConfig, error) {
	opt := VerifierConfig{
		// we cannot initialize HashToFieldFn here as we use different domain
		// separation tags for PLONK and Groth16
		ChallengeHash:  sha256.New(),
		KZGFoldingHash: sha256.New(),
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return VerifierConfig{}, err
		}
	}
	return opt, nil
}

// WithVerifierHashToFieldFunction changes the hash function used for hashing
// bytes to field. If not set then the default hash function based on RFC 9380
// is used. Used mainly for compatibility between different systems and
// efficient recursion.
func WithVerifierHashToFieldFunction(hFunc hash.Hash) VerifierOption {
	return func(cfg *VerifierConfig) error {
		cfg.HashToFieldFn = hFunc
		return nil
	}
}

// WithVerifierChallengeHashFunction sets the hash function used for computing
// non-interactive challenges in Fiat-Shamir heuristic. If not set then by
// default SHA2-256 is used. Used mainly for compatibility between different
// systems and efficient recursion.
func WithVerifierChallengeHashFunction(hFunc hash.Hash) VerifierOption {
	return func(pc *VerifierConfig) error {
		pc.ChallengeHash = hFunc
		return nil
	}
}

// WithVerifierKZGFoldingHashFunction sets the hash function used for computing
// the challenge when folding the KZG opening proofs. If not set then by default
// SHA2-256 is used. Used mainly for compatibility between different systems and
// efficient recursion.
func WithVerifierKZGFoldingHashFunction(hFunc hash.Hash) VerifierOption {
	return func(pc *VerifierConfig) error {
		pc.KZGFoldingHash = hFunc
		return nil
	}
}
