package main

// wgslTuning holds the code-generation knobs of the field arithmetic that
// trade shader size (and pipeline compile time) for throughput.
type wgslTuning struct {
	// MulUnrollOuter fully unrolls the outer digit loop of the Montgomery
	// multiplication (16 or 24 copies of the row body). When false only the
	// inner digit loops are unrolled and the outer loop runs over the 32-bit
	// limbs of the second operand.
	//
	// Measured on Apple silicon (Chrome/Dawn, Metal) for the 8-limb fields:
	// unrolling gains 3-7% on a compute-bound multiplication kernel
	// (fr_vector POWER at 2^20: 5.5 ms vs 5.8 ms per dispatch) and nothing
	// measurable on the fused NTT, but triples the size of every Fr shader
	// (fr_arith 738 -> 2167 lines) and of the per-shader pipeline compile
	// (3.5 ms -> 9 ms), and roughly doubles the cold curve-module
	// initialisation (29 ms -> 38-56 ms). The smaller shader is the default.
	MulUnrollOuter bool
}

// tuningFor returns the tuning of a field with the given number of 32-bit limbs.
func tuningFor(limbs int) wgslTuning {
	_ = limbs
	return wgslTuning{MulUnrollOuter: false}
}
