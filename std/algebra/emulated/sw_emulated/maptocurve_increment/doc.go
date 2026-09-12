// Package maptocurve_increment implements increment-and-check map-to-curve
// gadgets for emulated short Weierstrass curves y² = x³ + ax + b, following
// the constructions from https://eprint.iacr.org/2026/590.
//
// Two methods are provided:
//   - [Mapper.XIncrement]: encodes X = M·256 + K, verifies the curve equation,
//     and ensures Y has a 2^S-th root (inverse-exclusion witness) needed for
//     soundness on j=0 curves. Only practical for low 2-adicity fields
//     (S ≤ 4). For high 2-adicity fields (e.g. BLS12-377 with S=46, Grumpkin
//     with S=28) the witness search becomes infeasible — use
//     [Mapper.YIncrement] instead.
//   - [Mapper.YIncrement]: encodes Y = M·256 + K, verifies the curve equation.
//     Simpler (no inverse-exclusion witness), works for any 2-adicity, and is
//     the recommended method for j=0 curves.
//
// [Mapper.Increment] dispatches to whichever variant is appropriate for the
// instantiated curve.
//
// # Important caveats
//
// The mapping produced by these gadgets is NOT a cryptographic hash-to-curve.
// In particular:
//
//   - It is NOT unique: multiple values of K ∈ [0,256) may yield on-curve
//     points for the same message M. The implementation returns whatever K
//     the prover commits to via the hint. This makes the mapping unsafe in
//     any setting where uniqueness of (M ↦ point) is assumed (e.g. as a
//     drop-in replacement for SSWU + clear_cofactor in a hash-to-curve
//     context). If you need a canonical mapping, use the SSWU gadgets in
//     [sw_bls12381] etc.
//   - The returned point is NOT cleared to the prime-order subgroup. Curve
//     arithmetic for prime-order operations (scalar mul, signatures, …) can
//     break on small-subgroup or torsion points. Callers MUST clear the
//     cofactor explicitly if subgroup membership is required.
//   - The 256-element search is NOT guaranteed to converge. For
//     well-distributed inputs the probability that every K ∈ [0,256) yields
//     a quadratic non-residue (XIncrement) or a non-cube (YIncrement) is
//     bounded by ≈ 2^-256 (independent quadratic-residue heuristic), but
//     adversarial inputs could in principle push this higher. Treat the
//     probabilistic failure as part of the protocol's soundness budget.
//   - The gadgets assume M < q/256 (i.e. bitlen(q) − 8 bits of headroom in
//     M). This is NOT enforced in-circuit — callers must guarantee it.
//     With M ≥ q/256 the encoding M·256 + K wraps modulo q and the
//     committed K no longer matches the integer prover used in the search;
//     the (X,Y) is still on the curve but the encoding becomes ambiguous.
//
// [sw_bls12381]: https://pkg.go.dev/github.com/consensys/gnark/std/algebra/emulated/sw_bls12381
package maptocurve_increment
