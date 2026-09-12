// Package maptocurve_increment implements the y-increment map-to-curve gadget
// for the Grumpkin curve y² = x³ − 17 over its base field (= BN254 scalar
// field). Circuits compile over ecc.BN254.
//
// Only the y-increment variant is provided. The x-increment variant is not
// practical for Grumpkin because its high 2-adicity (S=28) makes the
// 2^S-th root witness search infeasible.
//
// # Important caveats
//
// The mapping produced by this gadget is NOT a cryptographic hash-to-curve.
// In particular:
//
//   - It is NOT unique: multiple values of K ∈ [0,256) may yield on-curve
//     points for the same message M. The mapping is unsafe in any setting
//     where uniqueness of (M ↦ point) is assumed.
//   - The returned point is NOT cleared to the prime-order subgroup; if
//     subgroup membership is required, the caller MUST clear the cofactor.
//   - The 256-element search is NOT guaranteed to converge; the failure
//     probability is bounded by ≈ 2^-256 for well-distributed inputs but
//     adversarial inputs may have a worse bound.
//   - The gadget assumes M < q/256 (i.e. bitlen(q) − 8 bits of headroom in
//     M). This is NOT enforced in-circuit — callers must guarantee it.
package maptocurve_increment
