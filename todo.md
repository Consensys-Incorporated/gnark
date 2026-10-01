1. Soundness hole — AssertIsInSubgroup is a silent no-op on BW6-761 G1
   (sw_emulated/point.go:488) The newly exported method delegates to
   assertPointInSubgroup, which returns immediately when CofactorClearing ==
   nil — and GetBW6761Params sets it to nil despite BW6-761 G1 having a
   cofactor. He reproduced it: an on-curve BW6-761 point with native
   IsInSubGroup() == false still satisfies AssertIsOnCurve +
   AssertIsInSubgroup. Wants an explicit failure for cofactor curves lacking a
   check (or implement it), plus a regression test. This is the one that
   actually blocks — exporting the method turned an internal "caller knows
   better" shortcut into a public API that lies.

2. Completeness risk — the +2 → +1 subscalar bound is under-justified
   (point.go:1923) Two objections. First, factual: γ₄ is √2, not ≈1.25 (you
   wrote 1.25 in both the comment and the PR description — that's the Hermite
   constant γ₄ = √2 ≈ 1.414; 1.25 looks like γ₄^{1/4} ≈ 1.19 or a misremembered
   table entry). Second, and the real point: an existence bound on a short
   lattice vector does not bound the particular denominator-nonzero row
   gnark-crypto's rationalReconstructExt actually selects after reduction. If
   any returned magnitude reaches 2^65, the hint range check fails and a valid
   scalar mul becomes unprovable. He'll accept either a bound on the
   dependency's actual row-selection algorithm, or honest framing as an
   empirical optimization backed by deterministic extremal vectors at the
   64/65-bit boundary for the generic, BN254 G2, and BLS12-381 G2 paths. Also
   notes the range-check comment at line 1968 still says +2.

3. [DONE] Factual error in the cofactor justification (params.go:110) Your comment
   claims every prime dividing h occurs squared — but the factorization
   directly above it has h = 3·11²·10177²·859267²·52437899², a single factor of
   3. He's right; the 3-primary component needs separating from the rest. He
   explicitly says this doesn't invalidate |x−1| — the group decomposition
   E(𝔽ₚ) ≅ ℤ_{(x−1)/3} × ℤ_{(x−1)·r} is the justification that carries. Same
   fix needed in the PR description.

   Resolved via ePrint 2021/1359 §3.2 Cor. 1 (El Housni-Guillevic): with
   n = (x-1)/3, the full n-torsion is rational (E[n] ⊂ E(Fp), n² points of
   order n, none of order n²), so the n-part is Z_n × Z_n. h = 3n² with 3 ∤ n,
   and the lone factor 3 is the 3 in 3n = x-1, contributing a cyclic Z_3. So
   the torsion is Z_n × Z_{3n}, exponent lcm(n, 3n) = 3n = x-1. The rank-2
   claim belongs to n, not to h — which is exactly the distinction Ivo asked
   for. Comments in params.go and sw_bls12381/g1.go corrected; the arithmetic
   is now pinned in TestBLS12381CofactorClearingConstant.

4. TestScalarMulBaseCombConstraints isn't a test (fixedbase_test.go:188) — it
   logs compile errors and continues, and only logs counts. It'd pass even if
   the selected window lost to another width. Make it fail on compile errors
   and assert the chosen minimum, or demote it to a benchmark. He independently
   measured and confirms w = 9, 9, 10.

5. Duplicated test helper (sw_bls12381/g1_test.go:81) — randomCurvePoint
   duplicates randomBLS12381CurvePoint in sw_emulated/point_test.go. Share it
   or construct the specific torsion points directly.

Separately, YaoJGalteland suggested the guarded-incomplete mulByConstant —
that's already incorporated (it's the "guarded incomplete" column in your
description, −22% R1CS vs unified).

