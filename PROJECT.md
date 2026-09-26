# Project: FRI-IOPP for gnark PLONK

Read this file at the start of every session and write to it during and at the end of every session, per `CLAUDE.md`.

## Goal

Add a FRI-based polynomial commitment backend for gnark's PLONK, fully segregated from the existing KZG backend (`backend/plonk/`), reusing the already-restored FRI code (`internal/nativefri`, `std/commitments/fri`, restored at `fb6e65da` on branch `restore-fri-gadget`) and the pre-2024 `backend/plonkfri` architecture (deleted in `1ed22f78`, "kill backend.PLONK_FRI").

## Key research finding

FRI's soundness doesn't depend on which field it runs over — "FRI over bn254 fr" is just as transparent/PQ as "FRI over koalabear." The old `backend/plonkfri` and the restored `internal/nativefri`/`std/commitments/fri` gadgets both target the curve's own `fr` field. gnark-crypto's koalabear assets (`vortex`, `iop`, `fft`) have **no FRI folding code** — Vortex is a different PCS. So "reuse what's restored" and "target koalabear" are two different, non-overlapping projects; we chose the former for v1.

Primary reference: `resources/2019-1400.pdf` — RedShift (Kattis/Panarin/Vlasov, CCS'22), the paper describing exactly this transformation (their "List Polynomial Commitment" wrapping FRI, Algorithm 2). Full architecture study (KZG seams): https://claude.ai/code/artifact/42bcd5a9-2492-4e0b-ae97-8c4efa2c89a4

`std/recursion/plonk` (in-circuit recursive PLONK verification) is deeply KZG/pairing-specific (G1El/G2El, emulated field arithmetic) — a FRI backend cannot plug into it. A FRI-based recursive verifier would be new, built on `std/commitments/fri`, and is out of scope for v1.

## Design decisions (locked in for v1)

- **Field**: curve scalar field (bn254 `fr`), not koalabear. Reuses `internal/nativefri` almost as-is.
- **Curve scope**: bn254 only, hand-written (no bavard codegen). Other curves are additive later.
- **Milestone scope**: native (out-of-circuit) backend only. No in-circuit verifier / recursion in v1.
- **Hash**: sha256 (matches the vendored `internal/nativefri` and old `backend/plonkfri` as-is). Poseidon2 swap deferred to when an in-circuit verifier is built.

## Plan

**Phase 0 — restore the skeleton (near-zero new logic)**
1. Add `PLONK_FRI` back to `backend.ID` (`backend/backend.go`).
2. Copy `backend/plonkfri/bn254/{setup,prove,verify}.go` from commit `1ed22f78^` (last commit before deletion).
3. Repoint their one import: `gnark-crypto/ecc/bn254/fr/fri` → `github.com/consensys/gnark/internal/nativefri` (API already matches: `RADIX_2_FRI`, `Iopp`, `ProofOfProximity`, `OpeningProof`, `GetRho`).
4. Add a thin `backend/plonkfri/plonkfri.go` dispatcher, bn254-only case.

**Phase 1 — make it compile against today's code**
5. Fix `constraint/bn254`/`iop.Polynomial` API drift since 2024 (custom gates, lookups, BSB22 commitments were added to `backend/plonk` after PLONK_FRI was deleted — the restored files predate all of that). Expect deletions/renames, not new design.
6. v1 ceiling (explicit scope cut): plain PLONK gates only (`qL,qR,qO,qM,qC` + copy constraints). No custom gates/lookups/BSB22.

**Phase 2 — prove it works**
7. End-to-end test in the shape of `backend/plonk/plonk_test.go`: toy circuit → `plonkfri.Setup` → `Prove` → `Verify`; assert success and assert tamper detection.

**Phase 3 (later, not v1)**: in-circuit verifier / recursion, building on `std/commitments/fri`.

## Pseudocode (mirrors backend/plonk/bn254, KZG replaced by FRI at each seam)

```
type ProvingKey struct {
    Domain[2] fft.Domain            // identical to plonk
    Ql, Qr, Qm, Qo, Qk []fr.Element  // selector polys, identical to plonk
    S1, S2, S3         []fr.Element  // permutation polys, identical to plonk
    Iopp fri.Iopp                    // <- replaces kzg.ProvingKey
}

type VerifyingKey struct {
    Size, Generator, CosetShift ...
    Qpp [5]fri.ProofOfProximity   // <- replaces KZG commitments to Ql,Qr,Qm,Qo,Qk
    Spp [3]fri.ProofOfProximity   // <- replaces KZG commitments to S1,S2,S3
    Iopp fri.Iopp
}

func Setup(ccs) (*ProvingKey, *VerifyingKey, error) {
    build fft domains, selector polys, permutation polys      // identical to plonk/bn254/setup.go
    pk.Iopp = fri.RADIX_2_FRI.New(domainSize, sha256.New())
    for each selector/permutation poly p:
        vk.*pp[i] = pk.Iopp.BuildProofOfProximity(p)           // was: kzg.Commit(p, srs)
}

func Prove(ccs, pk, witness) (*Proof, error) {
    compute + blind wire polys a,b,c                           // identical to plonk
    proof.LRO[i] = pk.Iopp.BuildProofOfProximity(blinded_i)     // was: kzg.Commit
    beta, gamma  = FiatShamir(transcript)                      // transcript absorbs Merkle roots, not G1 points
    Z = permutation grand product
    proof.Z = pk.Iopp.BuildProofOfProximity(Z)                 // was: kzg.Commit
    alpha = FiatShamir(transcript)
    F = qL*a + qR*b + qO*c + qM*a*b + qC + alpha*(perm check)  // identical algebra to plonk
    H0,H1,H2 = split(F / vanishingPoly)
    proof.H[i] = pk.Iopp.BuildProofOfProximity(Hi)              // was: kzg.Commit
    zeta = FiatShamir(transcript)
    for each committed poly p (+ Z at zeta*g):
        proof.Openings[p] = pk.Iopp.Open(p, positionOf(zeta))   // was: kzg.Open / BatchOpenSinglePoint
}

func Verify(proof, vk, publicWitness) error {
    beta, gamma, alpha, zeta = replay FiatShamir from proof's roots
    for each opened poly:
        vk.Iopp.VerifyOpening(position, proof.Openings[p], vk.*pp)  // was: KZG pairing check
    check PLONK identity at zeta using opened values             // identical algebra to plonk/bn254/verify.go
}
```

## Understanding notes: FRI-PLONK mechanics

Captured from a section-by-section design walkthrough of the pseudocode above, using a toy circuit as a running example, plus a full read of the real old `backend/plonkfri/bn254/{prove,verify}.go` (`1ed22f78^`). Read this before touching Phase 0/1 code — it resolves several mechanism questions the pseudocode alone leaves open.

### Toy example used throughout

Circuit: prove `x²·y = out`, `x=3, y=2, out=18`. Two multiplication gates:
```
gate0: a0=x=3, b0=x=3, c0=t=9      (checks x*x=t)
gate1: a1=t=9, b1=y=2, c1=out=18   (checks t*y=out)
```
`n=2`, Domain[0] = `{1,-1}` (generator `g=-1`). Copy constraints: `{a0,b0}` both hold `x=3`; `{c0,a1}` both hold `t=9`.

### Data structures (Section 1)

- **Two FFT domains**: Domain[0] (size `n`, one point per gate) holds selectors/wires directly. Domain[1] (`~4n`) exists because multiplying two degree-`~n` polynomials (e.g. `qM·a·b`) produces degree `~2n-3n`, which *aliases* on an `n`-point domain — two different higher-degree polynomials can look identical there. Toy check: `a,b` have degree `≤1` on the 2-point domain; `qM·a·b` reaches degree `2`, which 2 points can't pin down uniquely.
- **Selector polys** (`qL,qR,qO,qM,qC`): fixed per-gate "which operation" vectors, interpolated over Domain[0]. Toy: `qM=[1,1]`→constant poly `1`; `qO=[-1,-1]`→constant `-1`; others `0`.
- **Permutation polys** (`S1,S2,S3`/`Sid,Sσ`): encode copy constraints as a permutation over the `3n` wire slots, grouped into cycles. Toy: cycle `{a0,b0}`, cycle `{c0,a1}`, fixed points `{b1,c1}`.
- **Basis**: same polynomial, two representations — coefficients (canonical) vs. values-at-domain-points (evaluation/Lagrange); FFT converts between them. Matches real field names: `CQl` (canonical), `LQkIncompleteDomainSmall` (Lagrange, small domain), `EvaluationQlDomainBigBitReversed` (evaluation, big domain, bit-reversed).
- **VerifyingKey substitution**: KZG commitment (1 group element) → `fri.ProofOfProximity` (a full FRI proof: Merkle root + every folding round), baked into VK permanently at setup. Real cost trade-off: FRI VK is materially bigger than KZG's.

### Setup (Section 2)

Build domains/polys as usual, then `pk.Iopp = fri.RADIX_2_FRI.New(domainSize, sha256.New())` (domainSize = Domain[0].Cardinality + 2, padded for blinding), then commit every selector/permutation poly once via `BuildProofOfProximity` (was `kzg.Commit`). Runs once per circuit; cost is amortized into VK size, not paid per-proof.

### Prove, step by step (Section 3)

1. Interpolate wire polys `a,b,c` from the witness, then blind (add random·vanishing-poly) so an opening at a random challenge point later can't leak the witness.
2. Commit blinded `a,b,c` via FRI → `proof.LRO`.
3. Derive `beta,gamma` via Fiat-Shamir (hash of the just-published Merkle roots) — build the permutation grand-product `Z` (see below).
4. Commit `Z` via FRI.
5. Derive `alpha`, combine every "must vanish on the domain" check into one polynomial `F = check1 + alpha·check2 + alpha²·check3` (gate eq + Z's boundary/step conditions) — confirmed structure, see real-code findings below.
6. Quotient `H = F / vanishingPoly` — only divides evenly if the witness is valid. This is the core succinctness trick: one division stands in for `n` separate checks.
7. Split `H` into `H0,H1,H2` (same aliasing/degree reasoning as the two domains), commit each via FRI.
8. Derive `zeta`, open every committed polynomial there. Soundness argument: two different bounded-degree polynomials agree at a random point with negligible probability (Schwartz-Zippel), so one spot-check stands in for a full-domain check.

**`beta`/`gamma`/`Z` in depth**: gate equations only check *within* one gate — nothing stops a cheating prover from submitting an output on one gate and an unrelated input on the next, unless copy constraints are checked separately. Mechanism: give every wire slot a label (`Sid` = its own default label; `Sσ` = the label of whatever slot it's linked to). Toy labels: `Sid=(a0:1,a1:-1,b0:2,b1:-2,c0:3,c1:-3)`, `Sσ=(a0:2,a1:3,b0:1,b1:-2,c0:-1,c1:-3)`. For challenge `beta,gamma`, compute `value + beta·label + gamma` per slot and multiply all six together, once using `Sid` labels and once using `Sσ` labels — if real copy constraints hold, both products match (same multiset of factors, permuted); worked example with `beta=2,gamma=3` gives `216000` both ways. `Z` is the *running* product of these per-step ratios, and lands back on exactly `1` after a full domain pass iff every copy constraint held (toy: `1 → 1.8 → 1.0` exactly). Two challenges rather than one: `beta` ties each slot's *label* into the check (so it verifies "value X is specifically in slot L", not just "value X exists somewhere"); `gamma` is an independent second random shift — together they close off algebraic tricks a single random value would leave open.

**Fiat-Shamir mechanism** (confirmed by reading `gnark-crypto/fiat-shamir/transcript.go`): no live verifier — a hash function simulates one. `Transcript.ComputeChallenge(name) = H(name || previous_challenge_value || all_bound_values)`, chained. Prover commits (publishes Merkle roots) *before* the challenge derived from them exists, so it has zero freedom to pick convenient witness values for a known challenge. The verifier never trusts the prover's claimed challenges — it recomputes all of them itself from the same public data and the final check only passes if the prover used the same ones.

### Verify (Section 4)

Replay Fiat-Shamir from the proof's published roots + public inputs to get `beta,gamma,alpha`, and a `zeta` derived as `GenOpening^position` (see below). `VerifyOpening` does two jobs per polynomial: (1) Merkle-path check (this leaf really is at this position in the committed tree) and (2) low-degree/proximity check (the tree's leaves really are evaluations of *some* bounded-degree polynomial) — job (2) is what "IOPP" means and is unique to FRI; a KZG commitment gets it for free from how it's constructed. Setup polynomials get opened via FRI too, even though they're public, because direct evaluation would cost `O(d)` and break succinctness (this is explicitly called out in the RedShift paper). Final check: recombine `H0,H1,H2→H(zeta)`, rebuild `F(zeta)` from opened values via the same `alpha`-combination as `Prove`, evaluate the vanishing polynomial at `zeta`, and check `F(zeta) =? Z_H(zeta)·H(zeta)` — one scalar equation standing in for the whole circuit having been satisfied.

### Confirmed by reading the real old code (`backend/plonkfri/bn254/{prove,verify}.go` @ `1ed22f78^`)

- **`zeta` is not sampled as an arbitrary field element.** Fiat-Shamir output is reduced mod the FRI domain size (`friSize = 2·rho·vk.Size`) into an integer *position* first; `zeta = vk.GenOpening ^ position` is computed only afterward, purely for the final algebraic check. There is no general "open at an arbitrary point" (RedShift's Algorithm 1 LPC quotient-wrapper) anywhere in this code — it sidesteps that entirely by construction. This resolves what was an open question during the pseudocode walkthrough.
- **No batching, confirmed**: 18 separate `Open`/`VerifyOpening` calls per proof (`ql,qr,qm,qo,qk,l,r,o,h1,h2,h3,s1,s2,s3,id1,id2,id3,z,zshift`), each a full independent FRI proof. Real, measured proof-size cost vs. KZG's one batched opening — a likely future optimization target, out of scope for v1.
- **Public inputs bypass FRI entirely**: `qk` is committed/opened in an "incomplete" form (zeroed at public-input slots); the verifier adds the public-input contribution back in locally via `completeQk()`, a direct Lagrange-basis formula using the public witness it already has — no commitment needed since public inputs aren't secret.
- **Blinding degree isn't uniform**: `L,R,O` blinded with 2 random coefficients (order 1); `Z` blinded with 3 (order 2) — why `Setup`'s FRI domain padding is "+2" (sized for `Z`, the larger case) and why the final verify exponent is `zeta^(Size+2)`, not `zeta^Size`.
- **A naming swap in the real code (harmless, but a trap for future maintainers)** — identical in both `prove.go` and `verify.go`:
  ```go
  beta, err  := deriveRandomnessFixedSize(fs, "gamma", dataFiatShamir...)  // transcript slot "gamma" → Go var beta
  gamma, err := deriveRandomness(fs, "beta", nil)                          // transcript slot "beta"  → Go var gamma
  ```
  Internally consistent (prover and verifier both do the identical swap), so not a bug — do **not** "fix" this when porting without changing both sides identically.
- **Scope cut confirmed real**: `evalConstraintsInd` only computes `ql·l+qr·r+qm·l·r+qo·o+qk` — no custom gates, no lookups, no BSB22 commitments anywhere in this code. Consistent with the v1 ceiling already decided.
- **Not yet checked**: how much `constraint/bn254.SparseR1CS`'s `Solve()`/`SparseR1CSSolution` API has drifted since this code was written (2024) — still a Phase 1 task.
- **Not yet read**: `computeQuotientCanonical`'s coset-FFT trick in detail, and the permutation-index bookkeeping (`pk.Permutation[i]`) in `computeBlindedZCanonical` — flagged as unread, not blocking Phase 0/1 start.

## Open questions / next steps

- [ ] Start Phase 0: restore `backend/plonkfri/bn254` from `1ed22f78^`, repoint import to `internal/nativefri`.
- [ ] Phase 1: check `constraint/bn254.SparseR1CS`'s `Solve()`/`SparseR1CSSolution` API drift since 2024 against what `prove.go` calls.
- [ ] Read `computeQuotientCanonical`'s coset-FFT trick and the `pk.Permutation[i]` bookkeeping in `computeBlindedZCanonical` in full (not yet done).
- [ ] Clarify what `resources/` (`2019-1400.pdf`, `out.txt`) should be: commit it (it's the working reference paper) or gitignore it.

## Session Log

### 2026-09-26
- Reset to a clean start: confirmed `master` (`fd5c2443`) has no FRI code (SSH access to `origin` fixed and fetch confirmed up to date); created working branch `pq-pcs-dev` off master, leaving `restore-fri-gadget` (`fb6e65da`) intact for reference.
- Set up permanent SSH access to GitHub (Keychain-backed agent key + `~/.ssh/config` entry) so `git fetch`/`git log` on remote refs works in every future session.
- Read `resources/2019-1400.pdf` (RedShift paper) and inspected prior-art commits `1ed22f78` (deletion of `backend/plonkfri`) and the restored `internal/nativefri`/`std/commitments/fri` gadgets, plus gnark-crypto v0.21.0's koalabear packages (confirmed: no FRI code there, only Vortex).
- Locked in v1 design: bn254 fr field, single curve hand-written, native-backend-only milestone, sha256 hash. Wrote the restore-based plan and pseudocode above. No code changes yet — next session starts Phase 0.
- Walked the Setup/Prove/Verify pseudocode section by section with the user, building a worked toy-circuit numeric example (incl. a from-scratch derivation of the permutation grand-product `Z` with real numbers) and confirming the Fiat-Shamir transcript mechanism by reading `gnark-crypto/fiat-shamir/transcript.go`.
- Read the real old `backend/plonkfri/bn254/{prove,verify}.go` (`1ed22f78^`) in full and reconciled it against the pseudocode — see "Understanding notes" section above for what was confirmed, refined, or newly discovered (notably: `zeta` is `GenOpening^position`, not an arbitrary field element; no opening batching (18 separate FRI proofs per proof); public inputs bypass FRI via `completeQk()`; non-uniform blinding degrees; a harmless but confusing beta/gamma transcript-label swap present identically in both files). No code changes yet.
