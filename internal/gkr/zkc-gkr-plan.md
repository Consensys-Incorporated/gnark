# Poseidon2 by GKR in Ray: plan outline

The goal is to prove the Poseidon2 compressions of a Ray proof with gnark's GKR prover
(`gkr/koalabear` with the `gkr-poseidon2` circuit) instead of arithmetizing each compression, and
to verify the GKR proof inside the recursion guest through a ZkC precompile.

Facts this outline rests on:

- Ray's coins and gnark-crypto's `extensions.E6` are the same field,
  $\mathbb{F}_{p^6} = \mathbb{F}_{p^2}[v]/(v^3 - (u+1))$ over $\mathbb{F}_{p^2} = \mathbb{F}_p[u]/(u^2 - 3)$.
- Every column a ZkC program defines is committed in WIOP round 0, and coins exist only from
  round 1 on, so a ZkC program cannot read a coin of the proof it belongs to.
- Every Poseidon2 use in Verifier Ray is a compression $(\ell, r) \mapsto P(\ell, r)_{8..16} + r$:
  Merkle nodes, and the Merkle–Damgård transcript. Today these are built in Zig on top of a
  permutation precompile, whose ZkC implementation costs about $9 \cdot 10^4$ trace cells per call.
- The WIOP has no multilinear-evaluation query. Its queries reduce to univariate (Lagrange)
  evaluations, discharged by multi-size FRI.
- gnark's GKR `Prove` and `Verify` start drawing challenges from the hasher they are given. With
  `ConsolidateAll`, the claims they return are evaluations of the 24 input and output columns'
  multilinear extensions at a single point $r^\ast \in \mathbb{F}_{p^6}^n$, whose first coordinate
  is the most significant bit of the instance index.

## 1. Architecture (to decide)

**A. GKR as a WIOP protocol component (recommended).** In proof $k$:

1. The compressions form a table $T$ of 24 columns, a `#[native]` ZkC module with no
   constraints of its own, committed in round 0.
2. In round 1, the prover seeds gnark's transcript with $T$'s round-0 commitment root, runs
   `Prove`, and sends the proof and the claims $(r^\ast, y)$ as cells.
3. In round 2, the claims are discharged by an eq-table column and a `LogDerivativeSum`.
4. Proof $k$'s verifier runs gnark's `Verify` with the same seed. In the recursion guest of
   layer $k+1$, that verification is a ZkC precompile; its transcript compressions are ordinary
   compressions of layer $k+1$, proven by layer $k+1$'s GKR.

**B. GKR verified in the same proof.** The verifier is a ZkC program in proof $k$ itself. $T$
must then be committed in a preflight, as the bus columns are for the shared randomness
$\gamma$, with the seed passed as a public input that the next layer checks against the
preflight root. The verifier's own transcript compressions depend on that seed and so cannot be
rows of $T$; they need a second Poseidon2 arithmetization in the same proof.

A needs no preflight and no second Poseidon2 arithmetization. Its cost is a new WIOP query and a
verifier step in Verifier Ray. The rest of this outline assumes A.

## 2. Work packages

### gnark

- **G1. Export the compiled circuit and the schedule helpers** from `internal/gkr/gkrcore` to
  `gkr` (prompt written).
- **G2. Fix the transcript's byte stream** before the ZkC verifier is written. Today each
  element of $E_6$ costs one compression; writing a whole `Bind` at once would cost three
  quarters of one (see future work). Either way, document the stream: per write, the
  left-padding of each element's six coordinates into a block of eight, the separator write,
  and challenges read as the first six elements of the state.

### arithmetization (ZkC)

- **Z1. A compression precompile.** A `#[native]` ZkC function `poseidon2_compress` with 16
  inputs and 8 outputs, keeping today's permutation body plus the feed-forward as its reference
  body. It is reached through a custom opcode (predecoding check, interpreter case, RAM entry
  point) and exposed to Zig as `lineth_zkvm_poseidon2_compress`. Verifier Ray's `compressInPlace`
  switches to it.
- **Z2. An $E_6$ library.** Addition, subtraction, multiplication, multiplication by a base-field
  element, and inversion as a prover-supplied value checked by one multiplication. Inverses are
  needed for $1 - q_j$ in the single-source zero-check rounds.
- **Z3. The GKR transcript in ZkC.** `Bind` and `Challenge` over `poseidon2_compress`,
  reproducing G2's byte stream.
- **Z4. The GKR verifier precompile.** A custom opcode whose ZkC entry point reads the seed and
  the proof from guest RAM, runs the generated verifier (X1), and writes $(r^\ast, y)$ back.

### prover-ray

- **R1. The native module.** In `zkcdriver/native_modules.go`, a `poseidon2_compress` branch
  creating $T$'s 24 columns as a dynamic module. Its padding rows are the instance with zero
  inputs, so every column's padding value is the corresponding coordinate of that instance.
- **R2. The GKR query and its compiler pass.** A prover action builds the assignment from $T$,
  writes the seed into a `POSEIDON2_KOALABEAR` hasher and runs `gkrkoalabear.Prove`. The proof
  and the claims become round-1 cells.
- **R3. Multilinear evaluation.** In $T$'s module, an extension column $E$ with
  $E[i] = \mathrm{eq}(r^\ast, i)$, committed after $r^\ast$, and constrained by
  $E[0] = \prod_j (1 - r^\ast_j)$ and one shifted recurrence per variable on precomputed bit
  columns. Then a `LogDerivativeSum` with denominator 1 asserts
  $\sum_i \bigl(\sum_c \lambda^c C_c[i]\bigr) E[i] = \sum_c \lambda^c y_c$ for a coin $\lambda$.
  It may be worth making this a reusable `MultilinearEval` query with its own pass.
- **R4. The native verifier action.** `gkrkoalabear.Verify` with the same seed, checking that
  its claims equal the round-1 cells.
- **R5. Tests.** A small ZkC program calling `poseidon2_compress`, proven and verified end to
  end, and rejected when a row of $T$, a proof cell or a claim is tampered with.

### Verifier generator

- **X1. Generate the ZkC verifier from (Circuit, Schedule).** A Go program in prover-ray, using
  G1's exports, emits a straight-line ZkC function per level. The structure comes from the
  schedule; gate evaluations are transcriptions of the gate bytecode; constants come from the
  bytecode's constant pool. Repeated pieces (an $E_6$ product, a sumcheck round check, an eq
  evaluation) are ZkC functions, so that they become shared tables.
- **X2. Test it against gnark.** For proofs produced by `gkrkoalabear.Prove` at several $n$, the
  ZkC verifier executed by the ZkC tracer returns gnark's claims, and fails on tampered proofs.

### verifier-ray

- **V1. Proof ABI** for the GKR cells.
- **V2. The GKR query's verifier step** (`query/gkr.zig`): call the Z4 precompile on the seed and
  the proof, and compare its output with the claim cells. The eq-table and `LogDerivativeSum`
  checks are those of existing queries.
- **V3. A fallback without accelerators.** When `disable_accelerators` is set, a Zig GKR
  verifier is needed, which X1 could emit as a second backend.

## 3. Milestones

1. **Sound native proofs:** R1–R5. Until R2–R4 land, $T$ is unconstrained and the precompile
   unsound, so they belong together.
2. **The ZkC verifier in isolation:** G1, G2, Z2–Z3, X1–X2.
3. **Recursion:** Z1, Z4, V1–V3; a recursion guest verifies a proof containing the GKR query.
4. **Measurement:** trace cells per compression in recursion against today's $9 \cdot 10^4$.

## 4. Open questions

- **The seed.** Multi-size FRI commits one root per native size, covering every round-0 column
  of that size. The seed should bind that root and $T$'s size $n$.
- **Absorbing the proof.** The GKR proof is about 2500 elements of $E_6$ at $n = 16$. As cells,
  the WIOP transcript absorbs them too; absorbing only the GKR transcript's final state would
  bind them as well, at a fraction of the cost.
- **The terminal layer.** The last proof is verified by an emulated PLONK verifier in gnark,
  which would need an in-circuit GKR verifier over emulated $E_6$, unless the last layer proves
  its compressions without GKR.
- **Sharding.** Application shards contain $T$ too, each with its own GKR proof and seed.
- **The verifier's cost.** About $10^4$ products in $E_6$, one hint-checked inverse per round of
  each single-source level, about 2500 compressions and about $1.5 \cdot 10^4$ RAM reads at
  $n = 16$, all to be measured once X1 exists.
