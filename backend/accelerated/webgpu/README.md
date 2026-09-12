# gnark WebGPU backend

Experimental browser acceleration of gnark's Groth16 and PLONK provers over
BN254, BLS12-377 and BLS12-381. The prover is gnark's native Go prover compiled
to wasm; its heavy operations (multi-scalar multiplications, FFTs, the PLONK
quotient numerator) are offloaded to WGSL compute shaders driven by a
TypeScript runtime.

## Disclaimer

This package is experimental. The APIs may change and the backend is not
audited.

## How it works

The native provers (`backend/groth16`, `backend/plonk`) expose an
`Accelerator` interface on their proving keys: a handful of coarse-grained
hooks (`MultiExp`, `ComputeH` for Groth16; `MultiExp`, `ToCanonical`,
`ComputeNumerator` for PLONK). When no accelerator is attached the prover runs
gnark-crypto on the CPU, so the CPU path is unchanged. This package provides
WebGPU implementations of those hooks:

1. `Prepare(pk)` uploads the proving key bases to the GPU once, through
   `syscall/js`, and attaches the accelerator to the key.
2. `groth16.Prove` / `plonk.Prove` then run unchanged; each hook call crosses
   the Go to JavaScript boundary with the raw little-endian Montgomery limbs of
   gnark-crypto elements (no re-encoding on the Go side), the TypeScript runtime
   dispatches the WGSL kernels, and results come back as affine points or
   coefficient vectors.

KZG openings go through gnark-crypto's `kzg.OpenWithCommitter` and
`kzg.BatchOpenSinglePointWithCommitter`, so the opening and folding logic is
not duplicated here.

## Layout

- `groth16/`, `plonk/`: `Prepare` / `Release` facades and, per curve, one
  generated `accelerator.go` implementing the native prover's `Accelerator`
  interface. The `internal/wasmruntime/{native,webgpu}` commands are the wasm
  entrypoints loaded by the TypeScript package (native keeps the CPU prover for
  comparison).
- `internal/bridge/`: Go client of the JavaScript bridge objects
  (`gnarkGroth16WebGPU`, `gnarkPlonkWebGPU`) and the byte protocol.
- `internal/wasmruntime/`: JavaScript-facing runtime (read keys and
  constraint systems, prove, verify) shared by the four entrypoints.
- `internal/generator/`: bavard generator. Produces the per-curve Go
  accelerators (`templates/go`), the per-curve WGSL shaders (`templates/wgsl`,
  with all field constants computed from gnark-crypto) and the Go test-vector
  builders. Run `go run .` in that directory after editing a template.
- `shaders/`: WGSL kernels. `shaders/curves/*` are generated, `shaders/common/*`
  are hand-written and curve-agnostic (MSM bucket sort, Pippenger stages).
- `web/`: TypeScript runtime, browser test pages, the npm build and
  `scripts/e2e.mjs`, which runs the test pages headlessly with Playwright.

The Go packages build only for `GOOS=js GOARCH=wasm`.

## Build

```sh
cd backend/accelerated/webgpu/web
npm ci
npm run build:all        # lint, shaders bundle, TypeScript, Go wasm assets
```

Narrower targets: `npm run build`, `build:shaders`, `build:wasm`,
`build:wasm:groth16`, `build:wasm:plonk`, `lint`.

## Test

Test fixtures for the browser pages are produced with
`npm run build:test-fixtures:<suite>` (api, groth16, plonk). The pages can be
served from `web/` and opened at `tests/index.html`, or run headlessly:

```sh
npm run test:e2e     # API suites + one verified proof per system and curve
npm run bench:e2e    # prover benchmark matrix (2^15 and 2^18 fixtures)
```

Set `PW_CHANNEL=chrome` to use the system Chrome instead of Playwright's
Chromium. `.github/workflows/webgpu.yml` runs `test:e2e` on pull requests.
