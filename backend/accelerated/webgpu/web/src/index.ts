/**
 * gnark-webgpu — WebGPU-accelerated elliptic curve arithmetic for BN254, BLS12-381, and BLS12-377.
 *
 * ## Quick start
 *
 * ```typescript
 * import { createCurveGPUContext, createBN254 } from "gnark-webgpu";
 *
 * const ctx = await createCurveGPUContext();
 * const curve = await createBN254(ctx);
 *
 * // G1 scalar multiplication
 * const result = await curve.g1.scalarMulAffine(base, scalar);
 *
 * // Multi-scalar multiplication (Pippenger)
 * const msm = await curve.g1msm.pippengerPackedJacobianBases(bases, scalars, opts);
 *
 * ctx.close(); // release GPU resources
 * ```
 *
 * ## GPU context
 *
 * `createCurveGPUContext` requests a WebGPU device.  Pass {@link CurveGPUContextOptions}
 * to control power preference, required adapter limits, and debug logging.
 * The returned {@link CurveGPUContext} must be closed with `close()` when no longer needed
 * to release the underlying `GPUDevice` and buffer pool.
 *
 * ## Curve modules
 *
 * Use `createBN254`, `createBLS12381`, or `createBLS12377` (or the lower-level `createCurveModule`) to
 * create a {@link CurveModule}.  Each module contains sub-modules for field arithmetic
 * ({@link FieldModule} `fr`, `fp`), curve arithmetic ({@link GroupModule} as `g1` / `g2`),
 * NTT ({@link NTTModule}), MSM ({@link MSMModule} as `g1msm` / `g2msm`) and the Go WASM
 * provers ({@link ProofModule} as `groth16` / `plonk`).
 *
 * ## Coordinate conventions
 *
 * Public byte-oriented APIs use fixed-width little-endian `Uint8Array` values.
 * Field arithmetic and point coordinates use Montgomery form unless a method
 * explicitly says it accepts or returns regular little-endian values.
 *
 * - **MSM scalars** — regular little-endian scalar-field bytes.
 * - **Affine/Jacobian coordinates** — Montgomery little-endian base-field bytes.
 * - **Packed vectors** — concatenated fixed-width elements in the representation
 *   named by the method (`PackedRegular` or `PackedMont`).
 *
 * ## Shader bundling
 *
 * By default the library fetches WGSL shader sources at runtime.  To eliminate the runtime
 * `fetch()` dependency, import the generated bundle as a side-effect before creating any
 * curve module:
 *
 * ```typescript
 * import "gnark-webgpu/shader_bundle"; // sets bundled shaders via setBundledShaders()
 * ```
 *
 * Or call {@link setBundledShaders} directly with a `Record<string, string>` of path → WGSL.
 *
 * ## Error handling
 *
 * All errors thrown by this library are instances of {@link CurveGPUError} or one of its
 * subclasses:
 * - {@link CurveGPUNotSupportedError} — WebGPU unavailable or required limits not met
 * - {@link CurveGPUDeviceLostError} — GPU device was lost during operation
 * - {@link CurveGPUShaderError} — shader fetch or compilation failure
 *
 * @module
 */
export type {
  CurveGPUAffinePoint,
  CurveGPUAdapterDiagnostics,
  CurveGPUContext,
  CurveGPUContextOptions,
  CurveGPURequestedLimits,
  CurveGPUElementBytes,
  CurveGPUFp2Element,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  CurveGPUJacobianPoint,
  CurveGPUPackedPointLayout,
  CurveGPUMSMOptions,
  CurveModule,
  FieldModule,
  GroupModule,
  G1Module,
  G2Module,
  MSMModule,
  G1MSMModule,
  G2MSMModule,
  ResidentBases,
  NTTModule,
  Groth16QuotientModule,
  ProofConstraintSystem,
  ProofHandle,
  ProofModule,
  ProofRuntimeKind,
  ProofRuntimeOptions,
  Groth16Module,
  Groth16ProvingKeyFormat,
  PlonkModule,
  PlonkProvingKeyFormat,
  SupportedCurveID,
  // Deprecated aliases kept for source compatibility.
  Groth16ConstraintSystem,
  Groth16Handle,
  Groth16ProvingKey,
  Groth16RuntimeKind,
  Groth16RuntimeOptions,
  Groth16VerificationKey,
  PlonkConstraintSystem,
  PlonkHandle,
  PlonkProvingKey,
  PlonkRuntimeKind,
  PlonkRuntimeOptions,
  PlonkVerificationKey,
} from "./curvegpu/api.js";

export {
  CurveGPUError,
  CurveGPUNotSupportedError,
  CurveGPUDeviceLostError,
  CurveGPUShaderError,
} from "./curvegpu/errors.js";

export { setBundledShaders } from "./curvegpu/shaders.js";

export { createCurveGPUContext } from "./curvegpu/context.js";

export {
  createBLS12377,
  createBLS12381,
  createBN254,
  createCurveModule,
  curveDefinition,
  shapeFor,
  supportedCurveIds,
} from "./curvegpu/curves.js";

export type { CurveDefinition } from "./curvegpu/curves.js";

export type { CurveID, FieldID, FieldShape } from "./curvegpu/types.js";
export { defaultGroth16RuntimeURLs, defaultPlonkRuntimeURLs } from "./curvegpu/proof_module.js";

export type {
  MontgomeryLEBytes,
  PackedMontgomeryLEBytes,
  PackedRegularLEBytes,
  RegularLEBytes,
} from "./curvegpu/encoding.js";
export { hexToBytesLE } from "./curvegpu/encoding.js";

export {
  joinU32LimbsToBigUint64,
  joinU32LimbsToBytesLE,
  splitBigUint64WordsToU32,
  splitBytesLEToU32,
} from "./curvegpu/convert.js";
