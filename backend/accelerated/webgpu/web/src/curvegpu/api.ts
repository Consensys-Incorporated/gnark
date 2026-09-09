import type { FieldShape } from "./types.js";
import type { BufferPool } from "./buffer_pool.js";

export type { CurveGPUError, CurveGPUNotSupportedError, CurveGPUDeviceLostError, CurveGPUShaderError } from "./errors.js";

/**
 * Curves currently exposed by the browser library surface.
 */
export type SupportedCurveID = "bn254" | "bls12_381" | "bls12_377";

/**
 * Canonical byte representation for field and scalar values.
 *
 * For `fr` and `fp` module operations, values are little-endian byte strings
 * in Montgomery form unless explicitly converted with
 * `toMontgomery` / `fromMontgomery`.
 *
 * For scalar multiplication and MSM, scalars are little-endian 32-byte
 * scalar-field elements in regular form.
 */
export type CurveGPUElementBytes = Uint8Array;

/**
 * Affine G1 point represented as little-endian field-element byte strings.
 */
export interface CurveGPUAffinePoint {
  x: Uint8Array;
  y: Uint8Array;
}

/**
 * Jacobian G1 point represented as little-endian field-element byte strings.
 */
export interface CurveGPUJacobianPoint {
  x: Uint8Array;
  y: Uint8Array;
  z: Uint8Array;
}

/**
 * Quadratic-extension field element represented as two base-field coordinates.
 */
export interface CurveGPUFp2Element {
  c0: Uint8Array;
  c1: Uint8Array;
}

/**
 * Affine G2 point represented over the quadratic extension field.
 */
export interface CurveGPUG2AffinePoint {
  x: CurveGPUFp2Element;
  y: CurveGPUFp2Element;
}

/**
 * Jacobian G2 point represented over the quadratic extension field.
 */
export interface CurveGPUG2JacobianPoint {
  x: CurveGPUFp2Element;
  y: CurveGPUFp2Element;
  z: CurveGPUFp2Element;
}

/**
 * Options for affine MSM execution.
 *
 * All fields are optional; sensible defaults are chosen automatically.
 */
export type CurveGPUMSMOptions = {
  /**
   * Number of independent MSM instances to compute in a single call.
   * Each instance uses `termsPerInstance` consecutive base/scalar pairs
   * from the input arrays. Defaults to `1`.
   */
  count?: number;
  /**
   * Number of (base, scalar) pairs per MSM instance. When `count` is 1 and
   * this field is omitted, the full length of the input arrays is used.
   */
  termsPerInstance?: number;
  /**
   * Pippenger window size in bits. If omitted, the library selects a window
   * size based on `termsPerInstance` via `bestWindow()`.
   */
  window?: number;
  /**
   * Maximum number of terms processed per GPU bucket dispatch. Smaller values
   * spread work across more threads at the cost of more bucket entries.
   * Defaults to `256`.
   */
  maxChunkSize?: number;
};

/**
 * Supported packed point encodings for bulk APIs.
 *
 * `"jacobian_x_y_z_le"` — three consecutive little-endian coordinates in the
 * order `x, y, z`. For affine points represented in Jacobian form set `z` to
 * the Montgomery-form one element; for the point at infinity leave all
 * components zero-filled.
 */
export type CurveGPUPackedPointLayout = "jacobian_x_y_z_le";

/**
 * Subset of device limits that matter for the current curve workloads.
 */
export type CurveGPURequestedLimits = {
  /** Maximum byte size of a single storage buffer binding. */
  maxStorageBufferBindingSize?: number;
  /** Maximum byte size of a GPU buffer. */
  maxBufferSize?: number;
};

/**
 * Human-readable adapter details useful for logging, debugging, and telemetry.
 */
export type CurveGPUAdapterDiagnostics = {
  /** GPU vendor string, e.g. `"apple"`, `"nvidia"`, `"intel"`. */
  vendor?: string;
  /** GPU architecture string, e.g. `"common-3"`. */
  architecture?: string;
  /** Free-form GPU description provided by the driver. */
  description?: string;
  /** Whether the browser selected a software (fallback) adapter. */
  isFallbackAdapter?: boolean;
};

/**
 * Options for acquiring a browser WebGPU context.
 */
export type CurveGPUContextOptions = {
  /**
   * Hint to the browser about which GPU to prefer on multi-GPU systems.
   * `"high-performance"` requests a discrete GPU; `"low-power"` requests an
   * integrated GPU. Defaults to the browser's own selection.
   */
  powerPreference?: GPUPowerPreference;
  /**
   * When `true` (the default), the adapter's reported limits for
   * `maxStorageBufferBindingSize` and `maxBufferSize` are propagated to
   * `requestDevice`. Set to `false` to request a device with default limits,
   * which may restrict the maximum MSM size.
   */
  requireAdapterLimits?: boolean;
  /**
   * Explicit device limits to request, overriding the adapter-derived values.
   * Useful when you know the exact buffer sizes your workload needs.
   */
  requiredLimits?: CurveGPURequestedLimits;
  /** Enable verbose debug logging from GPU operations. Defaults to `false`. */
  debug?: boolean;
};

/**
 * Shared browser WebGPU context for all curve operations.
 *
 * This is the top-level object a consumer creates once, then reuses for
 * field, group, NTT, and MSM work.
 */
export interface CurveGPUContext {
  /** The underlying WebGPU adapter selected by the browser. */
  readonly adapter: GPUAdapter;
  /** The WebGPU logical device used for all GPU operations. */
  readonly device: GPUDevice;
  /** Adapter metadata, or `null` if `requestAdapterInfo()` is unavailable. */
  readonly adapterInfo: GPUAdapterInfo | null;
  /** Human-readable diagnostics derived from the adapter. */
  readonly diagnostics: CurveGPUAdapterDiagnostics;
  /** Limits that were requested when the device was created. */
  readonly requestedLimits: CurveGPURequestedLimits;
  /** Whether verbose debug logging is enabled for GPU operations. */
  readonly debug: boolean;
  /** Maximum compute workgroup size supported by the device. */
  readonly maxWorkgroupSize: number;
  /** Largest storage buffer binding the device accepts, in bytes. */
  readonly maxStorageBufferBindingSize: number;
  /** Required alignment of storage buffer binding offsets, in bytes. */
  readonly minStorageBufferOffsetAlignment: number;
  /** GPU buffer pool shared across all operations on this context. */
  readonly bufferPool: BufferPool;
  /**
   * Resolves when the GPU device is lost.
   *
   * Consumers can attach a handler to this promise to react to unexpected
   * device loss (driver crash, GPU reset, tab backgrounded on mobile, etc.).
   * The resolved value is the browser's `GPUDeviceLostInfo` object.
   */
  readonly deviceLost: Promise<GPUDeviceLostInfo>;
  /**
   * Release any library-owned resources associated with the context.
   *
   * Drains the buffer pool and performs any other cleanup. Browser WebGPU
   * device lifetime is still managed by the browser, so this is a logical
   * shutdown hook rather than a hard device destroy.
   */
  close(): void;
}

/**
 * Field arithmetic bound to a specific curve field.
 *
 * All methods except `toMontgomery` and `fromMontgomery` operate on
 * Montgomery-form little-endian byte strings.
 *
 * Batch variants execute the same operation element-wise over equal-length
 * slices.
 */
export interface FieldModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly field: "fr" | "fp";
  readonly shape: FieldShape;
  readonly byteSize: number;
  /** Return the additive identity as a zero-filled byte string. */
  zero(): CurveGPUElementBytes;
  /** Copy one element through the GPU implementation. */
  copy(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  copyBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Return the multiplicative identity in Montgomery form. */
  montOne(): Promise<CurveGPUElementBytes>;
  /** Check modular equality. */
  equal(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<boolean>;
  equalBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<boolean[]>;
  /** Modular addition. */
  add(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  addBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular subtraction. */
  sub(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  subBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular negation. */
  neg(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  negBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular doubling. */
  double(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  doubleBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Modular multiplication. */
  mul(a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  mulBatch(a: readonly CurveGPUElementBytes[], b: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Element-wise multiplication over packed Montgomery-form field elements. */
  mulPackedMont(a: Uint8Array, b: Uint8Array): Promise<Uint8Array>;
  /** Modular squaring. */
  square(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  squareBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Reduce a value into canonical Montgomery form. */
  normalizeMont(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  normalizeMontBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Convert a regular little-endian field element into Montgomery form. */
  toMontgomery(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  toMontgomeryBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /**
   * Convert a packed sequence of regular little-endian field elements into
   * Montgomery form.
   */
  toMontgomeryPacked(values: Uint8Array): Promise<Uint8Array>;
  /** Convert a Montgomery-form element back into regular little-endian bytes. */
  fromMontgomery(value: CurveGPUElementBytes): Promise<CurveGPUElementBytes>;
  fromMontgomeryBatch(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /**
   * Convert a packed sequence of Montgomery-form field elements back into
   * regular little-endian bytes.
   */
  fromMontgomeryPacked(values: Uint8Array): Promise<Uint8Array>;
}

/**
 * Group arithmetic for a specific curve, generic over the point
 * representation: `A` is the affine point type and `J` the Jacobian one.
 *
 * G1 points use base-field byte strings as coordinates; G2 points use
 * `CurveGPUFp2Element` pairs. Results returned "in affine form" are Jacobian
 * points normalized to `z = 1` with only `x` and `y` reported.
 */
export interface GroupModule<A, J> {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly group: "g1" | "g2";
  /** Byte size of one coordinate (base field for G1, `Fp2` for G2). */
  readonly coordinateBytes: number;
  /** Byte size of one Jacobian point (`3 * coordinateBytes`). */
  readonly pointBytes: number;
  /** Return the affine point at infinity (all-zero coordinates). */
  affineInfinity(): A;
  /** Return the zero Jacobian point (all-zero coordinates) synchronously. */
  jacobianZero(): J;
  /** Copy a Jacobian point through the GPU implementation. */
  copy(point: J): Promise<J>;
  copyBatch(points: readonly J[]): Promise<J[]>;
  /** Construct the Jacobian point at infinity via the GPU. */
  jacobianInfinity(): Promise<J>;
  jacobianInfinityBatch(count: number): Promise<J[]>;
  /** Lift affine points into Jacobian coordinates. */
  affineToJacobian(point: A): Promise<J>;
  affineToJacobianBatch(points: readonly A[]): Promise<J[]>;
  /** Negate Jacobian points. */
  negJacobian(point: J): Promise<J>;
  negJacobianBatch(points: readonly J[]): Promise<J[]>;
  /** Double Jacobian points. */
  doubleJacobian(point: J): Promise<J>;
  doubleJacobianBatch(points: readonly J[]): Promise<J[]>;
  /** Add an affine point into a Jacobian accumulator (mixed addition). */
  addMixed(point: J, affine: A): Promise<J>;
  addMixedBatch(points: readonly J[], affine: readonly A[]): Promise<J[]>;
  /** Convert Jacobian points to affine coordinates. */
  jacobianToAffine(point: J): Promise<A>;
  jacobianToAffineBatch(points: readonly J[]): Promise<A[]>;
  /** Add two affine points and return the result in Jacobian form (`z = 1`). */
  affineAdd(a: A, b: A): Promise<J>;
  affineAddBatch(a: readonly A[], b: readonly A[]): Promise<J[]>;
  /** Multiply an affine base by a scalar and return the result in Jacobian form (`z = 1`). */
  scalarMulAffine(base: A, scalar: CurveGPUElementBytes): Promise<J>;
  scalarMulAffineBatch(bases: readonly A[], scalars: readonly CurveGPUElementBytes[]): Promise<J[]>;
  /** Add two affine points and return the result in affine form. */
  addAffine(a: A, b: A): Promise<A>;
  addAffineBatch(a: readonly A[], b: readonly A[]): Promise<A[]>;
  /** Negate an affine point and return the result in affine form. */
  negAffine(point: A): Promise<A>;
  negAffineBatch(points: readonly A[]): Promise<A[]>;
  /** Double an affine point and return the result in affine form. */
  doubleAffine(point: A): Promise<A>;
  doubleAffineBatch(points: readonly A[]): Promise<A[]>;
  /** Multiply an affine base by a scalar and return the result in affine form. */
  scalarMulAffineResult(base: A, scalar: CurveGPUElementBytes): Promise<A>;
  scalarMulAffineResultBatch(bases: readonly A[], scalars: readonly CurveGPUElementBytes[]): Promise<A[]>;
}

/** G1 point operations. */
export type G1Module = GroupModule<CurveGPUAffinePoint, CurveGPUJacobianPoint> & {
  readonly zeroHex: string;
};

/** G2 point operations over the quadratic extension field. */
export type G2Module = GroupModule<CurveGPUG2AffinePoint, CurveGPUG2JacobianPoint> & {
  /** Byte size of one base-field component (`c0` or `c1`). */
  readonly componentBytes: number;
};

/**
 * Scalar-field NTT module for a specific curve.
 */
export interface NTTModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly field: "fr";
  /** Report the power-of-two domain sizes available from loaded metadata. */
  supportedSizes(): Promise<number[]>;
  /** Run the forward NTT over a power-of-two batch of Montgomery-form values. */
  forward(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Run the inverse NTT over a power-of-two batch of Montgomery-form values. */
  inverse(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]>;
  /** Run the forward NTT over packed regular little-endian field elements. */
  forwardPackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Run the inverse NTT over packed regular little-endian field elements. */
  inversePackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Run the inverse NTT over bit-reversed packed regular little-endian field elements. */
  inverseBitReversePackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Convert packed regular little-endian values from Lagrange coset form to canonical regular form. */
  inverseCosetPackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Run the forward NTT over packed Montgomery-form field elements. */
  forwardPackedMont(values: Uint8Array): Promise<Uint8Array>;
  /** Run the inverse NTT over packed Montgomery-form field elements. */
  inversePackedMont(values: Uint8Array): Promise<Uint8Array>;
  /** Run forward NTTs over packed Montgomery-form vectors of equal size. */
  forwardPackedMontBatch(values: Uint8Array, vectorSize: number, vectorCount: number): Promise<Uint8Array>;
  /** Run inverse NTTs over packed Montgomery-form vectors of equal size. */
  inversePackedMontBatch(values: Uint8Array, vectorSize: number, vectorCount: number): Promise<Uint8Array>;
  /**
   * Convert packed regular little-endian values from bit-reversed Lagrange
   * coset form to canonical regular form.
   */
  inverseCosetBitReversePackedRegular(values: Uint8Array): Promise<Uint8Array>;
  /** Precompute and cache domain data (twiddles, coset factors) on the GPU for a power-of-two size. */
  prewarmDomain(size: number): Promise<void>;
}

/**
 * Groth16 quotient helpers.
 *
 * These methods are separated from the generic NTT module even though they reuse
 * the same NTT/vector kernels internally.
 */
export interface Groth16QuotientModule {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  /**
   * Compute the Groth16 quotient vector H from packed regular little-endian
   * A, B, and C witness polynomials already padded to the FFT domain size.
   *
   * The returned packed vector is in regular little-endian form, bit-reversed
   * order, and has the same element count as the padded inputs.
   */
  computeGroth16QuotientPackedRegular(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array>;
  /**
   * Same as `computeGroth16QuotientPackedRegular` for packed Montgomery
   * little-endian inputs. The output is still regular little-endian.
   */
  computeGroth16QuotientPackedMont(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array>;
  /**
   * Same as `computeGroth16QuotientPackedMont` but the result is also returned
   * in Montgomery form (still bit-reversed), skipping the final conversion.
   */
  computeGroth16QuotientMont(a: Uint8Array, b: Uint8Array, c: Uint8Array): Promise<Uint8Array>;
  /** Precompute and cache Groth16 quotient-domain data for a power-of-two domain size. */
  prewarmGroth16QuotientDomain(size: number): Promise<void>;
}

/**
 * A base vector uploaded once to the GPU in the shader point layout, possibly
 * split into several buffers to respect `maxStorageBufferBindingSize`.
 */
export interface ResidentBases {
  /** Total number of points. */
  readonly count: number;
  /** Byte size of one point in the GPU layout. */
  readonly pointBytes: number;
  /** Consecutive chunks; `first` is the index of the chunk's first point. */
  readonly chunks: readonly { buffer: GPUBuffer; first: number; count: number }[];
  /** Destroy the GPU buffers. */
  release(): void;
}

/**
 * Multi-scalar multiplication over affine bases, generic over the point
 * representation (see `GroupModule`).
 */
export interface MSMModule<A, J> {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  readonly group: "g1" | "g2";
  /** Choose the default Pippenger window size for a given term count. */
  bestWindow(termCount: number): number;
  /** Run a single affine-base Pippenger MSM and return the result in Jacobian form (`z = 1`). */
  pippengerAffine(bases: readonly A[], scalars: readonly CurveGPUElementBytes[], options?: CurveGPUMSMOptions): Promise<J>;
  /** Run a single affine-base Pippenger MSM and return the result in affine form. */
  pippengerAffineResult(bases: readonly A[], scalars: readonly CurveGPUElementBytes[], options?: CurveGPUMSMOptions): Promise<A>;
  /**
   * Run a batched affine-base Pippenger MSM.
   *
   * `bases` and `scalars` are interleaved: the first `termsPerInstance` pairs
   * belong to instance 0, the next `termsPerInstance` pairs to instance 1, etc.
   * `options.count` and `options.termsPerInstance` must both be provided.
   */
  pippengerAffineBatch(bases: readonly A[], scalars: readonly CurveGPUElementBytes[], options: CurveGPUMSMOptions): Promise<J[]>;
  /**
   * Run Pippenger MSM from packed bytes.
   *
   * `basesPacked` is expected in `jacobian_x_y_z_le` layout with one packed
   * point per term (`z` = Montgomery one for affine inputs, all-zero for
   * infinity). `scalarsPacked` is a packed sequence of regular-form 32-byte
   * scalars. The result is returned in the same packed layout, one point per
   * MSM instance.
   */
  pippengerPackedJacobianBases(
    basesPacked: Uint8Array,
    scalarsPacked: Uint8Array,
    options: CurveGPUMSMOptions & { layout?: CurveGPUPackedPointLayout },
  ): Promise<Uint8Array>;
  /**
   * Upload a packed affine base vector (per point: the coordinates `x, y` in
   * Montgomery little-endian form, infinity all-zero) once, expanding it to
   * the shader layout on the way. The result stays on the GPU until released.
   */
  uploadAffineBases(packedAffine: Uint8Array): Promise<ResidentBases>;
  /**
   * MSM over `bases[start : start + scalarsPacked.length / 32]` using
   * GPU-resident bases. Returns the affine result packed as `x, y`
   * (`2 * coordinateBytes`), all-zero for the point at infinity.
   */
  msmResident(
    bases: ResidentBases,
    start: number,
    scalarsPacked: Uint8Array,
    options?: Pick<CurveGPUMSMOptions, "window" | "maxChunkSize">,
  ): Promise<Uint8Array>;
}

/** Multi-scalar multiplication over G1 affine bases. */
export type G1MSMModule = MSMModule<CurveGPUAffinePoint, CurveGPUJacobianPoint>;
/** Multi-scalar multiplication over G2 affine bases. */
export type G2MSMModule = MSMModule<CurveGPUG2AffinePoint, CurveGPUG2JacobianPoint>;

export type ProofRuntimeKind = "webgpu" | "native";

export type ProofRuntimeOptions = {
  /** Optional URL for Go's wasm_exec.js runtime shim. Defaults to the package asset. */
  wasmExecURL?: string;
  /** Optional URL for the WebGPU-accelerated Go WASM runtime. Defaults to the package asset. */
  webgpuWasmURL?: string;
  /** Optional URL for the native gnark Go WASM runtime. Defaults to the package asset. */
  nativeWasmURL?: string;
};

export interface ProofHandle {
  /** Release the corresponding Go WASM runtime handle. */
  dispose(): Promise<void>;
}

export interface ProofConstraintSystem extends ProofHandle {
  /** Number of constraints reported by the deserialized constraint system. */
  readonly constraints: number;
}

/**
 * Browser proof helpers backed by a long-lived Go WASM runtime. `F` is the
 * set of proving-key serialization formats the system accepts.
 */
export interface ProofModule<F extends string> {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  /**
   * Load the Go WASM runtime.
   *
   * Defaults to the WebGPU runtime and package-shipped assets. Override URLs
   * when serving the runtime from an application asset path or CDN.
   */
  loadRuntime(options?: ProofRuntimeOptions & { kind?: ProofRuntimeKind }): Promise<void>;
  /** Deserialize a gnark constraint system. */
  readConstraintSystem(bytes: Uint8Array): Promise<ProofConstraintSystem>;
  /** Deserialize a gnark proving key. */
  readProvingKey(bytes: Uint8Array, options?: { format?: F }): Promise<ProofHandle>;
  /** Deserialize a gnark verification key. */
  readVerificationKey(bytes: Uint8Array): Promise<ProofHandle>;
  /**
   * Precompute browser-side proving key caches (uploads the key bases to the
   * GPU for the WebGPU runtime).
   *
   * Passing the constraint system lets the PLONK WebGPU runtime prepare
   * trace-derived caches outside the timed prove path.
   */
  prepareProvingKey(pk: ProofHandle, ccs?: ProofConstraintSystem): Promise<void>;
  /** Prove with a gnark binary witness and return gnark-serialized proof bytes. */
  prove(ccs: ProofConstraintSystem, pk: ProofHandle, witness: Uint8Array): Promise<Uint8Array>;
  /** Verify gnark-serialized proof bytes against a gnark binary public witness. */
  verify(proof: Uint8Array, vk: ProofHandle, publicWitness: Uint8Array): Promise<boolean>;
  /**
   * Encode flat regular field values as a gnark binary witness.
   *
   * Values must be ordered `[public | private]`. The binary witness protocol
   * stores field elements as fixed-width big-endian bytes.
   */
  encodeWitness(values: readonly bigint[], options: { publicCount: number }): Uint8Array;
}

export type Groth16ProvingKeyFormat = "serialized" | "dump";
export type PlonkProvingKeyFormat = "serialized" | "unsafe";

/** Groth16 proof helpers plus the quotient primitives the prover uses. */
export type Groth16Module = ProofModule<Groth16ProvingKeyFormat> & Groth16QuotientModule;
/** PLONK proof helpers. */
export type PlonkModule = ProofModule<PlonkProvingKeyFormat>;

/** @deprecated Use {@link ProofRuntimeKind}. */
export type Groth16RuntimeKind = ProofRuntimeKind;
/** @deprecated Use {@link ProofRuntimeKind}. */
export type PlonkRuntimeKind = ProofRuntimeKind;
/** @deprecated Use {@link ProofRuntimeOptions}. */
export type Groth16RuntimeOptions = ProofRuntimeOptions;
/** @deprecated Use {@link ProofRuntimeOptions}. */
export type PlonkRuntimeOptions = ProofRuntimeOptions;
/** @deprecated Use {@link ProofHandle}. */
export type Groth16Handle = ProofHandle;
/** @deprecated Use {@link ProofHandle}. */
export type PlonkHandle = ProofHandle;
/** @deprecated Use {@link ProofConstraintSystem}. */
export type Groth16ConstraintSystem = ProofConstraintSystem;
/** @deprecated Use {@link ProofConstraintSystem}. */
export type PlonkConstraintSystem = ProofConstraintSystem;
/** @deprecated Use {@link ProofHandle}. */
export type Groth16ProvingKey = ProofHandle;
/** @deprecated Use {@link ProofHandle}. */
export type PlonkProvingKey = ProofHandle;
/** @deprecated Use {@link ProofHandle}. */
export type Groth16VerificationKey = ProofHandle;
/** @deprecated Use {@link ProofHandle}. */
export type PlonkVerificationKey = ProofHandle;

/**
 * High-level curve module returned by the library.
 *
 * This groups the curve-specific submodules behind one stable object per
 * supported curve. Obtain an instance via `createCurveModule` (or the
 * curve-specific helpers `createBN254` / `createBLS12381` / `createBLS12377`).
 */
export interface CurveModule {
  /** The curve this module was created for. */
  readonly id: SupportedCurveID;
  /** The WebGPU context shared across all submodules. */
  readonly context: CurveGPUContext;
  /** Scalar-field (`Fr`) arithmetic. */
  readonly fr: FieldModule;
  /** Base-field (`Fp`) arithmetic. */
  readonly fp: FieldModule;
  /** G1 point operations. */
  readonly g1: G1Module;
  /** G2 point operations over the quadratic extension field. */
  readonly g2: G2Module;
  /** Scalar-field NTT. */
  readonly ntt: NTTModule;
  /** Groth16 proof helpers. */
  readonly groth16: Groth16Module;
  /** PLONK proof helpers. */
  readonly plonk: PlonkModule;
  /** Multi-scalar multiplication over G1. */
  readonly g1msm: G1MSMModule;
  /** Multi-scalar multiplication over G2. */
  readonly g2msm: G2MSMModule;
}
