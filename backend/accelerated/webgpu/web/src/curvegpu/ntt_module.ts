import type { CurveGPUContext, CurveGPUElementBytes, FieldModule, Groth16QuotientModule, NTTModule, SupportedCurveID } from "./api.js";
import type { BufferBinding, CommandBatch, Kernel } from "./gpu.js";
import {
  createGPUBuffer,
  ensureByteLength,
  ensurePackedElements,
  packElementBatch,
  recordAndRead,
  STORAGE_IN_USAGE,
  STORAGE_RW_USAGE,
  UNIFORM_USAGE,
  unpackElementBatch,
  uploadGPUBuffer,
} from "./gpu.js";
import { FIELD_OP } from "./field_module.js";

/** Opcodes of the `fr_vector_main` shader. */
const VECTOR_OP = { COPY: 0, MUL_FACTORS: 3, BIT_REVERSE_COPY: 4, POWER: 5 } as const;

/** Flags of the `fr_ntt_fused_main` shader. */
const NTT_FLAG = { BIT_REVERSE: 1, LOAD_SCALE: 2, STORE_SCALE: 4, INVERSE: 8 } as const;

/** Uniform sizes in 32-bit words (`Params` structs of the vector and NTT shaders). */
const VECTOR_PARAM_WORDS = 16;
const NTT_PARAM_WORDS = 24;

/** Maximum workgroups per grid dimension (WebGPU `maxComputeWorkgroupsPerDimension` default). */
const MAX_WORKGROUPS_PER_DIMENSION = 65535;

/** Montgomery radix for 32-byte scalar fields (8 × 32-bit limbs). */
const MONT_R = 1n << 256n;

/**
 * GPU-resident constants of one power-of-two domain. Uploaded once per
 * (curve, size) and reused by every NTT over that domain. The tables are
 * computed on the GPU (`FR_VECTOR_OP_POWER`), so preparing a domain costs a
 * few dispatches rather than `n` host-side big-integer multiplications.
 */
type PreparedDomain = {
  size: number;
  logN: number;
  /** `omega^i` for `i < n/2` (Montgomery form). Inverse twiddles derive from it in-kernel. */
  twiddles: GPUBuffer;
  /** `g^i` and `g^-i` for the coset generator `g` (Montgomery form). */
  cosetPowers: GPUBuffer;
  inverseCosetPowers: GPUBuffer;
  /** `1/n` as a regular integer. */
  inverseSize: bigint;
  /** `1 / (g^n - 1)` as a regular integer. */
  cosetDenInv: bigint;
};

/** Ping-pong pair of state buffers; `current` holds the live vector. */
type State = { current: GPUBuffer; next: GPUBuffer };

/**
 * A constant multiplier for the `scale` slots of the shaders, which apply a
 * Montgomery multiplication `x * c * R^-1`. `value` is the regular integer to
 * multiply by, `inputMont` / `outputMont` the representation of the operand
 * and of the wanted result; `c` is then `value * R^(1 + outputMont - inputMont)`.
 */
type Scale = { value: bigint; inputMont: boolean; outputMont: boolean };

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let acc = base % mod;
  let power = exp;
  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = (result * acc) % mod;
    }
    acc = (acc * acc) % mod;
    power >>= 1n;
  }
  return result;
}

function modInv(value: bigint, mod: bigint): bigint {
  if (value === 0n) {
    throw new Error("cannot invert zero");
  }
  return modPow(value, mod - 2n, mod);
}

function twoAdicity(value: bigint): number {
  let x = value;
  let count = 0;
  while ((x & 1n) === 0n) {
    count += 1;
    x >>= 1n;
  }
  return count;
}

function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") || hex.startsWith("0X") ? hex : `0x${hex}`);
}

function log2PowerOfTwo(size: number, label: string): number {
  const logN = Math.log2(size);
  if (!Number.isSafeInteger(size) || size <= 0 || !Number.isInteger(logN)) {
    throw new Error(`${label}: NTT size must be a positive power of two, got ${size}`);
  }
  return logN;
}

/** Write a 256-bit value as eight little-endian words at `offset`. */
function writeWords(out: Uint32Array, offset: number, value: bigint): void {
  let x = value;
  for (let i = 0; i < 8; i += 1) {
    out[offset + i] = Number(x & 0xffffffffn);
    x >>= 32n;
  }
}

/** Split `workgroups` over a 2D grid when it exceeds the per-dimension limit (fused NTT kernel only). */
function workgroupGrid(workgroups: number): [number, number, number] {
  if (workgroups <= MAX_WORKGROUPS_PER_DIMENSION) {
    return [workgroups, 1, 1];
  }
  const x = 32768;
  return [x, Math.ceil(workgroups / x), 1];
}

export function createNTTModule(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    vectorKernel: Kernel;
    fieldKernel: Kernel;
    nttKernel: Kernel;
    modulusHex: string;
    multiplicativeGeneratorHex: string;
    cosetGeneratorHex: string;
  },
  fr: FieldModule,
): NTTModule & Groth16QuotientModule {
  const { curve, vectorKernel, fieldKernel, nttKernel, modulusHex, multiplicativeGeneratorHex, cosetGeneratorHex } = options;
  const label = `${curve}-fr-ntt`;
  const elementBytes = fr.byteSize;
  const device = context.device;

  const modulus = BigInt(modulusHex);
  const multiplicativeGenerator = hexToBigInt(multiplicativeGeneratorHex);
  const cosetGenerator = hexToBigInt(cosetGeneratorHex);
  const maxLogSize = twoAdicity(modulus - 1n);
  const domainCache = new Map<number, PreparedDomain>();

  /** Elements per fused NTT dispatch tile, and the most stages one dispatch can fuse. */
  const tileElements = 2 * nttKernel.workgroupSize;
  const maxStagesPerDispatch = Math.round(Math.log2(tileElements));

  /** Montgomery form of a regular value. */
  const toMont = (value: bigint): bigint => (value * MONT_R) % modulus;

  /** Placeholder for the unused read-only bindings of table-generating dispatches. */
  const unusedInput = createGPUBuffer(device, `${label}-unused-input`, 4, STORAGE_IN_USAGE);

  const scaleConstant = (scale: Scale): bigint => {
    let c = scale.value % modulus;
    if (!scale.inputMont) {
      c = toMont(c);
    }
    if (scale.outputMont) {
      c = toMont(c);
    }
    return c;
  };

  /** Uniform words of the vector kernel. */
  function vectorParams(count: number, opcode: number, extra: { logCount?: number; vectorSize?: number; scale?: Scale } = {}): Uint32Array {
    const words = new Uint32Array(VECTOR_PARAM_WORDS);
    words[0] = count;
    words[1] = opcode;
    words[2] = extra.logCount ?? 0;
    words[3] = extra.vectorSize ?? 0;
    if (extra.scale) {
      words[4] = 1;
      writeWords(words, 8, scaleConstant(extra.scale));
    }
    return words;
  }

  /** `base^i` for `i < count` (Montgomery form), computed on the GPU. */
  function powerTable(base: bigint, count: number, name: string): GPUBuffer {
    const buffer = createGPUBuffer(device, `${label}-${name}`, count * elementBytes, STORAGE_RW_USAGE);
    if (count === 0) {
      return buffer;
    }
    const logCount = Math.ceil(Math.log2(count));
    const words = new Uint32Array(VECTOR_PARAM_WORDS);
    words[0] = count;
    words[1] = VECTOR_OP.POWER;
    words[2] = logCount;
    writeWords(words, 8, toMont(base));
    const params = uploadGPUBuffer(device, `${label}-${name}-params`, words, UNIFORM_USAGE);
    const bindGroup = device.createBindGroup({
      label: `${label}-${name}-bg`,
      layout: vectorKernel.bindGroupLayout,
      entries: [unusedInput, unusedInput, buffer, params].map((resource, binding) => ({ binding, resource: { buffer: resource } })),
    });
    const encoder = device.createCommandEncoder({ label: `${label}-${name}` });
    const pass = encoder.beginComputePass();
    pass.setPipeline(vectorKernel.pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(Math.ceil(count / vectorKernel.workgroupSize));
    pass.end();
    device.queue.submit([encoder.finish()]);
    params.destroy();
    return buffer;
  }

  function prepareDomain(size: number): PreparedDomain {
    const cached = domainCache.get(size);
    if (cached) {
      return cached;
    }
    const logN = log2PowerOfTwo(size, label);
    if (logN > maxLogSize) {
      throw new Error(`${label}: NTT size ${size} exceeds scalar field two-adicity 2^${maxLogSize}`);
    }
    const sizeBig = BigInt(size);
    const omega = modPow(multiplicativeGenerator, (modulus - 1n) / sizeBig, modulus);
    const cosetDen = (modPow(cosetGenerator, sizeBig, modulus) - 1n + modulus) % modulus;

    const domain: PreparedDomain = {
      size,
      logN,
      twiddles: powerTable(omega, size / 2, `twiddles-${size}`),
      cosetPowers: powerTable(cosetGenerator, size, `coset-powers-${size}`),
      inverseCosetPowers: powerTable(modInv(cosetGenerator, modulus), size, `inverse-coset-powers-${size}`),
      inverseSize: modInv(sizeBig, modulus),
      cosetDenInv: modInv(cosetDen, modulus),
    };
    domainCache.set(size, domain);
    return domain;
  }

  // --- recording helpers -------------------------------------------------

  function swap(state: State): void {
    const tmp = state.current;
    state.current = state.next;
    state.next = tmp;
  }

  function uploadState(batch: CommandBatch, values: Uint8Array): State {
    return {
      current: batch.upload(values, STORAGE_RW_USAGE, "state-a"),
      next: batch.temp(values.byteLength, STORAGE_RW_USAGE, "state-b"),
    };
  }

  /** Element-wise op over the whole state: `current (op) aux -> next`, then swap. */
  function recordElementwise(batch: CommandBatch, kernel: Kernel, state: State, aux: GPUBuffer, totalCount: number, params: Uint32Array, opLabel: string): void {
    batch.dispatch(kernel, [state.current, aux, state.next, batch.uniform(params)], Math.ceil(totalCount / kernel.workgroupSize), opLabel);
    swap(state);
  }

  /**
   * Multiply each of `vectorCount` vectors by the same per-size factor table
   * (`current[i] * factors[i mod vectorSize] -> next`), optionally scaling the
   * result by a constant in the same pass.
   */
  function recordMulFactors(batch: CommandBatch, state: State, factors: GPUBuffer, vectorSize: number, vectorCount: number, opLabel: string, scale?: Scale): void {
    const totalCount = vectorSize * vectorCount;
    recordElementwise(batch, vectorKernel, state, factors, totalCount, vectorParams(totalCount, VECTOR_OP.MUL_FACTORS, { vectorSize, scale }), opLabel);
  }

  /**
   * Record a full NTT over `vectorCount` vectors of `domain.size` elements
   * held in `state`, as `ceil(logN / maxStagesPerDispatch)` fused-stage
   * dispatches. The optional bit-reversal of the input and the constant
   * multiplications (Montgomery conversions, `1/n`, `loadFactor`) are folded
   * into the first and last dispatch.
   */
  function recordPipeline(
    batch: CommandBatch,
    state: State,
    domain: PreparedDomain,
    pipeline: {
      vectorCount: number;
      inverse: boolean;
      inputRegular: boolean;
      outputRegular: boolean;
      inputBitReversed?: boolean;
      inverseCoset?: boolean;
      /** Extra regular-integer factor applied to the input. */
      loadFactor?: bigint;
    },
  ): void {
    const { vectorCount, inverse, inputRegular, outputRegular, inputBitReversed = false, inverseCoset = false, loadFactor = 1n } = pipeline;
    const totalCount = domain.size * vectorCount;
    // The coset scaling is a separate table pass after the transform; the
    // conversion back to regular form is folded into it when present.
    const outputRegularHere = outputRegular && !inverseCoset;

    const stagePlan: { first: number; count: number }[] = [];
    for (let first = 0; first < domain.logN; first += maxStagesPerDispatch) {
      stagePlan.push({ first, count: Math.min(maxStagesPerDispatch, domain.logN - first) });
    }
    if (stagePlan.length === 0) {
      stagePlan.push({ first: 0, count: 0 });
    }

    stagePlan.forEach((stages, i) => {
      const isFirst = i === 0;
      const isLast = i === stagePlan.length - 1;
      const words = new Uint32Array(NTT_PARAM_WORDS);
      words[0] = totalCount;
      words[1] = stages.first;
      words[2] = stages.count;
      words[4] = domain.logN;
      let flags = inverse ? NTT_FLAG.INVERSE : 0;
      if (isFirst) {
        if (!inputBitReversed) {
          flags |= NTT_FLAG.BIT_REVERSE;
        }
        if (inputRegular || loadFactor !== 1n) {
          flags |= NTT_FLAG.LOAD_SCALE;
          writeWords(words, 8, scaleConstant({ value: loadFactor, inputMont: !inputRegular, outputMont: true }));
        }
      }
      if (isLast && (inverse || outputRegularHere)) {
        flags |= NTT_FLAG.STORE_SCALE;
        writeWords(words, 16, scaleConstant({ value: inverse ? domain.inverseSize : 1n, inputMont: true, outputMont: !outputRegularHere }));
      }
      words[3] = flags;
      batch.dispatch(
        nttKernel,
        [state.current, domain.twiddles, state.next, batch.uniform(words)],
        workgroupGrid(Math.ceil(totalCount / tileElements)),
        `ntt-${inverse ? "inv" : "fwd"}-stages-${stages.first}-${stages.first + stages.count}`,
      );
      swap(state);
    });

    if (inverseCoset) {
      recordMulFactors(batch, state, domain.inverseCosetPowers, domain.size, vectorCount, "inverse-coset-scale", outputRegular ? { value: 1n, inputMont: true, outputMont: false } : undefined);
    }
  }

  // --- public operations -------------------------------------------------

  async function runPipelinePackedBatch(options: {
    values: Uint8Array;
    vectorSize: number;
    vectorCount: number;
    inverse: boolean;
    inputRegular: boolean;
    outputRegular: boolean;
    inputBitReversed?: boolean;
    inverseCoset?: boolean;
  }): Promise<Uint8Array> {
    const { values, vectorSize, vectorCount } = options;
    if (options.inverseCoset && !options.inverse) {
      throw new Error(`${label}: inverseCoset requires inverse NTT`);
    }
    log2PowerOfTwo(vectorSize, label);
    if (!Number.isInteger(vectorCount) || vectorCount <= 0) {
      throw new Error(`${label}: NTT vector count must be positive`);
    }
    const totalCount = ensurePackedElements(values, elementBytes, `${label}.pipeline.values`);
    if (totalCount !== vectorSize * vectorCount) {
      throw new Error(`${label}: expected ${vectorSize * vectorCount} packed elements, got ${totalCount}`);
    }
    const domain = prepareDomain(vectorSize);
    return recordAndRead(device, context.bufferPool, `${label}-pipeline`, (batch) => {
      const state = uploadState(batch, values);
      recordPipeline(batch, state, domain, options);
      return { buffer: state.current, size: values.byteLength };
    }, context.debug);
  }

  async function runPipelinePacked(options: {
    values: Uint8Array;
    inverse: boolean;
    inputRegular: boolean;
    outputRegular: boolean;
    inputBitReversed?: boolean;
    inverseCoset?: boolean;
  }): Promise<Uint8Array> {
    const count = ensurePackedElements(options.values, elementBytes, `${label}.pipeline.values`);
    return runPipelinePackedBatch({ ...options, vectorSize: count, vectorCount: 1 });
  }

  /**
   * Groth16 quotient `h = ifft_coset(fft_coset(ifft(a)) * fft_coset(ifft(b)) - fft_coset(ifft(c)))`,
   * returned in bit-reversed order (regular form unless `outputMontgomery`), in
   * one GPU submission.
   */
  async function computeGroth16QuotientPacked(a: Uint8Array, b: Uint8Array, c: Uint8Array, inputMontgomery: boolean, outputMontgomery = false): Promise<Uint8Array> {
    const count = ensurePackedElements(a, elementBytes, `${label}.groth16.a`);
    if (b.byteLength !== a.byteLength || c.byteLength !== a.byteLength) {
      throw new Error(`${label}: Groth16 quotient inputs must have identical packed lengths`);
    }
    if (count === 0 || (count & (count - 1)) !== 0) {
      throw new Error(`${label}: Groth16 quotient input length must be a non-zero power of two`);
    }
    const domain = prepareDomain(count);
    const mont = { vectorCount: 1, inputRegular: false, outputRegular: false };
    const fieldParams = (opcode: number): Uint32Array => Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]);

    return recordAndRead(device, context.bufferPool, `${label}-groth16-quotient`, (batch) => {
      const states = [a, b, c].map((values) => uploadState(batch, values));
      // Coefficients, then evaluations on the coset.
      for (const state of states) {
        recordPipeline(batch, state, domain, { ...mont, inputRegular: !inputMontgomery, inverse: true });
        recordMulFactors(batch, state, domain.cosetPowers, count, 1, "coset-shift");
        recordPipeline(batch, state, domain, { ...mont, inverse: false });
      }
      const [h, bCoset, cCoset] = states;
      // h = (a * b - c) / (g^n - 1) on the coset; the division is folded into
      // the input scaling of the inverse transform.
      recordElementwise(batch, fieldKernel, h, bCoset.current, count, fieldParams(FIELD_OP.MUL), "ab");
      recordElementwise(batch, fieldKernel, h, cCoset.current, count, fieldParams(FIELD_OP.SUB), "ab-minus-c");
      recordPipeline(batch, h, domain, { ...mont, inverse: true, loadFactor: domain.cosetDenInv });
      // Undo the coset shift (converting to regular form in the same pass), then bit-reverse.
      recordMulFactors(batch, h, domain.inverseCosetPowers, count, 1, "inverse-coset-shift", outputMontgomery ? undefined : { value: 1n, inputMont: true, outputMont: false });
      recordElementwise(batch, vectorKernel, h, h.current, count, vectorParams(count, VECTOR_OP.BIT_REVERSE_COPY, { logCount: domain.logN }), "bit-reverse");
      return { buffer: h.current, size: a.byteLength };
    }, context.debug);
  }

  async function prewarmDomain(size: number): Promise<void> {
    prepareDomain(size);
  }

  // --- recording API (for callers that batch several passes into one submission) ---

  /** Forward or inverse NTT of `vectorCount` Montgomery vectors; returns a batch temporary holding the result. */
  function recordTransform(batch: CommandBatch, values: GPUBuffer, vectorSize: number, vectorCount: number, inverse: boolean): GPUBuffer {
    const domain = prepareDomain(vectorSize);
    const state: State = { current: values, next: batch.temp(vectorSize * vectorCount * elementBytes, STORAGE_RW_USAGE, inverse ? "ntt-inv" : "ntt-fwd") };
    recordPipeline(batch, state, domain, { vectorCount, inverse, inputRegular: false, outputRegular: false });
    if (state.current === values) {
      // An even number of passes landed back in the input; copy so the input stays untouched.
      batch.copy(values, state.next, vectorSize * vectorCount * elementBytes);
      return state.next;
    }
    return state.current;
  }

  /** In place: `values[i] *= factors[i mod vectorSize]` (Montgomery). */
  function recordMulVector(batch: CommandBatch, values: GPUBuffer, factors: BufferBinding, vectorSize: number, vectorCount: number): void {
    const totalCount = vectorSize * vectorCount;
    const product = batch.temp(totalCount * elementBytes, STORAGE_RW_USAGE, "mul-vector");
    batch.dispatch(vectorKernel, [values, factors, product, batch.uniform(vectorParams(totalCount, VECTOR_OP.MUL_FACTORS, { vectorSize }))], Math.ceil(totalCount / vectorKernel.workgroupSize), "mul-vector");
    batch.copy(product, values, totalCount * elementBytes);
  }

  return {
    context,
    curve,
    field: "fr",
    async supportedSizes(): Promise<number[]> {
      const sizes: number[] = [];
      for (let logN = 3; logN <= maxLogSize; logN += 1) {
        sizes.push(2 ** logN);
      }
      return sizes;
    },
    async forward(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      values.forEach((value, index) => ensureByteLength(value, elementBytes, `${label}.forward[${index}]`));
      log2PowerOfTwo(values.length, label);
      const output = await runPipelinePacked({ values: packElementBatch(values, elementBytes, `${label}.forward.values`), inverse: false, inputRegular: false, outputRegular: false });
      return unpackElementBatch(output, elementBytes, values.length);
    },
    async inverse(values: readonly CurveGPUElementBytes[]): Promise<CurveGPUElementBytes[]> {
      values.forEach((value, index) => ensureByteLength(value, elementBytes, `${label}.inverse[${index}]`));
      log2PowerOfTwo(values.length, label);
      const output = await runPipelinePacked({ values: packElementBatch(values, elementBytes, `${label}.inverse.values`), inverse: true, inputRegular: false, outputRegular: false });
      return unpackElementBatch(output, elementBytes, values.length);
    },
    forwardPackedMont: (values) => runPipelinePacked({ values, inverse: false, inputRegular: false, outputRegular: false }),
    inversePackedMont: (values) => runPipelinePacked({ values, inverse: true, inputRegular: false, outputRegular: false }),
    forwardPackedMontBatch: (values, vectorSize, vectorCount) =>
      runPipelinePackedBatch({ values, vectorSize, vectorCount, inverse: false, inputRegular: false, outputRegular: false }),
    inversePackedMontBatch: (values, vectorSize, vectorCount) =>
      runPipelinePackedBatch({ values, vectorSize, vectorCount, inverse: true, inputRegular: false, outputRegular: false }),
    inverseBitReversePackedRegular: (values) => runPipelinePacked({ values, inverse: true, inputRegular: true, outputRegular: true, inputBitReversed: true }),
    inverseCosetPackedRegular: (values) => runPipelinePacked({ values, inverse: true, inputRegular: true, outputRegular: true, inverseCoset: true }),
    inverseCosetBitReversePackedRegular: (values) =>
      runPipelinePacked({ values, inverse: true, inputRegular: true, outputRegular: true, inputBitReversed: true, inverseCoset: true }),
    forwardPackedRegular: (values) => runPipelinePacked({ values, inverse: false, inputRegular: true, outputRegular: true }),
    inversePackedRegular: (values) => runPipelinePacked({ values, inverse: true, inputRegular: true, outputRegular: true }),
    transformPackedMont: (values, transform) => {
      const count = ensurePackedElements(values, elementBytes, `${label}.transform.values`);
      const vectorCount = transform.vectorCount ?? 1;
      if (!Number.isInteger(vectorCount) || vectorCount <= 0 || count % vectorCount !== 0) {
        throw new Error(`${label}: ${count} packed elements do not split into ${vectorCount} vectors`);
      }
      return runPipelinePackedBatch({
        values,
        vectorSize: count / vectorCount,
        vectorCount,
        inverse: transform.inverse,
        inputRegular: false,
        outputRegular: false,
        inputBitReversed: transform.inputBitReversed,
        inverseCoset: transform.inverseCoset,
      });
    },
    recordForward: (batch, values, vectorSize, vectorCount) => recordTransform(batch, values, vectorSize, vectorCount, false),
    recordInverse: (batch, values, vectorSize, vectorCount) => recordTransform(batch, values, vectorSize, vectorCount, true),
    recordMulVector,
    prewarmDomain,
    prewarmGroth16QuotientDomain: prewarmDomain,
    computeGroth16QuotientPackedRegular: (a, b, c) => computeGroth16QuotientPacked(a, b, c, false),
    computeGroth16QuotientPackedMont: (a, b, c) => computeGroth16QuotientPacked(a, b, c, true),
    computeGroth16QuotientMont: (a, b, c) => computeGroth16QuotientPacked(a, b, c, true, true),
  };
}
