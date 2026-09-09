import type { CurveGPUContext, CurveGPUElementBytes, FieldModule, Groth16QuotientModule, NTTModule, SupportedCurveID } from "./api.js";
import type { BufferBinding, CommandBatch, Kernel } from "./gpu.js";
import {
  alignBytes,
  ensureByteLength,
  ensurePackedElements,
  packElementBatch,
  recordAndRead,
  STORAGE_IN_USAGE,
  STORAGE_RW_USAGE,
  unpackElementBatch,
  uploadGPUBuffer,
} from "./gpu.js";
import { FIELD_OP } from "./field_module.js";

/** Opcodes of the `fr_vector_main` shader. */
const VECTOR_OP_MUL_FACTORS = 3;
const VECTOR_OP_BIT_REVERSE_COPY = 4;

/** Montgomery radix for 32-byte scalar fields (8 × 32-bit limbs). */
const MONT_R = 1n << 256n;

/**
 * GPU-resident constants of one power-of-two domain. Uploaded once per
 * (curve, size) and reused by every NTT over that domain.
 */
type PreparedDomain = {
  size: number;
  logN: number;
  /** Per-direction twiddle buffers; stage `s` occupies `[stageOffsets[s], stageOffsets[s] + stageSizes[s])`. */
  forwardTwiddles: GPUBuffer;
  inverseTwiddles: GPUBuffer;
  stageOffsets: number[];
  stageSizes: number[];
  /** `n` copies of `1/n` (the vector kernel has no scalar-multiply opcode). */
  inverseScaleFactors: GPUBuffer;
  /** `g^i` and `g^-i` for the coset generator `g`. */
  cosetPowers: GPUBuffer;
  inverseCosetPowers: GPUBuffer;
  /** `n` copies of `1 / (g^n - 1)`. */
  cosetDenInvFactors: GPUBuffer;
};

/** Ping-pong pair of state buffers; `current` holds the live vector. */
type State = { current: GPUBuffer; next: GPUBuffer };

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
  const alignment = context.minStorageBufferOffsetAlignment;

  const modulus = BigInt(modulusHex);
  const multiplicativeGenerator = hexToBigInt(multiplicativeGeneratorHex);
  const cosetGenerator = hexToBigInt(cosetGeneratorHex);
  const maxLogSize = twoAdicity(modulus - 1n);
  const domainCache = new Map<number, PreparedDomain>();

  /** Montgomery form of one: the starting point of every power sequence below. */
  const oneMont = MONT_R % modulus;

  /** Write an element already in Montgomery form as little-endian bytes. */
  function writeElement(out: Uint8Array, offset: number, montValue: bigint): void {
    let x = montValue;
    for (let i = 0; i < elementBytes; i += 1) {
      out[offset + i] = Number(x & 0xffn);
      x >>= 8n;
    }
  }

  /**
   * `base^i` for `i < count` in Montgomery form. Multiplying a Montgomery
   * value by a regular one keeps it in Montgomery form, so no per-element
   * conversion is needed.
   */
  function powerVectorMont(base: bigint, count: number): Uint8Array {
    const out = new Uint8Array(count * elementBytes);
    let acc = oneMont;
    for (let i = 0; i < count; i += 1) {
      writeElement(out, i * elementBytes, acc);
      acc = (acc * base) % modulus;
    }
    return out;
  }

  function repeatedMont(value: bigint, count: number): Uint8Array {
    const out = new Uint8Array(count * elementBytes);
    writeElement(out, 0, (value * MONT_R) % modulus);
    for (let i = 1; i < count; i += 1) {
      out.copyWithin(i * elementBytes, 0, elementBytes);
    }
    return out;
  }

  /** Stage twiddles `omega^(i * 2^(logN - stage))` for `stage = 1..logN`, packed at aligned offsets. */
  function twiddleBuffer(omega: bigint, logN: number, offsets: number[], sizes: number[], name: string): GPUBuffer {
    const out = new Uint8Array(logN === 0 ? 4 : offsets[logN - 1] + sizes[logN - 1]);
    for (let stage = 1; stage <= logN; stage += 1) {
      const m = 2 ** (stage - 1);
      const step = modPow(omega, 1n << BigInt(logN - stage), modulus);
      let acc = oneMont;
      for (let i = 0; i < m; i += 1) {
        writeElement(out, offsets[stage - 1] + i * elementBytes, acc);
        acc = (acc * step) % modulus;
      }
    }
    return uploadGPUBuffer(device, `${label}-${name}`, out, STORAGE_IN_USAGE);
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

    const stageOffsets: number[] = [];
    const stageSizes: number[] = [];
    let offset = 0;
    for (let stage = 0; stage < logN; stage += 1) {
      stageOffsets.push(offset);
      stageSizes.push(alignBytes((1 << stage) * elementBytes));
      offset += Math.ceil(stageSizes[stage] / alignment) * alignment;
    }

    const domain: PreparedDomain = {
      size,
      logN,
      forwardTwiddles: twiddleBuffer(omega, logN, stageOffsets, stageSizes, `twiddles-fwd-${size}`),
      inverseTwiddles: twiddleBuffer(modInv(omega, modulus), logN, stageOffsets, stageSizes, `twiddles-inv-${size}`),
      stageOffsets,
      stageSizes,
      inverseScaleFactors: uploadGPUBuffer(device, `${label}-inverse-scale-${size}`, repeatedMont(modInv(sizeBig, modulus), size)),
      cosetPowers: uploadGPUBuffer(device, `${label}-coset-powers-${size}`, powerVectorMont(cosetGenerator, size)),
      inverseCosetPowers: uploadGPUBuffer(device, `${label}-inverse-coset-powers-${size}`, powerVectorMont(modInv(cosetGenerator, modulus), size)),
      cosetDenInvFactors: uploadGPUBuffer(device, `${label}-coset-den-inv-${size}`, repeatedMont(modInv(cosetDen, modulus), size)),
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
   * Multiply each of `vectorCount` vectors by the same per-size factor buffer
   * (`current[i] * factors[i mod vectorSize] -> next`). Vectors are addressed
   * through bind-group offsets when the alignment allows, otherwise the factor
   * vector is repeated into a scratch buffer.
   */
  function recordMulFactors(batch: CommandBatch, state: State, factors: GPUBuffer, vectorSize: number, vectorCount: number, opLabel: string): void {
    const vectorBytes = vectorSize * elementBytes;
    if (vectorCount === 1) {
      recordElementwise(batch, vectorKernel, state, factors, vectorSize, Uint32Array.from([vectorSize, VECTOR_OP_MUL_FACTORS, 0, 0, 0, 0, 0, 0]), opLabel);
      return;
    }
    if (vectorBytes % alignment !== 0) {
      const repeated = batch.temp(vectorCount * vectorBytes, STORAGE_RW_USAGE, `${opLabel}-factors`);
      for (let i = 0; i < vectorCount; i += 1) {
        batch.copy(factors, repeated, vectorBytes, 0, i * vectorBytes);
      }
      recordElementwise(batch, vectorKernel, state, repeated, vectorSize * vectorCount, Uint32Array.from([vectorSize * vectorCount, VECTOR_OP_MUL_FACTORS, 0, 0, 0, 0, 0, 0]), opLabel);
      return;
    }
    const params = batch.uniform(Uint32Array.from([vectorSize, VECTOR_OP_MUL_FACTORS, 0, 0, 0, 0, 0, 0]));
    for (let i = 0; i < vectorCount; i += 1) {
      const input: BufferBinding = { buffer: state.current, offset: i * vectorBytes, size: vectorBytes };
      const output: BufferBinding = { buffer: state.next, offset: i * vectorBytes, size: vectorBytes };
      batch.dispatch(vectorKernel, [input, factors, output, params], Math.ceil(vectorSize / vectorKernel.workgroupSize), `${opLabel}-${i}`);
    }
    swap(state);
  }

  /**
   * Record a full NTT pipeline over `vectorCount` vectors of `vectorSize`
   * Montgomery (or regular, see `inputRegular`) elements held in `state`.
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
    },
  ): void {
    const { vectorCount, inverse, inputRegular, outputRegular, inputBitReversed = false, inverseCoset = false } = pipeline;
    const vectorSize = domain.size;
    const totalCount = vectorSize * vectorCount;
    const zeroAux = batch.upload(new Uint8Array(4), STORAGE_IN_USAGE, "zero-aux");

    if (inputRegular) {
      recordElementwise(batch, fieldKernel, state, zeroAux, totalCount, Uint32Array.from([totalCount, FIELD_OP.TO_MONT, 0, 0, 0, 0, 0, 0]), "to-mont");
    }
    if (!inputBitReversed) {
      recordElementwise(batch, vectorKernel, state, zeroAux, totalCount, Uint32Array.from([totalCount, VECTOR_OP_BIT_REVERSE_COPY, domain.logN, vectorSize, 0, 0, 0, 0]), "bit-reverse");
    }

    const twiddles = inverse ? domain.inverseTwiddles : domain.forwardTwiddles;
    for (let stage = 0; stage < domain.logN; stage += 1) {
      const stageTwiddles: BufferBinding = { buffer: twiddles, offset: domain.stageOffsets[stage], size: domain.stageSizes[stage] };
      batch.dispatch(
        nttKernel,
        [state.current, stageTwiddles, state.next, batch.uniform(Uint32Array.from([vectorSize, 1 << stage, vectorCount, inverse ? 1 : 0, 0, 0, 0, 0]))],
        [Math.ceil(vectorSize / 2 / nttKernel.workgroupSize), vectorCount, 1],
        `stage-${stage}-${inverse ? "inv" : "fwd"}`,
      );
      swap(state);
    }

    if (inverse) {
      recordMulFactors(batch, state, domain.inverseScaleFactors, vectorSize, vectorCount, "inverse-scale");
    }
    if (inverseCoset) {
      recordMulFactors(batch, state, domain.inverseCosetPowers, vectorSize, vectorCount, "inverse-coset-scale");
    }
    if (outputRegular) {
      recordElementwise(batch, fieldKernel, state, zeroAux, totalCount, Uint32Array.from([totalCount, FIELD_OP.FROM_MONT, 0, 0, 0, 0, 0, 0]), "from-mont");
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
    const mont = { vectorCount: 1, inputRegular: !inputMontgomery, outputRegular: false };
    const fieldParams = (opcode: number): Uint32Array => Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]);

    return recordAndRead(device, context.bufferPool, `${label}-groth16-quotient`, (batch) => {
      const states = [a, b, c].map((values) => uploadState(batch, values));
      // Coefficients, then evaluations on the coset.
      for (const state of states) {
        recordPipeline(batch, state, domain, { ...mont, inverse: true });
        recordMulFactors(batch, state, domain.cosetPowers, count, 1, "coset-shift");
        recordPipeline(batch, state, domain, { ...mont, inputRegular: false, inverse: false });
      }
      const [h, bCoset, cCoset] = states;
      // h = (a * b - c) / (g^n - 1) on the coset.
      recordElementwise(batch, fieldKernel, h, bCoset.current, count, fieldParams(FIELD_OP.MUL), "ab");
      recordElementwise(batch, fieldKernel, h, cCoset.current, count, fieldParams(FIELD_OP.SUB), "ab-minus-c");
      recordMulFactors(batch, h, domain.cosetDenInvFactors, count, 1, "coset-den-inv");
      // Back to coefficients, undo the coset shift, regular form, bit-reversed order.
      recordPipeline(batch, h, domain, { ...mont, inputRegular: false, inverse: true });
      recordMulFactors(batch, h, domain.inverseCosetPowers, count, 1, "inverse-coset-shift");
      if (!outputMontgomery) {
        recordElementwise(batch, fieldKernel, h, batch.upload(new Uint8Array(4)), count, fieldParams(FIELD_OP.FROM_MONT), "from-mont");
      }
      recordElementwise(batch, vectorKernel, h, batch.upload(new Uint8Array(4)), count, Uint32Array.from([count, VECTOR_OP_BIT_REVERSE_COPY, domain.logN, 0, 0, 0, 0, 0]), "bit-reverse");
      return { buffer: h.current, size: a.byteLength };
    }, context.debug);
  }

  async function prewarmDomain(size: number): Promise<void> {
    prepareDomain(size);
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
    prewarmDomain,
    prewarmGroth16QuotientDomain: prewarmDomain,
    computeGroth16QuotientPackedRegular: (a, b, c) => computeGroth16QuotientPacked(a, b, c, false),
    computeGroth16QuotientPackedMont: (a, b, c) => computeGroth16QuotientPacked(a, b, c, true),
    computeGroth16QuotientMont: (a, b, c) => computeGroth16QuotientPacked(a, b, c, true, true),
  };
}
