import type { CurveGPUContext, FieldModule, NTTModule, SupportedCurveID } from "./api.js";
import type { Kernel } from "./gpu.js";
import { alignBytes, recordAndRead, STORAGE_IN_USAGE, STORAGE_RW_USAGE, uploadGPUBuffer } from "./gpu.js";
import { fetchShaderParts } from "./shaders.js";

// Must match fr_plonk_quotient.wgsl and the Go accelerator.
const DYNAMIC_BASE_COUNT = 5; // L, R, O, Z, Qk, then the committed values
const STATIC_BASE_COUNT = 7; // Ql, Qr, Qm, Qo, S1, S2, S3, then the Qcp selectors
const BLIND_COUNT = 4;
const SCALAR_COUNT = 7;
const WORKGROUP_SIZE = 64;

/** Circuit polynomials of one proving key, resident on the GPU. */
export type PlonkQuotientStatics = {
  readonly n: number;
  readonly staticVectorCount: number;
  readonly cosetCount: number;
  /** canonical form, staticVectorCount vectors of n elements */
  readonly statics: GPUBuffer;
  /** cosetCount vectors: powers of the coset shift */
  readonly scaling: GPUBuffer;
  /** one vector: powers of the small domain generator */
  readonly twiddles: GPUBuffer;
  /** cosetCount vectors: 1/(s·ωⁱ − 1) */
  readonly denominators: GPUBuffer;
  release(): void;
};

export type PlonkQuotientEvaluateInput = {
  /** DYNAMIC_BASE_COUNT + commitmentCount vectors of n Montgomery elements, Lagrange basis */
  dynamic: Uint8Array;
  /** cosetCount × BLIND_COUNT × blindCoeffCount Montgomery elements */
  blinds: Uint8Array;
  /** cosetCount × SCALAR_COUNT Montgomery elements */
  scalars: Uint8Array;
  n: number;
  blindCoeffCount: number;
  commitmentCount: number;
  cosetCount: number;
};

export type PlonkQuotientModule = {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  /** Uploads the canonical circuit polynomials and coset tables under key (all Montgomery). */
  preloadStatics(key: number, input: { statics: Uint8Array; scaling: Uint8Array; twiddles: Uint8Array; denominators: Uint8Array; n: number; staticVectorCount: number; cosetCount: number }): Promise<void>;
  releaseStatics(key: number): void;
  /**
   * Evaluates the numerator on every coset in one GPU submission. Returns the
   * numerator in Montgomery form, already in the bit-reversed layout of the
   * large domain, and the canonical form of the dynamic vectors.
   */
  evaluate(key: number, input: PlonkQuotientEvaluateInput): Promise<{ numerator: Uint8Array; canonical: Uint8Array }>;
  prewarm(n: number, cosetCount: number, commitmentCount: number): Promise<void>;
};

function assertPowerOfTwo(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0 || (value & (value - 1)) !== 0) {
    throw new Error(`${label}: ${value} is not a power of two`);
  }
}

function assertBytes(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.byteLength !== expected) {
    throw new Error(`${label}: expected ${expected} bytes, got ${bytes.byteLength}`);
  }
}

export function createPlonkQuotientModule(config: {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  shaderParts: readonly string[];
  fr: FieldModule;
  ntt: NTTModule;
}): PlonkQuotientModule {
  const { context, curve, shaderParts, fr, ntt } = config;
  const device = context.device;
  const elementBytes = fr.byteSize;
  const kernels = new Map<number, Promise<Kernel>>();
  const statics = new Map<number, PlonkQuotientStatics>();
  let layouts: { bindGroupLayout: GPUBindGroupLayout; pipelineLayout: GPUPipelineLayout } | null = null;
  let shaderModule: Promise<GPUShaderModule> | null = null;

  function getLayouts(): { bindGroupLayout: GPUBindGroupLayout; pipelineLayout: GPUPipelineLayout } {
    if (!layouts) {
      const bindGroupLayout = device.createBindGroupLayout({
        label: `plonk-${curve}-quotient-bgl`,
        entries: [0, 1, 2, 3, 4, 5, 6, 7].map((binding) => ({
          binding,
          visibility: GPUShaderStage.COMPUTE,
          buffer: { type: binding === 7 ? "uniform" : binding === 6 ? "storage" : "read-only-storage" },
        })),
      });
      layouts = { bindGroupLayout, pipelineLayout: device.createPipelineLayout({ label: `plonk-${curve}-quotient-pl`, bindGroupLayouts: [bindGroupLayout] }) };
    }
    return layouts;
  }

  function getKernel(commitmentCount: number): Promise<Kernel> {
    let kernel = kernels.get(commitmentCount);
    if (!kernel) {
      kernel = (async (): Promise<Kernel> => {
        const { bindGroupLayout, pipelineLayout } = getLayouts();
        shaderModule ??= fetchShaderParts(shaderParts).then((code) => device.createShaderModule({ label: `plonk-${curve}-quotient-shader`, code }));
        const pipeline = await device.createComputePipelineAsync({
          label: `plonk-${curve}-quotient-c${commitmentCount}`,
          layout: pipelineLayout,
          compute: { module: await shaderModule, entryPoint: "fr_plonk_quotient_main", constants: { WORKGROUP_SIZE, COMMITMENT_COUNT: commitmentCount } },
        });
        return { pipeline, bindGroupLayout, workgroupSize: WORKGROUP_SIZE };
      })();
      kernels.set(commitmentCount, kernel);
    }
    return kernel;
  }

  function getStatics(key: number, n: number, cosetCount: number, staticVectorCount: number): PlonkQuotientStatics {
    const s = statics.get(key);
    if (!s) {
      throw new Error(`PLONK quotient: unknown statics key ${key}`);
    }
    if (s.n !== n || s.cosetCount !== cosetCount || s.staticVectorCount !== staticVectorCount) {
      throw new Error(`PLONK quotient: statics key ${key} were prepared for n=${s.n}, ${s.cosetCount} cosets, ${s.staticVectorCount} vectors`);
    }
    return s;
  }

  return {
    context,
    curve,

    async preloadStatics(key, input): Promise<void> {
      const { n, staticVectorCount, cosetCount } = input;
      assertPowerOfTwo(n, "PLONK quotient statics size");
      const vectorBytes = n * elementBytes;
      assertBytes(input.statics, staticVectorCount * vectorBytes, "PLONK quotient statics");
      assertBytes(input.scaling, cosetCount * vectorBytes, "PLONK quotient scaling");
      assertBytes(input.twiddles, vectorBytes, "PLONK quotient twiddles");
      assertBytes(input.denominators, cosetCount * vectorBytes, "PLONK quotient denominators");
      statics.get(key)?.release();
      // statics are copied into a scratch buffer per coset (COPY_SRC); the tables are only bound
      const upload = (bytes: Uint8Array, label: string, usage = STORAGE_IN_USAGE): GPUBuffer => uploadGPUBuffer(device, `plonk-${curve}-${label}-${key}`, bytes, usage);
      const buffers = {
        statics: upload(input.statics, "statics", STORAGE_RW_USAGE),
        scaling: upload(input.scaling, "scaling"),
        twiddles: upload(input.twiddles, "twiddles"),
        denominators: upload(input.denominators, "denominators"),
      };
      statics.set(key, {
        n,
        staticVectorCount,
        cosetCount,
        ...buffers,
        release: () => Object.values(buffers).forEach((b) => b.destroy()),
      });
      await ntt.prewarmDomain(n);
    },

    releaseStatics(key): void {
      statics.get(key)?.release();
      statics.delete(key);
    },

    async evaluate(key, input) {
      const { n, blindCoeffCount, commitmentCount, cosetCount } = input;
      assertPowerOfTwo(n, "PLONK quotient size");
      assertPowerOfTwo(cosetCount, "PLONK quotient coset count");
      const dynamicCount = DYNAMIC_BASE_COUNT + commitmentCount;
      const staticCount = STATIC_BASE_COUNT + commitmentCount;
      const vectorBytes = n * elementBytes;
      assertBytes(input.dynamic, dynamicCount * vectorBytes, "PLONK quotient dynamic vectors");
      assertBytes(input.blinds, cosetCount * BLIND_COUNT * blindCoeffCount * elementBytes, "PLONK quotient blinds");
      assertBytes(input.scalars, cosetCount * SCALAR_COUNT * elementBytes, "PLONK quotient scalars");
      const s = getStatics(key, n, cosetCount, staticCount);
      const kernel = await getKernel(commitmentCount);
      const logTotal = Math.log2(n * cosetCount);
      const numeratorBytes = cosetCount * vectorBytes;
      const canonicalBytes = dynamicCount * vectorBytes;

      const result = await recordAndRead(device, context.bufferPool, `plonk-${curve}-quotient`, (batch) => {
        // witness vectors to canonical form (kept for the caller), then per coset:
        // shift, evaluate on the coset, and run the numerator kernel.
        const out = batch.temp(alignBytes(numeratorBytes + canonicalBytes), STORAGE_RW_USAGE, "result");
        const dynamicCanonical = ntt.recordInverse(batch, batch.upload(input.dynamic, STORAGE_RW_USAGE, "dynamic"), n, dynamicCount);
        batch.copy(dynamicCanonical, out, canonicalBytes, 0, numeratorBytes);
        const blinds = batch.upload(input.blinds, STORAGE_IN_USAGE, "blinds");
        const scalars = batch.upload(input.scalars, STORAGE_IN_USAGE, "scalars");
        const dynamicCoset = batch.temp(canonicalBytes, STORAGE_RW_USAGE, "dynamic-coset");
        const staticCoset = batch.temp(staticCount * vectorBytes, STORAGE_RW_USAGE, "static-coset");
        for (let coset = 0; coset < cosetCount; coset += 1) {
          const shift = { buffer: s.scaling, offset: coset * vectorBytes, size: vectorBytes };
          batch.copy(dynamicCanonical, dynamicCoset, canonicalBytes);
          ntt.recordMulVector(batch, dynamicCoset, shift, n, dynamicCount);
          const dynamicEvals = ntt.recordForward(batch, dynamicCoset, n, dynamicCount);
          batch.copy(s.statics, staticCoset, staticCount * vectorBytes);
          ntt.recordMulVector(batch, staticCoset, shift, n, staticCount);
          const staticEvals = ntt.recordForward(batch, staticCoset, n, staticCount);
          batch.dispatch(
            kernel,
            [
              dynamicEvals,
              staticEvals,
              s.twiddles,
              { buffer: s.denominators, offset: coset * vectorBytes, size: vectorBytes },
              blinds,
              scalars,
              { buffer: out, offset: 0, size: numeratorBytes },
              batch.uniform(new Uint32Array([n, blindCoeffCount, cosetCount, coset, logTotal, 0, 0, 0])),
            ],
            Math.ceil(n / kernel.workgroupSize),
            `evaluate-coset-${coset}`,
          );
        }
        return { buffer: out, size: numeratorBytes + canonicalBytes };
      }, context.debug);
      return { numerator: result.subarray(0, numeratorBytes), canonical: result.subarray(numeratorBytes) };
    },

    async prewarm(n, cosetCount, commitmentCount): Promise<void> {
      assertPowerOfTwo(n, "PLONK quotient size");
      await Promise.all([ntt.prewarmDomain(n), ntt.prewarmDomain(n * cosetCount), getKernel(commitmentCount)]);
    },
  };
}

