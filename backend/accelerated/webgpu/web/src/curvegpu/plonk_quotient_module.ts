import type { CurveGPUContext, FieldModule, NTTModule, SupportedCurveID } from "./api.js";
import type { Kernel } from "./gpu.js";
import { cloneBytes, recordAndRead, STORAGE_IN_USAGE, STORAGE_RW_USAGE } from "./gpu.js";
import { fetchShaderParts } from "./shaders.js";

const PLONK_QUOTIENT_BASE_DYNAMIC_VECTOR_COUNT = 5;
const PLONK_QUOTIENT_BASE_STATIC_VECTOR_COUNT = 7;
const PLONK_QUOTIENT_BLIND_COUNT = 4;
const PLONK_QUOTIENT_SCALAR_COUNT = 7;
const PLONK_QUOTIENT_WORKGROUP_SIZE = 64;

export type PlonkTransformAndEvaluateQuotientCosetsInput = {
  dynamicValuesPacked: Uint8Array;
  scalingPacked: Uint8Array;
  staticValuesPacked: Uint8Array;
  staticMontCacheKeysPacked: Uint8Array;
  twiddlesPacked: Uint8Array;
  denominatorsPacked: Uint8Array;
  blindsPacked: Uint8Array;
  scalarsPacked: Uint8Array;
  elementCount: number;
  blindCoeffCount: number;
  commitmentCount: number;
  /** Accepted for wire compatibility; the transformed dynamic vectors are not cached. */
  dynamicTransformCacheKey?: number;
  cosetCount: number;
  auxMontCacheKey?: number;
};

export type PlonkPreloadQuotientStaticAndAuxInput = {
  staticValuesPacked: Uint8Array;
  staticMontCacheKeysPacked: Uint8Array;
  scalingPacked: Uint8Array;
  twiddlesPacked: Uint8Array;
  denominatorsPacked: Uint8Array;
  elementCount: number;
  staticVectorCount: number;
  cosetCount: number;
  auxMontCacheKey: number;
};

export type PlonkQuotientModule = {
  readonly context: CurveGPUContext;
  readonly curve: SupportedCurveID;
  transformAndEvaluateQuotientCosets(input: PlonkTransformAndEvaluateQuotientCosetsInput): Promise<Uint8Array>;
  preloadQuotientStaticAndAux(input: PlonkPreloadQuotientStaticAndAuxInput): Promise<void>;
  prewarmPlonkQuotientEvaluateKernel(commitmentCount?: number): Promise<void>;
};

function repeatPackedVector(value: Uint8Array, count: number): Uint8Array {
  const out = new Uint8Array(value.byteLength * count);
  for (let i = 0; i < count; i += 1) {
    out.set(value, i * value.byteLength);
  }
  return out;
}

function repeatEachPackedVector(values: Uint8Array, vectorBytes: number, repeatCount: number): Uint8Array {
  const vectorCount = values.byteLength / vectorBytes;
  const out = new Uint8Array(values.byteLength * repeatCount);
  for (let i = 0; i < vectorCount; i += 1) {
    const vector = values.subarray(i * vectorBytes, (i + 1) * vectorBytes);
    for (let j = 0; j < repeatCount; j += 1) {
      out.set(vector, (i * repeatCount + j) * vectorBytes);
    }
  }
  return out;
}

function unpackU32LE(bytes: Uint8Array, count: number, label: string): number[] {
  if (bytes.byteLength !== count * 4) {
    throw new Error(`${label}: expected ${count * 4} bytes, got ${bytes.byteLength}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Array.from({ length: count }, (_, i) => view.getUint32(i * 4, true));
}

function assertPowerOfTwo(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0 || (value & (value - 1)) !== 0) {
    throw new Error(`${label} ${value}`);
  }
}

function assertCount(value: number, label: string, allowZero = false): void {
  if (!Number.isInteger(value) || value < 0 || (!allowZero && value === 0)) {
    throw new Error(`${label} ${value}`);
  }
}

function assertBytes(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.byteLength !== expected) {
    throw new Error(`${label} expected ${expected} bytes, got ${bytes.byteLength}`);
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
  const quotientKernels = new Map<number, Promise<Kernel>>();
  const staticMontCache = new Map<number, { elementCount: number; staticVectorCount: number; mont: Uint8Array }>();
  const auxMontCache = new Map<
    number,
    { elementCount: number; cosetCount: number; scalingMont: Uint8Array; twiddlesMont: Uint8Array; denominatorsMont: Uint8Array }
  >();
  let layouts: { bindGroupLayout: GPUBindGroupLayout; pipelineLayout: GPUPipelineLayout } | null = null;
  let shaderModule: Promise<GPUShaderModule> | null = null;

  function getLayouts(): { bindGroupLayout: GPUBindGroupLayout; pipelineLayout: GPUPipelineLayout } {
    if (!layouts) {
      const bindGroupLayout = device.createBindGroupLayout({
        label: `plonk-${curve}-quotient-bgl`,
        entries: [0, 1, 2, 3, 4].map((binding) => ({
          binding,
          visibility: GPUShaderStage.COMPUTE,
          buffer: { type: binding === 4 ? "uniform" : binding === 3 ? "storage" : "read-only-storage" },
        })),
      });
      layouts = {
        bindGroupLayout,
        pipelineLayout: device.createPipelineLayout({ label: `plonk-${curve}-quotient-pl`, bindGroupLayouts: [bindGroupLayout] }),
      };
    }
    return layouts;
  }

  function getQuotientKernel(commitmentCount: number): Promise<Kernel> {
    assertCount(commitmentCount, "invalid PLONK quotient commitment count", true);
    let kernel = quotientKernels.get(commitmentCount);
    if (!kernel) {
      kernel = (async (): Promise<Kernel> => {
        const { bindGroupLayout, pipelineLayout } = getLayouts();
        shaderModule ??= fetchShaderParts(shaderParts).then((code) => device.createShaderModule({ label: `plonk-${curve}-quotient-shader`, code }));
        const pipeline = await device.createComputePipelineAsync({
          label: `plonk-${curve}-quotient-c${commitmentCount}`,
          layout: pipelineLayout,
          compute: {
            module: await shaderModule,
            entryPoint: "fr_plonk_quotient_main",
            constants: { WORKGROUP_SIZE: PLONK_QUOTIENT_WORKGROUP_SIZE, COMMITMENT_COUNT: commitmentCount },
          },
        });
        return { pipeline, bindGroupLayout, workgroupSize: PLONK_QUOTIENT_WORKGROUP_SIZE };
      })();
      quotientKernels.set(commitmentCount, kernel);
    }
    return kernel;
  }

  async function runQuotientKernelMont(
    vectorsMontPacked: Uint8Array,
    blindsMontPacked: Uint8Array,
    scalarsMontPacked: Uint8Array,
    elementCount: number,
    blindCoeffCount: number,
    commitmentCount: number,
    cosetCount: number,
  ): Promise<Uint8Array> {
    const outputBytes = cosetCount * elementCount * fr.byteSize;
    const kernel = await getQuotientKernel(commitmentCount);
    return recordAndRead(device, context.bufferPool, `plonk-${curve}-quotient`, (batch) => {
      const output = batch.temp(outputBytes, STORAGE_RW_USAGE, "output");
      batch.dispatch(
        kernel,
        [
          batch.upload(vectorsMontPacked, STORAGE_IN_USAGE, "vectors"),
          batch.upload(blindsMontPacked, STORAGE_IN_USAGE, "blinds"),
          batch.upload(scalarsMontPacked, STORAGE_IN_USAGE, "scalars"),
          output,
          batch.uniform(new Uint32Array([elementCount, blindCoeffCount, cosetCount, 0])),
        ],
        [Math.ceil(elementCount / kernel.workgroupSize), cosetCount, 1],
        "evaluate",
      );
      return { buffer: output, size: outputBytes };
    }, context.debug);
  }

  async function transformAndEvaluateQuotientCosets(input: PlonkTransformAndEvaluateQuotientCosetsInput): Promise<Uint8Array> {
    const {
      dynamicValuesPacked,
      scalingPacked,
      staticValuesPacked,
      staticMontCacheKeysPacked,
      twiddlesPacked,
      denominatorsPacked,
      blindsPacked,
      scalarsPacked,
      elementCount,
      blindCoeffCount,
      commitmentCount,
      cosetCount,
      auxMontCacheKey = 0,
    } = input;
    const elementBytes = fr.byteSize;
    const vectorBytes = elementCount * elementBytes;
    assertPowerOfTwo(elementCount, "invalid PLONK quotient evaluate element count");
    assertCount(blindCoeffCount, "invalid PLONK quotient blind coefficient count", true);
    assertCount(commitmentCount, "invalid PLONK quotient commitment count", true);
    assertCount(cosetCount, "invalid PLONK quotient coset count");
    assertCount(auxMontCacheKey, "invalid PLONK quotient aux cache key", true);

    const dynamicVectorCount = PLONK_QUOTIENT_BASE_DYNAMIC_VECTOR_COUNT + commitmentCount;
    const staticVectorCount = PLONK_QUOTIENT_BASE_STATIC_VECTOR_COUNT + commitmentCount;
    const vectorCount = dynamicVectorCount + staticVectorCount + 2;
    assertBytes(dynamicValuesPacked, dynamicVectorCount * vectorBytes, "PLONK quotient cosets dynamic");

    const cachedAux = auxMontCacheKey > 0 ? auxMontCache.get(auxMontCacheKey) : undefined;
    const canReuseAuxCache =
      scalingPacked.byteLength === 0 &&
      twiddlesPacked.byteLength === 0 &&
      denominatorsPacked.byteLength === 0 &&
      cachedAux !== undefined &&
      cachedAux.elementCount === elementCount &&
      cachedAux.cosetCount === cosetCount;
    if (!canReuseAuxCache) {
      assertBytes(scalingPacked, cosetCount * vectorBytes, "PLONK quotient cosets scaling");
      assertBytes(twiddlesPacked, vectorBytes, "PLONK quotient cosets twiddle");
      assertBytes(denominatorsPacked, cosetCount * vectorBytes, "PLONK quotient cosets denominator");
    }
    const staticMontCacheKeys = unpackU32LE(staticMontCacheKeysPacked, cosetCount, "PLONK quotient static cache keys");
    const canReuseStaticCache =
      staticValuesPacked.byteLength === 0 &&
      staticMontCacheKeys.every((key) => {
        const cached = key > 0 ? staticMontCache.get(key) : undefined;
        return cached?.elementCount === elementCount && cached.staticVectorCount === staticVectorCount;
      });
    if (!canReuseStaticCache) {
      assertBytes(staticValuesPacked, cosetCount * staticVectorCount * vectorBytes, "PLONK quotient cosets static");
    }
    const blindBytes = PLONK_QUOTIENT_BLIND_COUNT * blindCoeffCount * elementBytes;
    assertBytes(blindsPacked, cosetCount * blindBytes, "PLONK quotient cosets blinding");
    assertBytes(scalarsPacked, cosetCount * PLONK_QUOTIENT_SCALAR_COUNT * elementBytes, "PLONK quotient cosets scalar");

    const dynamicMont = await fr.toMontgomeryPacked(cloneBytes(dynamicValuesPacked));
    const dynamicCoeffMont = await ntt.inversePackedMontBatch(dynamicMont, elementCount, dynamicVectorCount);

    let scalingMont: Uint8Array;
    let twiddlesMont: Uint8Array;
    let denominatorsMont: Uint8Array;
    if (canReuseAuxCache) {
      ({ scalingMont, twiddlesMont, denominatorsMont } = cachedAux);
    } else {
      [scalingMont, twiddlesMont, denominatorsMont] = await Promise.all([
        fr.toMontgomeryPacked(cloneBytes(scalingPacked)),
        fr.toMontgomeryPacked(cloneBytes(twiddlesPacked)),
        fr.toMontgomeryPacked(cloneBytes(denominatorsPacked)),
      ]);
      if (auxMontCacheKey > 0) {
        auxMontCache.set(auxMontCacheKey, {
          elementCount,
          cosetCount,
          scalingMont: cloneBytes(scalingMont),
          twiddlesMont: cloneBytes(twiddlesMont),
          denominatorsMont: cloneBytes(denominatorsMont),
        });
      }
    }
    const shiftedCoeffMont = await fr.mulPackedMont(
      repeatPackedVector(dynamicCoeffMont, cosetCount),
      repeatEachPackedVector(scalingMont, vectorBytes, dynamicVectorCount),
    );
    const dynamicCosetsMont = await ntt.forwardPackedMontBatch(shiftedCoeffMont, elementCount, dynamicVectorCount * cosetCount);

    let staticMont: Uint8Array;
    if (canReuseStaticCache) {
      staticMont = new Uint8Array(cosetCount * staticVectorCount * vectorBytes);
      for (let i = 0; i < cosetCount; i += 1) {
        const cached = staticMontCache.get(staticMontCacheKeys[i]);
        if (!cached) {
          throw new Error(`PLONK quotient missing static cache key ${staticMontCacheKeys[i]}`);
        }
        staticMont.set(cached.mont, i * staticVectorCount * vectorBytes);
      }
    } else {
      staticMont = await fr.toMontgomeryPacked(cloneBytes(staticValuesPacked));
      for (let i = 0; i < cosetCount; i += 1) {
        const key = staticMontCacheKeys[i];
        if (key > 0) {
          const start = i * staticVectorCount * vectorBytes;
          staticMontCache.set(key, {
            elementCount,
            staticVectorCount,
            mont: cloneBytes(staticMont.subarray(start, start + staticVectorCount * vectorBytes)),
          });
        }
      }
    }

    const [blindsMont, scalarsMont] = await Promise.all([
      fr.toMontgomeryPacked(cloneBytes(blindsPacked)),
      fr.toMontgomeryPacked(cloneBytes(scalarsPacked)),
    ]);

    const vectorsMontPacked = new Uint8Array(cosetCount * vectorCount * vectorBytes);
    for (let i = 0; i < cosetCount; i += 1) {
      const vectorsStart = i * vectorCount * vectorBytes;
      const dynamicStart = i * dynamicVectorCount * vectorBytes;
      vectorsMontPacked.set(dynamicCosetsMont.subarray(dynamicStart, dynamicStart + dynamicVectorCount * vectorBytes), vectorsStart);
      const staticStart = i * staticVectorCount * vectorBytes;
      vectorsMontPacked.set(
        staticMont.subarray(staticStart, staticStart + staticVectorCount * vectorBytes),
        vectorsStart + dynamicVectorCount * vectorBytes,
      );
      vectorsMontPacked.set(twiddlesMont, vectorsStart + (dynamicVectorCount + staticVectorCount) * vectorBytes);
      const denominatorStart = i * vectorBytes;
      vectorsMontPacked.set(
        denominatorsMont.subarray(denominatorStart, denominatorStart + vectorBytes),
        vectorsStart + (dynamicVectorCount + staticVectorCount + 1) * vectorBytes,
      );
    }
    return runQuotientKernelMont(vectorsMontPacked, blindsMont, scalarsMont, elementCount, blindCoeffCount, commitmentCount, cosetCount);
  }

  async function preloadQuotientStaticAndAux(input: PlonkPreloadQuotientStaticAndAuxInput): Promise<void> {
    const {
      staticValuesPacked,
      staticMontCacheKeysPacked,
      scalingPacked,
      twiddlesPacked,
      denominatorsPacked,
      elementCount,
      staticVectorCount,
      cosetCount,
      auxMontCacheKey,
    } = input;
    const vectorBytes = elementCount * fr.byteSize;
    assertPowerOfTwo(elementCount, "invalid PLONK quotient preload element count");
    assertCount(staticVectorCount, "invalid PLONK quotient preload static vector count");
    assertCount(cosetCount, "invalid PLONK quotient preload coset count");
    assertCount(auxMontCacheKey, "invalid PLONK quotient preload aux cache key");
    assertBytes(staticValuesPacked, cosetCount * staticVectorCount * vectorBytes, "PLONK quotient preload static");
    assertBytes(scalingPacked, cosetCount * vectorBytes, "PLONK quotient preload scaling");
    assertBytes(twiddlesPacked, vectorBytes, "PLONK quotient preload twiddle");
    assertBytes(denominatorsPacked, cosetCount * vectorBytes, "PLONK quotient preload denominator");

    const staticMontCacheKeys = unpackU32LE(staticMontCacheKeysPacked, cosetCount, "PLONK quotient preload static cache keys");
    const [staticMont, scalingMont, twiddlesMont, denominatorsMont] = await Promise.all([
      fr.toMontgomeryPacked(cloneBytes(staticValuesPacked)),
      fr.toMontgomeryPacked(cloneBytes(scalingPacked)),
      fr.toMontgomeryPacked(cloneBytes(twiddlesPacked)),
      fr.toMontgomeryPacked(cloneBytes(denominatorsPacked)),
    ]);

    for (let i = 0; i < cosetCount; i += 1) {
      const key = staticMontCacheKeys[i];
      if (key <= 0) {
        throw new Error(`invalid PLONK quotient preload static cache key ${key}`);
      }
      const start = i * staticVectorCount * vectorBytes;
      staticMontCache.set(key, {
        elementCount,
        staticVectorCount,
        mont: cloneBytes(staticMont.subarray(start, start + staticVectorCount * vectorBytes)),
      });
    }
    auxMontCache.set(auxMontCacheKey, {
      elementCount,
      cosetCount,
      scalingMont: cloneBytes(scalingMont),
      twiddlesMont: cloneBytes(twiddlesMont),
      denominatorsMont: cloneBytes(denominatorsMont),
    });
  }

  return {
    context,
    curve,
    transformAndEvaluateQuotientCosets,
    preloadQuotientStaticAndAux,
    async prewarmPlonkQuotientEvaluateKernel(commitmentCount = 0): Promise<void> {
      await getQuotientKernel(commitmentCount);
    },
  };
}
