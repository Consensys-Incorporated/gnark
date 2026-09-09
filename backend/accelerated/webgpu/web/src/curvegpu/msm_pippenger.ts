import type { CommandBatch, Kernel } from "./gpu.js";
import { STORAGE_IN_USAGE, STORAGE_RW_USAGE } from "./gpu.js";

/** Number of signed-digit windows for a 256-bit scalar: the last one only carries. */
export function signedWindowCount(window: number): number {
  return Math.ceil(256 / window) + 1;
}

/** Bit length of the scalar fields of the supported curves (253 to 255); the windows above it stay empty. */
const SCALAR_BITS = 254;

/** Bucket chunk size the bucket stage is dispatched with (see `recordSparseSignedPippengerMSM`). */
const DEFAULT_CHUNK_SIZE = 256;

/**
 * Pick the Pippenger window for `count` terms.
 *
 * Cost model, fitted on per-stage timings of an Apple M-series GPU at 2^16 to
 * 2^18 terms: the bucket stage costs one mixed addition per term and populated
 * window (`ceil(254 / w)` windows plus the carry window, which only holds
 * carries), and the sort, reduce, weight and sum stages about three additions
 * per bucket. The single-threaded combine chain (256 doublings) does not
 * depend on the window. Below about 2^16 terms the GPU is latency-bound and a
 * window of 8 measures 10-20% faster than this model's pick.
 */
export function bestPippengerWindow(count: number): number {
  let best = 4;
  let bestCost = Number.POSITIVE_INFINITY;
  for (let window = 4; window <= 16; window += 1) {
    const buckets = 1 << (window - 1);
    const windows = Math.ceil(SCALAR_BITS / window) + 0.5;
    const cost = windows * (count + 3 * buckets);
    if (cost < bestCost) {
      bestCost = cost;
      best = window;
    }
  }
  return best;
}

/** The Jacobian Pippenger stages of one group's MSM shader (g1_msm_jac.wgsl / g2_msm_jac.wgsl). */
export type MSMKernels = {
  bucket: Kernel;
  fold_partial: Kernel;
  fold: Kernel;
  reduce: Kernel;
  weight: Kernel;
  sum: Kernel;
  sum_windows: Kernel;
  combine: Kernel;
};

/** Stage names in `MSMKernels`, in dispatch order; entry points are `${group}_msm_${stage}_jac_main`. */
export const MSM_STAGES = ["bucket", "fold_partial", "fold", "reduce", "weight", "sum", "sum_windows", "combine"] as const satisfies readonly (keyof MSMKernels)[];

/** Threads sharing one heavy slot in the fold_partial stage (`G1_MSM_FOLD_LANES` / `G2_MSM_FOLD_LANES`). */
const FOLD_LANES = 8;

/** The group-independent bucket assignment stages (shaders/common/msm_sort.wgsl). */
export type MSMSortKernels = {
  count: Kernel;
  scan: Kernel;
  scatter: Kernel;
  chunks: Kernel;
};

/** Sizes of one bucket assignment; see msm_sort.wgsl for the buffer layouts. */
export type BucketSortShape = {
  count: number;
  termsPerInstance: number;
  termCount: number;
  window: number;
  numWindows: number;
  bucketCount: number;
  /** `count * numWindows * bucketCount`. */
  slotCount: number;
  chunkSize: number;
  /** Upper bounds on the entry, chunk and heavy-slot counts (exact counts are computed on the GPU). */
  maxEntries: number;
  maxChunks: number;
  maxHeavy: number;
};

export function bucketSortShape(count: number, termsPerInstance: number, window: number, chunkSize: number): BucketSortShape {
  if (!Number.isInteger(window) || window < 2 || window > 16) {
    throw new Error(`msm: window must be an integer in [2, 16], got ${window}`);
  }
  if (!Number.isInteger(chunkSize) || chunkSize < 1) {
    throw new Error(`msm: maxChunkSize must be a positive integer, got ${chunkSize}`);
  }
  const numWindows = signedWindowCount(window);
  const bucketCount = 1 << (window - 1);
  const termCount = count * termsPerInstance;
  const slotCount = count * numWindows * bucketCount;
  const maxEntries = termCount * numWindows;
  return {
    count,
    termsPerInstance,
    termCount,
    window,
    numWindows,
    bucketCount,
    slotCount,
    chunkSize,
    maxEntries,
    maxChunks: Math.ceil(maxEntries / chunkSize) + slotCount,
    // A slot is heavy once it holds more than `chunkSize` entries.
    maxHeavy: Math.max(1, Math.min(slotCount, Math.floor(maxEntries / (chunkSize + 1)))),
  };
}

/** GPU buffers holding one bucket assignment (valid until the batch finishes). */
export type BucketSortBuffers = {
  shape: BucketSortShape;
  /** `2 * slotCount` u32: counts then scatter cursors. */
  counters: GPUBuffer;
  /** `2 * slotCount + 2` u32: entry offsets, chunk offsets (+ total chunks), total entries. */
  meta: GPUBuffer;
  /** Signed base indices grouped by slot. */
  indices: GPUBuffer;
  /** Per chunk: (start, size) into `indices`. */
  chunks: GPUBuffer;
  /** Slots with more than one chunk: `[0]` their number, slot ids from word 1. */
  heavy: GPUBuffer;
};

/** Word offset of the slot ids in `BucketSortBuffers.heavy`. */
const HEAVY_LIST_OFFSET = 1;

/** Baseline WebGPU `maxComputeWorkgroupsPerDimension`; the batches never request more. */
const MAX_WORKGROUPS_PER_DIMENSION = 65535;

function workgroupsFor(kernel: Kernel, items: number, label: string): number {
  return checkWorkgroups(Math.max(1, Math.ceil(items / kernel.workgroupSize)), label);
}

function checkWorkgroups(workgroups: number, label: string): number {
  if (workgroups > MAX_WORKGROUPS_PER_DIMENSION) {
    throw new Error(`msm: ${label} needs ${workgroups} workgroups, above the WebGPU limit of ${MAX_WORKGROUPS_PER_DIMENSION}`);
  }
  return workgroups;
}

/** Acquire a storage temporary, refusing sizes the device cannot bind. */
function storageTemp(batch: CommandBatch, size: number, label: string): GPUBuffer {
  const limit = batch.device.limits.maxStorageBufferBindingSize;
  if (size > limit) {
    throw new Error(`msm: ${label} needs ${size} bytes, above the device maxStorageBufferBindingSize of ${limit}; lower the window or split the MSM`);
  }
  return batch.temp(size, STORAGE_RW_USAGE, label);
}

/** Packed regular little-endian 32-byte scalars, uploaded as-is (WebGPU buffers are little-endian). */
export type PackedScalars = Uint8Array | Uint32Array;

/**
 * Record the GPU bucket assignment of `scalars` (`shape.termCount` packed
 * regular little-endian 32-byte scalars). Base index `i + baseIndexOffset` is
 * written for term `i`.
 */
export function recordBucketSort(
  batch: CommandBatch,
  kernels: MSMSortKernels,
  scalars: PackedScalars,
  shape: BucketSortShape,
  baseIndexOffset = 0,
): BucketSortBuffers {
  if (scalars.byteLength !== shape.termCount * 32) {
    throw new Error(`msm: expected ${shape.termCount * 32} scalar bytes, got ${scalars.byteLength}`);
  }
  const words = (n: number): number => Math.max(1, n) * 4;
  const scalarBuffer = batch.upload(scalars, STORAGE_IN_USAGE, "scalars");
  const counters = storageTemp(batch, words(2 * shape.slotCount), "sort-counters");
  const meta = storageTemp(batch, words(2 * shape.slotCount + 2), "sort-meta");
  const indices = storageTemp(batch, words(shape.maxEntries), "sort-indices");
  const chunks = storageTemp(batch, words(2 * shape.maxChunks), "sort-chunks");
  const heavy = storageTemp(batch, words(HEAVY_LIST_OFFSET + shape.maxHeavy), "sort-heavy");
  const params = batch.uniform(
    Uint32Array.of(shape.termCount, shape.termsPerInstance, shape.window, shape.numWindows, shape.bucketCount, shape.chunkSize, baseIndexOffset, shape.slotCount),
    "sort-params",
  );
  const bindings = [scalarBuffer, params, counters, meta, indices, chunks, heavy];

  batch.clear(counters, shape.slotCount * 4);
  batch.dispatch(kernels.count, bindings, workgroupsFor(kernels.count, shape.termCount, "sort-count"), "sort-count");
  batch.dispatch(kernels.scan, bindings, 1, "sort-scan");
  batch.dispatch(kernels.scatter, bindings, workgroupsFor(kernels.scatter, shape.termCount, "sort-scatter"), "sort-scatter");
  batch.dispatch(kernels.chunks, bindings, workgroupsFor(kernels.chunks, shape.slotCount, "sort-chunks"), "sort-chunks");
  return { shape, counters, meta, indices, chunks, heavy };
}

/** Uniform layout shared by all MSM kernels (`Params { lane0, lane1 }`); `offset` is the fold stage's workgroup offset. */
function msmParams(count: number, shape: BucketSortShape, groupsPerWindow: number, offset = 0): Uint32Array {
  return Uint32Array.of(count, offset, shape.termsPerInstance, shape.window, shape.numWindows, shape.bucketCount, shape.slotCount, groupsPerWindow);
}

/**
 * Longest bucket range a reduce thread walks. Each bucket costs two serial
 * Jacobian additions and a lone GPU thread is latency-bound, so long ranges
 * stall the stage; more groups instead cost one weighted partial each in the
 * sum stage.
 */
const REDUCE_MAX_BUCKETS_PER_THREAD = 32;

/**
 * Number of workgroups sharing one window in the reduce stage: the power of
 * two that caps every thread's range at `REDUCE_MAX_BUCKETS_PER_THREAD`
 * buckets while every thread still owns at least one.
 */
export function reduceGroupsPerWindow(shape: BucketSortShape, workgroupSize: number): number {
  let groups = 1;
  while (shape.bucketCount / (groups * workgroupSize) > REDUCE_MAX_BUCKETS_PER_THREAD) {
    groups *= 2;
  }
  // The sum_windows stage reduces the groups of a window with one thread each.
  if (groups > workgroupSize) {
    throw new Error(`msm: ${groups} reduce groups per window exceed the workgroup size ${workgroupSize}`);
  }
  return groups;
}

/**
 * Record a sparse signed-digit Pippenger MSM into `batch`.
 *
 * `bases` holds affine points (`x, y`; infinity all zero); term `i` of
 * instance `k` is read from base index `baseIndexOffset + k * termsPerInstance + i`.
 * Returns the buffer that will hold `count` result points once the batch is
 * submitted. The combine stage already normalizes to affine (`z = 1`, or all
 * zero for infinity), in the three-coordinate layout.
 *
 * Everything is recorded into the one command encoder of `batch`: the four
 * bucket-sort dispatches, then bucket -> fold_partial -> fold -> reduce ->
 * weight -> sum -> sum_windows -> combine. No per-term work happens on the host.
 */
export function recordSparseSignedPippengerMSM(
  batch: CommandBatch,
  options: {
    kernels: MSMKernels;
    sortKernels: MSMSortKernels;
    bases: GPUBuffer;
    baseIndexOffset?: number;
    pointBytes: number;
    scalars: PackedScalars;
    count: number;
    termsPerInstance: number;
    window: number;
    maxChunkSize?: number;
  },
): { buffer: GPUBuffer; size: number } {
  const { kernels, sortKernels, bases, baseIndexOffset = 0, pointBytes, scalars, count, termsPerInstance, window, maxChunkSize = DEFAULT_CHUNK_SIZE } = options;
  const shape = bucketSortShape(count, termsPerInstance, window, maxChunkSize);
  const threads = kernels.reduce.workgroupSize;
  const groups = reduceGroupsPerWindow(shape, threads);
  // One reduce workgroup per (instance, window, group) with `threads` partials
  // each; one sum workgroup per (instance, window).
  const windowCount = checkWorkgroups(count * shape.numWindows, "sum");
  const reduceCount = checkWorkgroups(windowCount * groups, "reduce");
  const partialCount = reduceCount * threads;
  if (batch.debug) {
    console.debug("[curvegpu] msm shape", { label: batch.label, pointBytes, groupsPerWindow: groups, partialCount, ...shape });
  }

  const sort = recordBucketSort(batch, sortKernels, scalars, shape, baseIndexOffset);

  const zero = batch.upload(new Uint8Array(pointBytes), STORAGE_IN_USAGE, "zero");
  const chunkOutput = storageTemp(batch, shape.maxChunks * pointBytes, "chunk-out");
  const foldPartials = storageTemp(batch, shape.maxHeavy * FOLD_LANES * pointBytes, "fold-partials");
  const partials = storageTemp(batch, 2 * partialCount * pointBytes, "reduce-out");
  const weights = storageTemp(batch, partialCount * pointBytes, "weight-out");
  const groupOutput = storageTemp(batch, reduceCount * pointBytes, "group-out");
  const windowOutput = storageTemp(batch, windowCount * pointBytes, "window-out");
  const finalSize = count * pointBytes;
  const finalOutput = storageTemp(batch, finalSize, "final-out");
  const params = (n: number, offset = 0): GPUBuffer => batch.uniform(msmParams(n, shape, groups, offset));

  // 1. Bucket accumulation: one thread per chunk (the exact chunk count is read on the GPU).
  batch.dispatch(
    kernels.bucket,
    [bases, zero, chunkOutput, params(shape.maxChunks), sort.indices, sort.chunks, sort.meta],
    workgroupsFor(kernels.bucket, shape.maxChunks, "bucket"),
    "bucket",
  );
  // 2. Fold the chunk sums of slots with several chunks into their first chunk:
  //    FOLD_LANES partial sums per possible heavy slot (the exact count is read
  //    on the GPU), then one workgroup per heavy slot.
  batch.dispatch(
    kernels.fold_partial,
    [chunkOutput, zero, foldPartials, params(0), sort.meta, sort.heavy, zero],
    workgroupsFor(kernels.fold_partial, shape.maxHeavy * FOLD_LANES, "fold-partial"),
    "fold-partial",
  );
  for (let offset = 0; offset < shape.maxHeavy; offset += MAX_WORKGROUPS_PER_DIMENSION) {
    const workgroups = Math.min(MAX_WORKGROUPS_PER_DIMENSION, shape.maxHeavy - offset);
    batch.dispatch(kernels.fold, [foldPartials, zero, chunkOutput, params(0, offset), sort.meta, sort.heavy, zero], workgroups, "fold");
  }
  // 3. Running sums: each thread of a (instance, window, group) workgroup owns a bucket range.
  batch.dispatch(kernels.reduce, [chunkOutput, zero, partials, params(partialCount), sort.meta, zero, zero], reduceCount, "reduce");
  // 4. Range-offset correction: lo * run per partial.
  batch.dispatch(kernels.weight, [partials, zero, weights, params(partialCount), zero, zero, zero], workgroupsFor(kernels.weight, partialCount, "weight"), "weight");
  // 5. Sums: a tree over the acc + lo * run of each (instance, window, group), then over the groups of each window.
  batch.dispatch(kernels.sum, [partials, weights, groupOutput, params(reduceCount), zero, zero, zero], reduceCount, "sum");
  batch.dispatch(kernels.sum_windows, [groupOutput, zero, windowOutput, params(windowCount), zero, zero, zero], windowCount, "sum-windows");
  // 6. Horner combine over windows, normalized to affine.
  batch.dispatch(kernels.combine, [windowOutput, zero, finalOutput, params(count), zero, zero, zero], workgroupsFor(kernels.combine, count, "combine"), "combine");

  return { buffer: finalOutput, size: finalSize };
}
