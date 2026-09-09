import type { CommandBatch, Kernel } from "./gpu.js";
import { STORAGE_IN_USAGE, STORAGE_RW_USAGE } from "./gpu.js";
import { buildSparseSignedBucketMetadataWords } from "./msm_shared.js";

/** The four Jacobian Pippenger stages of one group's MSM shader. */
export type MSMKernels = {
  bucket: Kernel;
  weight: Kernel;
  subsum: Kernel;
  combine: Kernel;
};

/** Uniform layout shared by all MSM kernels (`Params { lane0, lane1 }`). */
const UNIFORM_WORDS = 8;

function msmParams(values: {
  count: number;
  termsPerInstance?: number;
  window?: number;
  numWindows?: number;
  bucketCount?: number;
}): Uint32Array {
  const params = new Uint32Array(UNIFORM_WORDS);
  params[0] = values.count;
  params[2] = values.termsPerInstance ?? 0;
  params[3] = values.window ?? 0;
  params[4] = values.numWindows ?? 0;
  params[5] = values.bucketCount ?? 0;
  return params;
}

/**
 * Record a sparse signed-digit Pippenger MSM into `batch`.
 *
 * `bases` holds points in the shader layout (`x, y, z` with `z = 1` for
 * affine inputs); term `i` of instance `k` is read from base index
 * `baseIndexOffset + k * termsPerInstance + i`. Returns the buffer that will
 * hold `count` result points once the batch is submitted. The combine stage
 * already normalizes to affine (`z = 1`, or all zero for infinity).
 */
export function recordSparseSignedPippengerMSM(
  batch: CommandBatch,
  options: {
    kernels: MSMKernels;
    bases: GPUBuffer;
    baseIndexOffset?: number;
    pointBytes: number;
    scalarWords: Uint32Array;
    count: number;
    termsPerInstance: number;
    window: number;
    maxChunkSize?: number;
  },
): { buffer: GPUBuffer; size: number } {
  const { kernels, bases, baseIndexOffset = 0, pointBytes, scalarWords, count, termsPerInstance, window, maxChunkSize = 256 } = options;
  const metadata = buildSparseSignedBucketMetadataWords(scalarWords, count, termsPerInstance, window, maxChunkSize, baseIndexOffset);
  if (batch.debug) {
    console.debug("[curvegpu] msm metadata", {
      label: batch.label,
      count,
      termsPerInstance,
      window,
      pointBytes,
      numWindows: metadata.numWindows,
      bucketCount: metadata.bucketCount,
      bucketCountOut: metadata.bucketPointers.length,
      baseIndicesLen: metadata.baseIndices.length,
    });
  }

  const bucketCountOut = metadata.bucketPointers.length;
  const windowCount = count * metadata.numWindows;
  const workgroups = (kernel: Kernel, items: number): number => Math.ceil(items / kernel.workgroupSize);

  const zero = batch.upload(new Uint8Array(pointBytes), STORAGE_IN_USAGE, "zero");
  const baseIndices = batch.upload(metadata.baseIndices, STORAGE_IN_USAGE, "base-indices");
  const bucketPointers = batch.upload(metadata.bucketPointers, STORAGE_IN_USAGE, "bucket-pointers");
  const bucketSizes = batch.upload(metadata.bucketSizes, STORAGE_IN_USAGE, "bucket-sizes");
  const bucketValues = batch.upload(metadata.bucketValues, STORAGE_IN_USAGE, "bucket-values");
  const windowStarts = batch.upload(metadata.windowStarts, STORAGE_IN_USAGE, "window-starts");
  const windowCounts = batch.upload(metadata.windowCounts, STORAGE_IN_USAGE, "window-counts");

  const bucketOutput = batch.temp(Math.max(1, bucketCountOut) * pointBytes, STORAGE_RW_USAGE, "bucket-out");
  const weightedOutput = batch.temp(Math.max(1, bucketCountOut) * pointBytes, STORAGE_RW_USAGE, "weighted-out");
  const windowOutput = batch.temp(Math.max(1, windowCount) * pointBytes, STORAGE_RW_USAGE, "window-out");
  const finalSize = Math.max(1, count) * pointBytes;
  const finalOutput = batch.temp(finalSize, STORAGE_RW_USAGE, "final-out");

  const shape = { termsPerInstance, window, numWindows: metadata.numWindows, bucketCount: metadata.bucketCount };

  // 1. Bucket accumulation: each dispatched bucket sums its signed bases.
  batch.dispatch(
    kernels.bucket,
    [bases, zero, bucketOutput, batch.uniform(msmParams({ count: bucketCountOut, ...shape })), baseIndices, bucketPointers, bucketSizes],
    workgroups(kernels.bucket, bucketCountOut),
    "bucket",
  );
  // 2. Weight each bucket sum by its digit value.
  batch.dispatch(
    kernels.weight,
    [bucketOutput, zero, weightedOutput, batch.uniform(msmParams({ count: bucketCountOut })), bucketValues, bucketValues, bucketValues],
    workgroups(kernels.weight, bucketCountOut),
    "weight",
  );
  // 3. Reduce the weighted buckets of each window: one workgroup per window.
  batch.dispatch(
    kernels.subsum,
    [weightedOutput, zero, windowOutput, batch.uniform(msmParams({ count: windowCount })), bucketValues, windowStarts, windowCounts],
    windowCount,
    "subsum",
  );
  // 4. Horner combine over windows, normalized to affine.
  batch.dispatch(
    kernels.combine,
    [windowOutput, zero, finalOutput, batch.uniform(msmParams({ count, ...shape })), zero, zero, zero],
    workgroups(kernels.combine, count),
    "combine",
  );

  return { buffer: finalOutput, size: finalSize };
}
