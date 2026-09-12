import type {
  CurveGPUContext,
  CurveGPUElementBytes,
  CurveGPUMSMOptions,
  CurveGPUPackedPointLayout,
  FieldModule,
  GroupModule,
  MSMModule,
  ResidentBases,
  SupportedCurveID,
} from "./api.js";
import { packElementBatch, recordAndRead, STORAGE_IN_USAGE, uploadGPUBuffer } from "./gpu.js";
import type { MSMKernels, MSMSortKernels } from "./msm_pippenger.js";
import { bestPippengerWindow, recordSparseSignedPippengerMSM } from "./msm_pippenger.js";
import type { PointCodec } from "./point_codec.js";
import { unpackJacobianPoints } from "./point_codec.js";

function positiveInteger(value: number, label: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

/**
 * Pippenger MSM (G1 or G2) over the shared Jacobian MSM kernels.
 *
 * Bases live on the GPU as packed affine points (`x, y` per point, infinity
 * all zero); results come back in the three-coordinate layout with `z = 1`.
 */
export function createMSMModule<A, J>(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    group: "g1" | "g2";
    codec: PointCodec<A, J>;
    kernels: MSMKernels;
    sortKernels: MSMSortKernels;
  },
  group: GroupModule<A, J>,
  fp: FieldModule,
): MSMModule<A, J> {
  const { curve, codec, kernels, sortKernels } = options;
  const { coordinateBytes, pointBytes } = codec;
  const affineBytes = 2 * coordinateBytes;
  const label = `${curve}-${options.group}-msm`;

  let oneMont: Promise<Uint8Array> | null = null;
  const getOneMontgomery = (): Promise<Uint8Array> => {
    oneMont ??= fp.montOne();
    return oneMont;
  };

  function checkPackedScalars(scalarsPacked: Uint8Array, count: number): void {
    if (scalarsPacked.byteLength !== count * 32) {
      throw new Error(`${label}: expected ${count * 32} scalar bytes, got ${scalarsPacked.byteLength}`);
    }
  }

  /** Pack affine points as `x, y` per point (infinity all zero). */
  function packAffineCoordinates(points: readonly A[], one: Uint8Array): Uint8Array {
    const out = new Uint8Array(points.length * affineBytes);
    const scratch = new Uint8Array(pointBytes);
    points.forEach((point, index) => {
      codec.writeAffine(scratch, 0, point, one, `${label}.bases[${index}]`);
      out.set(scratch.subarray(0, affineBytes), index * affineBytes);
    });
    return out;
  }

  /**
   * Drop the `z` coordinate of packed `jacobian_x_y_z_le` points whose `z` is
   * one (affine) or zero (infinity, which stays all zero).
   */
  function affineFromPackedJacobian(packed: Uint8Array): Uint8Array {
    const count = packed.byteLength / pointBytes;
    const out = new Uint8Array(count * affineBytes);
    for (let i = 0; i < count; i += 1) {
      const base = i * pointBytes;
      if (!packed.subarray(base + affineBytes, base + pointBytes).every((byte) => byte === 0)) {
        out.set(packed.subarray(base, base + affineBytes), i * affineBytes);
      }
    }
    return out;
  }

  /** Upload packed affine bases and run one batched MSM over them. */
  async function runPackedMSM(affinePacked: Uint8Array, scalarsPacked: Uint8Array, count: number, termsPerInstance: number, msmOptions: CurveGPUMSMOptions): Promise<Uint8Array> {
    return recordAndRead(
      context.device,
      context.bufferPool,
      label,
      (batch) =>
        recordSparseSignedPippengerMSM(batch, {
          kernels,
          sortKernels,
          bases: batch.upload(affinePacked, STORAGE_IN_USAGE, "bases"),
          pointBytes,
          scalars: scalarsPacked,
          count,
          termsPerInstance,
          window: msmOptions.window ?? bestPippengerWindow(termsPerInstance),
          maxChunkSize: msmOptions.maxChunkSize,
        }),
      context.debug,
    );
  }

  async function runBatch(bases: readonly A[], scalars: readonly CurveGPUElementBytes[], msmOptions: CurveGPUMSMOptions = {}): Promise<J[]> {
    if (bases.length !== scalars.length) {
      throw new Error(`${label}: bases and scalars length mismatch`);
    }
    const count = positiveInteger(msmOptions.count ?? 1, `${label}: count`);
    const termsPerInstance = positiveInteger(msmOptions.termsPerInstance ?? (count === 1 ? bases.length : 0), `${label}: termsPerInstance`);
    if (bases.length !== count * termsPerInstance) {
      throw new Error(`${label}: expected ${count * termsPerInstance} bases/scalars for count=${count} termsPerInstance=${termsPerInstance}`);
    }
    const scalarsPacked = packElementBatch(scalars, 32, `${label}: scalars`);
    const output = await runPackedMSM(packAffineCoordinates(bases, await getOneMontgomery()), scalarsPacked, count, termsPerInstance, msmOptions);
    return unpackJacobianPoints(codec, output, count);
  }

  async function uploadAffineBases(packedAffine: Uint8Array): Promise<ResidentBases> {
    if (packedAffine.byteLength % affineBytes !== 0) {
      throw new Error(`${label}: packed affine bases must be a multiple of ${affineBytes} bytes, got ${packedAffine.byteLength}`);
    }
    const count = packedAffine.byteLength / affineBytes;
    const pointsPerChunk = Math.floor(context.maxStorageBufferBindingSize / affineBytes);
    if (pointsPerChunk <= 0) {
      throw new Error(`${label}: device maxStorageBufferBindingSize ${context.maxStorageBufferBindingSize} cannot hold a single point`);
    }
    const chunks: { buffer: GPUBuffer; first: number; count: number }[] = [];
    try {
      for (let first = 0; first < count; first += pointsPerChunk) {
        const chunkCount = Math.min(pointsPerChunk, count - first);
        chunks.push({
          first,
          count: chunkCount,
          buffer: uploadGPUBuffer(
            context.device,
            `${label}-resident-${chunks.length}`,
            packedAffine.subarray(first * affineBytes, (first + chunkCount) * affineBytes),
            STORAGE_IN_USAGE,
          ),
        });
      }
    } catch (error) {
      chunks.forEach((chunk) => chunk.buffer.destroy());
      throw error;
    }
    let released = false;
    return {
      count,
      pointBytes: affineBytes,
      chunks,
      release(): void {
        if (released) {
          return;
        }
        released = true;
        chunks.forEach((chunk) => chunk.buffer.destroy());
      },
    };
  }

  async function msmResident(
    bases: ResidentBases,
    start: number,
    scalarsPacked: Uint8Array,
    msmOptions: Pick<CurveGPUMSMOptions, "window" | "maxChunkSize"> = {},
  ): Promise<Uint8Array> {
    if (bases.pointBytes !== affineBytes) {
      throw new Error(`${label}: resident bases belong to a different group (pointBytes=${bases.pointBytes})`);
    }
    if (scalarsPacked.byteLength % 32 !== 0) {
      throw new Error(`${label}: scalars must be a multiple of 32 bytes, got ${scalarsPacked.byteLength}`);
    }
    const termCount = scalarsPacked.byteLength / 32;
    if (!Number.isInteger(start) || start < 0 || start + termCount > bases.count) {
      throw new Error(`${label}: MSM range [${start}, ${start + termCount}) exceeds ${bases.count} resident bases`);
    }
    if (termCount === 0) {
      return new Uint8Array(affineBytes);
    }

    // The range may straddle several resident chunks; each piece is one MSM
    // whose affine results are then summed on the GPU.
    const partials: A[] = [];
    let cursor = start;
    const end = start + termCount;
    for (const chunk of bases.chunks) {
      const chunkEnd = chunk.first + chunk.count;
      if (cursor >= end || chunkEnd <= cursor) {
        continue;
      }
      const pieceEnd = Math.min(end, chunkEnd);
      const pieceCount = pieceEnd - cursor;
      const output = await recordAndRead(
        context.device,
        context.bufferPool,
        label,
        (batch) =>
          recordSparseSignedPippengerMSM(batch, {
            kernels,
            sortKernels,
            bases: chunk.buffer,
            baseIndexOffset: cursor - chunk.first,
            pointBytes,
            scalars: scalarsPacked.subarray((cursor - start) * 32, (pieceEnd - start) * 32),
            count: 1,
            termsPerInstance: pieceCount,
            window: msmOptions.window ?? bestPippengerWindow(pieceCount),
            maxChunkSize: msmOptions.maxChunkSize,
          }),
        context.debug,
      );
      if (partials.length === 0 && pieceEnd === end) {
        // Common case: a single piece. The combine kernel output is already affine.
        return output.slice(0, affineBytes);
      }
      partials.push(codec.affineOf(codec.readJacobian(output, 0)));
      cursor = pieceEnd;
    }
    let sum = partials[0];
    for (let i = 1; i < partials.length; i += 1) {
      sum = await group.addAffine(sum, partials[i]);
    }
    const out = new Uint8Array(pointBytes);
    codec.writeAffine(out, 0, sum, await getOneMontgomery(), `${label}.result`);
    return out.slice(0, affineBytes);
  }

  return {
    context,
    curve,
    group: options.group,
    bestWindow: bestPippengerWindow,
    async pippengerAffine(bases, scalars, msmOptions = {}) {
      return (await runBatch(bases, scalars, { ...msmOptions, count: msmOptions.count ?? 1 }))[0];
    },
    async pippengerAffineResult(bases, scalars, msmOptions = {}) {
      return group.jacobianToAffine((await runBatch(bases, scalars, { ...msmOptions, count: msmOptions.count ?? 1 }))[0]);
    },
    pippengerAffineBatch: runBatch,
    async pippengerPackedJacobianBases(
      basesPacked: Uint8Array,
      scalarsPacked: Uint8Array,
      msmOptions: CurveGPUMSMOptions & { layout?: CurveGPUPackedPointLayout },
    ): Promise<Uint8Array> {
      const count = positiveInteger(msmOptions.count ?? 1, `${label}: count`);
      const termsPerInstance = positiveInteger(msmOptions.termsPerInstance ?? 0, `${label}: termsPerInstance`);
      if ((msmOptions.layout ?? "jacobian_x_y_z_le") !== "jacobian_x_y_z_le") {
        throw new Error(`${label}: unsupported packed point layout ${msmOptions.layout}`);
      }
      const expectedPointBytes = count * termsPerInstance * pointBytes;
      if (basesPacked.byteLength !== expectedPointBytes) {
        throw new Error(`${label}: expected ${expectedPointBytes} base bytes, got ${basesPacked.byteLength}`);
      }
      checkPackedScalars(scalarsPacked, count * termsPerInstance);
      return runPackedMSM(affineFromPackedJacobian(basesPacked), scalarsPacked, count, termsPerInstance, msmOptions);
    },
    uploadAffineBases,
    msmResident,
  };
}
