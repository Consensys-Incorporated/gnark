import type { BufferPool } from "./buffer_pool.js";

/**
 * A compiled compute entry point together with its bind group layout and the
 * workgroup size it was compiled with (either an `override WORKGROUP_SIZE`
 * constant or the value hard-coded in the shader).
 */
export type Kernel = {
  pipeline: GPUComputePipeline;
  bindGroupLayout: GPUBindGroupLayout;
  workgroupSize: number;
};

/** A whole buffer, or a sub-range of one (offset must respect device alignment). */
export type BufferBinding = GPUBuffer | { buffer: GPUBuffer; offset: number; size: number };

export const STORAGE_IN_USAGE = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST;
export const STORAGE_RW_USAGE = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST;
export const UNIFORM_USAGE = GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST;
const STAGING_USAGE = GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ;

/** Round a byte count up to the 4-byte granularity WebGPU requires for copies and writes. */
export function alignBytes(size: number): number {
  return Math.max(4, Math.ceil(size / 4) * 4);
}

export function cloneBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

export function ensureByteLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.byteLength !== expected) {
    throw new Error(`${label}: expected ${expected} bytes, got ${bytes.byteLength}`);
  }
}

export function ensurePackedElements(bytes: Uint8Array, elementBytes: number, label: string): number {
  if (bytes.byteLength % elementBytes !== 0) {
    throw new Error(`${label}: expected a multiple of ${elementBytes} bytes, got ${bytes.byteLength}`);
  }
  return bytes.byteLength / elementBytes;
}

export function packElementBatch(values: readonly Uint8Array[], elementBytes: number, label: string): Uint8Array {
  const out = new Uint8Array(values.length * elementBytes);
  values.forEach((value, index) => {
    ensureByteLength(value, elementBytes, `${label}[${index}]`);
    out.set(value, index * elementBytes);
  });
  return out;
}

export function unpackElementBatch(bytes: Uint8Array, elementBytes: number, count: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i += 1) {
    out.push(bytes.slice(i * elementBytes, (i + 1) * elementBytes));
  }
  return out;
}

export function createGPUBuffer(device: GPUDevice, label: string, size: number, usage: GPUBufferUsageFlags): GPUBuffer {
  return device.createBuffer({ label, size: alignBytes(size), usage });
}

/** Create a buffer and enqueue a write of `bytes` into it. */
export function uploadGPUBuffer(
  device: GPUDevice,
  label: string,
  bytes: Uint8Array | Uint32Array,
  usage: GPUBufferUsageFlags = STORAGE_IN_USAGE,
): GPUBuffer {
  const buffer = createGPUBuffer(device, label, bytes.byteLength, usage);
  writeBytes(device, buffer, bytes);
  return buffer;
}

function writeBytes(device: GPUDevice, buffer: GPUBuffer, bytes: Uint8Array | Uint32Array): void {
  if (bytes.byteLength === 0) {
    return;
  }
  if (bytes.byteLength % 4 !== 0) {
    const padded = new Uint8Array(alignBytes(bytes.byteLength));
    padded.set(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
    device.queue.writeBuffer(buffer, 0, padded.buffer, 0, padded.byteLength);
    return;
  }
  device.queue.writeBuffer(buffer, 0, bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function bindingEntry(binding: number, resource: BufferBinding): GPUBindGroupEntry {
  return "offset" in resource
    ? { binding, resource }
    : { binding, resource: { buffer: resource } };
}

/**
 * Records an arbitrary number of compute dispatches and buffer copies into a
 * single command encoder, then submits once and reads back one buffer.
 *
 * WebGPU orders passes within a queue submission, so data dependencies between
 * dispatches that go through storage buffers need no host-side waits. All
 * temporaries acquired through the batch (`temp`, `upload`, `uniform`) are
 * released back to the pool (or destroyed) once the submission has completed.
 */
export class CommandBatch {
  private readonly encoder: GPUCommandEncoder;
  private readonly temporaries: GPUBuffer[] = [];
  private dispatchCount = 0;
  private done = false;

  constructor(
    readonly device: GPUDevice,
    readonly pool: BufferPool | undefined,
    readonly label: string,
    readonly debug = false,
  ) {
    this.encoder = device.createCommandEncoder({ label: `${label}-encoder` });
  }

  /** Acquire a scratch buffer that lives until the batch finishes. */
  temp(size: number, usage: GPUBufferUsageFlags, label = "temp"): GPUBuffer {
    const buffer = this.pool
      ? this.pool.acquire(alignBytes(size), usage, `${this.label}-${label}`)
      : createGPUBuffer(this.device, `${this.label}-${label}`, size, usage);
    this.temporaries.push(buffer);
    return buffer;
  }

  /** Acquire a scratch buffer and enqueue a write of `bytes` into it. */
  upload(bytes: Uint8Array | Uint32Array, usage: GPUBufferUsageFlags = STORAGE_IN_USAGE, label = "input"): GPUBuffer {
    const buffer = this.temp(bytes.byteLength, usage, label);
    writeBytes(this.device, buffer, bytes);
    return buffer;
  }

  /** Acquire a uniform buffer holding `words`. */
  uniform(words: Uint32Array, label = "params"): GPUBuffer {
    return this.upload(words, UNIFORM_USAGE, label);
  }

  /** Record one compute pass with a single dispatch. */
  dispatch(kernel: Kernel, bindings: readonly BufferBinding[], workgroups: number | readonly [number, number, number], label: string): void {
    this.assertOpen();
    const bindGroup = this.device.createBindGroup({
      label: `${this.label}-${label}-bg`,
      layout: kernel.bindGroupLayout,
      entries: bindings.map((binding, index) => bindingEntry(index, binding)),
    });
    const pass = this.encoder.beginComputePass({ label: `${this.label}-${label}` });
    pass.setPipeline(kernel.pipeline);
    pass.setBindGroup(0, bindGroup);
    if (typeof workgroups === "number") {
      pass.dispatchWorkgroups(workgroups);
    } else {
      pass.dispatchWorkgroups(workgroups[0], workgroups[1], workgroups[2]);
    }
    pass.end();
    this.dispatchCount += 1;
    if (this.debug) {
      console.debug(`[curvegpu] ${this.label}: recorded ${label} workgroups=${JSON.stringify(workgroups)}`);
    }
  }

  /** Record a fill of the first `size` bytes of `buffer` with zeros. */
  clear(buffer: GPUBuffer, size: number): void {
    this.assertOpen();
    this.encoder.clearBuffer(buffer, 0, alignBytes(size));
  }

  /** Record a buffer-to-buffer copy. */
  copy(source: GPUBuffer, destination: GPUBuffer, size: number, sourceOffset = 0, destinationOffset = 0): void {
    this.assertOpen();
    this.encoder.copyBufferToBuffer(source, sourceOffset, destination, destinationOffset, alignBytes(size));
  }

  /**
   * Copy `size` bytes of `buffer` into a staging buffer, submit everything
   * recorded so far, wait for completion, and return the bytes.
   */
  async finish(readback: { buffer: GPUBuffer; size: number }): Promise<Uint8Array> {
    this.assertOpen();
    const staging = this.temp(readback.size, STAGING_USAGE, "staging");
    this.encoder.copyBufferToBuffer(readback.buffer, 0, staging, 0, alignBytes(readback.size));
    this.done = true;
    let mapped = false;
    try {
      if (this.debug) {
        console.debug(`[curvegpu] ${this.label}: submit dispatches=${this.dispatchCount}`);
      }
      this.device.queue.submit([this.encoder.finish()]);
      await staging.mapAsync(GPUMapMode.READ, 0, alignBytes(readback.size));
      mapped = true;
      const out = new Uint8Array(staging.getMappedRange(0, alignBytes(readback.size)).slice(0, readback.size));
      staging.unmap();
      mapped = false;
      return out;
    } finally {
      if (mapped) {
        staging.unmap();
      }
      this.release();
    }
  }

  /** Drop the batch without submitting (error path during recording). */
  dispose(): void {
    if (this.done) {
      return;
    }
    this.done = true;
    this.release();
  }

  private release(): void {
    for (const buffer of this.temporaries) {
      if (this.pool) {
        this.pool.release(buffer);
      } else {
        buffer.destroy();
      }
    }
    this.temporaries.length = 0;
  }

  private assertOpen(): void {
    if (this.done) {
      throw new Error(`${this.label}: command batch already finished`);
    }
  }
}

/**
 * Record a batch with `record`, then submit it once and read back the buffer
 * the recorder returns. Temporaries are released on every exit path.
 */
export async function recordAndRead(
  device: GPUDevice,
  pool: BufferPool | undefined,
  label: string,
  record: (batch: CommandBatch) => Promise<{ buffer: GPUBuffer; size: number }> | { buffer: GPUBuffer; size: number },
  debug = false,
): Promise<Uint8Array> {
  const batch = new CommandBatch(device, pool, label, debug);
  let readback: { buffer: GPUBuffer; size: number };
  try {
    readback = await record(batch);
  } catch (error) {
    batch.dispose();
    throw error;
  }
  return batch.finish(readback);
}

/**
 * Run one dispatch of a 4-binding "ops" kernel (input A, input B, output,
 * uniform params) over host byte arrays and read the output back.
 */
export async function runKernelOnce(options: {
  device: GPUDevice;
  pool?: BufferPool;
  kernel: Kernel;
  label: string;
  inputA: Uint8Array;
  inputB: Uint8Array;
  outputBytes: number;
  uniformWords: Uint32Array;
  workgroups: number;
}): Promise<Uint8Array> {
  const { device, pool, kernel, label, inputA, inputB, outputBytes, uniformWords, workgroups } = options;
  return recordAndRead(device, pool, label, (batch) => {
    const a = batch.upload(inputA, STORAGE_IN_USAGE, "input-a");
    const b = batch.upload(inputB, STORAGE_IN_USAGE, "input-b");
    const out = batch.temp(outputBytes, STORAGE_RW_USAGE, "output");
    batch.dispatch(kernel, [a, b, out, batch.uniform(uniformWords)], workgroups, "op");
    return { buffer: out, size: outputBytes };
  });
}
