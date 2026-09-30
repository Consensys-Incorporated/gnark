function nextPowerOfTwo(n: number): number {
  let p = 1;
  while (p < n) {
    p *= 2;
  }
  return p;
}

type PoolKey = string;
type PoolEntry = { buffer: GPUBuffer; size: number };

function poolKey(size: number, usage: number): PoolKey {
  return `${size}:${usage}`;
}

/**
 * Per-device GPU buffer pool. Caches released buffers keyed by
 * (rounded-size, usage) and re-issues them on acquire, avoiding
 * repeated GPU allocations on hot paths.
 *
 * Sizes are rounded up to the next power of two to reduce fragmentation.
 * Total pooled memory is capped at `maxPooledBytes` (default 64 MB).
 * Buffers that would exceed the cap are destroyed rather than pooled.
 */
export class BufferPool {
  private readonly device: GPUDevice;
  private readonly maxBytes: number;
  private readonly pool: Map<PoolKey, PoolEntry[]> = new Map();
  private readonly meta = new WeakMap<GPUBuffer, { size: number; usage: number }>();
  private totalBytes = 0;

  constructor(device: GPUDevice, options?: { maxPooledBytes?: number }) {
    this.device = device;
    this.maxBytes = options?.maxPooledBytes ?? 64 * 1024 * 1024;
  }

  /**
   * Return a buffer of at least `size` bytes with the given `usage`.
   * May return a cached buffer from a previous `release` call.
   */
  acquire(size: number, usage: number, label?: string): GPUBuffer {
    const roundedSize = nextPowerOfTwo(Math.max(4, size));
    const key = poolKey(roundedSize, usage);
    const entries = this.pool.get(key);
    if (entries && entries.length > 0) {
      const entry = entries.pop()!;
      this.totalBytes -= entry.size;
      return entry.buffer;
    }
    const buffer = this.device.createBuffer({ label, size: roundedSize, usage });
    this.meta.set(buffer, { size: roundedSize, usage });
    return buffer;
  }

  /**
   * Return a buffer to the pool. If the pool is at capacity, the buffer
   * is destroyed instead. Do not use the buffer after calling `release`.
   */
  release(buffer: GPUBuffer): void {
    const m = this.meta.get(buffer);
    if (!m) {
      // Buffer was not created by this pool (e.g. staging buffers). Destroy it.
      buffer.destroy();
      return;
    }
    if (this.totalBytes + m.size > this.maxBytes) {
      buffer.destroy();
      this.meta.delete(buffer);
      return;
    }
    const key = poolKey(m.size, m.usage);
    let entries = this.pool.get(key);
    if (!entries) {
      entries = [];
      this.pool.set(key, entries);
    }
    entries.push({ buffer, size: m.size });
    this.totalBytes += m.size;
  }

  /**
   * Destroy all pooled buffers and clear the pool. Call when the context
   * is closed to avoid GPU memory leaks.
   */
  destroy(): void {
    for (const entries of this.pool.values()) {
      for (const { buffer } of entries) {
        buffer.destroy();
      }
    }
    this.pool.clear();
    this.totalBytes = 0;
  }
}
