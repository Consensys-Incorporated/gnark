export type SparseSignedBucketMetadata = {
  baseIndices: Uint32Array;
  bucketPointers: Uint32Array;
  bucketSizes: Uint32Array;
  bucketValues: Uint32Array;
  windowStarts: Uint32Array;
  windowCounts: Uint32Array;
  numWindows: number;
  bucketCount: number;
};

export const INDEX_SIGN_BIT = 0x80000000;

export function bestPippengerWindow(count: number): number {
  const windows = [4, 5, 6, 7, 8, 9, 10, 11, 12];
  let best = windows[0];
  let bestCost = Number.POSITIVE_INFINITY;
  for (const window of windows) {
    const cost = Math.ceil(255 / window) * (count + (1 << window));
    if (cost < bestCost) {
      bestCost = cost;
      best = window;
    }
  }
  return best;
}

/** Reinterpret packed little-endian 32-byte scalars as u32 words. */
export function scalarWordsFromPacked(scalarsPacked: Uint8Array): Uint32Array {
  if (scalarsPacked.byteLength % 32 !== 0) {
    throw new Error(`packed scalars: expected a multiple of 32 bytes, got ${scalarsPacked.byteLength}`);
  }
  const out = new Uint32Array(scalarsPacked.byteLength / 4);
  const view = new DataView(scalarsPacked.buffer, scalarsPacked.byteOffset, scalarsPacked.byteLength);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = view.getUint32(i * 4, true);
  }
  return out;
}

/**
 * Build the sparse signed-digit bucket layout consumed by the MSM kernels.
 *
 * `baseIndexOffset` is added to every base index written to `baseIndices`, so
 * the kernels can address a sub-range of a larger GPU-resident base buffer.
 */
export function buildSparseSignedBucketMetadataWords(
  scalarWords: Uint32Array,
  count: number,
  termsPerInstance: number,
  window: number,
  maxChunkSize = 256,
  baseIndexOffset = 0,
): SparseSignedBucketMetadata {
  const numWindows = Math.ceil(256 / window) + 1;
  const bucketCount = 1 << (window - 1);
  const totalWindows = count * numWindows;
  const logicalBucketSizes = new Uint32Array(totalWindows * bucketCount);
  const half = 1 << (window - 1);
  const full = 1 << window;

  // Signed digit decomposition of one scalar; calls `visit(win, value, neg)` for each non-zero digit.
  const forEachDigit = (idx: number, visit: (win: number, value: number, neg: boolean) => void): void => {
    const scalarBase = idx * 8;
    let carry = 0;
    for (let win = 0; win < numWindows; win += 1) {
      const unsigned = win < numWindows - 1 ? extractWindowDigitWords(scalarWords, scalarBase, win * window, window) : 0;
      let value = unsigned + carry;
      carry = 0;
      let neg = false;
      if (value >= half) {
        value = full - value;
        neg = value !== 0;
        carry = 1;
      }
      if (value !== 0) {
        visit(win, value, neg);
      }
    }
  };

  for (let instance = 0; instance < count; instance += 1) {
    for (let term = 0; term < termsPerInstance; term += 1) {
      forEachDigit(instance * termsPerInstance + term, (win, value) => {
        logicalBucketSizes[(instance * numWindows + win) * bucketCount + (value - 1)] += 1;
      });
    }
  }

  const logicalBucketPointers = new Uint32Array(totalWindows * bucketCount);
  let totalEntries = 0;
  for (let i = 0; i < logicalBucketSizes.length; i += 1) {
    logicalBucketPointers[i] = totalEntries;
    totalEntries += logicalBucketSizes[i];
  }
  const baseIndices = new Uint32Array(totalEntries);
  const writeOffsets = logicalBucketPointers.slice();

  for (let instance = 0; instance < count; instance += 1) {
    for (let term = 0; term < termsPerInstance; term += 1) {
      const idx = instance * termsPerInstance + term;
      forEachDigit(idx, (win, value, neg) => {
        const slot = (instance * numWindows + win) * bucketCount + (value - 1);
        const shifted = idx + baseIndexOffset;
        baseIndices[writeOffsets[slot]] = neg ? ((shifted | INDEX_SIGN_BIT) >>> 0) : shifted;
        writeOffsets[slot] += 1;
      });
    }
  }

  const bucketPointers: number[] = [];
  const bucketSizes: number[] = [];
  const bucketValues: number[] = [];
  const windowStarts = new Uint32Array(totalWindows);
  const windowCounts = new Uint32Array(totalWindows);
  for (let windowSlot = 0; windowSlot < totalWindows; windowSlot += 1) {
    windowStarts[windowSlot] = bucketPointers.length;
    let dispatchedInWindow = 0;
    const bucketBase = windowSlot * bucketCount;
    for (let value = 1; value <= bucketCount; value += 1) {
      const slot = bucketBase + (value - 1);
      const size = logicalBucketSizes[slot];
      if (size === 0) {
        continue;
      }
      const ptr = logicalBucketPointers[slot];
      for (let offset = 0; offset < size; offset += maxChunkSize) {
        bucketPointers.push(ptr + offset);
        bucketSizes.push(Math.min(size - offset, maxChunkSize));
        bucketValues.push(value);
        dispatchedInWindow += 1;
      }
    }
    windowCounts[windowSlot] = dispatchedInWindow;
  }

  return {
    baseIndices,
    bucketPointers: Uint32Array.from(bucketPointers),
    bucketSizes: Uint32Array.from(bucketSizes),
    bucketValues: Uint32Array.from(bucketValues),
    windowStarts,
    windowCounts,
    numWindows,
    bucketCount,
  };
}

function extractWindowDigitWords(words: Uint32Array, scalarBase: number, bitOffset: number, window: number): number {
  if (window <= 0) {
    return 0;
  }
  const word = Math.floor(bitOffset / 32);
  const shift = bitOffset % 32;
  const mask = (1 << window) - 1;
  if (word >= 8) {
    return 0;
  }
  const lo = words[scalarBase + word] >>> shift;
  if (shift + window <= 32 || word + 1 >= 8) {
    return lo & mask;
  }
  const highWidth = shift + window - 32;
  const hiMask = (1 << highWidth) - 1;
  const hi = words[scalarBase + word + 1] & hiMask;
  return (lo | (hi << (32 - shift))) & mask;
}
