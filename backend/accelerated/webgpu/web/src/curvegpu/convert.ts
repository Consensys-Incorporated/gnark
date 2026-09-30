export function splitBigUint64WordsToU32(words: readonly bigint[]): Uint32Array {
  if (words.length !== 4 && words.length !== 6) {
    throw new Error(`unsupported host word count ${words.length}`);
  }
  const out = new Uint32Array(words.length * 2);
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    out[2 * i] = Number(word & 0xffff_ffffn);
    out[2 * i + 1] = Number((word >> 32n) & 0xffff_ffffn);
  }
  return out;
}

export function splitBytesLEToU32(bytes: Uint8Array): Uint32Array {
  if (bytes.length !== 32 && bytes.length !== 48) {
    throw new Error(`unsupported byte length ${bytes.length}`);
  }
  const out = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < out.length; i += 1) {
    const offset = i * 4;
    out[i] =
      bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24);
  }
  return out;
}

export function joinU32LimbsToBigUint64(limbs: Uint32Array): bigint[] {
  if (limbs.length !== 8 && limbs.length !== 12) {
    throw new Error(`unsupported gpu limb count ${limbs.length}`);
  }
  const out: bigint[] = [];
  for (let i = 0; i < limbs.length; i += 2) {
    const lo = BigInt(limbs[i]);
    const hi = BigInt(limbs[i + 1]) << 32n;
    out.push(lo | hi);
  }
  return out;
}

export function joinU32LimbsToBytesLE(limbs: Uint32Array): Uint8Array {
  if (limbs.length !== 8 && limbs.length !== 12) {
    throw new Error(`unsupported gpu limb count ${limbs.length}`);
  }
  const out = new Uint8Array(limbs.length * 4);
  for (let i = 0; i < limbs.length; i += 1) {
    const limb = limbs[i];
    const offset = i * 4;
    out[offset] = limb & 0xff;
    out[offset + 1] = (limb >>> 8) & 0xff;
    out[offset + 2] = (limb >>> 16) & 0xff;
    out[offset + 3] = (limb >>> 24) & 0xff;
  }
  return out;
}
