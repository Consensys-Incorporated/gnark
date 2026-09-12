import { getAdapterInfo } from "../../../../src/curvegpu/context.js";
import { fetchShaderText } from "../../../../src/curvegpu/shaders.js";

export function mustElement<T>(value: T | null, name: string): T {
  if (value === null) {
    throw new Error(`missing element: ${name}`);
  }
  return value;
}

export function createPageUI(statusEl: HTMLElement | null, logEl: HTMLElement | null): {
  setStatus: (text: string) => void;
  setPageState: (state: string) => void;
  writeLog: (lines: string[]) => void;
} {
  return {
    setStatus(text: string): void {
      mustElement(statusEl, "status").textContent = text;
    },
    setPageState(state: string): void {
      document.body.dataset.status = state;
    },
    writeLog(lines: string[]): void {
      mustElement(logEl, "log").textContent = lines.join("\n");
    },
  };
}

export async function fetchText(path: string): Promise<string> {
  if (path.startsWith("/shaders/")) {
    return fetchShaderText(path);
  }
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`failed to load ${path}: ${response.status} ${response.statusText}`);
  }
  return response.text();
}

export async function fetchJSON<T>(path: string): Promise<T> {
  return JSON.parse(await fetchText(path)) as T;
}

export async function fetchBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`failed to load ${path}: ${response.status} ${response.statusText}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`invalid hex length ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function yieldToBrowser(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(() => {
      requestAnimationFrame(() => resolve());
    }, 0);
  });
}

/** Deterministic xorshift-based pseudo-random 32-byte scalars for benchmarks. */
export function makeRandomScalars(count: number, salt = 0x9e3779b9): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let index = 0; index < count; index += 1) {
    const bytes = new Uint8Array(32);
    let state = (salt ^ count ^ index) >>> 0;
    for (let i = 0; i < bytes.length; i += 1) {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      bytes[i] = state & 0xff;
    }
    out.push(bytes);
  }
  return out;
}

export function packBytes(values: readonly Uint8Array[], elementBytes: number): Uint8Array {
  const out = new Uint8Array(values.length * elementBytes);
  values.forEach((value, index) => out.set(value, index * elementBytes));
  return out;
}

/** Human-readable adapter lines for pages that request their own adapter. */
export async function getAdapterDiagnosticLines(adapter: GPUAdapter): Promise<string[]> {
  const lines: string[] = [];
  const adapterWithFallback = adapter as GPUAdapter & { isFallbackAdapter?: boolean };
  if ("isFallbackAdapter" in adapterWithFallback) {
    lines.push(`adapter.isFallbackAdapter = ${String(adapterWithFallback.isFallbackAdapter)}`);
  }
  const info = await getAdapterInfo(adapter);
  if (!info) {
    lines.push("adapter.info = unavailable");
    return lines;
  }
  if (info.vendor) {
    lines.push(`adapter.vendor = ${info.vendor}`);
  }
  if (info.architecture) {
    lines.push(`adapter.architecture = ${info.architecture}`);
  }
  return lines;
}
