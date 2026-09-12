import type {
  CurveGPUAffinePoint,
  CurveGPUFp2Element,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  CurveGPUJacobianPoint,
  SupportedCurveID,
} from "../../../../src/index.js";
import { bytesToHex, hexToBytes } from "./browser_utils.js";
import { curveDisplayName } from "./page_library.js";

export type Log = (msg: string) => void;
export type SuiteResult = { passed: number; failed: number };

// --- fixture locations -----------------------------------------------------

export type VectorKind = "fr" | "fp" | "g1" | "g2";

/** `/tests/fixtures/api/vectors/<kind>/<curve>_<suffix>.json` */
export function vectorPath(kind: VectorKind, curve: SupportedCurveID, suffix: string): string {
  return `/tests/fixtures/api/vectors/${kind}/${curve}_${suffix}.json`;
}

/** Large generated base fixtures used by the MSM benchmarks. */
export function baseFixturePaths(kind: "g1" | "g2", curve: SupportedCurveID): { fixtureJSONPath: string; fixtureBinPath: string } {
  const base = `/tests/fixtures/api/fixtures/${kind}/${curve}_bases_jacobian`;
  return { fixtureJSONPath: `${base}.json`, fixtureBinPath: `${base}.bin` };
}

export function curveShaderPath(curve: SupportedCurveID, file: string): string {
  return `/shaders/curves/${curve}/${file}`;
}

export function suiteTitle(curve: SupportedCurveID, label: string, kind = "Smoke"): string {
  return `${curveDisplayName(curve)} ${label} Browser ${kind}`;
}

// --- hex point encodings used by the JSON vectors ----------------------------

export type HexAffine = { x_bytes_le: string; y_bytes_le: string };
export type HexJacobian = { x_bytes_le: string; y_bytes_le: string; z_bytes_le: string };
export type HexFp2 = { c0_bytes_le: string; c1_bytes_le: string };
export type HexG2Affine = { x: HexFp2; y: HexFp2 };
export type HexG2Jacobian = { x: HexFp2; y: HexFp2; z: HexFp2 };

export function bytesList(hexValues: readonly string[]): Uint8Array[] {
  return hexValues.map(hexToBytes);
}

export function affineFromHex(point: HexAffine): CurveGPUAffinePoint {
  return { x: hexToBytes(point.x_bytes_le), y: hexToBytes(point.y_bytes_le) };
}

export function jacobianFromHex(point: HexJacobian): CurveGPUJacobianPoint {
  return { x: hexToBytes(point.x_bytes_le), y: hexToBytes(point.y_bytes_le), z: hexToBytes(point.z_bytes_le) };
}

export function fp2FromHex(value: HexFp2): CurveGPUFp2Element {
  return { c0: hexToBytes(value.c0_bytes_le), c1: hexToBytes(value.c1_bytes_le) };
}

export function g2AffineFromHex(point: HexG2Affine): CurveGPUG2AffinePoint {
  return { x: fp2FromHex(point.x), y: fp2FromHex(point.y) };
}

export function g2JacobianFromHex(point: HexG2Jacobian): CurveGPUG2JacobianPoint {
  return { x: fp2FromHex(point.x), y: fp2FromHex(point.y), z: fp2FromHex(point.z) };
}

function fp2Hex(value: CurveGPUFp2Element): string {
  return `${bytesToHex(value.c0)}/${bytesToHex(value.c1)}`;
}

function hexFp2Hex(value: HexFp2): string {
  return `${value.c0_bytes_le}/${value.c1_bytes_le}`;
}

// --- assertions --------------------------------------------------------------

function expectLength(name: string, got: number, want: number): void {
  if (got !== want) {
    throw new Error(`${name}: length mismatch got=${got} want=${want}`);
  }
}

/** Compare element-wise using `render` on both sides; log `name: OK` on success. */
function expectRendered<G, W>(name: string, got: readonly G[], want: readonly W[], renderGot: (g: G) => string, renderWant: (w: W) => string, log?: Log): void {
  expectLength(name, got.length, want.length);
  for (let i = 0; i < got.length; i += 1) {
    const g = renderGot(got[i]);
    const w = renderWant(want[i]);
    if (g !== w) {
      throw new Error(`${name}: mismatch at index ${i}: got=${g} want=${w}`);
    }
  }
  log?.(`${name}: OK`);
}

export function expectHexBatch(name: string, got: readonly Uint8Array[], wantHex: readonly string[], log?: Log): void {
  expectRendered(name, got, wantHex, bytesToHex, (w) => w, log);
}

export function expectBoolBatch(name: string, got: readonly boolean[], want: readonly boolean[], log?: Log): void {
  expectRendered(name, got, want, String, String, log);
}

export function expectJacobianBatch(name: string, got: readonly CurveGPUJacobianPoint[], want: readonly HexJacobian[], log?: Log): void {
  expectRendered(
    name,
    got,
    want,
    (p) => `(${bytesToHex(p.x)},${bytesToHex(p.y)},${bytesToHex(p.z)})`,
    (w) => `(${w.x_bytes_le},${w.y_bytes_le},${w.z_bytes_le})`,
    log,
  );
}

/** Compare affine coordinates only (`want` may carry an ignored `z`). */
export function expectAffineBatch(name: string, got: readonly CurveGPUAffinePoint[], want: readonly HexAffine[], log?: Log): void {
  expectRendered(name, got, want, (p) => `(${bytesToHex(p.x)},${bytesToHex(p.y)})`, (w) => `(${w.x_bytes_le},${w.y_bytes_le})`, log);
}

export function expectG2JacobianBatch(name: string, got: readonly CurveGPUG2JacobianPoint[], want: readonly HexG2Jacobian[], log?: Log): void {
  expectRendered(
    name,
    got,
    want,
    (p) => `(${fp2Hex(p.x)},${fp2Hex(p.y)},${fp2Hex(p.z)})`,
    (w) => `(${hexFp2Hex(w.x)},${hexFp2Hex(w.y)},${hexFp2Hex(w.z)})`,
    log,
  );
}

export function expectG2AffineBatch(name: string, got: readonly CurveGPUG2AffinePoint[], want: readonly HexG2Affine[], log?: Log): void {
  expectRendered(name, got, want, (p) => `(${fp2Hex(p.x)},${fp2Hex(p.y)})`, (w) => `(${hexFp2Hex(w.x)},${hexFp2Hex(w.y)})`, log);
}
