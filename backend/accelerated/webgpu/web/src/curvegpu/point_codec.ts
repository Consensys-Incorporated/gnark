import type {
  CurveGPUAffinePoint,
  CurveGPUFp2Element,
  CurveGPUG2AffinePoint,
  CurveGPUG2JacobianPoint,
  CurveGPUJacobianPoint,
} from "./api.js";
import { cloneBytes, ensureByteLength } from "./gpu.js";

/**
 * Byte layout of the points of one group. The shaders store every point as
 * three consecutive coordinates `x, y, z` of `coordinateBytes` each; affine
 * points are Jacobian points with `z = 1` (Montgomery form) and the point at
 * infinity is all zeros.
 *
 * G1 coordinates are base-field elements; G2 coordinates are `Fp2` pairs
 * `(c0, c1)` stored consecutively.
 */
export interface PointCodec<A, J> {
  readonly coordinateBytes: number;
  readonly pointBytes: number;
  affineInfinity(): A;
  jacobianZero(): J;
  isAffineInfinity(point: A): boolean;
  /** Write an affine point as `x, y, z` with `z = one` (or all zero for infinity). */
  writeAffine(out: Uint8Array, offset: number, point: A, oneMont: Uint8Array, label: string): void;
  writeJacobian(out: Uint8Array, offset: number, point: J, label: string): void;
  /** Write the `z = one` coordinate (Montgomery one in `c0`, zero elsewhere). */
  writeOne(out: Uint8Array, offset: number, oneMont: Uint8Array): void;
  readJacobian(bytes: Uint8Array, offset: number): J;
  affineOf(point: J): A;
  cloneJacobian(point: J): J;
  cloneAffine(point: A): A;
}

function allZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

export function g1Codec(coordinateBytes: number): PointCodec<CurveGPUAffinePoint, CurveGPUJacobianPoint> {
  const pointBytes = 3 * coordinateBytes;
  return {
    coordinateBytes,
    pointBytes,
    affineInfinity: () => ({ x: new Uint8Array(coordinateBytes), y: new Uint8Array(coordinateBytes) }),
    jacobianZero: () => ({ x: new Uint8Array(coordinateBytes), y: new Uint8Array(coordinateBytes), z: new Uint8Array(coordinateBytes) }),
    isAffineInfinity: (point) => allZero(point.x) && allZero(point.y),
    writeAffine(out, offset, point, oneMont, label) {
      ensureByteLength(point.x, coordinateBytes, `${label}.x`);
      ensureByteLength(point.y, coordinateBytes, `${label}.y`);
      out.set(point.x, offset);
      out.set(point.y, offset + coordinateBytes);
      if (!(allZero(point.x) && allZero(point.y))) {
        out.set(oneMont, offset + 2 * coordinateBytes);
      }
    },
    writeJacobian(out, offset, point, label) {
      ensureByteLength(point.x, coordinateBytes, `${label}.x`);
      ensureByteLength(point.y, coordinateBytes, `${label}.y`);
      ensureByteLength(point.z, coordinateBytes, `${label}.z`);
      out.set(point.x, offset);
      out.set(point.y, offset + coordinateBytes);
      out.set(point.z, offset + 2 * coordinateBytes);
    },
    writeOne(out, offset, oneMont) {
      out.set(oneMont, offset);
    },
    readJacobian: (bytes, offset) => ({
      x: bytes.slice(offset, offset + coordinateBytes),
      y: bytes.slice(offset + coordinateBytes, offset + 2 * coordinateBytes),
      z: bytes.slice(offset + 2 * coordinateBytes, offset + 3 * coordinateBytes),
    }),
    affineOf: (point) => ({ x: cloneBytes(point.x), y: cloneBytes(point.y) }),
    cloneJacobian: (point) => ({ x: cloneBytes(point.x), y: cloneBytes(point.y), z: cloneBytes(point.z) }),
    cloneAffine: (point) => ({ x: cloneBytes(point.x), y: cloneBytes(point.y) }),
  };
}

export function g2Codec(componentBytes: number): PointCodec<CurveGPUG2AffinePoint, CurveGPUG2JacobianPoint> {
  const coordinateBytes = 2 * componentBytes;
  const pointBytes = 3 * coordinateBytes;
  const zeroFp2 = (): CurveGPUFp2Element => ({ c0: new Uint8Array(componentBytes), c1: new Uint8Array(componentBytes) });
  const cloneFp2 = (value: CurveGPUFp2Element): CurveGPUFp2Element => ({ c0: cloneBytes(value.c0), c1: cloneBytes(value.c1) });
  const fp2IsZero = (value: CurveGPUFp2Element): boolean => allZero(value.c0) && allZero(value.c1);
  const writeFp2 = (out: Uint8Array, offset: number, value: CurveGPUFp2Element, label: string): void => {
    ensureByteLength(value.c0, componentBytes, `${label}.c0`);
    ensureByteLength(value.c1, componentBytes, `${label}.c1`);
    out.set(value.c0, offset);
    out.set(value.c1, offset + componentBytes);
  };
  const readFp2 = (bytes: Uint8Array, offset: number): CurveGPUFp2Element => ({
    c0: bytes.slice(offset, offset + componentBytes),
    c1: bytes.slice(offset + componentBytes, offset + 2 * componentBytes),
  });
  return {
    coordinateBytes,
    pointBytes,
    affineInfinity: () => ({ x: zeroFp2(), y: zeroFp2() }),
    jacobianZero: () => ({ x: zeroFp2(), y: zeroFp2(), z: zeroFp2() }),
    isAffineInfinity: (point) => fp2IsZero(point.x) && fp2IsZero(point.y),
    writeAffine(out, offset, point, oneMont, label) {
      writeFp2(out, offset, point.x, `${label}.x`);
      writeFp2(out, offset + coordinateBytes, point.y, `${label}.y`);
      if (!(fp2IsZero(point.x) && fp2IsZero(point.y))) {
        out.set(oneMont, offset + 2 * coordinateBytes);
      }
    },
    writeJacobian(out, offset, point, label) {
      writeFp2(out, offset, point.x, `${label}.x`);
      writeFp2(out, offset + coordinateBytes, point.y, `${label}.y`);
      writeFp2(out, offset + 2 * coordinateBytes, point.z, `${label}.z`);
    },
    writeOne(out, offset, oneMont) {
      out.set(oneMont, offset);
    },
    readJacobian: (bytes, offset) => ({
      x: readFp2(bytes, offset),
      y: readFp2(bytes, offset + coordinateBytes),
      z: readFp2(bytes, offset + 2 * coordinateBytes),
    }),
    affineOf: (point) => ({ x: cloneFp2(point.x), y: cloneFp2(point.y) }),
    cloneJacobian: (point) => ({ x: cloneFp2(point.x), y: cloneFp2(point.y), z: cloneFp2(point.z) }),
    cloneAffine: (point) => ({ x: cloneFp2(point.x), y: cloneFp2(point.y) }),
  };
}

/** Pack Jacobian points into the shader layout. */
export function packJacobianPoints<A, J>(codec: PointCodec<A, J>, points: readonly J[], label: string): Uint8Array {
  const out = new Uint8Array(points.length * codec.pointBytes);
  points.forEach((point, index) => codec.writeJacobian(out, index * codec.pointBytes, point, `${label}[${index}]`));
  return out;
}

/** Pack affine points into the shader layout (`z = one`, infinity all-zero). */
export function packAffinePoints<A, J>(codec: PointCodec<A, J>, points: readonly A[], oneMont: Uint8Array, label: string): Uint8Array {
  const out = new Uint8Array(points.length * codec.pointBytes);
  points.forEach((point, index) => codec.writeAffine(out, index * codec.pointBytes, point, oneMont, `${label}[${index}]`));
  return out;
}

export function unpackJacobianPoints<A, J>(codec: PointCodec<A, J>, bytes: Uint8Array, count: number): J[] {
  const out: J[] = [];
  for (let i = 0; i < count; i += 1) {
    out.push(codec.readJacobian(bytes, i * codec.pointBytes));
  }
  return out;
}
