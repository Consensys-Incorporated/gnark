import type { CurveGPUContext, CurveGPUElementBytes, FieldModule, GroupModule, SupportedCurveID } from "./api.js";
import type { Kernel } from "./gpu.js";
import { ensureByteLength, runKernelOnce } from "./gpu.js";
import type { PointCodec } from "./point_codec.js";
import { packAffinePoints, packJacobianPoints, unpackJacobianPoints } from "./point_codec.js";

const OP_COPY = 0;
const OP_JAC_INFINITY = 1;
const OP_AFFINE_TO_JAC = 2;
const OP_NEG_JAC = 3;
const OP_DOUBLE_JAC = 4;
const OP_ADD_MIXED = 5;
const OP_JAC_TO_AFFINE = 6;
const OP_AFFINE_ADD = 7;

function scalarBit(scalar: Uint8Array, bit: number): boolean {
  ensureByteLength(scalar, 32, "scalar");
  return ((scalar[bit >> 3] >> (bit & 7)) & 1) !== 0;
}

/**
 * Group arithmetic (G1 or G2) over the shared `*_ops_main` kernel. The point
 * representation is abstracted by `codec`, so one implementation serves both
 * groups.
 */
export function createGroupModule<A, J>(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    group: "g1" | "g2";
    codec: PointCodec<A, J>;
    kernel: Kernel;
  },
  fp: FieldModule,
): GroupModule<A, J> {
  const { curve, group, codec, kernel } = options;
  const label = `${curve}-${group}`;
  const { coordinateBytes, pointBytes } = codec;

  let oneMont: Promise<Uint8Array> | null = null;
  const getOneMontgomery = (): Promise<Uint8Array> => {
    oneMont ??= fp.montOne();
    return oneMont;
  };

  function zeros(count: number): J[] {
    return Array.from({ length: count }, () => codec.jacobianZero());
  }

  async function run(opcode: number, inputA: Uint8Array, inputB: Uint8Array, count: number): Promise<J[]> {
    const output = await runKernelOnce({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-op-${opcode}`,
      inputA,
      inputB,
      outputBytes: count * pointBytes,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
    return unpackJacobianPoints(codec, output, count);
  }

  function checkLengths(a: number, b: number, kind: string): number {
    if (a !== b) {
      throw new Error(`${label}: mismatched ${kind} batch lengths`);
    }
    return a;
  }

  async function runJacobianBatch(opcode: number, inputA: readonly J[], inputB: readonly J[]): Promise<J[]> {
    const count = checkLengths(inputA.length, inputB.length, "jacobian");
    if (count === 0) {
      return [];
    }
    return run(opcode, packJacobianPoints(codec, inputA, `${label}.inputA`), packJacobianPoints(codec, inputB, `${label}.inputB`), count);
  }

  async function runMixedBatch(opcode: number, inputA: readonly J[], inputB: readonly A[]): Promise<J[]> {
    const count = checkLengths(inputA.length, inputB.length, "mixed");
    if (count === 0) {
      return [];
    }
    const one = await getOneMontgomery();
    return run(opcode, packJacobianPoints(codec, inputA, `${label}.inputA`), packAffinePoints(codec, inputB, one, `${label}.inputB`), count);
  }

  async function runAffineInputBatch(opcode: number, inputA: readonly A[]): Promise<J[]> {
    const count = inputA.length;
    if (count === 0) {
      return [];
    }
    const one = await getOneMontgomery();
    return run(opcode, packAffinePoints(codec, inputA, one, `${label}.inputA`), packJacobianPoints(codec, zeros(count), `${label}.inputB`), count);
  }

  async function runJacobianUnary(opcode: number, point: J): Promise<J> {
    return (await runJacobianBatch(opcode, [point], zeros(1)))[0];
  }

  const module: GroupModule<A, J> = {
    context,
    curve,
    group,
    coordinateBytes,
    pointBytes,
    affineInfinity: () => codec.affineInfinity(),
    jacobianZero: () => codec.jacobianZero(),
    copy: (point) => runJacobianUnary(OP_COPY, point),
    copyBatch: (points) => runJacobianBatch(OP_COPY, points, zeros(points.length)),
    jacobianInfinity: async () => (await runJacobianBatch(OP_JAC_INFINITY, zeros(1), zeros(1)))[0],
    jacobianInfinityBatch: (count) => runJacobianBatch(OP_JAC_INFINITY, zeros(count), zeros(count)),
    affineToJacobian: async (point) => (await runAffineInputBatch(OP_AFFINE_TO_JAC, [point]))[0],
    affineToJacobianBatch: (points) => runAffineInputBatch(OP_AFFINE_TO_JAC, points),
    negJacobian: (point) => runJacobianUnary(OP_NEG_JAC, point),
    negJacobianBatch: (points) => runJacobianBatch(OP_NEG_JAC, points, zeros(points.length)),
    doubleJacobian: (point) => runJacobianUnary(OP_DOUBLE_JAC, point),
    doubleJacobianBatch: (points) => runJacobianBatch(OP_DOUBLE_JAC, points, zeros(points.length)),
    addMixed: async (point, affine) => (await runMixedBatch(OP_ADD_MIXED, [point], [affine]))[0],
    addMixedBatch: (points, affine) => runMixedBatch(OP_ADD_MIXED, points, affine),
    jacobianToAffine: async (point) => codec.affineOf(await runJacobianUnary(OP_JAC_TO_AFFINE, point)),
    jacobianToAffineBatch: async (points) => (await runJacobianBatch(OP_JAC_TO_AFFINE, points, zeros(points.length))).map(codec.affineOf),
    affineAdd: async (a, b) => (await module.affineAddBatch([a], [b]))[0],
    async affineAddBatch(a, b) {
      checkLengths(a.length, b.length, "affine");
      const left = await runAffineInputBatch(OP_AFFINE_TO_JAC, a);
      return runMixedBatch(OP_AFFINE_ADD, left, b);
    },
    scalarMulAffine: async (base, scalar) => (await module.scalarMulAffineBatch([base], [scalar]))[0],
    async scalarMulAffineBatch(bases: readonly A[], scalars: readonly CurveGPUElementBytes[]): Promise<J[]> {
      checkLengths(bases.length, scalars.length, "scalar-mul");
      const zero = zeros(bases.length);
      let acc = await runJacobianBatch(OP_JAC_INFINITY, zero, zero);
      for (let bit = 255; bit >= 0; bit -= 1) {
        acc = await runJacobianBatch(OP_DOUBLE_JAC, acc, zero);
        const activeBases = bases.map((point, index) => (scalarBit(scalars[index], bit) ? point : codec.affineInfinity()));
        if (activeBases.every((point) => codec.isAffineInfinity(point))) {
          continue;
        }
        acc = await runMixedBatch(OP_ADD_MIXED, acc, activeBases);
      }
      return runJacobianBatch(OP_JAC_TO_AFFINE, acc, zero);
    },
    addAffine: async (a, b) => codec.affineOf(await module.affineAdd(a, b)),
    addAffineBatch: async (a, b) => (await module.affineAddBatch(a, b)).map(codec.affineOf),
    negAffine: async (point) => codec.affineOf(await module.negJacobian(await module.affineToJacobian(point))),
    negAffineBatch: async (points) => (await module.negJacobianBatch(await module.affineToJacobianBatch(points))).map(codec.affineOf),
    doubleAffine: async (point) => codec.affineOf(await module.doubleJacobian(await module.affineToJacobian(point))),
    doubleAffineBatch: async (points) => (await module.doubleJacobianBatch(await module.affineToJacobianBatch(points))).map(codec.affineOf),
    scalarMulAffineResult: async (base, scalar) => codec.affineOf(await module.scalarMulAffine(base, scalar)),
    scalarMulAffineResultBatch: async (bases, scalars) => (await module.scalarMulAffineBatch(bases, scalars)).map(codec.affineOf),
  };
  return module;
}
