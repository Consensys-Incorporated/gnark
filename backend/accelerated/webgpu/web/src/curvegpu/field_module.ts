import type { CurveGPUContext, CurveGPUElementBytes, FieldModule, SupportedCurveID } from "./api.js";
import type { FieldShape } from "./types.js";
import type { Kernel } from "./gpu.js";
import { cloneBytes, ensureByteLength, ensurePackedElements, packElementBatch, runKernelOnce, unpackElementBatch } from "./gpu.js";

/** Opcodes of the `fr_ops_main` / `fp_ops_main` shaders. */
export const FIELD_OP = {
  COPY: 0,
  ONE: 2,
  ADD: 3,
  SUB: 4,
  NEG: 5,
  DOUBLE: 6,
  NORMALIZE: 7,
  EQUAL: 8,
  MUL: 9,
  SQUARE: 10,
  TO_MONT: 11,
  FROM_MONT: 12,
} as const;

function isNonZero(bytes: Uint8Array): boolean {
  return bytes.some((byte) => byte !== 0);
}

export function createFieldModule(
  context: CurveGPUContext,
  options: {
    curve: SupportedCurveID;
    field: "fr" | "fp";
    shape: FieldShape;
    kernel: Kernel;
  },
): FieldModule {
  const { curve, field, shape, kernel } = options;
  const byteSize = shape.byteSize;
  const label = `${curve}-${field}`;
  const zeroValue = new Uint8Array(byteSize);

  function zeros(count: number): Uint8Array[] {
    return Array.from({ length: count }, () => new Uint8Array(byteSize));
  }

  async function runPacked(opcode: number, inputA: Uint8Array, inputB?: Uint8Array): Promise<Uint8Array> {
    const count = ensurePackedElements(inputA, byteSize, `${label}.packedA`);
    const b = inputB ?? new Uint8Array(inputA.byteLength);
    if (b.byteLength !== inputA.byteLength) {
      throw new Error(`${label}.packedB: expected ${inputA.byteLength} bytes, got ${b.byteLength}`);
    }
    return runKernelOnce({
      device: context.device,
      pool: context.bufferPool,
      kernel,
      label: `${label}-op-${opcode}`,
      inputA,
      inputB: b,
      outputBytes: count * byteSize,
      uniformWords: Uint32Array.from([count, opcode, 0, 0, 0, 0, 0, 0]),
      workgroups: Math.ceil(count / kernel.workgroupSize),
    });
  }

  async function runBatch(opcode: number, inputA: readonly CurveGPUElementBytes[], inputB: readonly CurveGPUElementBytes[]): Promise<Uint8Array[]> {
    const count = Math.max(inputA.length, inputB.length);
    if (count === 0) {
      return [];
    }
    const a = inputA.length === 0 ? zeros(count) : inputA;
    const b = inputB.length === 0 ? zeros(count) : inputB;
    if (a.length !== count || b.length !== count) {
      throw new Error(`${label}: mismatched batch lengths`);
    }
    const output = await runPacked(opcode, packElementBatch(a, byteSize, `${label}.inputA`), packElementBatch(b, byteSize, `${label}.inputB`));
    return unpackElementBatch(output, byteSize, count);
  }

  async function runUnary(opcode: number, value: CurveGPUElementBytes): Promise<Uint8Array> {
    ensureByteLength(value, byteSize, `${label}.value`);
    return (await runBatch(opcode, [value], [zeroValue]))[0];
  }

  async function runBinary(opcode: number, a: CurveGPUElementBytes, b: CurveGPUElementBytes): Promise<Uint8Array> {
    ensureByteLength(a, byteSize, `${label}.a`);
    ensureByteLength(b, byteSize, `${label}.b`);
    return (await runBatch(opcode, [a], [b]))[0];
  }

  let montOne: Promise<Uint8Array> | null = null;

  return {
    context,
    curve,
    field,
    shape,
    byteSize,
    zero: () => cloneBytes(zeroValue),
    copy: (value) => runUnary(FIELD_OP.COPY, value),
    copyBatch: (values) => runBatch(FIELD_OP.COPY, values, values),
    async montOne() {
      montOne ??= runBatch(FIELD_OP.ONE, [zeroValue], [zeroValue]).then((out) => out[0]);
      return cloneBytes(await montOne);
    },
    equal: async (a, b) => isNonZero(await runBinary(FIELD_OP.EQUAL, a, b)),
    equalBatch: async (a, b) => (await runBatch(FIELD_OP.EQUAL, a, b)).map(isNonZero),
    add: (a, b) => runBinary(FIELD_OP.ADD, a, b),
    addBatch: (a, b) => runBatch(FIELD_OP.ADD, a, b),
    sub: (a, b) => runBinary(FIELD_OP.SUB, a, b),
    subBatch: (a, b) => runBatch(FIELD_OP.SUB, a, b),
    neg: (value) => runUnary(FIELD_OP.NEG, value),
    negBatch: (values) => runBatch(FIELD_OP.NEG, values, zeros(values.length)),
    double: (value) => runUnary(FIELD_OP.DOUBLE, value),
    doubleBatch: (values) => runBatch(FIELD_OP.DOUBLE, values, zeros(values.length)),
    mul: (a, b) => runBinary(FIELD_OP.MUL, a, b),
    mulBatch: (a, b) => runBatch(FIELD_OP.MUL, a, b),
    mulPackedMont: (a, b) => runPacked(FIELD_OP.MUL, a, b),
    square: (value) => runUnary(FIELD_OP.SQUARE, value),
    squareBatch: (values) => runBatch(FIELD_OP.SQUARE, values, zeros(values.length)),
    normalizeMont: (value) => runUnary(FIELD_OP.NORMALIZE, value),
    normalizeMontBatch: (values) => runBatch(FIELD_OP.NORMALIZE, values, zeros(values.length)),
    toMontgomery: (value) => runUnary(FIELD_OP.TO_MONT, value),
    toMontgomeryBatch: (values) => runBatch(FIELD_OP.TO_MONT, values, zeros(values.length)),
    toMontgomeryPacked: (values) => runPacked(FIELD_OP.TO_MONT, values),
    fromMontgomery: (value) => runUnary(FIELD_OP.FROM_MONT, value),
    fromMontgomeryBatch: (values) => runBatch(FIELD_OP.FROM_MONT, values, zeros(values.length)),
    fromMontgomeryPacked: (values) => runPacked(FIELD_OP.FROM_MONT, values),
  };
}
