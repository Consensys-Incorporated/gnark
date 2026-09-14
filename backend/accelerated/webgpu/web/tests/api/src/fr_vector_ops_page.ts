import type { CurveModule } from "../../../src/index.js";
import { bytesToHex, fetchJSON, fetchText, hexToBytes, packBytes } from "./shared/browser_utils.js";
import { curveShaderPath, expectHexBatch, suiteTitle, vectorPath, type Log, type SuiteResult } from "./shared/fixtures.js";
import { createRawKernel, runRawKernel, type RawKernel } from "./shared/raw_kernel.js";

type VectorCase = {
  name: string;
  regular_inputs_le: string[];
  mont_inputs_le: string[];
  mont_factors_le: string[];
  add_expected_le: string[];
  sub_expected_le: string[];
  mul_expected_le: string[];
  to_mont_expected_le: string[];
  from_mont_expected_le: string[];
  bit_reverse_expected_le: string[];
};

const FR_OP_ADD = 3;
const FR_OP_SUB = 4;
const FR_OP_MUL = 9;
const FR_OP_TO_MONT = 11;
const FR_OP_FROM_MONT = 12;
const FR_VECTOR_OP_MUL_FACTORS = 3;
const FR_VECTOR_OP_BIT_REVERSE_COPY = 4;
const ELEMENT_BYTES = 32;

/** Runs the raw `fr_arith` / `fr_vector` shaders directly, bypassing the library runtime. */
export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  const device = module.context.device;
  log(`=== ${suiteTitle(module.id, "fr Vector Ops")} ===`);
  log("");

  const [arithShader, vectorShader] = await Promise.all([
    fetchText(curveShaderPath(module.id, "fr_arith.wgsl")),
    fetchText(curveShaderPath(module.id, "fr_vector.wgsl")),
  ]);
  const { vector_cases: cases } = await fetchJSON<{ vector_cases: VectorCase[] }>(vectorPath("fr", module.id, "fr_vector_ops"));
  log(`cases.vector = ${cases.length}`);

  const arithKernel = createRawKernel(device, `${module.id}-fr`, arithShader, "fr_ops_main");
  const vectorKernel = createRawKernel(device, `${module.id}-fr-vector`, vectorShader, "fr_vector_main");

  const run = async (kernel: RawKernel, a: readonly string[], b: readonly string[], opcode: number, logCount: number): Promise<Uint8Array[]> => {
    const { out } = await runRawKernel(device, kernel, packBytes(a.map(hexToBytes), ELEMENT_BYTES), packBytes(b.map(hexToBytes), ELEMENT_BYTES), ELEMENT_BYTES, opcode, logCount);
    return Array.from({ length: a.length }, (_, i) => out.slice(i * ELEMENT_BYTES, (i + 1) * ELEMENT_BYTES));
  };

  for (const item of cases) {
    const zeros = item.mont_inputs_le.map(() => bytesToHex(new Uint8Array(ELEMENT_BYTES)));
    expectHexBatch(`${item.name}:add`, await run(arithKernel, item.mont_inputs_le, item.mont_factors_le, FR_OP_ADD, 0), item.add_expected_le);
    expectHexBatch(`${item.name}:sub`, await run(arithKernel, item.mont_inputs_le, item.mont_factors_le, FR_OP_SUB, 0), item.sub_expected_le);
    expectHexBatch(`${item.name}:mul`, await run(arithKernel, item.mont_inputs_le, item.mont_factors_le, FR_OP_MUL, 0), item.mul_expected_le);
    expectHexBatch(`${item.name}:to_mont`, await run(arithKernel, item.regular_inputs_le, zeros, FR_OP_TO_MONT, 0), item.to_mont_expected_le);
    expectHexBatch(`${item.name}:from_mont`, await run(arithKernel, item.mont_inputs_le, zeros, FR_OP_FROM_MONT, 0), item.from_mont_expected_le);
    expectHexBatch(`${item.name}:mul_factors`, await run(vectorKernel, item.mont_inputs_le, item.mont_factors_le, FR_VECTOR_OP_MUL_FACTORS, 0), item.mul_expected_le);
    const logCount = Math.round(Math.log2(item.mont_inputs_le.length));
    expectHexBatch(`${item.name}:bit_reverse_copy`, await run(vectorKernel, item.mont_inputs_le, zeros, FR_VECTOR_OP_BIT_REVERSE_COPY, logCount), item.bit_reverse_expected_le);
  }

  for (const op of ["add", "sub", "mul", "to_mont", "from_mont", "mul_factors", "bit_reverse_copy"]) {
    log(`${op}: OK`);
  }
  log("");
  log(`PASS: ${suiteTitle(module.id, "fr Vector Ops")} succeeded`);
  return { passed: 1, failed: 0 };
}
