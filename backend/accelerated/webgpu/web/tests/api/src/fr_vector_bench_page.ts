import { installBenchPage } from "./shared/bench_page.js";
import { fetchText, getAdapterDiagnosticLines } from "./shared/browser_utils.js";
import { curveShaderPath, suiteTitle } from "./shared/fixtures.js";
import { getRequestedCurveId } from "./shared/page_library.js";
import { createRawKernel, runRawKernel, type RawKernel, type RawProfile } from "./shared/raw_kernel.js";

const FR_OP_TO_MONT = 11;
const FR_VECTOR_OP_ADD = 1;
const FR_VECTOR_OP_SUB = 2;
const FR_VECTOR_OP_MUL_FACTORS = 3;
const FR_VECTOR_OP_BIT_REVERSE_COPY = 4;
const ELEMENT_BYTES = 32;

const curveId = getRequestedCurveId();

/** Random elements with only the low 64 bits set (always below the modulus). */
function makeRegularBatch(count: number, seed: number): Uint8Array {
  const out = new Uint8Array(count * ELEMENT_BYTES);
  const view = new DataView(out.buffer);
  let state = seed >>> 0;
  for (let i = 0; i < count; i += 1) {
    for (let word = 0; word < 2; word += 1) {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      view.setUint32(i * ELEMENT_BYTES + word * 4, state >>> 0, true);
    }
  }
  return out;
}

async function benchOp(device: GPUDevice, kernel: RawKernel, a: Uint8Array, b: Uint8Array, opcode: number, logCount: number, iters: number): Promise<{ cold: RawProfile; warm: RawProfile }> {
  const cold = (await runRawKernel(device, kernel, a, b, ELEMENT_BYTES, opcode, logCount)).profile;
  if (iters === 1) {
    return { cold, warm: cold };
  }
  const warm: RawProfile = { uploadMs: 0, kernelMs: 0, readbackMs: 0, totalMs: 0 };
  for (let i = 0; i < iters; i += 1) {
    const { profile } = await runRawKernel(device, kernel, a, b, ELEMENT_BYTES, opcode, logCount);
    warm.uploadMs += profile.uploadMs / iters;
    warm.kernelMs += profile.kernelMs / iters;
    warm.readbackMs += profile.readbackMs / iters;
    warm.totalMs += profile.totalMs / iters;
  }
  return { cold, warm };
}

function profileColumns(profile: RawProfile): string[] {
  return [profile.uploadMs, profile.kernelMs, profile.readbackMs, profile.totalMs].map((value) => value.toFixed(3));
}

installBenchPage({
  title: suiteTitle(curveId, "fr Vector", "Benchmark"),
  idleMessage: `Press Run to benchmark ${curveId} fr vector kernels in browser WebGPU.`,
  async body(lines, writeLog, { minLog, maxLog, iters }) {
    if (!navigator.gpu) {
      throw new Error("WebGPU is not available in this browser");
    }
    const initStart = performance.now();
    lines.push("1. Requesting adapter... OK");
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) {
      throw new Error("requestAdapter returned null");
    }
    lines.push(...(await getAdapterDiagnosticLines(adapter)));
    lines.push("2. Requesting device... OK");
    const device = await adapter.requestDevice();
    const [arithShader, vectorShader] = await Promise.all([
      fetchText(curveShaderPath(curveId, "fr_arith.wgsl")),
      fetchText(curveShaderPath(curveId, "fr_vector.wgsl")),
    ]);
    lines.push("3. Loading shaders... OK");
    const arithKernel = createRawKernel(device, `${curveId}-fr`, arithShader, "fr_ops_main");
    const vectorKernel = createRawKernel(device, `${curveId}-fr-vector`, vectorShader, "fr_vector_main");
    const initMs = performance.now() - initStart;
    lines.push("4. Creating pipelines... OK", `init_ms = ${initMs.toFixed(3)}`, "");
    lines.push(
      "size,op,init_ms,cold_upload_ms,cold_kernel_ms,cold_readback_ms,cold_total_ms,cold_with_init_ms,warm_upload_ms,warm_kernel_ms,warm_readback_ms,warm_total_ms",
    );

    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      const size = 1 << logSize;
      const zeros = new Uint8Array(size * ELEMENT_BYTES);
      const toMont = async (regular: Uint8Array): Promise<Uint8Array> => (await runRawKernel(device, arithKernel, regular, zeros, ELEMENT_BYTES, FR_OP_TO_MONT, 0)).out;
      const leftMont = await toMont(makeRegularBatch(size, 0x12345678 ^ size));
      const rightMont = await toMont(makeRegularBatch(size, 0x9e3779b9 ^ size));

      const ops: [string, Uint8Array, number, number][] = [
        ["add", rightMont, FR_VECTOR_OP_ADD, 0],
        ["sub", rightMont, FR_VECTOR_OP_SUB, 0],
        ["mul", rightMont, FR_VECTOR_OP_MUL_FACTORS, 0],
        ["bit_reverse", zeros, FR_VECTOR_OP_BIT_REVERSE_COPY, logSize],
      ];
      for (const [name, right, opcode, logCount] of ops) {
        const bench = await benchOp(device, vectorKernel, leftMont, right, opcode, logCount, iters);
        lines.push(
          [size, name, initMs.toFixed(3), ...profileColumns(bench.cold), (initMs + bench.cold.totalMs).toFixed(3), ...profileColumns(bench.warm)].join(","),
        );
      }
      writeLog(lines);
    }
    return `${curveId} fr vector browser benchmark completed`;
  },
});
