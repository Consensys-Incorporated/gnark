import type { CurveGPUAffinePoint, CurveModule } from "../../../src/index.js";
import { installBenchPage } from "./shared/bench_page.js";
import { benchmarkTotalDuration } from "./shared/bench_total.js";
import { fetchJSON, makeRandomScalars } from "./shared/browser_utils.js";
import { affineFromHex, baseFixturePaths, suiteTitle, vectorPath } from "./shared/fixtures.js";
import { createPreferredByteBaseSource } from "./shared/msm_bench_sources.js";
import { appendContextDiagnostics, createRequestedCurveModule, curveDisplayName, getRequestedCurveId } from "./shared/page_library.js";
import type { G1ScalarMulVectors } from "./g1_scalar_mul_page.js";

const curveId = getRequestedCurveId();

function scalarFromUint64(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

/** `i * G` for `i = 1..count`, packed in the shader (Jacobian) layout. */
async function buildGeneratedBases(curve: CurveModule, generator: CurveGPUAffinePoint, count: number): Promise<Uint8Array> {
  const { coordinateBytes, pointBytes } = curve.g1;
  const generated = await curve.g1.scalarMulAffineBatch(
    Array.from({ length: count }, () => generator),
    Array.from({ length: count }, (_, index) => scalarFromUint64(BigInt(index + 1))),
  );
  const out = new Uint8Array(count * pointBytes);
  generated.forEach((point, index) => {
    out.set(point.x, index * pointBytes);
    out.set(point.y, index * pointBytes + coordinateBytes);
    out.set(point.z, index * pointBytes + 2 * coordinateBytes);
  });
  return out;
}

function unpackAffineBases(bytes: Uint8Array, count: number, coordinateBytes: number, pointBytes: number): CurveGPUAffinePoint[] {
  return Array.from({ length: count }, (_, i) => ({
    x: bytes.slice(i * pointBytes, i * pointBytes + coordinateBytes),
    y: bytes.slice(i * pointBytes + coordinateBytes, i * pointBytes + 2 * coordinateBytes),
  }));
}

installBenchPage({
  title: suiteTitle(curveId, "G1 MSM", "Benchmark"),
  idleMessage: `Press Run to benchmark ${curveDisplayName(curveId)} G1 MSM in browser WebGPU.`,
  async body(lines, writeLog, { minLog, maxLog, iters }) {
    const initStart = performance.now();
    const curve = await createRequestedCurveModule(curveId);
    const { coordinateBytes, pointBytes } = curve.g1;
    const scalarVectors = await fetchJSON<G1ScalarMulVectors>(vectorPath("g1", curveId, "g1_scalar_mul"));
    const generator = affineFromHex(scalarVectors.generator_affine);
    const baseSourceProvider = createPreferredByteBaseSource({
      locationSearch: window.location.search,
      pointBytes,
      ...baseFixturePaths("g1", curveId),
      generatedLoadBases: (size) => buildGeneratedBases(curve, generator, size),
      generateHint: (size) => `make fixture-${curveId}-g1 COUNT=${size <= 0 ? 1 << 19 : size}`,
    });
    const baseSourceInit = await baseSourceProvider.init();
    const initMs = performance.now() - initStart;

    lines.push("1. Requesting adapter... OK");
    appendContextDiagnostics(lines, curve.context);
    lines.push("2. Requesting device... OK", `3. Loading base source... OK (${baseSourceInit.context.baseSource})`, `init_ms = ${initMs.toFixed(3)}`);
    lines.push(...(baseSourceInit.postMetricLines ?? []), "");
    lines.push("size,op,window,init_ms,prep_ms,cold_total_ms,cold_with_init_prep_ms,warm_total_ms");
    writeLog(lines);

    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      const size = 1 << logSize;
      const prepStart = performance.now();
      const { bases: baseBytes } = await baseSourceProvider.loadBases({ context: baseSourceInit.context, size });
      const bases = unpackAffineBases(baseBytes, size, coordinateBytes, pointBytes);
      const scalars = makeRandomScalars(size);
      const prepMs = performance.now() - prepStart;
      const window = curve.g1msm.bestWindow(size);
      const benchmark = await benchmarkTotalDuration(iters, async () => {
        await curve.g1msm.pippengerAffine(bases, scalars, { termsPerInstance: size, window });
      });
      lines.push(
        [size, "msm_jac_pippenger_affine_input", window, initMs.toFixed(3), prepMs.toFixed(3), benchmark.coldMs.toFixed(3), (initMs + prepMs + benchmark.coldMs).toFixed(3), benchmark.warmMs.toFixed(3)].join(","),
      );
      writeLog(lines);
    }
    return `${curveDisplayName(curveId)} G1 MSM browser benchmark completed`;
  },
});
