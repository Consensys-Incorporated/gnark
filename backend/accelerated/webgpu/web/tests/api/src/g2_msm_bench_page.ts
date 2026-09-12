import type { CurveGPUG2AffinePoint, CurveModule } from "../../../src/index.js";
import { installBenchPage } from "./shared/bench_page.js";
import { benchmarkTotalDuration } from "./shared/bench_total.js";
import { fetchJSON, makeRandomScalars, packBytes, yieldToBrowser } from "./shared/browser_utils.js";
import { baseFixturePaths, g2AffineFromHex, suiteTitle, vectorPath, type HexG2Affine } from "./shared/fixtures.js";
import { createPreferredByteBaseSource } from "./shared/msm_bench_sources.js";
import { appendContextDiagnostics, createRequestedCurveModule, curveDisplayName, getRequestedCurveId } from "./shared/page_library.js";

type G2OpsVectors = { point_cases: { p_affine: HexG2Affine; q_affine: HexG2Affine }[] };

const params = new URLSearchParams(window.location.search);
const curveId = getRequestedCurveId();

function findGeneratorPoint(vectors: G2OpsVectors): CurveGPUG2AffinePoint {
  for (const item of vectors.point_cases) {
    for (const point of [item.p_affine, item.q_affine]) {
      const parsed = g2AffineFromHex(point);
      if ([parsed.x.c0, parsed.x.c1, parsed.y.c0, parsed.y.c1].some((part) => part.some((byte) => byte !== 0))) {
        return parsed;
      }
    }
  }
  throw new Error("no non-infinity G2 point found in vectors");
}

function scalarFromUint64(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

/** `i * G` for `i = 1..count`, packed in the shader (Jacobian) layout. */
async function buildGeneratedBases(curve: CurveModule, generator: CurveGPUG2AffinePoint, count: number): Promise<Uint8Array> {
  const { componentBytes, pointBytes } = curve.g2;
  const generated = await curve.g2.scalarMulAffineBatch(
    Array.from({ length: count }, () => generator),
    Array.from({ length: count }, (_, index) => scalarFromUint64(BigInt(index + 1))),
  );
  const out = new Uint8Array(count * pointBytes);
  generated.forEach((point, index) => {
    [point.x.c0, point.x.c1, point.y.c0, point.y.c1, point.z.c0, point.z.c1].forEach((part, j) => out.set(part, index * pointBytes + j * componentBytes));
  });
  return out;
}

installBenchPage({
  title: suiteTitle(curveId, "G2 MSM", "Benchmark"),
  idleMessage: `Press Run to benchmark ${curveId} G2 MSM in browser WebGPU.`,
  autorun: params.get("autorun") === "1",
  async body(lines, writeLog, { minLog, maxLog, iters }) {
    const initStart = performance.now();
    const curve = await createRequestedCurveModule(curveId);
    const generator = findGeneratorPoint(await fetchJSON<G2OpsVectors>(vectorPath("g2", curveId, "g2_ops")));
    const baseSourceProvider = createPreferredByteBaseSource({
      locationSearch: window.location.search,
      pointBytes: curve.g2.pointBytes,
      ...baseFixturePaths("g2", curveId),
      generatedLoadBases: (size) => buildGeneratedBases(curve, generator, size),
      generateHint: (size) => `make fixture-${curveId}-g2 COUNT=${size <= 0 ? 1 << 14 : size}`,
      fixtureLabel: "G2 base",
    });
    const baseSourceInit = await baseSourceProvider.init();
    const initMs = performance.now() - initStart;

    lines.push("1. Requesting adapter... OK");
    appendContextDiagnostics(lines, curve.context);
    lines.push("2. Requesting device... OK", `3. Loading base source... OK (${baseSourceInit.context.baseSource})`, `init_ms = ${initMs.toFixed(3)}`);
    lines.push(...(baseSourceInit.postMetricLines ?? []));

    const prewarmSize = 1 << minLog;
    lines.push(`4. Prewarming G2 MSM runtime at size ${prewarmSize}...`);
    writeLog(lines);
    await yieldToBrowser();
    {
      const { bases } = await baseSourceProvider.loadBases({ context: baseSourceInit.context, size: prewarmSize });
      await curve.g2msm.pippengerPackedJacobianBases(bases, packBytes(makeRandomScalars(prewarmSize), 32), {
        count: 1,
        termsPerInstance: prewarmSize,
        window: curve.g2msm.bestWindow(prewarmSize),
      });
    }
    lines[lines.length - 1] = `4. Prewarming G2 MSM runtime at size ${prewarmSize}... OK`;
    lines.push("", "size,op,window,init_ms,prep_ms,cold_total_ms,cold_with_init_prep_ms,warm_total_ms");
    writeLog(lines);
    await yieldToBrowser();

    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      await yieldToBrowser();
      const size = 1 << logSize;
      const prepStart = performance.now();
      const { bases: baseBytes } = await baseSourceProvider.loadBases({ context: baseSourceInit.context, size });
      const scalarsPacked = packBytes(makeRandomScalars(size), 32);
      const prepMs = performance.now() - prepStart;
      const window = curve.g2msm.bestWindow(size);
      const benchmark = await benchmarkTotalDuration(
        iters,
        async () => {
          await curve.g2msm.pippengerPackedJacobianBases(baseBytes, scalarsPacked, { count: 1, termsPerInstance: size, window });
        },
        yieldToBrowser,
      );
      lines.push(
        [size, "msm_jac_pippenger_packed", window, initMs.toFixed(3), prepMs.toFixed(3), benchmark.coldMs.toFixed(3), (initMs + prepMs + benchmark.coldMs).toFixed(3), benchmark.warmMs.toFixed(3)].join(","),
      );
      writeLog(lines);
    }
    return `${curveDisplayName(curveId)} G2 MSM browser benchmark completed`;
  },
});
