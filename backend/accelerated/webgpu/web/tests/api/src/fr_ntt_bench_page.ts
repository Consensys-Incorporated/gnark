import { installBenchPage } from "./shared/bench_page.js";
import { benchmarkTotalDuration } from "./shared/bench_total.js";
import { makeRandomScalars } from "./shared/browser_utils.js";
import { suiteTitle } from "./shared/fixtures.js";
import { appendContextDiagnostics, createRequestedCurveModule, curveDisplayName, getRequestedCurveId } from "./shared/page_library.js";

const curveId = getRequestedCurveId();

installBenchPage({
  title: suiteTitle(curveId, "fr NTT", "Benchmark"),
  idleMessage: `Press Run to benchmark ${curveDisplayName(curveId)} fr NTT in browser WebGPU.`,
  async body(lines, writeLog, { minLog, maxLog, iters }) {
    const initStart = performance.now();
    const curve = await createRequestedCurveModule(curveId);
    const initMs = performance.now() - initStart;

    lines.push("1. Requesting adapter... OK");
    appendContextDiagnostics(lines, curve.context);
    lines.push("2. Requesting device... OK", "3. Initializing curve module... OK", `init_ms = ${initMs.toFixed(3)}`, "");
    lines.push("size,op,init_ms,cold_total_ms,cold_with_init_ms,warm_total_ms");
    writeLog(lines);

    const row = (size: number, op: string, bench: { coldMs: number; warmMs: number }): string =>
      [size, op, initMs.toFixed(3), bench.coldMs.toFixed(3), (initMs + bench.coldMs).toFixed(3), bench.warmMs.toFixed(3)].join(",");

    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      const size = 1 << logSize;
      const inputMont = await curve.fr.toMontgomeryBatch(makeRandomScalars(size, 0x9e3779b9 ^ size));
      lines.push(row(size, "forward_ntt", await benchmarkTotalDuration(iters, async () => void (await curve.ntt.forward(inputMont)))));
      writeLog(lines);
      const forwardValues = await curve.ntt.forward(inputMont);
      lines.push(row(size, "inverse_ntt", await benchmarkTotalDuration(iters, async () => void (await curve.ntt.inverse(forwardValues)))));
      writeLog(lines);
    }
    return `${curveDisplayName(curveId)} fr NTT browser benchmark completed`;
  },
});
