import { installBenchPage } from "./shared/bench_page.js";
import { benchmarkTotalDuration } from "./shared/bench_total.js";
import { makeRandomScalars } from "./shared/browser_utils.js";
import { suiteTitle } from "./shared/fixtures.js";
import { appendContextDiagnostics, createRequestedCurveModule, curveDisplayName, getRequestedCurveId } from "./shared/page_library.js";

const curveId = getRequestedCurveId();

/** Concatenate fixed-size elements into one packed buffer. */
function pack(values: readonly Uint8Array[], elementBytes: number): Uint8Array {
  const out = new Uint8Array(values.length * elementBytes);
  values.forEach((value, index) => out.set(value, index * elementBytes));
  return out;
}

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

    // The packed entry points are the ones the provers use; they measure the
    // GPU pipeline plus one upload and one readback, without per-element
    // JavaScript allocations. The cold run includes the domain preparation.
    for (let logSize = minLog; logSize <= maxLog; logSize += 1) {
      const size = 1 << logSize;
      const inputMont = pack(await curve.fr.toMontgomeryBatch(makeRandomScalars(size, 0x9e3779b9 ^ size)), curve.fr.byteSize);
      lines.push(row(size, "forward_ntt", await benchmarkTotalDuration(iters, async () => void (await curve.ntt.forwardPackedMont(inputMont)))));
      writeLog(lines);
      const forwardValues = await curve.ntt.forwardPackedMont(inputMont);
      lines.push(row(size, "inverse_ntt", await benchmarkTotalDuration(iters, async () => void (await curve.ntt.inversePackedMont(forwardValues)))));
      writeLog(lines);
      lines.push(
        row(size, "inverse_coset_bitrev_regular", await benchmarkTotalDuration(iters, async () => void (await curve.ntt.inverseCosetBitReversePackedRegular(inputMont)))),
      );
      writeLog(lines);
    }
    return `${curveDisplayName(curveId)} fr NTT browser benchmark completed`;
  },
});
