import type { CurveModule } from "../../../src/index.js";
import { fetchJSON } from "./shared/browser_utils.js";
import { bytesList, expectHexBatch, suiteTitle, vectorPath, type Log, type SuiteResult } from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

type NTTCase = {
  name: string;
  size: number;
  input_mont_le: string[];
  forward_expected_le: string[];
  inverse_expected_le: string[];
};

export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  log(`=== ${suiteTitle(module.id, "fr NTT")} ===`);
  log("");
  const { ntt_cases: cases } = await fetchJSON<{ ntt_cases: NTTCase[] }>(vectorPath("fr", module.id, "fr_ntt"));
  log(`cases.ntt = ${cases.length}`);

  for (const item of cases) {
    const forward = await module.ntt.forward(bytesList(item.input_mont_le));
    expectHexBatch(`${item.name}: forward_ntt`, forward, item.forward_expected_le);
    expectHexBatch(`${item.name}: inverse_ntt`, await module.ntt.inverse(forward), item.inverse_expected_le);
  }

  log("forward_ntt: OK");
  log("inverse_ntt: OK");
  log("");
  log(`PASS: ${curveDisplayName(module.id)} fr NTT browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
