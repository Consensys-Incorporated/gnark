import type { CurveModule } from "../../../src/index.js";
import { bytesToHex, fetchJSON, hexToBytes } from "./shared/browser_utils.js";
import { bytesList, expectBoolBatch, expectHexBatch, suiteTitle, vectorPath, type Log, type SuiteResult } from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

type ElementCase = {
  name: string;
  a_bytes_le: string;
  b_bytes_le: string;
  equal_bytes_le: string;
  add_bytes_le: string;
  sub_bytes_le: string;
  neg_a_bytes_le: string;
  double_a_bytes_le: string;
  mul_bytes_le: string;
  square_a_bytes_le: string;
};

type NormalizeCase = { name: string; input_bytes_le: string; expected_bytes_le: string };
type ConvertCase = { name: string; regular_bytes_le: string; mont_bytes_le: string };

type FieldOpsVectors = {
  element_cases: ElementCase[];
  edge_cases: ElementCase[];
  differential_cases: ElementCase[];
  normalize_cases: NormalizeCase[];
  convert_cases: ConvertCase[];
};

/** Shared smoke suite for the `fr` and `fp` field modules; `suiteId` selects the field. */
export async function runSuite(module: CurveModule, log: Log, suiteId = "fr_ops"): Promise<SuiteResult> {
  const field = suiteId.startsWith("fp") ? "fp" : "fr";
  const f = module[field];
  log(`=== ${suiteTitle(module.id, `${field} Ops`)} ===`);
  log("");
  const vectors = await fetchJSON<FieldOpsVectors>(vectorPath(field, module.id, `${field}_ops`));
  log(`cases.sanity = ${vectors.element_cases.length}`);
  log(`cases.edge = ${vectors.edge_cases.length}`);
  log(`cases.differential = ${vectors.differential_cases.length}`);
  log(`cases.normalize = ${vectors.normalize_cases.length}`);
  log(`cases.convert = ${vectors.convert_cases.length}`);

  const cases = [...vectors.element_cases, ...vectors.edge_cases, ...vectors.differential_cases];
  const aHex = cases.map((item) => item.a_bytes_le);
  const aBytes = bytesList(aHex);
  const bBytes = bytesList(cases.map((item) => item.b_bytes_le));
  const zeroHex = bytesToHex(new Uint8Array(f.byteSize));
  const oneMontHex = bytesToHex(await f.montOne());
  const repeat = <T>(value: T): T[] => cases.map(() => value);

  expectHexBatch("copy", await f.copyBatch(aBytes), aHex, log);
  expectBoolBatch("equal", await f.equalBatch(aBytes, bBytes), cases.map((item) => hexToBytes(item.equal_bytes_le).some((byte) => byte !== 0)), log);
  expectHexBatch("zero", repeat(f.zero()), repeat(zeroHex), log);
  expectHexBatch("one", repeat(hexToBytes(oneMontHex)), repeat(oneMontHex), log);
  expectHexBatch("add", await f.addBatch(aBytes, bBytes), cases.map((item) => item.add_bytes_le), log);
  expectHexBatch("sub", await f.subBatch(aBytes, bBytes), cases.map((item) => item.sub_bytes_le), log);
  expectHexBatch("neg", await f.negBatch(aBytes), cases.map((item) => item.neg_a_bytes_le), log);
  expectHexBatch("double", await f.doubleBatch(aBytes), cases.map((item) => item.double_a_bytes_le), log);
  expectHexBatch("mul", await f.mulBatch(aBytes, bBytes), cases.map((item) => item.mul_bytes_le), log);
  expectHexBatch("square", await f.squareBatch(aBytes), cases.map((item) => item.square_a_bytes_le), log);
  expectHexBatch(
    "to_mont",
    await f.toMontgomeryBatch(bytesList(vectors.convert_cases.map((item) => item.regular_bytes_le))),
    vectors.convert_cases.map((item) => item.mont_bytes_le),
    log,
  );
  expectHexBatch(
    "from_mont",
    await f.fromMontgomeryBatch(bytesList(vectors.convert_cases.map((item) => item.mont_bytes_le))),
    vectors.convert_cases.map((item) => item.regular_bytes_le),
    log,
  );
  expectHexBatch(
    "normalize",
    await f.normalizeMontBatch(bytesList(vectors.normalize_cases.map((item) => item.input_bytes_le))),
    vectors.normalize_cases.map((item) => item.expected_bytes_le),
    log,
  );

  const oneCase = vectors.convert_cases.find((item) => item.name === "one");
  if (!oneCase) {
    throw new Error("missing convert case one");
  }
  if (oneMontHex !== oneCase.mont_bytes_le) {
    throw new Error(`one: mismatch got=${oneMontHex} want=${oneCase.mont_bytes_le}`);
  }

  log("");
  log(`PASS: ${curveDisplayName(module.id)} ${field} browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
