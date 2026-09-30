import type { CurveModule } from "../../../src/index.js";
import { fetchJSON } from "./shared/browser_utils.js";
import { affineFromHex, bytesList, expectJacobianBatch, suiteTitle, vectorPath, type HexAffine, type HexJacobian, type Log, type SuiteResult } from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

export type G1ScalarMulVectors = {
  generator_affine: HexAffine;
  scalar_cases: { name: string; base_affine: HexAffine; scalar_bytes_le: string; scalar_mul_affine: HexJacobian }[];
  base_cases: { name: string; scalar_bytes_le: string; scalar_mul_base_affine: HexJacobian }[];
};

export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  log(`=== ${suiteTitle(module.id, "G1 Scalar Mul")} ===`);
  log("");
  const vectors = await fetchJSON<G1ScalarMulVectors>(vectorPath("g1", module.id, "g1_scalar_mul"));
  log(`cases.scalar = ${vectors.scalar_cases.length}`);
  log(`cases.base = ${vectors.base_cases.length}`);

  expectJacobianBatch(
    "scalar_mul_affine",
    await module.g1.scalarMulAffineBatch(
      vectors.scalar_cases.map((item) => affineFromHex(item.base_affine)),
      bytesList(vectors.scalar_cases.map((item) => item.scalar_bytes_le)),
    ),
    vectors.scalar_cases.map((item) => item.scalar_mul_affine),
    log,
  );

  const generator = affineFromHex(vectors.generator_affine);
  expectJacobianBatch(
    "scalar_mul_base_affine",
    await module.g1.scalarMulAffineBatch(
      vectors.base_cases.map(() => generator),
      bytesList(vectors.base_cases.map((item) => item.scalar_bytes_le)),
    ),
    vectors.base_cases.map((item) => item.scalar_mul_base_affine),
    log,
  );

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G1 scalar mul browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
