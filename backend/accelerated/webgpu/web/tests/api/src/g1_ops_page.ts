import type { CurveModule } from "../../../src/index.js";
import { bytesToHex, fetchJSON } from "./shared/browser_utils.js";
import {
  affineFromHex,
  expectAffineBatch,
  expectJacobianBatch,
  jacobianFromHex,
  suiteTitle,
  vectorPath,
  type HexAffine,
  type HexJacobian,
  type Log,
  type SuiteResult,
} from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

type G1Case = {
  name: string;
  p_affine: HexAffine;
  q_affine: HexAffine;
  p_jacobian: HexJacobian;
  p_affine_output: HexJacobian;
  neg_p_jacobian: HexJacobian;
  double_p_jacobian: HexJacobian;
  add_mixed_p_plus_q_jacobian: HexJacobian;
  affine_add_p_plus_q: HexJacobian;
};

export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  log(`=== ${suiteTitle(module.id, "G1 Ops")} ===`);
  log("");
  const { point_cases: cases } = await fetchJSON<{ point_cases: G1Case[] }>(vectorPath("g1", module.id, "g1_ops"));
  log(`cases.g1 = ${cases.length}`);

  const g1 = module.g1;
  const pAffine = cases.map((item) => affineFromHex(item.p_affine));
  const qAffine = cases.map((item) => affineFromHex(item.q_affine));
  const pJacobian = cases.map((item) => jacobianFromHex(item.p_jacobian));
  const oneMont = bytesToHex(await module.fp.montOne());
  const jacInfinityWant = cases.map(() => ({ x_bytes_le: oneMont, y_bytes_le: oneMont, z_bytes_le: bytesToHex(module.fp.zero()) }));

  expectJacobianBatch("copy", await g1.copyBatch(pJacobian), cases.map((item) => item.p_jacobian), log);
  expectJacobianBatch("jac_infinity", await g1.jacobianInfinityBatch(cases.length), jacInfinityWant, log);
  expectJacobianBatch("affine_to_jac", await g1.affineToJacobianBatch(pAffine), cases.map((item) => item.p_jacobian), log);
  expectJacobianBatch("neg_jac", await g1.negJacobianBatch(pJacobian), cases.map((item) => item.neg_p_jacobian), log);
  expectAffineBatch("jac_to_affine", await g1.jacobianToAffineBatch(pJacobian), cases.map((item) => item.p_affine_output), log);
  expectJacobianBatch("double_jac", await g1.doubleJacobianBatch(pJacobian), cases.map((item) => item.double_p_jacobian), log);
  expectJacobianBatch("add_mixed", await g1.addMixedBatch(pJacobian, qAffine), cases.map((item) => item.add_mixed_p_plus_q_jacobian), log);
  expectJacobianBatch("affine_add", await g1.affineAddBatch(pAffine, qAffine), cases.map((item) => item.affine_add_p_plus_q), log);

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G1 browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
