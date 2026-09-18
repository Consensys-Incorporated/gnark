import type { CurveModule } from "../../../src/index.js";
import { bytesToHex, fetchJSON } from "./shared/browser_utils.js";
import {
  expectG2AffineBatch,
  expectG2JacobianBatch,
  g2AffineFromHex,
  g2JacobianFromHex,
  suiteTitle,
  vectorPath,
  type HexG2Affine,
  type HexG2Jacobian,
  type Log,
  type SuiteResult,
} from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

type G2Case = {
  name: string;
  p_affine: HexG2Affine;
  q_affine: HexG2Affine;
  p_jacobian: HexG2Jacobian;
  p_affine_output: HexG2Jacobian;
  neg_p_jacobian: HexG2Jacobian;
  double_p_jacobian: HexG2Jacobian;
  add_mixed_p_plus_q_jacobian: HexG2Jacobian;
  affine_add_p_plus_q: HexG2Jacobian;
};

export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  log(`=== ${suiteTitle(module.id, "G2 Ops")} ===`);
  log("");
  const { point_cases: cases } = await fetchJSON<{ point_cases: G2Case[] }>(vectorPath("g2", module.id, "g2_ops"));
  log(`cases.g2 = ${cases.length}`);

  const g2 = module.g2;
  const pAffine = cases.map((item) => g2AffineFromHex(item.p_affine));
  const qAffine = cases.map((item) => g2AffineFromHex(item.q_affine));
  const pJacobian = cases.map((item) => g2JacobianFromHex(item.p_jacobian));
  const oneFp2 = { c0_bytes_le: bytesToHex(await module.fp.montOne()), c1_bytes_le: bytesToHex(module.fp.zero()) };
  const zero = bytesToHex(new Uint8Array(g2.componentBytes));
  const jacInfinityWant = cases.map(() => ({ x: oneFp2, y: oneFp2, z: { c0_bytes_le: zero, c1_bytes_le: zero } }));

  expectG2JacobianBatch("copy", await g2.copyBatch(pJacobian), cases.map((item) => item.p_jacobian), log);
  expectG2JacobianBatch("jac_infinity", await g2.jacobianInfinityBatch(cases.length), jacInfinityWant, log);
  expectG2JacobianBatch("affine_to_jac", await g2.affineToJacobianBatch(pAffine), cases.map((item) => item.p_jacobian), log);
  expectG2JacobianBatch("neg_jac", await g2.negJacobianBatch(pJacobian), cases.map((item) => item.neg_p_jacobian), log);
  expectG2AffineBatch("jac_to_affine", await g2.jacobianToAffineBatch(pJacobian), cases.map((item) => item.p_affine_output), log);
  expectG2JacobianBatch("double_jac", await g2.doubleJacobianBatch(pJacobian), cases.map((item) => item.double_p_jacobian), log);
  expectG2JacobianBatch("add_mixed", await g2.addMixedBatch(pJacobian, qAffine), cases.map((item) => item.add_mixed_p_plus_q_jacobian), log);
  expectG2JacobianBatch("affine_add", await g2.affineAddBatch(pAffine, qAffine), cases.map((item) => item.affine_add_p_plus_q), log);

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G2 browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
