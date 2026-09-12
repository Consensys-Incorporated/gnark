import type { CurveGPUG2AffinePoint, CurveGPUG2JacobianPoint, CurveModule } from "../../../src/index.js";
import { fetchJSON, packBytes } from "./shared/browser_utils.js";
import {
  bytesList,
  expectG2AffineBatch,
  g2AffineFromHex,
  suiteTitle,
  vectorPath,
  type HexG2Affine,
  type HexG2Jacobian,
  type Log,
  type SuiteResult,
} from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

type G2MSMVectors = {
  terms_per_instance: number;
  msm_cases: { name: string; bases_affine: HexG2Affine[]; scalars_bytes_le: string[]; expected_affine: HexG2Jacobian }[];
};

async function naiveMSMAffine(module: CurveModule, bases: CurveGPUG2AffinePoint[], scalars: Uint8Array[]): Promise<CurveGPUG2AffinePoint> {
  const scaled = await module.g2.scalarMulAffineBatch(bases, scalars);
  if (scaled.length === 0) {
    return module.g2.affineInfinity();
  }
  let acc = await module.g2.affineToJacobian(scaled[0]);
  for (let i = 1; i < scaled.length; i += 1) {
    acc = await module.g2.addMixed(acc, scaled[i]);
  }
  return module.g2.jacobianToAffine(acc);
}

/** Pack affine G2 points into the shader layout (`z = (one, 0)`, infinity all-zero). */
function packG2AffineWithOneZ(module: CurveModule, bases: readonly CurveGPUG2AffinePoint[], oneMont: Uint8Array): Uint8Array {
  const { componentBytes, pointBytes } = module.g2;
  const out = new Uint8Array(bases.length * pointBytes);
  bases.forEach((point, i) => {
    const base = i * pointBytes;
    const parts = [point.x.c0, point.x.c1, point.y.c0, point.y.c1];
    parts.forEach((part, j) => out.set(part, base + j * componentBytes));
    if (parts.some((part) => part.some((byte) => byte !== 0))) {
      out.set(oneMont, base + 4 * componentBytes);
    }
  });
  return out;
}

function unpackG2Jacobian(module: CurveModule, bytes: Uint8Array, count: number): CurveGPUG2JacobianPoint[] {
  const { componentBytes, pointBytes } = module.g2;
  const part = (base: number, j: number): Uint8Array => bytes.slice(base + j * componentBytes, base + (j + 1) * componentBytes);
  return Array.from({ length: count }, (_, i) => {
    const base = i * pointBytes;
    return { x: { c0: part(base, 0), c1: part(base, 1) }, y: { c0: part(base, 2), c1: part(base, 3) }, z: { c0: part(base, 4), c1: part(base, 5) } };
  });
}

export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  log(`=== ${suiteTitle(module.id, "G2 MSM")} ===`);
  log("");
  const vectors = await fetchJSON<G2MSMVectors>(vectorPath("g2", module.id, "g2_msm"));
  log(`terms_per_instance = ${vectors.terms_per_instance}`);
  log(`cases.msm = ${vectors.msm_cases.length}`);
  const expected = vectors.msm_cases.map((item) => item.expected_affine);
  const allBases = vectors.msm_cases.flatMap((item) => item.bases_affine.map(g2AffineFromHex));
  const allScalars = vectors.msm_cases.flatMap((item) => bytesList(item.scalars_bytes_le));

  const naiveResults: CurveGPUG2AffinePoint[] = [];
  for (const msmCase of vectors.msm_cases) {
    naiveResults.push(await naiveMSMAffine(module, msmCase.bases_affine.map(g2AffineFromHex), bytesList(msmCase.scalars_bytes_le)));
  }
  expectG2AffineBatch("msm_naive_affine", naiveResults, expected, log);

  const window = 4;
  const batchOptions = { count: vectors.msm_cases.length, termsPerInstance: vectors.terms_per_instance, window };
  const pippengerResults = await module.g2msm.pippengerAffineBatch(allBases, allScalars, batchOptions);
  expectG2AffineBatch(`msm_jac_pippenger_affine_input (window=${window})`, await module.g2.jacobianToAffineBatch(pippengerResults), expected, log);

  const packedBases = packG2AffineWithOneZ(module, allBases, await module.fp.montOne());
  const packedScalars = packBytes(allScalars, 32);
  const packedResults = unpackG2Jacobian(module, await module.g2msm.pippengerPackedJacobianBases(packedBases, packedScalars, batchOptions), vectors.msm_cases.length);
  expectG2AffineBatch(`msm_jac_pippenger_packed (window=${window})`, await module.g2.jacobianToAffineBatch(packedResults), expected, log);

  // GPU-resident bases, as used by the Groth16 bridge for the G2 part of B.
  const componentBytes = module.g2.componentBytes;
  const affinePacked = new Uint8Array(allBases.length * 4 * componentBytes);
  allBases.forEach((point, i) => {
    [point.x.c0, point.x.c1, point.y.c0, point.y.c1].forEach((part, j) => affinePacked.set(part, (4 * i + j) * componentBytes));
  });
  const resident = await module.g2msm.uploadAffineBases(affinePacked);
  try {
    const residentResults: CurveGPUG2AffinePoint[] = [];
    for (let i = 0; i < vectors.msm_cases.length; i += 1) {
      const start = i * vectors.terms_per_instance;
      const out = await module.g2msm.msmResident(resident, start, packBytes(allScalars.slice(start, start + vectors.terms_per_instance), 32), { window });
      const part = (j: number): Uint8Array => out.slice(j * componentBytes, (j + 1) * componentBytes);
      residentResults.push({ x: { c0: part(0), c1: part(1) }, y: { c0: part(2), c1: part(3) } });
    }
    expectG2AffineBatch(`msm_resident_bases (window=${window})`, residentResults, expected, log);
  } finally {
    resident.release();
  }

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G2 MSM browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
