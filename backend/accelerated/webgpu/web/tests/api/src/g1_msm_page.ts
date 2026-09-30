import type { CurveGPUAffinePoint, CurveModule } from "../../../src/index.js";
import { fetchJSON, packBytes } from "./shared/browser_utils.js";
import {
  affineFromHex,
  bytesList,
  expectAffineBatch,
  expectJacobianBatch,
  suiteTitle,
  vectorPath,
  type HexAffine,
  type HexJacobian,
  type Log,
  type SuiteResult,
} from "./shared/fixtures.js";
import { curveDisplayName } from "./shared/page_library.js";

type G1MSMVectors = {
  terms_per_instance: number;
  msm_cases: { name: string; bases_affine: HexAffine[]; scalars_bytes_le: string[]; expected_affine: HexJacobian }[];
  one_mont_z: string;
};

/** Reference MSM: per-term scalar multiplications summed with mixed additions. */
async function naiveMSMAffine(module: CurveModule, bases: CurveGPUAffinePoint[], scalars: Uint8Array[]): Promise<CurveGPUAffinePoint> {
  const scaled = await module.g1.scalarMulAffineBatch(bases, scalars);
  if (scaled.length === 0) {
    return module.g1.affineInfinity();
  }
  let acc = await module.g1.affineToJacobian(scaled[0]);
  for (let i = 1; i < scaled.length; i += 1) {
    acc = await module.g1.addMixed(acc, scaled[i]);
  }
  return module.g1.jacobianToAffine(acc);
}

export async function runSuite(module: CurveModule, log: Log): Promise<SuiteResult> {
  log(`=== ${suiteTitle(module.id, "G1 MSM")} ===`);
  log("");
  const vectors = await fetchJSON<G1MSMVectors>(vectorPath("g1", module.id, "g1_msm"));
  log(`terms_per_instance = ${vectors.terms_per_instance}`);
  log(`cases.msm = ${vectors.msm_cases.length}`);
  const expected = vectors.msm_cases.map((item) => item.expected_affine);
  const allBases = vectors.msm_cases.flatMap((item) => item.bases_affine.map(affineFromHex));
  const allScalars = vectors.msm_cases.flatMap((item) => bytesList(item.scalars_bytes_le));

  const naiveResults: CurveGPUAffinePoint[] = [];
  for (const msmCase of vectors.msm_cases) {
    naiveResults.push(await naiveMSMAffine(module, msmCase.bases_affine.map(affineFromHex), bytesList(msmCase.scalars_bytes_le)));
  }
  expectAffineBatch("msm_naive_affine", naiveResults, expected, log);

  const window = 4;
  const batchOptions = { count: vectors.msm_cases.length, termsPerInstance: vectors.terms_per_instance, window };
  expectJacobianBatch(`msm_jac_pippenger_affine_input (window=${window})`, await module.g1msm.pippengerAffineBatch(allBases, allScalars, batchOptions), expected, log);

  // GPU-resident bases, as used by the Go bridges: upload once, then MSM sub-ranges.
  const affinePacked = new Uint8Array(allBases.length * 2 * module.g1.coordinateBytes);
  allBases.forEach((point, i) => {
    affinePacked.set(point.x, i * 2 * module.g1.coordinateBytes);
    affinePacked.set(point.y, (2 * i + 1) * module.g1.coordinateBytes);
  });
  const resident = await module.g1msm.uploadAffineBases(affinePacked);
  try {
    const residentResults: CurveGPUAffinePoint[] = [];
    for (let i = 0; i < vectors.msm_cases.length; i += 1) {
      const start = i * vectors.terms_per_instance;
      const scalars = packBytes(allScalars.slice(start, start + vectors.terms_per_instance), 32);
      const out = await module.g1msm.msmResident(resident, start, scalars, { window });
      residentResults.push({ x: out.slice(0, module.g1.coordinateBytes), y: out.slice(module.g1.coordinateBytes) });
    }
    expectAffineBatch(`msm_resident_bases (window=${window})`, residentResults, expected, log);
  } finally {
    resident.release();
  }

  log("");
  log(`PASS: ${curveDisplayName(module.id)} G1 MSM browser smoke succeeded`);
  return { passed: 1, failed: 0 };
}
