import { installProverPage } from "../shared/prover_page.js";

function targetConstraints(sizeLog) {
  return 1 << sizeLog;
}

function estimatedConstraints(steps, commitments) {
  return 4 * steps + commitments * (Math.floor(steps / 4) + 2);
}

/** Largest multiple-of-4 chain length whose estimated constraint count fits the fixture domain. */
function chainStepsForTarget(sizeLog, commitments) {
  const target = targetConstraints(sizeLog) - 4;
  const commitmentCount = Math.max(0, Math.min(2, commitments));
  let steps = 4;
  for (;;) {
    const next = steps + 4;
    if (estimatedConstraints(next, commitmentCount) > target) {
      return steps;
    }
    steps = next;
  }
}

installProverPage({
  name: "PLONK",
  fixtureDir: "plonk",
  provingKeyFile: "pk.bin",
  // The proving key is trusted, so skip subgroup membership checks.
  provingKeyFormat: "unsafe",
  prepareWithConstraintSystem: true,
  module: (curve) => curve.plonk,
  depthLabel: "chain_steps",
  chainSteps: chainStepsForTarget,
  step: (acc, mul, x, modulus) => (acc * mul + acc + x + 1n) % modulus,
  extraWitnessMetrics: (config) => ({ target_constraints: targetConstraints(config.sizeLog) }),
});
