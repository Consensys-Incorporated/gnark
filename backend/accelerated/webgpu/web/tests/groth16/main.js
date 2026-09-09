import { installProverPage } from "../shared/prover_page.js";

installProverPage({
  name: "Groth16",
  fixtureDir: "groth16",
  provingKeyFile: "pk.dump",
  provingKeyFormat: "dump",
  prepareWithConstraintSystem: false,
  module: (curve) => curve.groth16,
  depthLabel: "depth",
  chainSteps: (sizeLog) => 1 << sizeLog,
  step: (acc, mul, _x, modulus) => (acc * mul + 1n) % modulus,
  extraWitnessMetrics: () => ({}),
});
