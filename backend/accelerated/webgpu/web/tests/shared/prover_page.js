// Shared driver for the Groth16 and PLONK browser prover comparison pages.
// Each page supplies a `system` descriptor (fixture layout, witness builder,
// module accessor) and this file owns the UI, timing, and reporting.

import "../../src/curvegpu/shader_bundle.generated.js";
import { createCurveGPUContext, createCurveModule, curveDefinition } from "../../index.js";

const SUPPORTED_CURVES = ["bn254", "bls12_377", "bls12_381"];

/**
 * @typedef {object} ProverSystem
 * @property {string} name Display name ("Groth16" or "PLONK").
 * @property {string} fixtureDir Fixture directory under /tests/fixtures.
 * @property {string} provingKeyFile Proving key file name inside a fixture directory.
 * @property {string} provingKeyFormat Format passed to readProvingKey.
 * @property {boolean} prepareWithConstraintSystem Whether prepareProvingKey also receives the ccs.
 * @property {(curve: any) => any} module Selects `curve.groth16` or `curve.plonk`.
 * @property {(sizeLog: number, commitments: number) => number} chainSteps Circuit chain depth for a fixture.
 * @property {(acc: bigint, mul: bigint, x: bigint, modulus: bigint) => bigint} step One chain step.
 * @property {(config: {sizeLog: number}) => Record<string, number>} extraWitnessMetrics Extra lines/fields to report.
 */

/** @param {ProverSystem} system */
export function installProverPage(system) {
  const implSelect = document.getElementById("impl");
  const curveSelect = document.getElementById("curve");
  const sizeLogSelect = document.getElementById("size-log");
  const commitmentsSelect = document.getElementById("commitments");
  const proveRunsInput = document.getElementById("prove-runs");
  const runButton = document.getElementById("run");
  const statusEl = document.getElementById("status");
  const logEl = document.getElementById("log");

  const appendLog = (line = "") => {
    logEl.textContent += `${line}\n`;
  };
  const setStatus = (text) => {
    statusEl.textContent = text;
  };
  const formatMs = (value) => Number(value).toFixed(3);

  function readConfig() {
    return {
      curve: curveSelect.value,
      sizeLog: Number.parseInt(sizeLogSelect.value, 10),
      commitments: Number.parseInt(commitmentsSelect.value, 10),
      proveRuns: Number.parseInt(proveRunsInput.value, 10),
    };
  }

  function applyQueryDefaults() {
    const params = new URLSearchParams(window.location.search);
    const impl = params.get("impl");
    const curve = params.get("curve");
    const sizeLog = params.get("size-log") ?? params.get("sizeLog");
    const commitments = params.get("commitments") ?? params.get("commitment-count") ?? params.get("commitmentCount");
    const proveRuns = params.get("prove-runs") ?? params.get("proveRuns");
    if (impl && ["both", "webgpu-go", "native-go"].includes(impl)) {
      implSelect.value = impl;
    }
    if (curve && SUPPORTED_CURVES.includes(curve)) {
      curveSelect.value = curve;
    }
    if (sizeLog && ["12", "15", "18"].includes(sizeLog)) {
      sizeLogSelect.value = sizeLog;
    }
    if (commitments && ["0", "1", "2"].includes(commitments)) {
      commitmentsSelect.value = commitments;
    }
    if (proveRuns) {
      proveRunsInput.value = proveRuns;
    }
  }

  async function fetchBytes(path) {
    const response = await fetch(path);
    if (!response.ok) {
      throw new Error(`failed to fetch ${path}: ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  function buildWitnesses(curve, config) {
    const modulus = BigInt(curveDefinition(config.curve).frModulusHex);
    const depth = system.chainSteps(config.sizeLog, config.commitments);
    const x = 3n;
    const y = 5n;
    let acc = x % modulus;
    const mul = y % modulus;
    for (let i = 0; i < depth; i++) {
      acc = system.step(acc, mul, x, modulus);
    }
    const proofModule = system.module(curve);
    return {
      depth,
      fullWitness: proofModule.encodeWitness([acc, x, y], { publicCount: 1 }),
      publicWitness: proofModule.encodeWitness([acc], { publicCount: 1 }),
    };
  }

  async function loadFixture(curve, config) {
    const base = `/tests/fixtures/${system.fixtureDir}/${config.curve}/2pow${config.sizeLog}/commit${config.commitments}`;
    const [ccsBytes, pkBytes, vkBytes] = await Promise.all([
      fetchBytes(`${base}/ccs.bin`),
      fetchBytes(`${base}/${system.provingKeyFile}`),
      fetchBytes(`${base}/vk.bin`),
    ]);
    const proofModule = system.module(curve);
    const [ccs, pk, vk] = await Promise.all([
      proofModule.readConstraintSystem(ccsBytes),
      proofModule.readProvingKey(pkBytes, { format: system.provingKeyFormat }),
      proofModule.readVerificationKey(vkBytes),
    ]);
    return { ccs, pk, vk };
  }

  async function runImpl(label, runtimeKind, curve, config) {
    const proofModule = system.module(curve);
    appendLog(`--- ${label} ---`);
    appendLog(`=== ${runtimeKind === "webgpu" ? `TS -> WebGPU ${system.name}` : `TS -> Native ${system.name}`} (${config.curve}) ===`);
    appendLog(`fixture = 2^${config.sizeLog}`);
    appendLog(`commitments = ${config.commitments}`);
    appendLog(`prove_runs = ${config.proveRuns}`);

    const handles = [];
    const overallStart = performance.now();
    try {
      setStatus(`Loading ${label} runtime`);
      await proofModule.loadRuntime({ kind: runtimeKind });

      setStatus(`Loading ${label} fixture`);
      const fixtureStart = performance.now();
      const fixture = await loadFixture(curve, config);
      handles.push(fixture.ccs, fixture.pk, fixture.vk);
      const fixtureDuration = performance.now() - fixtureStart;
      appendLog(`fixture_load_ms = ${formatMs(fixtureDuration)}`);
      appendLog(`constraints = ${fixture.ccs.constraints}`);

      setStatus(`Building ${label} witness`);
      const witnessStart = performance.now();
      const { depth, fullWitness, publicWitness } = buildWitnesses(curve, config);
      const witnessDuration = performance.now() - witnessStart;
      const extraMetrics = system.extraWitnessMetrics(config);
      for (const [key, value] of Object.entries(extraMetrics)) {
        appendLog(`${key} = ${value}`);
      }
      appendLog(`${system.depthLabel} = ${depth}`);
      appendLog(`witness_build_ms = ${formatMs(witnessDuration)}`);

      setStatus(`Preparing ${label} proving key`);
      const prepareStart = performance.now();
      await proofModule.prepareProvingKey(fixture.pk, system.prepareWithConstraintSystem ? fixture.ccs : undefined);
      const prepareDuration = performance.now() - prepareStart;
      if (runtimeKind === "webgpu") {
        appendLog(`prepare_ms = ${formatMs(prepareDuration)}`);
      }
      const startupDuration = fixtureDuration + witnessDuration + (runtimeKind === "webgpu" ? prepareDuration : 0);
      appendLog(`startup_ms = ${formatMs(startupDuration)}`);

      let proveDuration = 0;
      let verifyDuration = 0;
      let proofSizeBytes = 0;
      const steadyStateStart = performance.now();
      for (let i = 0; i < config.proveRuns; i++) {
        setStatus(`Proving ${label} round ${i + 1}/${config.proveRuns}`);
        const proveStart = performance.now();
        const proofBytes = await proofModule.prove(fixture.ccs, fixture.pk, fullWitness);
        const roundProveDuration = performance.now() - proveStart;
        proveDuration += roundProveDuration;
        appendLog(`prove_round_${i}_ms = ${formatMs(roundProveDuration)}`);

        const verifyStart = performance.now();
        const verified = await proofModule.verify(proofBytes, fixture.vk, publicWitness);
        verifyDuration += performance.now() - verifyStart;
        if (!verified) {
          throw new Error(`verify round ${i}: proof rejected`);
        }
        if (proofSizeBytes === 0) {
          proofSizeBytes = proofBytes.byteLength;
          appendLog(`proof_size_bytes = ${proofSizeBytes}`);
        }
        appendLog(`roundtrip_verify_round_${i} = OK`);
      }
      const steadyStateDuration = performance.now() - steadyStateStart;
      const overallDuration = performance.now() - overallStart;

      appendLog(`prove_total_ms = ${formatMs(proveDuration)}`);
      appendLog(`prove_avg_ms = ${formatMs(proveDuration / config.proveRuns)}`);
      appendLog(`verify_total_ms = ${formatMs(verifyDuration)}`);
      appendLog(`verify_avg_ms = ${formatMs(verifyDuration / config.proveRuns)}`);
      appendLog(`steady_state_total_ms = ${formatMs(steadyStateDuration)}`);
      appendLog(`overall_total_ms = ${formatMs(overallDuration)}`);

      return {
        impl: label,
        curve: config.curve,
        prove_runs: config.proveRuns,
        constraints: fixture.ccs.constraints,
        size_log: config.sizeLog,
        commitments: config.commitments,
        depth,
        ...extraMetrics,
        fixture_duration_ms: fixtureDuration,
        witness_duration_ms: witnessDuration,
        prepare_duration_ms: runtimeKind === "webgpu" ? prepareDuration : 0,
        startup_duration_ms: startupDuration,
        prove_duration_ms: proveDuration,
        verify_duration_ms: verifyDuration,
        steady_state_duration_ms: steadyStateDuration,
        overall_duration_ms: overallDuration,
        proof_size_bytes: proofSizeBytes,
        roundtrip_verify_succeeded: true,
      };
    } finally {
      await Promise.allSettled(handles.map((handle) => handle.dispose()));
    }
  }

  function compareResults(webgpu, nativeImpl) {
    appendLog("");
    appendLog("--- comparison ---");
    appendLog(`curve: ${webgpu.curve}`);
    appendLog(`fixture: 2^${webgpu.size_log}`);
    appendLog(`commitments: ${webgpu.commitments}`);
    for (const key of Object.keys(system.extraWitnessMetrics({ sizeLog: webgpu.size_log }))) {
      appendLog(`${key.replaceAll("_", " ")}: ${webgpu[key]}`);
    }
    appendLog(`${system.depthLabel.replaceAll("_", " ")}: ${webgpu.depth}`);
    appendLog(`prove runs: ${webgpu.prove_runs}`);
    appendLog(`constraints: ${webgpu.constraints}`);
    appendLog(`roundtrip verify: webgpu=${webgpu.roundtrip_verify_succeeded} native=${nativeImpl.roundtrip_verify_succeeded}`);
    appendLog(`proof size bytes: webgpu=${webgpu.proof_size_bytes} native=${nativeImpl.proof_size_bytes}`);
    appendLog(`startup ms: webgpu=${formatMs(webgpu.startup_duration_ms)} native=${formatMs(nativeImpl.startup_duration_ms)}`);
    appendLog(
      `startup breakdown: webgpu fixture=${formatMs(webgpu.fixture_duration_ms)} witness=${formatMs(webgpu.witness_duration_ms)} prepare=${formatMs(webgpu.prepare_duration_ms)} | native fixture=${formatMs(nativeImpl.fixture_duration_ms)} witness=${formatMs(nativeImpl.witness_duration_ms)}`,
    );
    appendLog(`steady-state total ms: webgpu=${formatMs(webgpu.steady_state_duration_ms)} native=${formatMs(nativeImpl.steady_state_duration_ms)}`);
    appendLog(`overall total ms: webgpu=${formatMs(webgpu.overall_duration_ms)} native=${formatMs(nativeImpl.overall_duration_ms)}`);
    appendLog(`prove avg ms: webgpu=${formatMs(webgpu.prove_duration_ms / webgpu.prove_runs)} native=${formatMs(nativeImpl.prove_duration_ms / nativeImpl.prove_runs)}`);
    appendLog(`verify avg ms: webgpu=${formatMs(webgpu.verify_duration_ms / webgpu.prove_runs)} native=${formatMs(nativeImpl.verify_duration_ms / nativeImpl.prove_runs)}`);
  }

  async function runSelected() {
    logEl.textContent = "";
    runButton.disabled = true;
    const impl = implSelect.value;
    const config = readConfig();

    appendLog(`=== ${system.name} ===`);
    appendLog(`impl = ${impl}`);
    appendLog(`curve = ${config.curve}`);
    appendLog(`fixture = 2^${config.sizeLog}`);
    appendLog(`commitments = ${config.commitments}`);
    appendLog(`prove_runs = ${config.proveRuns}`);
    appendLog("");

    setStatus("Initializing curve module");
    try {
      if (!SUPPORTED_CURVES.includes(config.curve)) {
        throw new Error(`unsupported curve ${config.curve}`);
      }
      const curve = await createCurveModule(await createCurveGPUContext(), config.curve);
      let webgpuResult = null;
      let nativeResult = null;
      if (impl === "webgpu-go" || impl === "both") {
        webgpuResult = await runImpl("webgpu-go", "webgpu", curve, config);
      }
      if (impl === "native-go" || impl === "both") {
        nativeResult = await runImpl("native-go", "native", curve, config);
      }
      if (webgpuResult && nativeResult) {
        compareResults(webgpuResult, nativeResult);
      }
      setStatus("PASS");
    } catch (error) {
      setStatus("FAIL");
      appendLog("");
      appendLog(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    } finally {
      runButton.disabled = false;
    }
  }

  runButton.addEventListener("click", () => {
    void runSelected();
  });
  applyQueryDefaults();
  if (new URLSearchParams(window.location.search).get("autorun") === "1") {
    void runSelected();
  }
}
