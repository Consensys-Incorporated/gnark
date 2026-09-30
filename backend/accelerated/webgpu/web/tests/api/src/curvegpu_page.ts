export { };

import "../../../src/curvegpu/shader_bundle.generated.js";
import type { CurveModule, SupportedCurveID } from "../../../src/index.js";
import { createCurveGPUContext, createCurveModule } from "../../../src/index.js";
import { appendContextDiagnostics } from "./shared/page_library.js";

type SuiteKind = "smoke" | "bench";

type SuiteConfig = {
  curve: SupportedCurveID;
  id: string;
  label: string;
  kind: SuiteKind;
  script: string;
  defaultMinLog?: number;
  defaultMaxLog?: number;
  defaultIters?: number;
};

const BENCH_MIN_LOG = 10;
const BENCH_MAX_LOG = 12;

const CURVES: SupportedCurveID[] = ["bn254", "bls12_377", "bls12_381"];

const SMOKE_SUITES = [
  { id: "fr_ops", label: "fr ops", kind: "smoke", script: "/dist/tests/api/src/field_ops_page.js" },
  { id: "fr_vector_ops", label: "fr vector ops", kind: "smoke", script: "/dist/tests/api/src/fr_vector_ops_page.js" },
  { id: "fr_ntt", label: "fr NTT", kind: "smoke", script: "/dist/tests/api/src/fr_ntt_page.js" },
  { id: "fp_ops", label: "fp ops", kind: "smoke", script: "/dist/tests/api/src/field_ops_page.js" },
  { id: "g1_ops", label: "G1 ops", kind: "smoke", script: "/dist/tests/api/src/g1_ops_page.js" },
  { id: "g1_scalar_mul", label: "G1 scalar mul", kind: "smoke", script: "/dist/tests/api/src/g1_scalar_mul_page.js" },
  { id: "g1_msm", label: "G1 MSM", kind: "smoke", script: "/dist/tests/api/src/g1_msm_page.js" },
  { id: "g2_ops", label: "G2 ops", kind: "smoke", script: "/dist/tests/api/src/g2_ops_page.js" },
  { id: "g2_msm", label: "G2 MSM", kind: "smoke", script: "/dist/tests/api/src/g2_msm_page.js" },
] as const;

const BENCH_SUITES = [
  { id: "fr_vector_bench", label: "fr vector bench", kind: "bench", script: "/dist/tests/api/src/fr_vector_bench_page.js", defaultIters: 3 },
  { id: "fr_ntt_bench", label: "fr NTT bench", kind: "bench", script: "/dist/tests/api/src/fr_ntt_bench_page.js", defaultIters: 1 },
  { id: "g1_msm_bench", label: "G1 MSM bench", kind: "bench", script: "/dist/tests/api/src/g1_msm_bench_page.js", defaultIters: 1 },
  { id: "g2_msm_bench", label: "G2 MSM bench", kind: "bench", script: "/dist/tests/api/src/g2_msm_bench_page.js", defaultIters: 1 },
] as const;

const SUITES: SuiteConfig[] = CURVES.flatMap((curve) => [
  ...SMOKE_SUITES.map((suite) => ({ curve, ...suite })),
  ...BENCH_SUITES.map((suite) => ({
    curve,
    ...suite,
    defaultMinLog: BENCH_MIN_LOG,
    defaultMaxLog: BENCH_MAX_LOG,
  })),
]);

type SuiteRunner = {
  /** `suiteId` lets one page serve several suites (e.g. `fr_ops` / `fp_ops`). */
  runSuite: (module: CurveModule, log: (msg: string) => void, suiteId: string) => Promise<{ passed: number; failed: number }>;
};

function getById<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLElement)) {
    throw new Error(`missing element: ${id}`);
  }
  return el as T;
}

function makeLogger(logEl: HTMLPreElement): (msg: string) => void {
  const lines: string[] = [];
  return (msg: string) => {
    lines.push(msg);
    logEl.textContent = lines.join("\n");
  };
}

async function buildModule(curve: SupportedCurveID, log: (msg: string) => void): Promise<CurveModule> {
  const context = await createCurveGPUContext();
  const diagLines: string[] = [];
  appendContextDiagnostics(diagLines, context);
  for (const line of diagLines) {
    log(line);
  }
  return createCurveModule(context, curve);
}

async function runAllSmoke(
  module: CurveModule,
  suites: SuiteConfig[],
  log: (msg: string) => void,
): Promise<{ passed: number; failed: number }> {
  let passed = 0;
  let failed = 0;
  for (const suite of suites) {
    try {
      const mod = await import(suite.script) as SuiteRunner;
      const result = await mod.runSuite(module, log, suite.id);
      passed += result.passed;
      failed += result.failed;
    } catch (error) {
      log(`FAIL [${suite.id}]: ${error instanceof Error ? error.message : String(error)}`);
      failed += 1;
    }
  }
  return { passed, failed };
}

function populateSelectors(
  curveSelect: HTMLSelectElement,
  suiteSelect: HTMLSelectElement,
  curve: string,
  suiteId: string,
): void {
  const curves = [...new Set(SUITES.map((s) => s.curve))];
  curveSelect.replaceChildren();
  for (const c of curves) {
    const opt = document.createElement("option");
    opt.value = c;
    opt.textContent = c;
    if (c === curve) {
      opt.selected = true;
    }
    curveSelect.appendChild(opt);
  }

  function updateSuiteOptions(selectedCurve: string): void {
    suiteSelect.replaceChildren();
    const addOpt = (value: string, text: string, selected: boolean): void => {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = text;
      if (selected) {
        opt.selected = true;
      }
      suiteSelect.appendChild(opt);
    };
    addOpt("all", "all smoke", suiteId === "all");
    for (const s of SUITES.filter((entry) => entry.curve === selectedCurve)) {
      addOpt(s.id, s.label, s.id === suiteId);
    }
  }

  updateSuiteOptions(curve);
  curveSelect.addEventListener("change", () => {
    updateSuiteOptions(curveSelect.value);
  });
}

async function main(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  const curve = (params.get("curve") ?? "bn254") as SupportedCurveID;
  const suiteId = params.get("suite") ?? "fr_ops";

  const logEl = getById<HTMLPreElement>("log");
  const statusEl = getById<HTMLSpanElement>("status");
  const runButton = getById<HTMLButtonElement>("run");
  const curveSelect = getById<HTMLSelectElement>("curve-select");
  const suiteSelect = getById<HTMLSelectElement>("suite-select");
  const openButton = getById<HTMLButtonElement>("open-suite");
  const benchControls = getById<HTMLElement>("bench-controls");

  populateSelectors(curveSelect, suiteSelect, curve, suiteId);

  openButton.addEventListener("click", () => {
    const newParams = new URLSearchParams(window.location.search);
    newParams.set("curve", curveSelect.value);
    newParams.set("suite", suiteSelect.value);
    window.location.search = newParams.toString();
  });

  function setStatus(s: string): void {
    statusEl.textContent = s;
  }
  function setPageState(s: "idle" | "running" | "pass" | "fail"): void {
    document.body.setAttribute("data-status", s);
  }

  if (suiteId === "all") {
    const smokeSuites = SUITES.filter((s) => s.curve === curve && s.kind === "smoke");

    const runAll = async (): Promise<void> => {
      runButton.disabled = true;
      setStatus("Running");
      setPageState("running");
      const log = makeLogger(logEl);
      try {
        const module = await buildModule(curve, log);
        const result = await runAllSmoke(module, smokeSuites, log);
        log("");
        log(`Total: ${result.passed} passed, ${result.failed} failed`);
        setStatus(result.failed === 0 ? "Pass" : "Fail");
        setPageState(result.failed === 0 ? "pass" : "fail");
      } catch (error) {
        log(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
        setStatus("Fail");
        setPageState("fail");
      } finally {
        runButton.disabled = false;
      }
    };

    runButton.addEventListener("click", () => void runAll());
    if (params.get("autorun") === "1") {
      void runAll();
    } else {
      logEl.textContent = `Press Run to execute all ${curve} smoke suites.`;
    }
    return;
  }

  const selected = SUITES.find((s) => s.curve === curve && s.id === suiteId);
  if (!selected) {
    logEl.textContent = `Unknown suite: ${curve}:${suiteId}`;
    return;
  }

  if (selected.kind === "bench") {
    benchControls.hidden = false;
    if (selected.defaultMinLog !== undefined) {
      getById<HTMLInputElement>("min-log").value = `${selected.defaultMinLog}`;
    }
    if (selected.defaultMaxLog !== undefined) {
      getById<HTMLInputElement>("max-log").value = `${selected.defaultMaxLog}`;
    }
    if (selected.defaultIters !== undefined) {
      getById<HTMLInputElement>("iters").value = `${selected.defaultIters}`;
    }
    // Bench page registers its own Run button listener on import
    await import(`${selected.script}`);
    return;
  }

  // Smoke suite: orchestrator owns the Run button
  const run = async (): Promise<void> => {
    runButton.disabled = true;
    setStatus("Running");
    setPageState("running");
    const log = makeLogger(logEl);
    try {
      const module = await buildModule(curve, log);
      const mod = await import(selected.script) as SuiteRunner;
      await mod.runSuite(module, log, selected.id);
      setStatus("Pass");
      setPageState("pass");
    } catch (error) {
      log(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
      setStatus("Fail");
      setPageState("fail");
    } finally {
      runButton.disabled = false;
    }
  };

  runButton.addEventListener("click", () => void run());
  if (params.get("autorun") === "1") {
    void run();
  } else {
    logEl.textContent = `Press Run to execute the ${curve} ${selected.id} suite.`;
  }
}

void main();
