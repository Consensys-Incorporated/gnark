#!/usr/bin/env node
// Runs the browser test pages headlessly with Playwright and WebGPU.
//
//   node scripts/e2e.mjs                 # API smoke suites + one small proof per system/curve
//   node scripts/e2e.mjs --bench         # full prover benchmark matrix (needs the 2^15/2^18 fixtures)
//   node scripts/e2e.mjs --out out.json  # write results as JSON
//
// Env: PW_CHANNEL=chrome uses the system Chrome instead of Playwright's Chromium;
// E2E_CURVES=bn254,bls12_381 restricts the curves; E2E_SYSTEMS=api,groth16,plonk
// restricts what runs; E2E_PROVE_RUNS sets the number of proofs per
// configuration (default 1, 3 in --bench mode).
// Requires `npm run build` (and `build:wasm`) and the fixtures from
// `npm run build:test-fixtures:*`.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const bench = args.includes("--bench");
const outFile = args.includes("--out") ? args[args.indexOf("--out") + 1] : null;
const curves = (process.env.E2E_CURVES ?? "bn254,bls12_377,bls12_381").split(",");
const proveRuns = Number(process.env.E2E_PROVE_RUNS ?? (bench ? 3 : 1));
const systems = (process.env.E2E_SYSTEMS ?? "api,groth16,plonk").split(",");

const MIME = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm", ".json": "application/json", ".map": "application/json", ".wgsl": "text/plain" };
const server = http.createServer((req, res) => {
  let p = path.join(root, decodeURIComponent(new URL(req.url, "http://x").pathname));
  try {
    if (fs.statSync(p).isDirectory()) p = path.join(p, "index.html");
  } catch {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, { "content-type": MIME[path.extname(p)] ?? "application/octet-stream" });
  fs.createReadStream(p).on("error", () => res.destroy()).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch({
  headless: true,
  channel: process.env.PW_CHANNEL || undefined,
  args: ["--enable-unsafe-webgpu", "--enable-features=WebGPU", "--ignore-gpu-blocklist", "--use-angle=metal", "--enable-dawn-features=allow_unsafe_apis"],
});

const jobs = [];
if (systems.includes("api")) for (const curve of curves) jobs.push({ kind: "api", curve, url: `/tests/api/index.html?curve=${curve}&suite=all&autorun=1`, done: () => ["Pass", "Fail"] });
const matrix = bench
  ? { sizes: [15, 18], commitments: [0, 1], curves: curves.filter((c) => c !== "bls12_377") }
  : { sizes: [15], commitments: [1], curves };
for (const system of ["groth16", "plonk"].filter((s) => systems.includes(s)))
  for (const curve of matrix.curves)
    for (const sizeLog of matrix.sizes)
      for (const commitments of matrix.commitments)
        jobs.push({ kind: system, curve, sizeLog, commitments, url: `/tests/${system}/index.html?impl=both&curve=${curve}&size-log=${sizeLog}&commitments=${commitments}&prove-runs=${proveRuns}&autorun=1` });

const results = [];
let failed = 0;
for (const job of jobs) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const label = `${job.kind} ${job.curve}${job.sizeLog ? ` 2^${job.sizeLog} c${job.commitments}` : ""}`;
  process.stderr.write(`>> ${label} ... `);
  const t0 = Date.now();
  let status = "TIMEOUT";
  try {
    await page.goto(base + job.url);
    // eslint-disable-next-line no-undef -- evaluated in the page
    await page.waitForFunction(() => /^(PASS|FAIL|Pass|Fail)$/.test(document.getElementById("status")?.textContent ?? ""), null, { timeout: 30 * 60 * 1000 });
    status = (await page.textContent("#status")).toUpperCase();
  } catch (e) {
    errors.push(String(e));
  }
  const log = (await page.textContent("#log").catch(() => "")) ?? "";
  const metrics = {};
  let impl = null;
  for (const line of log.split("\n")) {
    const m = line.match(/^--- (webgpu-go|native-go) ---$/);
    if (m) { impl = m[1]; continue; }
    const kv = line.match(/^([a-z_0-9]+) = ([-0-9.]+)$/);
    if (kv && impl) metrics[`${impl}.${kv[1]}`] = Number(kv[2]);
  }
  if (status !== "PASS") failed += 1;
  results.push({ ...job, url: undefined, done: undefined, status, wallMs: Date.now() - t0, metrics, errors, log: status === "PASS" ? undefined : log });
  const gpu = metrics["webgpu-go.prove_avg_ms"], cpu = metrics["native-go.prove_avg_ms"];
  process.stderr.write(`${status} (${((Date.now() - t0) / 1000).toFixed(0)}s)${gpu ? ` gpu ${gpu.toFixed(0)} ms, cpu ${cpu.toFixed(0)} ms` : ""}\n`);
  if (status !== "PASS") process.stderr.write(log.split("\n").filter((l) => /FAIL|Error|error/.test(l)).slice(0, 10).join("\n") + "\n");
  if (outFile) fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
  await ctx.close();
}
await browser.close();
server.close();
process.exit(failed === 0 ? 0 : 1);
