import type {
  CurveGPUContext,
  FieldModule,
  G1MSMModule,
  G2MSMModule,
  Groth16Module,
  Groth16ProvingKeyFormat,
  Groth16QuotientModule,
  NTTModule,
  PlonkModule,
  PlonkProvingKeyFormat,
  ProofConstraintSystem,
  ProofHandle,
  ProofModule,
  ProofRuntimeKind,
  ProofRuntimeOptions,
  SupportedCurveID,
} from "./api.js";
import type { PlonkQuotientModule } from "./plonk_quotient_module.js";
import { installGroth16WebGPUBridge, installPlonkWebGPUBridge } from "./bridge.js";
import { cloneBytes } from "./gpu.js";

// --- Go WASM runtime loading ------------------------------------------------

type GoInstance = {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
};

type GoConstructor = new () => GoInstance;

/** Functions the Go runtime installs on `globalThis` once it has started. */
type RuntimeGlobal = {
  readConstraintSystem(curve: SupportedCurveID, bytes: Uint8Array): Promise<{ handle: string; constraints: number }>;
  readProvingKey(curve: SupportedCurveID, bytes: Uint8Array, format: string): Promise<{ handle: string }>;
  readVerificationKey(curve: SupportedCurveID, bytes: Uint8Array): Promise<{ handle: string }>;
  prepareProvingKey(handle: string, ccsHandle?: string): Promise<void>;
  prove(ccsHandle: string, pkHandle: string, witness: Uint8Array): Promise<Uint8Array>;
  verify(proof: Uint8Array, vkHandle: string, publicWitness: Uint8Array): Promise<boolean>;
  release(handle: string): Promise<void>;
};

type ProofSystem = {
  /** Human-readable name used in error messages. */
  name: string;
  /** `globalThis` property the Go runtime of each kind installs itself on. */
  runtimeGlobals: Record<ProofRuntimeKind, string>;
  defaultURLs: Required<ProofRuntimeOptions>;
};

const loadedScripts = new Map<string, Promise<void>>();
const loadedRuntimes = new Map<string, Promise<RuntimeGlobal>>();

function getGlobalObject<T>(name: string): T | undefined {
  return (globalThis as typeof globalThis & Record<string, T | undefined>)[name];
}

function setGlobalObject<T>(name: string, value: T | undefined): void {
  (globalThis as typeof globalThis & Record<string, T | undefined>)[name] = value;
}

async function loadScript(system: ProofSystem, url: string): Promise<void> {
  if (typeof document === "undefined") {
    throw new Error(`${system.name} WASM runtime loading requires a browser document`);
  }
  let promise = loadedScripts.get(url);
  if (!promise) {
    promise = new Promise<void>((resolve, reject) => {
      const script = document.createElement("script");
      script.src = url;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`failed to load ${url}`));
      document.head.appendChild(script);
    });
    loadedScripts.set(url, promise);
  }
  await promise;
}

async function waitForRuntimeGlobal(system: ProofSystem, name: string): Promise<RuntimeGlobal> {
  const deadline = performance.now() + 10_000;
  while (performance.now() < deadline) {
    const runtime = getGlobalObject<RuntimeGlobal>(name);
    if (runtime) {
      return runtime;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`${system.name} WASM runtime ${name} did not initialize`);
}

/**
 * Instantiate (once per URL set) the Go WASM runtime of `kind` and wait for it
 * to publish its API on `globalThis`. `beforeStart` runs on every call so the
 * WebGPU bridge is (re)installed before Go looks it up.
 */
async function loadGoRuntime(
  system: ProofSystem,
  kind: ProofRuntimeKind,
  options: Required<ProofRuntimeOptions>,
  beforeStart: () => void,
): Promise<RuntimeGlobal> {
  const wasmURL = kind === "native" ? options.nativeWasmURL : options.webgpuWasmURL;
  const cacheKey = `${system.name}\n${kind}\n${options.wasmExecURL}\n${wasmURL}`;
  beforeStart();
  let promise = loadedRuntimes.get(cacheKey);
  if (!promise) {
    promise = (async () => {
      if (typeof getGlobalObject<GoConstructor>("Go") !== "function") {
        await loadScript(system, options.wasmExecURL);
      }
      const Go = getGlobalObject<GoConstructor>("Go");
      if (typeof Go !== "function") {
        throw new Error("Go WASM runtime is not available after loading wasm_exec.js");
      }
      const response = await fetch(wasmURL);
      if (!response.ok) {
        throw new Error(`failed to fetch ${wasmURL}: ${response.status}`);
      }
      const bytes = await response.arrayBuffer();
      const go = new Go();
      const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
      setGlobalObject<RuntimeGlobal>(system.runtimeGlobals[kind], undefined);
      void go.run(instance).catch((error: unknown) => {
        console.error(`${system.name} ${kind} WASM runtime exited`, error);
      });
      return waitForRuntimeGlobal(system, system.runtimeGlobals[kind]);
    })();
    loadedRuntimes.set(cacheKey, promise);
  }
  return promise;
}

// --- handles ---------------------------------------------------------------

type HandleType = "ccs" | "pk" | "vk";

class RuntimeHandle implements ProofHandle {
  #disposed = false;

  constructor(
    readonly system: ProofSystem,
    readonly runtime: RuntimeGlobal,
    readonly kind: ProofRuntimeKind,
    readonly curve: SupportedCurveID,
    readonly type: HandleType,
    readonly handle: string,
  ) {}

  async dispose(): Promise<void> {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    await this.runtime.release(this.handle);
  }

  assertUsable(system: ProofSystem, expectedType: HandleType): void {
    if (this.system !== system) {
      throw new Error(`${system.name} received a ${this.system.name} handle`);
    }
    if (this.#disposed) {
      throw new Error(`${system.name} ${this.type} handle has been disposed`);
    }
    if (this.type !== expectedType) {
      throw new Error(`expected ${system.name} ${expectedType} handle, got ${this.type}`);
    }
  }
}

class ConstraintSystemHandle extends RuntimeHandle implements ProofConstraintSystem {
  constructor(system: ProofSystem, runtime: RuntimeGlobal, kind: ProofRuntimeKind, curve: SupportedCurveID, handle: string, readonly constraints: number) {
    super(system, runtime, kind, curve, "ccs", handle);
  }
}

function writeUint32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function writeBigIntBE(out: Uint8Array, offset: number, byteSize: number, value: bigint): void {
  let remaining = value;
  for (let i = byteSize - 1; i >= 0; i--) {
    out[offset + i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

// --- generic proof module --------------------------------------------------

function createProofModule<F extends string>(
  system: ProofSystem,
  config: {
    context: CurveGPUContext;
    curve: SupportedCurveID;
    modulusHex: string;
    frBytes: number;
    installBridge: () => void;
  },
): ProofModule<F> {
  const { context, curve, frBytes, installBridge } = config;
  const modulus = BigInt(config.modulusHex);
  let currentRuntime: Promise<RuntimeGlobal> | null = null;
  let currentKind: ProofRuntimeKind = "webgpu";

  function runtimeHandle(handle: ProofHandle, type: HandleType): RuntimeHandle {
    if (!(handle instanceof RuntimeHandle)) {
      throw new Error(`${system.name} handle was not created by this module`);
    }
    handle.assertUsable(system, type);
    return handle;
  }

  function assertSameRuntime(a: RuntimeHandle, b: RuntimeHandle): void {
    if (a.runtime !== b.runtime || a.kind !== b.kind) {
      throw new Error(`${system.name} handles belong to different runtimes`);
    }
    if (a.curve !== b.curve) {
      throw new Error(`${system.name} handles belong to different curves: ${a.curve} and ${b.curve}`);
    }
  }

  async function loadRuntime(options?: ProofRuntimeOptions & { kind?: ProofRuntimeKind }): Promise<void> {
    currentKind = options?.kind ?? "webgpu";
    const urls: Required<ProofRuntimeOptions> = {
      wasmExecURL: options?.wasmExecURL ?? system.defaultURLs.wasmExecURL,
      webgpuWasmURL: options?.webgpuWasmURL ?? system.defaultURLs.webgpuWasmURL,
      nativeWasmURL: options?.nativeWasmURL ?? system.defaultURLs.nativeWasmURL,
    };
    currentRuntime = loadGoRuntime(system, currentKind, urls, currentKind === "webgpu" ? installBridge : () => {});
    await currentRuntime;
  }

  async function getRuntime(): Promise<{ runtime: RuntimeGlobal; kind: ProofRuntimeKind }> {
    if (!currentRuntime) {
      await loadRuntime();
    }
    return { runtime: await currentRuntime!, kind: currentKind };
  }

  return {
    context,
    curve,
    loadRuntime,
    async readConstraintSystem(bytes) {
      const { runtime, kind } = await getRuntime();
      const result = await runtime.readConstraintSystem(curve, cloneBytes(bytes));
      return new ConstraintSystemHandle(system, runtime, kind, curve, result.handle, result.constraints);
    },
    async readProvingKey(bytes, options) {
      const { runtime, kind } = await getRuntime();
      const result = await runtime.readProvingKey(curve, cloneBytes(bytes), options?.format ?? "serialized");
      return new RuntimeHandle(system, runtime, kind, curve, "pk", result.handle);
    },
    async readVerificationKey(bytes) {
      const { runtime, kind } = await getRuntime();
      const result = await runtime.readVerificationKey(curve, cloneBytes(bytes));
      return new RuntimeHandle(system, runtime, kind, curve, "vk", result.handle);
    },
    async prepareProvingKey(pk, ccs) {
      const pkHandle = runtimeHandle(pk, "pk");
      if (ccs) {
        const ccsHandle = runtimeHandle(ccs, "ccs");
        assertSameRuntime(ccsHandle, pkHandle);
        await pkHandle.runtime.prepareProvingKey(pkHandle.handle, ccsHandle.handle);
        return;
      }
      await pkHandle.runtime.prepareProvingKey(pkHandle.handle);
    },
    async prove(ccs, pk, witness) {
      const ccsHandle = runtimeHandle(ccs, "ccs");
      const pkHandle = runtimeHandle(pk, "pk");
      assertSameRuntime(ccsHandle, pkHandle);
      return ccsHandle.runtime.prove(ccsHandle.handle, pkHandle.handle, cloneBytes(witness));
    },
    async verify(proof, vk, publicWitness) {
      const vkHandle = runtimeHandle(vk, "vk");
      return vkHandle.runtime.verify(cloneBytes(proof), vkHandle.handle, cloneBytes(publicWitness));
    },
    encodeWitness(values, options) {
      if (!Number.isInteger(options.publicCount) || options.publicCount < 0 || options.publicCount > values.length) {
        throw new Error(`invalid publicCount ${options.publicCount}`);
      }
      const out = new Uint8Array(12 + values.length * frBytes);
      writeUint32BE(out, 0, options.publicCount);
      writeUint32BE(out, 4, values.length - options.publicCount);
      writeUint32BE(out, 8, values.length);
      for (let i = 0; i < values.length; i++) {
        const value = values[i];
        if (value < 0n || value >= modulus) {
          throw new Error(`witness value at index ${i} is outside the scalar field`);
        }
        writeBigIntBE(out, 12 + i * frBytes, frBytes, value);
      }
      return out;
    },
  };
}

// --- Groth16 ---------------------------------------------------------------

export const defaultGroth16RuntimeURLs = Object.freeze({
  wasmExecURL: new URL("../../assets/wasm_exec.js", import.meta.url).toString(),
  webgpuWasmURL: new URL("../../assets/groth16-webgpu.wasm", import.meta.url).toString(),
  nativeWasmURL: new URL("../../assets/groth16-native.wasm", import.meta.url).toString(),
});

const GROTH16: ProofSystem = {
  name: "Groth16",
  runtimeGlobals: { webgpu: "gnarkGroth16RuntimeWebGPU", native: "gnarkGroth16RuntimeNative" },
  defaultURLs: defaultGroth16RuntimeURLs,
};

export function createGroth16Module(config: {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  modulusHex: string;
  frBytes: number;
  fr: FieldModule;
  quotient: Groth16QuotientModule;
  g1msm: G1MSMModule;
  g2msm: G2MSMModule;
}): Groth16Module {
  const { context, curve, fr, quotient, g1msm, g2msm } = config;
  return {
    ...createProofModule<Groth16ProvingKeyFormat>(GROTH16, {
      ...config,
      installBridge: () => installGroth16WebGPUBridge({ context, curve, fr, g1msm, g2msm, quotient }),
    }),
    computeGroth16QuotientPackedRegular: (a, b, c) => quotient.computeGroth16QuotientPackedRegular(a, b, c),
    computeGroth16QuotientPackedMont: (a, b, c) => quotient.computeGroth16QuotientPackedMont(a, b, c),
    computeGroth16QuotientMont: (a, b, c) => quotient.computeGroth16QuotientMont(a, b, c),
    prewarmGroth16QuotientDomain: (size) => quotient.prewarmGroth16QuotientDomain(size),
  };
}

// --- PLONK -----------------------------------------------------------------

export const defaultPlonkRuntimeURLs = Object.freeze({
  wasmExecURL: new URL("../../assets/wasm_exec.js", import.meta.url).toString(),
  webgpuWasmURL: new URL("../../assets/plonk-webgpu.wasm", import.meta.url).toString(),
  nativeWasmURL: new URL("../../assets/plonk-native.wasm", import.meta.url).toString(),
});

const PLONK: ProofSystem = {
  name: "PLONK",
  runtimeGlobals: { webgpu: "gnarkPlonkRuntimeWebGPU", native: "gnarkPlonkRuntimeNative" },
  defaultURLs: defaultPlonkRuntimeURLs,
};

export function createPlonkModule(config: {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  modulusHex: string;
  frBytes: number;
  fr: FieldModule;
  ntt: NTTModule;
  quotient: PlonkQuotientModule;
  g1msm: G1MSMModule;
}): PlonkModule {
  const { context, curve, fr, ntt, quotient, g1msm } = config;
  return createProofModule<PlonkProvingKeyFormat>(PLONK, {
    ...config,
    installBridge: () => installPlonkWebGPUBridge({ context, curve, fr, ntt, quotient, g1msm }),
  });
}
