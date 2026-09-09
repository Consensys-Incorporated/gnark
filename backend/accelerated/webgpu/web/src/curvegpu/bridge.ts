/**
 * WebGPU bridge exposed to the Go WASM provers.
 *
 * The Groth16 and PLONK Go runtimes call back into the browser through two
 * objects installed on `globalThis`: `gnarkGroth16WebGPU` and
 * `gnarkPlonkWebGPU`. Every function is async and returns a Promise. Several
 * curves and several prepared keys may be live at the same time; the curve is
 * either passed explicitly or encoded in the key handle.
 *
 * Byte formats: field elements are little-endian; coordinates are in
 * Montgomery form of the base field size (32 bytes bn254, 48 bytes bls12);
 * MSM scalars are regular (non-Montgomery) 32-byte little-endian.
 *
 * Common to both bridges:
 *
 * - `init(curve)` → `{ curve, adapter: { vendor, architecture, description } }`.
 * - `prepareKey(curve, { g1: Record<name, Uint8Array>, g2: Record<name, Uint8Array> })`
 *   → `{ handle }`. Each value is a packed AFFINE point vector: per point
 *   `X, Y` for G1 and `X.c0, X.c1, Y.c0, Y.c1` for G2, infinity all-zero. The
 *   point count is `byteLength / pointBytes`. Bases are expanded to the shader
 *   layout and uploaded to the GPU once.
 *   Groth16 G1 names: `A`, `B`, `K`, `Z`, `commitmentBasis<i>`,
 *   `commitmentBasisExpSigma<i>`; G2 name: `B`. PLONK G1 names: `kzg`,
 *   `kzgLagrange`; no G2.
 * - `releaseKey(handle)` destroys the GPU buffers of a prepared key.
 * - `msmG1(handle, name, start, scalars)` → `Uint8Array` of the affine result
 *   `X, Y` (2 × coordinate bytes), all-zero for infinity. Uses
 *   `bases[start : start + scalars.length / 32]`.
 * - `msmG2(handle, name, start, scalars)` → `X.c0, X.c1, Y.c0, Y.c1`
 *   (4 × coordinate bytes).
 *
 * Groth16 only:
 *
 * - `computeH(curve, a, b, c, n)`: `a`, `b`, `c` are Montgomery 32-byte
 *   elements, possibly shorter than `n` (zero-padded to `n`, the FFT domain
 *   cardinality). Returns `h` as `n` Montgomery little-endian elements in
 *   bit-reversed order (the order in which gnark stores `pk.G1.Z`); Go copies
 *   them straight into `[]fr.Element`.
 * - `prewarmQuotientDomain(curve, n)`.
 *
 * PLONK only (all vectors are Montgomery little-endian):
 *
 * - `canonicalizeVectors(curve, values, vectorCount, elementCount, inputBitReversed, inverseCoset)`:
 *   Lagrange (or Lagrange-coset) to canonical basis, Regular layout.
 * - `preloadQuotientStatics(curve, key, statics, scaling, twiddles, denominators, elementCount, staticVectorCount, cosetCount)`:
 *   uploads the canonical circuit polynomials and the per-coset tables once; `releaseQuotientStatics(curve, key)` frees them.
 * - `evaluateQuotient(curve, key, dynamic, blinds, scalars, elementCount, blindCoeffCount, commitmentCount, cosetCount)`
 *   -> `{ numerator, canonical }`: the numerator on all cosets in the bit-reversed layout of the large
 *   domain, and the canonical form of the dynamic vectors.
 * - `prewarmQuotient(curve, elementCount, cosetCount, commitmentCount)`.
 */
import type {
  CurveGPUContext,
  FieldModule,
  G1MSMModule,
  G2MSMModule,
  Groth16QuotientModule,
  NTTModule,
  ResidentBases,
  SupportedCurveID,
} from "./api.js";
import type { PlonkQuotientModule } from "./plonk_quotient_module.js";
import { cloneBytes } from "./gpu.js";

/** Dependencies shared by both bridges. */
type BridgeDependencies = {
  context: CurveGPUContext;
  curve: SupportedCurveID;
  g1msm: G1MSMModule;
  g2msm?: G2MSMModule;
};

export type Groth16BridgeDependencies = BridgeDependencies & {
  fr: FieldModule;
  g2msm: G2MSMModule;
  quotient: Groth16QuotientModule;
};

export type PlonkBridgeDependencies = BridgeDependencies & {
  fr: FieldModule;
  ntt: NTTModule;
  quotient: PlonkQuotientModule;
};

type PreparedKey = {
  curve: SupportedCurveID;
  g1: Map<string, ResidentBases>;
  g2: Map<string, ResidentBases>;
};

type PrepareKeyPayload = {
  g1?: Record<string, Uint8Array | undefined>;
  g2?: Record<string, Uint8Array | undefined>;
};

/**
 * Per-bridge registry: one set of dependencies per curve, and the prepared
 * keys of all curves keyed by handle.
 */
class BridgeRegistry<D extends BridgeDependencies> {
  private readonly curves = new Map<SupportedCurveID, D>();
  private readonly keys = new Map<string, PreparedKey>();
  private nextHandle = 1;

  constructor(readonly name: string) {}

  register(dependencies: D): void {
    this.curves.set(dependencies.curve, dependencies);
  }

  deps(curve: SupportedCurveID): D {
    const dependencies = this.curves.get(curve);
    if (!dependencies) {
      throw new Error(`${this.name} WebGPU bridge is not initialized for curve ${curve}`);
    }
    return dependencies;
  }

  key(handle: string): PreparedKey {
    const key = this.keys.get(handle);
    if (!key) {
      throw new Error(`unknown ${this.name} key handle ${handle}`);
    }
    return key;
  }

  async prepareKey(curve: SupportedCurveID, payload: PrepareKeyPayload): Promise<{ handle: string }> {
    const dependencies = this.deps(curve);
    const key: PreparedKey = { curve, g1: new Map(), g2: new Map() };
    const upload = async (group: "g1" | "g2", vectors: Record<string, Uint8Array | undefined> | undefined): Promise<void> => {
      for (const [name, bytes] of Object.entries(vectors ?? {})) {
        if (!(bytes instanceof Uint8Array)) {
          throw new Error(`${this.name} key payload ${group}.${name} is not a Uint8Array`);
        }
        const msm = group === "g1" ? dependencies.g1msm : dependencies.g2msm;
        if (!msm) {
          throw new Error(`${this.name} WebGPU bridge has no ${group} MSM for curve ${curve}`);
        }
        key[group].set(name, await msm.uploadAffineBases(bytes));
      }
    };
    try {
      await upload("g1", payload.g1);
      await upload("g2", payload.g2);
    } catch (error) {
      releaseKey(key);
      throw error;
    }
    const handle = `${curve}:${this.nextHandle++}`;
    this.keys.set(handle, key);
    return { handle };
  }

  async releaseKey(handle: string): Promise<void> {
    const key = this.keys.get(handle);
    if (key) {
      this.keys.delete(handle);
      releaseKey(key);
    }
  }

  async msm(group: "g1" | "g2", handle: string, name: string, start: number, scalars: Uint8Array): Promise<Uint8Array> {
    const key = this.key(handle);
    const bases = key[group].get(name);
    if (!bases) {
      throw new Error(`${this.name} key ${handle} has no ${group} vector ${name}`);
    }
    const dependencies = this.deps(key.curve);
    const msm = group === "g1" ? dependencies.g1msm : dependencies.g2msm;
    if (!msm) {
      throw new Error(`${this.name} WebGPU bridge has no ${group} MSM for curve ${key.curve}`);
    }
    if (!Number.isInteger(start) || start < 0) {
      throw new Error(`${this.name} MSM start must be a non-negative integer, got ${start}`);
    }
    return msm.msmResident(bases, start, cloneBytes(scalars));
  }

  /** Bridge functions common to Groth16 and PLONK. */
  commonMethods(): Record<string, (...args: never[]) => Promise<unknown>> {
    return {
      init: async (curve: SupportedCurveID) => {
        const { context } = this.deps(curve);
        return {
          curve,
          adapter: {
            vendor: context.diagnostics.vendor ?? "",
            architecture: context.diagnostics.architecture ?? "",
            description: context.diagnostics.description ?? "",
          },
        };
      },
      prepareKey: (curve: SupportedCurveID, payload: PrepareKeyPayload) => this.prepareKey(curve, payload),
      releaseKey: (handle: string) => this.releaseKey(handle),
      msmG1: (handle: string, name: string, start: number, scalars: Uint8Array) => this.msm("g1", handle, name, start, scalars),
      msmG2: (handle: string, name: string, start: number, scalars: Uint8Array) => this.msm("g2", handle, name, start, scalars),
    };
  }
}

function releaseKey(key: PreparedKey): void {
  for (const bases of [...key.g1.values(), ...key.g2.values()]) {
    bases.release();
  }
}

function assertPowerOfTwo(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0 || (value & (value - 1)) !== 0) {
    throw new Error(`${label} ${value}`);
  }
}

function assertPositive(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} ${value}`);
  }
}

function installGlobal(name: string, methods: Record<string, unknown>): void {
  (globalThis as typeof globalThis & Record<string, unknown>)[name] = methods;
}

// --- Groth16 ---------------------------------------------------------------

const groth16Registry = new BridgeRegistry<Groth16BridgeDependencies>("Groth16");

async function computeH(curve: SupportedCurveID, a: Uint8Array, b: Uint8Array, c: Uint8Array, n: number): Promise<Uint8Array> {
  const { quotient } = groth16Registry.deps(curve);
  assertPowerOfTwo(n, "invalid Groth16 quotient domain size");
  const elementBytes = 32;
  const pad = (values: Uint8Array, name: string): Uint8Array => {
    if (values.byteLength % elementBytes !== 0 || values.byteLength > n * elementBytes) {
      throw new Error(`Groth16 computeH: ${name} has ${values.byteLength} bytes, expected a multiple of ${elementBytes} up to ${n * elementBytes}`);
    }
    const out = new Uint8Array(n * elementBytes);
    out.set(values);
    return out;
  };
  // Montgomery in, Montgomery out (bit-reversed, matching the layout of pk.G1.Z).
  return quotient.computeGroth16QuotientMont(pad(a, "a"), pad(b, "b"), pad(c, "c"));
}

export function installGroth16WebGPUBridge(dependencies: Groth16BridgeDependencies): void {
  groth16Registry.register(dependencies);
  installGlobal("gnarkGroth16WebGPU", {
    ...groth16Registry.commonMethods(),
    computeH,
    prewarmQuotientDomain: async (curve: SupportedCurveID, size: number) => {
      await groth16Registry.deps(curve).quotient.prewarmGroth16QuotientDomain(Number(size));
    },
  });
}

// --- PLONK -----------------------------------------------------------------

const plonkRegistry = new BridgeRegistry<PlonkBridgeDependencies>("PLONK");

export function installPlonkWebGPUBridge(dependencies: PlonkBridgeDependencies): void {
  plonkRegistry.register(dependencies);
  installGlobal("gnarkPlonkWebGPU", {
    ...plonkRegistry.commonMethods(),
    canonicalizeVectors: async (
      curve: SupportedCurveID,
      values: Uint8Array,
      vectorCount: number,
      elementCount: number,
      inputBitReversed: boolean,
      inverseCoset: boolean,
    ) => {
      const { fr, ntt } = plonkRegistry.deps(curve);
      assertPositive(vectorCount, "invalid PLONK canonicalize vector count");
      assertPowerOfTwo(elementCount, "invalid PLONK canonicalize element count");
      if (values.byteLength !== vectorCount * elementCount * fr.byteSize) {
        throw new Error(`PLONK canonicalize expected ${vectorCount * elementCount * fr.byteSize} bytes, got ${values.byteLength}`);
      }
      return ntt.transformPackedMont(cloneBytes(values), { inverse: true, vectorCount, inputBitReversed, inverseCoset });
    },
    preloadQuotientStatics: async (
      curve: SupportedCurveID,
      key: number,
      statics: Uint8Array,
      scaling: Uint8Array,
      twiddles: Uint8Array,
      denominators: Uint8Array,
      elementCount: number,
      staticVectorCount: number,
      cosetCount: number,
    ) =>
      plonkRegistry.deps(curve).quotient.preloadStatics(key, {
        statics: cloneBytes(statics),
        scaling: cloneBytes(scaling),
        twiddles: cloneBytes(twiddles),
        denominators: cloneBytes(denominators),
        n: elementCount,
        staticVectorCount,
        cosetCount,
      }),
    releaseQuotientStatics: async (curve: SupportedCurveID, key: number) => plonkRegistry.deps(curve).quotient.releaseStatics(key),
    evaluateQuotient: async (
      curve: SupportedCurveID,
      key: number,
      dynamic: Uint8Array,
      blinds: Uint8Array,
      scalars: Uint8Array,
      elementCount: number,
      blindCoeffCount: number,
      commitmentCount: number,
      cosetCount: number,
    ) =>
      plonkRegistry.deps(curve).quotient.evaluate(key, {
        dynamic: cloneBytes(dynamic),
        blinds: cloneBytes(blinds),
        scalars: cloneBytes(scalars),
        n: elementCount,
        blindCoeffCount,
        commitmentCount,
        cosetCount,
      }),
    prewarmQuotient: async (curve: SupportedCurveID, elementCount: number, cosetCount: number, commitmentCount: number) =>
      plonkRegistry.deps(curve).quotient.prewarm(elementCount, cosetCount, commitmentCount),
  });
}
