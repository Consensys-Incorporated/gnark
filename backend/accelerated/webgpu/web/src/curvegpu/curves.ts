import type { CurveModule, CurveGPUContext, G1Module, G2Module, SupportedCurveID } from "./api.js";
import type { CurveID, FieldID, FieldShape } from "./types.js";
import { createFieldModule } from "./field_module.js";
import { createGroupModule } from "./group_module.js";
import { g1Codec, g2Codec } from "./point_codec.js";
import { createMSMModule } from "./msm_module.js";
import { createNTTModule } from "./ntt_module.js";
import { createPlonkQuotientModule } from "./plonk_quotient_module.js";
import { createGroth16Module, createPlonkModule } from "./proof_module.js";
import type { MSMSortShaderSpec } from "./pipeline_registry.js";
import { buildPipelineRegistry } from "./pipeline_registry.js";
import type { MSMKernels, MSMSortKernels } from "./msm_pippenger.js";
import { MSM_STAGES } from "./msm_pippenger.js";

/**
 * Curve-specific constants. Everything else (byte sizes, shader paths, limb
 * counts) is derived from this table.
 */
const CURVE_PARAMS: Record<SupportedCurveID, {
  /** Base-field element size in bytes (scalar field is always 32 bytes). */
  fpBytes: 32 | 48;
  frModulusHex: string;
  /** Multiplicative generator of Fr, also used as the FFT coset generator. */
  frGeneratorHex: string;
  /** Workgroup size hard-coded in the G1 / G2 MSM shaders. */
  g1MSMWorkgroupSize: number;
  g2MSMWorkgroupSize: number;
}> = {
  bn254: {
    fpBytes: 32,
    frModulusHex: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    frGeneratorHex: "5",
    g1MSMWorkgroupSize: 64,
    g2MSMWorkgroupSize: 32,
  },
  bls12_381: {
    fpBytes: 48,
    frModulusHex: "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
    frGeneratorHex: "7",
    g1MSMWorkgroupSize: 64,
    g2MSMWorkgroupSize: 32,
  },
  bls12_377: {
    fpBytes: 48,
    frModulusHex: "0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001",
    frGeneratorHex: "16",
    g1MSMWorkgroupSize: 64,
    g2MSMWorkgroupSize: 32,
  },
};

const FR_BYTES = 32;

/** The group-independent MSM bucket-sort shader (shared by all curves and groups). */
export const MSM_SORT_SHADER_SPEC: MSMSortShaderSpec = {
  shaderParts: ["/shaders/common/msm_sort.wgsl"],
  entryPoints: ["msm_sort_count_main", "msm_sort_scan_main", "msm_sort_scatter_main", "msm_sort_chunks_main"],
  workgroupSize: 256,
};

/** Entry points of one group's MSM shader, in `MSM_STAGES` order. */
function msmEntryPoints(group: "g1" | "g2"): string[] {
  return MSM_STAGES.map((stage) => `${group}_msm_${stage}_jac_main`);
}

/**
 * Runtime metadata for a supported curve.
 */
export interface CurveDefinition {
  readonly id: SupportedCurveID;
  readonly frArithShaderPath: string;
  readonly frVectorShaderPath: string;
  readonly frNTTShaderPath: string;
  readonly frPlonkQuotientShaderParts: readonly string[];
  readonly frModulusHex: string;
  readonly frMultiplicativeGeneratorHex: string;
  readonly frCosetGeneratorHex: string;
  readonly fpArithShaderPath: string;
  readonly g1ArithShaderParts: readonly string[];
  readonly g1MSMShaderParts: readonly string[];
  readonly g2ArithShaderParts: readonly string[];
  readonly g2MSMShaderParts: readonly string[];
  /** Base-field element size in bytes. */
  readonly fpBytes: number;
  /** Scalar-field element size in bytes. */
  readonly frBytes: number;
  /** G1 coordinate size in bytes (`fpBytes`). */
  readonly coordinateBytes: number;
  /** G1 Jacobian point size in bytes (`3 * fpBytes`). */
  readonly pointBytes: number;
  /** G2 coordinate size in bytes (`2 * fpBytes`). */
  readonly g2CoordinateBytes: number;
  /** G2 Jacobian point size in bytes (`6 * fpBytes`). */
  readonly g2PointBytes: number;
  readonly g1MSMWorkgroupSize: number;
  readonly g2MSMWorkgroupSize: number;
  readonly zeroHex: string;
}

function buildDefinition(id: SupportedCurveID): CurveDefinition {
  const params = CURVE_PARAMS[id];
  const dir = `/shaders/curves/${id}`;
  const fp = `${dir}/fp_arith.wgsl`;
  const fr = `${dir}/fr_arith.wgsl`;
  const fpSections = [`${fp}#section=fp-types`, `${fp}#section=fp-consts`, `${fp}#section=fp-core`];
  const g2Arith = `${dir}/g2_arith.wgsl`;
  const g1IO = `${dir}/g1_io.wgsl`;
  const g2IO = `${dir}/g2_io.wgsl`;
  return {
    id,
    frArithShaderPath: fr,
    frVectorShaderPath: `${dir}/fr_vector.wgsl`,
    frNTTShaderPath: `${dir}/fr_ntt.wgsl`,
    frPlonkQuotientShaderParts: [
      `${fr}#section=fr_types`,
      `${fr}#section=fr_constants`,
      `${fr}#section=fr_core`,
      `${dir}/fr_plonk_quotient.wgsl`,
    ],
    frModulusHex: params.frModulusHex,
    frMultiplicativeGeneratorHex: params.frGeneratorHex,
    frCosetGeneratorHex: params.frGeneratorHex,
    fpArithShaderPath: fp,
    g1ArithShaderParts: [...fpSections, "/shaders/common/g1_core.wgsl", "/shaders/common/g1_ops_bindings.wgsl", g1IO, "/shaders/common/g1_ops_main.wgsl"],
    g1MSMShaderParts: [...fpSections, "/shaders/common/g1_core.wgsl", "/shaders/common/g1_msm_bindings.wgsl", g1IO, "/shaders/common/g1_msm_jac.wgsl"],
    g2ArithShaderParts: [...fpSections, "/shaders/common/g2_ops_bindings.wgsl", g2Arith, g2IO, "/shaders/common/g2_ops_main.wgsl"],
    g2MSMShaderParts: [...fpSections, "/shaders/common/g2_msm_bindings.wgsl", g2Arith, g2IO, "/shaders/common/g2_msm_jac.wgsl"],
    fpBytes: params.fpBytes,
    frBytes: FR_BYTES,
    coordinateBytes: params.fpBytes,
    pointBytes: 3 * params.fpBytes,
    g2CoordinateBytes: 2 * params.fpBytes,
    g2PointBytes: 6 * params.fpBytes,
    g1MSMWorkgroupSize: params.g1MSMWorkgroupSize,
    g2MSMWorkgroupSize: params.g2MSMWorkgroupSize,
    zeroHex: "00".repeat(params.fpBytes),
  };
}

const CURVE_DEFINITIONS: Record<SupportedCurveID, CurveDefinition> = {
  bn254: buildDefinition("bn254"),
  bls12_381: buildDefinition("bls12_381"),
  bls12_377: buildDefinition("bls12_377"),
};

/**
 * Ordered list of curves currently exposed by the browser library.
 */
export const supportedCurveIds = Object.freeze(Object.keys(CURVE_DEFINITIONS)) as readonly SupportedCurveID[];

/**
 * Return the runtime metadata for a supported curve.
 */
export function curveDefinition(curve: SupportedCurveID): CurveDefinition {
  const definition = CURVE_DEFINITIONS[curve];
  if (!definition) {
    throw new Error(`unsupported curve ${curve}`);
  }
  return definition;
}

/**
 * Return the host/GPU layout of a field element for a curve.
 */
export function shapeFor(curve: CurveID, field: FieldID): FieldShape {
  const definition = curveDefinition(curve);
  if (field !== "fr" && field !== "fp") {
    throw new Error(`unsupported field ${field} for curve ${curve}`);
  }
  const byteSize = (field === "fr" ? FR_BYTES : definition.fpBytes) as 32 | 48;
  return {
    curve,
    field,
    byteSize,
    hostWords: (byteSize / 8) as 4 | 6,
    gpuLimbs: (byteSize / 4) as 8 | 12,
  };
}

/**
 * Create the high-level curve module for a supported curve.
 */
export async function createCurveModule(context: CurveGPUContext, curve: SupportedCurveID): Promise<CurveModule> {
  const definition = curveDefinition(curve);
  const frShape = shapeFor(curve, "fr");
  const fpShape = shapeFor(curve, "fp");

  const opsWorkgroupSize = Math.min(context.maxWorkgroupSize, 256);
  const registry = await buildPipelineRegistry({
    device: context.device,
    opsWorkgroupSize,
    opsShaders: [
      { shaderParts: [definition.frArithShaderPath], entryPoint: "fr_ops_main" },
      { shaderParts: [definition.fpArithShaderPath], entryPoint: "fp_ops_main" },
      { shaderParts: definition.g1ArithShaderParts, entryPoint: "g1_ops_main" },
      { shaderParts: definition.g2ArithShaderParts, entryPoint: "g2_ops_main" },
      { shaderParts: [definition.frVectorShaderPath], entryPoint: "fr_vector_main" },
      { shaderParts: [definition.frNTTShaderPath], entryPoint: "fr_ntt_fused_main" },
    ],
    msmShaders: [
      {
        shaderParts: definition.g1MSMShaderParts,
        workgroupSize: definition.g1MSMWorkgroupSize,
        entryPoints: msmEntryPoints("g1"),
      },
      {
        shaderParts: definition.g2MSMShaderParts,
        workgroupSize: definition.g2MSMWorkgroupSize,
        entryPoints: msmEntryPoints("g2"),
      },
    ],
    sortShaders: [MSM_SORT_SHADER_SPEC],
    debug: context.debug,
  });

  const fr = createFieldModule(context, { curve, field: "fr", shape: frShape, kernel: registry.getKernel("fr_ops_main") });
  const fp = createFieldModule(context, { curve, field: "fp", shape: fpShape, kernel: registry.getKernel("fp_ops_main") });

  const g1Points = g1Codec(definition.coordinateBytes);
  const g2Points = g2Codec(fpShape.byteSize);

  const g1: G1Module = {
    ...createGroupModule(context, { curve, group: "g1", codec: g1Points, kernel: registry.getKernel("g1_ops_main") }, fp),
    zeroHex: definition.zeroHex,
  };
  const g2: G2Module = {
    ...createGroupModule(context, { curve, group: "g2", codec: g2Points, kernel: registry.getKernel("g2_ops_main") }, fp),
    componentBytes: fpShape.byteSize,
  };
  const ntt = createNTTModule(
    context,
    {
      curve,
      modulusHex: definition.frModulusHex,
      multiplicativeGeneratorHex: definition.frMultiplicativeGeneratorHex,
      cosetGeneratorHex: definition.frCosetGeneratorHex,
      vectorKernel: registry.getKernel("fr_vector_main"),
      fieldKernel: registry.getKernel("fr_ops_main"),
      nttKernel: registry.getKernel("fr_ntt_fused_main"),
    },
    fr,
  );
  const msmKernels = (group: "g1" | "g2"): MSMKernels =>
    Object.fromEntries(MSM_STAGES.map((stage, i) => [stage, registry.getKernel(msmEntryPoints(group)[i])])) as MSMKernels;
  const [count, scan, scatter, chunks] = MSM_SORT_SHADER_SPEC.entryPoints.map((entryPoint) => registry.getKernel(entryPoint));
  const sortKernels: MSMSortKernels = { count, scan, scatter, chunks };
  const g1msm = createMSMModule(context, { curve, group: "g1", codec: g1Points, kernels: msmKernels("g1"), sortKernels }, g1, fp);
  const g2msm = createMSMModule(context, { curve, group: "g2", codec: g2Points, kernels: msmKernels("g2"), sortKernels }, g2, fp);
  const groth16 = createGroth16Module({
    context,
    curve,
    modulusHex: definition.frModulusHex,
    frBytes: frShape.byteSize,
    fr,
    quotient: ntt,
    g1msm,
    g2msm,
  });
  const plonkQuotient = createPlonkQuotientModule({
    context,
    curve,
    shaderParts: definition.frPlonkQuotientShaderParts,
    fr,
    ntt,
  });
  const plonk = createPlonkModule({
    context,
    curve,
    modulusHex: definition.frModulusHex,
    frBytes: frShape.byteSize,
    fr,
    ntt,
    quotient: plonkQuotient,
    g1msm,
  });
  return { id: curve, context, fr, fp, g1, g2, ntt, groth16, plonk, g1msm, g2msm };
}

/**
 * Create the BN254 module bound to an existing context.
 */
export function createBN254(context: CurveGPUContext): Promise<CurveModule> {
  return createCurveModule(context, "bn254");
}

/**
 * Create the BLS12-381 module bound to an existing context.
 */
export function createBLS12381(context: CurveGPUContext): Promise<CurveModule> {
  return createCurveModule(context, "bls12_381");
}

/**
 * Create the BLS12-377 module bound to an existing context.
 */
export function createBLS12377(context: CurveGPUContext): Promise<CurveModule> {
  return createCurveModule(context, "bls12_377");
}
