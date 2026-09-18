import type { Kernel } from "./gpu.js";
import { fetchShaderParts } from "./shaders.js";

export interface PipelineRegistry {
  getKernel(entryPoint: string): Kernel;
}

/** A 4-binding "ops" shader (`override WORKGROUP_SIZE`, one entry point). */
export type OpsShaderSpec = {
  shaderParts: readonly string[];
  entryPoint: string;
};

/** A 7-binding MSM shader with several entry points sharing a hard-coded workgroup size. */
export type MSMShaderSpec = {
  shaderParts: readonly string[];
  entryPoints: readonly string[];
  workgroupSize: number;
};

/**
 * The MSM bucket-sort shader: scalars (read-only), params (uniform) and five
 * read-write metadata buffers; several entry points, hard-coded workgroup size.
 */
export type MSMSortShaderSpec = MSMShaderSpec;

type BufferKind = "read-only-storage" | "storage" | "uniform";

function layoutEntries(kinds: readonly BufferKind[]): GPUBindGroupLayoutEntry[] {
  return kinds.map((type, binding) => ({ binding, visibility: GPUShaderStage.COMPUTE, buffer: { type } }));
}

const RO: BufferKind = "read-only-storage";
const RW: BufferKind = "storage";
const UNIFORM: BufferKind = "uniform";

export async function buildPipelineRegistry(options: {
  device: GPUDevice;
  opsShaders: OpsShaderSpec[];
  msmShaders: MSMShaderSpec[];
  sortShaders?: MSMSortShaderSpec[];
  /** Workgroup size passed as `WORKGROUP_SIZE` to ops kernels. Defaults to 64. */
  opsWorkgroupSize?: number;
  debug?: boolean;
}): Promise<PipelineRegistry> {
  const { device, opsShaders, msmShaders, sortShaders = [], opsWorkgroupSize = 64, debug = false } = options;

  // Ops kernels: read-only-storage×2, storage, uniform.
  const opsLayout = device.createBindGroupLayout({ label: "curvegpu-ops-bgl", entries: layoutEntries([RO, RO, RW, UNIFORM]) });
  // MSM kernels: same four plus read-only-storage×3 metadata buffers.
  const msmLayout = device.createBindGroupLayout({ label: "curvegpu-msm-bgl", entries: layoutEntries([RO, RO, RW, UNIFORM, RO, RO, RO]) });
  // Bucket-sort kernels: scalars, params, then read-write metadata.
  const sortLayout = device.createBindGroupLayout({ label: "curvegpu-msm-sort-bgl", entries: layoutEntries([RO, UNIFORM, RW, RW, RW, RW, RW]) });
  const pipelineLayout = (label: string, bindGroupLayout: GPUBindGroupLayout): GPUPipelineLayout =>
    device.createPipelineLayout({ label, bindGroupLayouts: [bindGroupLayout] });
  const opsPipelineLayout = pipelineLayout("curvegpu-ops-pl", opsLayout);
  const msmPipelineLayout = pipelineLayout("curvegpu-msm-pl", msmLayout);
  const sortPipelineLayout = pipelineLayout("curvegpu-msm-sort-pl", sortLayout);

  const [opsShaderTexts, msmShaderTexts, sortShaderTexts] = await Promise.all([
    Promise.all(opsShaders.map((spec) => fetchShaderParts(spec.shaderParts))),
    Promise.all(msmShaders.map((spec) => fetchShaderParts(spec.shaderParts))),
    Promise.all(sortShaders.map((spec) => fetchShaderParts(spec.shaderParts))),
  ]);

  const kernels = new Map<string, Kernel>();

  async function compile(
    label: string,
    module: GPUShaderModule,
    layout: GPUPipelineLayout,
    bindGroupLayout: GPUBindGroupLayout,
    entryPoint: string,
    workgroupSize: number,
    constants?: Record<string, number>,
  ): Promise<void> {
    if (debug) {
      console.debug(`[curvegpu] createComputePipelineAsync: ${entryPoint}`);
    }
    const pipeline = await device.createComputePipelineAsync({
      label,
      layout,
      compute: constants ? { module, entryPoint, constants } : { module, entryPoint },
    });
    kernels.set(entryPoint, { pipeline, bindGroupLayout, workgroupSize });
  }

  /** Compile every entry point of a multi-entry shader against one layout. */
  function compileMulti(prefix: string, specs: MSMShaderSpec[], texts: string[], layout: GPUPipelineLayout, bindGroupLayout: GPUBindGroupLayout): Promise<unknown>[] {
    return specs.map((spec, i) => {
      const module = device.createShaderModule({ label: `${prefix}-${spec.entryPoints[0]}-shader`, code: texts[i] });
      return Promise.all(spec.entryPoints.map((entryPoint) => compile(`${prefix}-${entryPoint}`, module, layout, bindGroupLayout, entryPoint, spec.workgroupSize)));
    });
  }

  await Promise.all([
    ...opsShaders.map((spec, i) => {
      const module = device.createShaderModule({ label: `curvegpu-ops-${spec.entryPoint}-shader`, code: opsShaderTexts[i] });
      return compile(`curvegpu-ops-${spec.entryPoint}`, module, opsPipelineLayout, opsLayout, spec.entryPoint, opsWorkgroupSize, {
        WORKGROUP_SIZE: opsWorkgroupSize,
      });
    }),
    ...compileMulti("curvegpu-msm", msmShaders, msmShaderTexts, msmPipelineLayout, msmLayout),
    ...compileMulti("curvegpu-msm-sort", sortShaders, sortShaderTexts, sortPipelineLayout, sortLayout),
  ]);

  return {
    getKernel(entryPoint: string): Kernel {
      const kernel = kernels.get(entryPoint);
      if (!kernel) {
        throw new Error(`[curvegpu] kernel not found: ${entryPoint}`);
      }
      return kernel;
    },
  };
}
