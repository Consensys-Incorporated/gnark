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

function storageLayoutEntries(count: number, writableIndex: number, uniformIndex: number): GPUBindGroupLayoutEntry[] {
  return Array.from({ length: count }, (_, binding) => ({
    binding,
    visibility: GPUShaderStage.COMPUTE,
    buffer: { type: binding === uniformIndex ? "uniform" : binding === writableIndex ? "storage" : "read-only-storage" },
  }));
}

export async function buildPipelineRegistry(options: {
  device: GPUDevice;
  opsShaders: OpsShaderSpec[];
  msmShaders: MSMShaderSpec[];
  /** Workgroup size passed as `WORKGROUP_SIZE` to ops kernels. Defaults to 64. */
  opsWorkgroupSize?: number;
  debug?: boolean;
}): Promise<PipelineRegistry> {
  const { device, opsShaders, msmShaders, opsWorkgroupSize = 64, debug = false } = options;

  // Ops kernels: read-only-storage×2, storage, uniform.
  const opsLayout = device.createBindGroupLayout({ label: "curvegpu-ops-bgl", entries: storageLayoutEntries(4, 2, 3) });
  // MSM kernels: same four plus read-only-storage×3 metadata buffers.
  const msmLayout = device.createBindGroupLayout({ label: "curvegpu-msm-bgl", entries: storageLayoutEntries(7, 2, 3) });
  const opsPipelineLayout = device.createPipelineLayout({ label: "curvegpu-ops-pl", bindGroupLayouts: [opsLayout] });
  const msmPipelineLayout = device.createPipelineLayout({ label: "curvegpu-msm-pl", bindGroupLayouts: [msmLayout] });

  const [opsShaderTexts, msmShaderTexts] = await Promise.all([
    Promise.all(opsShaders.map((spec) => fetchShaderParts(spec.shaderParts))),
    Promise.all(msmShaders.map((spec) => fetchShaderParts(spec.shaderParts))),
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

  await Promise.all([
    ...opsShaders.map((spec, i) => {
      const module = device.createShaderModule({ label: `curvegpu-ops-${spec.entryPoint}-shader`, code: opsShaderTexts[i] });
      return compile(`curvegpu-ops-${spec.entryPoint}`, module, opsPipelineLayout, opsLayout, spec.entryPoint, opsWorkgroupSize, {
        WORKGROUP_SIZE: opsWorkgroupSize,
      });
    }),
    ...msmShaders.map((spec, i) => {
      const module = device.createShaderModule({ label: `curvegpu-msm-${spec.entryPoints[0]}-shader`, code: msmShaderTexts[i] });
      return Promise.all(
        spec.entryPoints.map((entryPoint) =>
          compile(`curvegpu-msm-${entryPoint}`, module, msmPipelineLayout, msmLayout, entryPoint, spec.workgroupSize),
        ),
      );
    }),
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
