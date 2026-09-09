/**
 * Minimal hand-rolled WebGPU plumbing for the `fr_vector` pages, which
 * deliberately bypass the library runtime to exercise the shaders directly.
 */
export type RawKernel = {
  pipeline: GPUComputePipeline;
  bindGroupLayout: GPUBindGroupLayout;
};

export type RawProfile = {
  uploadMs: number;
  kernelMs: number;
  readbackMs: number;
  totalMs: number;
};

// Large enough for the `Params` struct of every ops shader (`fr_vector` is 64 bytes).
const UNIFORM_BYTES = 64;
const WORKGROUP_SIZE = 64;

export function createRawKernel(device: GPUDevice, label: string, shaderCode: string, entryPoint: string): RawKernel {
  const shaderModule = device.createShaderModule({ label: `${label}-shader`, code: shaderCode });
  const bindGroupLayout = device.createBindGroupLayout({
    label: `${label}-bgl`,
    entries: [
      { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
      { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
      { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } },
    ],
  });
  const pipeline = device.createComputePipeline({
    label: `${label}-pipeline`,
    layout: device.createPipelineLayout({ label: `${label}-pl`, bindGroupLayouts: [bindGroupLayout] }),
    compute: { module: shaderModule, entryPoint },
  });
  return { pipeline, bindGroupLayout };
}

/**
 * Run `kernel` once over `count` elements of `elementBytes` and read back the
 * output, timing upload / dispatch / readback separately.
 */
export async function runRawKernel(
  device: GPUDevice,
  kernel: RawKernel,
  inputA: Uint8Array,
  inputB: Uint8Array,
  elementBytes: number,
  opcode: number,
  logCount: number,
): Promise<{ out: Uint8Array; profile: RawProfile }> {
  const count = inputA.byteLength / elementBytes;
  const dataBytes = inputA.byteLength;
  const totalStart = performance.now();
  const inputABuffer = device.createBuffer({ label: "input-a", size: dataBytes, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
  const inputBBuffer = device.createBuffer({ label: "input-b", size: dataBytes, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
  const outputBuffer = device.createBuffer({ label: "output", size: dataBytes, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
  const stagingBuffer = device.createBuffer({ label: "staging", size: dataBytes, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
  const uniformBuffer = device.createBuffer({ label: "params", size: UNIFORM_BYTES, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });

  const uploadStart = performance.now();
  device.queue.writeBuffer(inputABuffer, 0, inputA.buffer, inputA.byteOffset, inputA.byteLength);
  device.queue.writeBuffer(inputBBuffer, 0, inputB.buffer, inputB.byteOffset, inputB.byteLength);
  const params = new Uint32Array(UNIFORM_BYTES / 4);
  params[0] = count;
  params[1] = opcode;
  params[2] = logCount;
  device.queue.writeBuffer(uniformBuffer, 0, params);
  const bindGroup = device.createBindGroup({
    label: "bind-group",
    layout: kernel.bindGroupLayout,
    entries: [
      { binding: 0, resource: { buffer: inputABuffer } },
      { binding: 1, resource: { buffer: inputBBuffer } },
      { binding: 2, resource: { buffer: outputBuffer } },
      { binding: 3, resource: { buffer: uniformBuffer } },
    ],
  });
  const uploadMs = performance.now() - uploadStart;

  const kernelStart = performance.now();
  const encoder = device.createCommandEncoder({ label: "encoder" });
  const pass = encoder.beginComputePass({ label: "pass" });
  pass.setPipeline(kernel.pipeline);
  pass.setBindGroup(0, bindGroup);
  pass.dispatchWorkgroups(Math.ceil(count / WORKGROUP_SIZE));
  pass.end();
  encoder.copyBufferToBuffer(outputBuffer, 0, stagingBuffer, 0, dataBytes);
  device.queue.submit([encoder.finish()]);
  const kernelMs = performance.now() - kernelStart;

  const readbackStart = performance.now();
  await stagingBuffer.mapAsync(GPUMapMode.READ);
  const out = new Uint8Array(stagingBuffer.getMappedRange().slice(0));
  stagingBuffer.unmap();
  const readbackMs = performance.now() - readbackStart;

  inputABuffer.destroy();
  inputBBuffer.destroy();
  outputBuffer.destroy();
  stagingBuffer.destroy();
  uniformBuffer.destroy();

  return { out, profile: { uploadMs, kernelMs, readbackMs, totalMs: performance.now() - totalStart } };
}
