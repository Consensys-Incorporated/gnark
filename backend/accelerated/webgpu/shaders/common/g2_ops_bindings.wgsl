struct Params {
  count: u32,
  opcode: u32,
  _pad0: u32,
  _pad1: u32,
}

@group(0) @binding(0) var<storage, read> input_a: array<u32>;
@group(0) @binding(1) var<storage, read> input_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> output: array<u32>;
@group(0) @binding(3) var<uniform> params: Params;

fn params_count() -> u32 {
  return params.count;
}

fn params_opcode() -> u32 {
  return params.opcode;
}
