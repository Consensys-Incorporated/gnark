struct Params {
  lane0: vec4<u32>,
  lane1: vec4<u32>,
}

@group(0) @binding(0) var<storage, read> input_a: array<u32>;
@group(0) @binding(1) var<storage, read> input_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> output: array<u32>;
@group(0) @binding(3) var<uniform> params: Params;
@group(0) @binding(4) var<storage, read> input_meta0: array<u32>;
@group(0) @binding(5) var<storage, read> input_meta1: array<u32>;
@group(0) @binding(6) var<storage, read> input_meta2: array<u32>;

fn params_count() -> u32 {
  return params.lane0.x;
}

// Unused by the MSM stages except the fold, which reads its workgroup offset here.
fn params_opcode() -> u32 {
  return params.lane0.y;
}

fn params_terms_per_instance() -> u32 {
  return params.lane0.z;
}

fn params_window() -> u32 {
  return params.lane0.w;
}

fn params_num_windows() -> u32 {
  return params.lane1.x;
}

fn params_bucket_count() -> u32 {
  return params.lane1.y;
}

// count * num_windows * bucket_count: the number of bucket slots.
fn params_slot_count() -> u32 {
  return params.lane1.z;
}

// Workgroups sharing the buckets of one window in the reduce stage.
fn params_groups_per_window() -> u32 {
  return params.lane1.w;
}
