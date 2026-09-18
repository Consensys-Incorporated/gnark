override WORKGROUP_SIZE: u32 = 64;

@compute @workgroup_size(WORKGROUP_SIZE)
fn g1_ops_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params.count) {
    return;
  }
  g1_store(i, g1_dispatch(params.opcode, g1_load_from(0u, i), g1_load_from(1u, i)));
}
