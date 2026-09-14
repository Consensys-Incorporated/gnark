override WORKGROUP_SIZE: u32 = 64;

@compute @workgroup_size(WORKGROUP_SIZE)
fn g2_ops_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) {
    return;
  }
  g2_store(i, g2_dispatch(params_opcode(), g2_load_from(0u, i), g2_load_from(1u, i)));
}
