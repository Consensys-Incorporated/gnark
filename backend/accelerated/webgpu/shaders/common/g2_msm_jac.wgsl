// Pippenger MSM stages over Jacobian G2 points; mirrors g2_msm_jac.wgsl
// stage for stage (see that file for the documentation of each kernel and
// shaders/common/msm_sort.wgsl for the data layout).
//
// Keep every kernel small and in the same shape as its G1 counterpart: on
// Metal (Chrome/Dawn on Apple GPUs) larger G2 kernels return wrong results,
// deterministically for a fused reduce (running sums + small scalar
// multiplication + workgroup tree, even on paths that only add the point at
// infinity) and sporadically under GPU contention for kernels that select
// the buffer they read at run time or rewrite a buffer they read.

const G2_MSM_WG: u32 = 32u;
// Threads sharing the chunk list of one heavy slot in the fold_partial stage.
const G2_MSM_FOLD_LANES: u32 = 8u;

var<workgroup> g2_jac_wg: array<G2Point, 32>;

// Bucket accumulation: one thread per chunk sums its signed affine bases.
//   input_a    affine bases (x, y; infinity all zero)
//   output     one Jacobian partial sum per chunk
//   meta0      signed base indices, meta1 chunk (start, size) pairs,
//   meta2      sort metadata (meta2[2 * slot_count] = chunk count)
@compute @workgroup_size(32)
fn g2_msm_bucket_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= input_meta2[2u * params_slot_count()]) { return; }
  let start = input_meta1[2u * i];
  let size = input_meta1[2u * i + 1u];
  var acc = g2_jac_infinity();
  for (var j = 0u; j < size; j = j + 1u) {
    let raw = input_meta0[start + j];
    var point = g2_load_affine(raw & 0x7fffffffu);
    if ((raw & 0x80000000u) != 0u) { point = g2_neg_affine(point); }
    acc = g2_add_mixed(acc, point);
  }
  g2_store(i, acc);
}

// Fold, step 1: the chunk sums of every slot with several chunks (listed by
// the sort stage; the dispatch covers the upper bound and threads past the
// GPU-side count exit) are summed by G2_MSM_FOLD_LANES threads each, lane l
// taking chunks l, l + LANES, ... Without the fold, the reduce thread owning
// a bucket with hundreds of chunks (the top window of most window sizes only
// holds a few bits, so its entries pile up in a handful of buckets) walks
// them sequentially and stalls the stage.
//   input_a    chunk sums (bucket stage output)
//   output     LANES partial sums per heavy slot
//   meta0      sort metadata (chunk offsets at [slot_count + s])
//   meta1      heavy-slot list ([0] count, slot ids from word 1)
@compute @workgroup_size(32)
fn g2_msm_fold_partial_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let h = id.x / G2_MSM_FOLD_LANES;
  let lane = id.x % G2_MSM_FOLD_LANES;
  if (h >= input_meta1[0u]) { return; }
  let slot = input_meta1[1u + h];
  let slot_count = params_slot_count();
  let end = input_meta0[slot_count + slot + 1u];
  var acc = g2_jac_infinity();
  for (var c = input_meta0[slot_count + slot] + lane; c < end; c = c + G2_MSM_FOLD_LANES) {
    acc = g2_add_jac(acc, g2_load_from(0u, c));
  }
  g2_store(id.x, acc);
}

// Fold, step 2: one workgroup per heavy slot (params_opcode() is the
// workgroup offset of this dispatch) tree-reduces the LANES partials and
// rewrites the slot's chunk list as its total followed by points at infinity,
// so the reduce stage reads chunk lists only.
//   input_a    fold_partial output
//   output     chunk sums, rewritten for the heavy slots
//   meta0      sort metadata, meta1 heavy-slot list
@compute @workgroup_size(32)
fn g2_msm_fold_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let tid = local_id.x;
  let h = params_opcode() + wg_id.x;
  if (h >= input_meta1[0u]) { return; }
  var acc = g2_jac_infinity();
  if (tid < G2_MSM_FOLD_LANES) {
    acc = g2_load_from(0u, h * G2_MSM_FOLD_LANES + tid);
  }
  g2_jac_wg[tid] = acc;
  workgroupBarrier();

  var stride = G2_MSM_WG / 2u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g2_jac_wg[tid] = g2_add_jac(g2_jac_wg[tid], g2_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  let slot = input_meta1[1u + h];
  let slot_count = params_slot_count();
  let begin = input_meta0[slot_count + slot];
  let end = input_meta0[slot_count + slot + 1u];
  if (tid == 0u) {
    g2_store(begin, g2_jac_wg[0u]);
  }
  for (var c = begin + 1u + tid; c < end; c = c + G2_MSM_WG) {
    g2_store(c, g2_jac_infinity());
  }
}

// Bucket range [lo, hi) owned by thread `tid` of reduce workgroup `wg`.
// Workgroups (instance, window, group) share a window: `groups_per_window`
// of them split its bucket_count buckets and each thread owns a contiguous
// slice of its group's share.
fn g2_msm_thread_range(wg: u32, tid: u32) -> vec2<u32> {
  let groups = params_groups_per_window();
  let per_group = params_bucket_count() / groups;
  let per_thread = (per_group + G2_MSM_WG - 1u) / G2_MSM_WG;
  let group_lo = (wg % groups) * per_group;
  let lo = min(group_lo + tid * per_thread, group_lo + per_group);
  let hi = min(lo + per_thread, group_lo + per_group);
  return vec2<u32>(lo, hi);
}

// Running sums: each thread walks its bucket range [lo, hi) from the top:
// run = sum of the buckets seen so far, acc = sum of the running sums, so
// acc = sum (k - lo + 1) b_k and the range contributes acc + lo * run to the
// window total sum (k + 1) b_k. Partial p = wg * WG + tid stores acc at p
// and run at count + p (count = total number of partials).
//   input_a    chunk sums (bucket and fold output)
//   output     2 * count Jacobian points: acc partials, then run partials
//   meta0      sort metadata (chunk offsets at [slot_count + s])
@compute @workgroup_size(32)
fn g2_msm_reduce_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  let p = i * G2_MSM_WG + tid;
  let count = params_count();
  if (p >= count) { return; }
  let range = g2_msm_thread_range(i, tid);
  let slot_count = params_slot_count();
  let slot_base = (i / params_groups_per_window()) * params_bucket_count();

  var run = g2_jac_infinity();
  var acc = g2_jac_infinity();
  var k = range.y;
  loop {
    if (k <= range.x) { break; }
    k = k - 1u;
    let s = slot_base + k;
    let chunk_end = input_meta0[slot_count + s + 1u];
    for (var c = input_meta0[slot_count + s]; c < chunk_end; c = c + 1u) {
      run = g2_add_jac(run, g2_load_from(0u, c));
    }
    acc = g2_add_jac(acc, run);
  }
  g2_store(p, acc);
  g2_store(count + p, run);
}

// Range-offset correction: lo * run for every partial (infinity when lo = 0).
//   input_a    reduce output
//   output     one Jacobian point per partial
@compute @workgroup_size(32)
fn g2_msm_weight_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let p = id.x;
  let count = params_count();
  if (p >= count) { return; }
  let lo = g2_msm_thread_range(p / G2_MSM_WG, p % G2_MSM_WG).x;
  let run = g2_load_from(0u, count + p);
  var weighted = g2_jac_infinity();
  if (lo != 0u && !g2_jac_is_infinity(run)) {
    weighted = g2_scalar_mul_jac_small(run, lo);
  }
  g2_store(p, weighted);
}

// Sum: one workgroup per (instance, window, group) tree-reduces the
// acc + lo * run of its WG partials.
//   input_a    reduce output (acc partials), input_b  weight output
//   output     one Jacobian point per workgroup
@compute @workgroup_size(32)
fn g2_msm_sum_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  if (i >= params_count()) { return; }
  let p = i * G2_MSM_WG + tid;
  g2_jac_wg[tid] = g2_add_jac(g2_load_from(0u, p), g2_load_from(1u, p));
  workgroupBarrier();

  var stride = G2_MSM_WG / 2u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g2_jac_wg[tid] = g2_add_jac(g2_jac_wg[tid], g2_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  if (tid == 0u) {
    g2_store(i, g2_jac_wg[0u]);
  }
}

// Window sum: one workgroup per (instance, window) tree-reduces the
// `groups_per_window` (at most WG) group sums of the window.
//   input_a    sum output: (instance * num_windows + win) * groups + g
//   output     one Jacobian point per (instance, window)
@compute @workgroup_size(32)
fn g2_msm_sum_windows_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  if (i >= params_count()) { return; }
  let groups = params_groups_per_window();
  var acc = g2_jac_infinity();
  if (tid < groups) {
    acc = g2_load_from(0u, i * groups + tid);
  }
  g2_jac_wg[tid] = acc;
  workgroupBarrier();

  var stride = G2_MSM_WG / 2u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g2_jac_wg[tid] = g2_add_jac(g2_jac_wg[tid], g2_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  if (tid == 0u) {
    g2_store(i, g2_jac_wg[0u]);
  }
}

// Combine: Horner evaluation over the window sums of one instance,
// normalized to affine (z = 1, or all zero for infinity). One thread per
// instance: the 256 doublings are an inherent serial chain.
//   input_a    sum_windows output: instance * num_windows + win
@compute @workgroup_size(32)
fn g2_msm_combine_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) { return; }
  let num_windows = params_num_windows();
  let window = params_window();
  var acc = g2_jac_infinity();
  var win = num_windows;
  loop {
    if (win == 0u) { break; }
    win = win - 1u;
    if (win + 1u != num_windows) {
      for (var step = 0u; step < window; step = step + 1u) {
        acc = g2_double_jac(acc);
      }
    }
    acc = g2_add_jac(acc, g2_load_from(0u, i * num_windows + win));
  }
  g2_store(i, g2_jac_to_affine(acc));
}
