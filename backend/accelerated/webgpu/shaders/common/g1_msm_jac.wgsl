// Pippenger MSM stages over Jacobian G1 points. The bucket assignment
// (signed digits, per-slot entry lists, chunk descriptors) is produced by
// shaders/common/msm_sort.wgsl; see its header for the metadata layout.
//
// Stages: bucket (chunk sums) -> fold_partial, fold (slots with several
// chunks) -> reduce (per-thread running sums) -> weight (range-offset
// correction) -> sum (per window and group) -> sum_windows (per window) ->
// combine (Horner over windows, affine output).
//
// Serial chains are what cost time on the GPU (a lone thread runs one
// dependent group operation every ~25-80 us), so every stage keeps its
// per-thread work short and the combine gets exactly one point per window.
//
// The stages are deliberately many and small, and g2_msm_jac.wgsl must keep
// the same shapes: on Metal (Chrome/Dawn on Apple GPUs) larger G2 kernels
// return wrong results, deterministically for a fused reduce (even on paths
// that only add the point at infinity) and sporadically under GPU contention
// for kernels that select the buffer they read at run time or rewrite a
// buffer they read. Every kernel here reads each point from a fixed buffer
// and never reads a buffer it writes.

const G1_MSM_WG: u32 = 64u;
// Threads sharing the chunk list of one heavy slot in the fold_partial stage.
const G1_MSM_FOLD_LANES: u32 = 8u;

var<workgroup> g1_jac_wg: array<G1Point, 64>;

// Bucket accumulation: one thread per chunk sums its signed affine bases.
//   input_a    affine bases (x, y; infinity all zero)
//   output     one Jacobian partial sum per chunk
//   meta0      signed base indices, meta1 chunk (start, size) pairs,
//   meta2      sort metadata (meta2[2 * slot_count] = chunk count)
@compute @workgroup_size(64)
fn g1_msm_bucket_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= input_meta2[2u * params_slot_count()]) { return; }
  let start = input_meta1[2u * i];
  let size = input_meta1[2u * i + 1u];
  var acc = g1_jac_infinity();
  for (var j = 0u; j < size; j = j + 1u) {
    let raw = input_meta0[start + j];
    var point = g1_load_affine(raw & 0x7fffffffu);
    if ((raw & 0x80000000u) != 0u) { point = g1_neg_affine(point); }
    acc = g1_add_mixed(acc, point);
  }
  g1_store(i, acc);
}

// Fold, step 1: the chunk sums of every slot with several chunks (listed by
// the sort stage; the dispatch covers the upper bound and threads past the
// GPU-side count exit) are summed by G1_MSM_FOLD_LANES threads each, lane l
// taking chunks l, l + LANES, ... Without the fold, the reduce thread owning
// a bucket with hundreds of chunks (the top window of most window sizes only
// holds a few bits, so its entries pile up in a handful of buckets) walks
// them sequentially and stalls the stage.
//   input_a    chunk sums (bucket stage output)
//   output     LANES partial sums per heavy slot
//   meta0      sort metadata (chunk offsets at [slot_count + s])
//   meta1      heavy-slot list ([0] count, slot ids from word 1)
@compute @workgroup_size(64)
fn g1_msm_fold_partial_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let h = id.x / G1_MSM_FOLD_LANES;
  let lane = id.x % G1_MSM_FOLD_LANES;
  if (h >= input_meta1[0u]) { return; }
  let slot = input_meta1[1u + h];
  let slot_count = params_slot_count();
  let end = input_meta0[slot_count + slot + 1u];
  var acc = g1_jac_infinity();
  for (var c = input_meta0[slot_count + slot] + lane; c < end; c = c + G1_MSM_FOLD_LANES) {
    acc = g1_add_jac(acc, g1_load_from(0u, c));
  }
  g1_store(id.x, acc);
}

// Fold, step 2: one workgroup per heavy slot (params_opcode() is the
// workgroup offset of this dispatch) tree-reduces the LANES partials and
// rewrites the slot's chunk list as its total followed by points at infinity,
// so the reduce stage reads chunk lists only.
//   input_a    fold_partial output
//   output     chunk sums, rewritten for the heavy slots
//   meta0      sort metadata, meta1 heavy-slot list
@compute @workgroup_size(64)
fn g1_msm_fold_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let tid = local_id.x;
  let h = params_opcode() + wg_id.x;
  if (h >= input_meta1[0u]) { return; }
  var acc = g1_jac_infinity();
  if (tid < G1_MSM_FOLD_LANES) {
    acc = g1_load_from(0u, h * G1_MSM_FOLD_LANES + tid);
  }
  g1_jac_wg[tid] = acc;
  workgroupBarrier();

  var stride = G1_MSM_WG / 2u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g1_jac_wg[tid] = g1_add_jac(g1_jac_wg[tid], g1_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  let slot = input_meta1[1u + h];
  let slot_count = params_slot_count();
  let begin = input_meta0[slot_count + slot];
  let end = input_meta0[slot_count + slot + 1u];
  if (tid == 0u) {
    g1_store(begin, g1_jac_wg[0u]);
  }
  for (var c = begin + 1u + tid; c < end; c = c + G1_MSM_WG) {
    g1_store(c, g1_jac_infinity());
  }
}

// Bucket range [lo, hi) owned by thread `tid` of reduce workgroup `wg`.
// Workgroups (instance, window, group) share a window: `groups_per_window`
// of them split its bucket_count buckets and each thread owns a contiguous
// slice of its group's share.
fn g1_msm_thread_range(wg: u32, tid: u32) -> vec2<u32> {
  let groups = params_groups_per_window();
  let per_group = params_bucket_count() / groups;
  let per_thread = (per_group + G1_MSM_WG - 1u) / G1_MSM_WG;
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
@compute @workgroup_size(64)
fn g1_msm_reduce_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  let p = i * G1_MSM_WG + tid;
  let count = params_count();
  if (p >= count) { return; }
  let range = g1_msm_thread_range(i, tid);
  let slot_count = params_slot_count();
  let slot_base = (i / params_groups_per_window()) * params_bucket_count();

  var run = g1_jac_infinity();
  var acc = g1_jac_infinity();
  var k = range.y;
  loop {
    if (k <= range.x) { break; }
    k = k - 1u;
    let s = slot_base + k;
    let chunk_end = input_meta0[slot_count + s + 1u];
    for (var c = input_meta0[slot_count + s]; c < chunk_end; c = c + 1u) {
      run = g1_add_jac(run, g1_load_from(0u, c));
    }
    acc = g1_add_jac(acc, run);
  }
  g1_store(p, acc);
  g1_store(count + p, run);
}

// Range-offset correction: lo * run for every partial (infinity when lo = 0).
//   input_a    reduce output
//   output     one Jacobian point per partial
@compute @workgroup_size(64)
fn g1_msm_weight_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let p = id.x;
  let count = params_count();
  if (p >= count) { return; }
  let lo = g1_msm_thread_range(p / G1_MSM_WG, p % G1_MSM_WG).x;
  let run = g1_load_from(0u, count + p);
  var weighted = g1_jac_infinity();
  if (lo != 0u && !g1_jac_is_infinity(run)) {
    weighted = g1_scalar_mul_jac_small(run, lo);
  }
  g1_store(p, weighted);
}

// Sum: one workgroup per (instance, window, group) tree-reduces the
// acc + lo * run of its WG partials.
//   input_a    reduce output (acc partials), input_b  weight output
//   output     one Jacobian point per workgroup
@compute @workgroup_size(64)
fn g1_msm_sum_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  if (i >= params_count()) { return; }
  let p = i * G1_MSM_WG + tid;
  g1_jac_wg[tid] = g1_add_jac(g1_load_from(0u, p), g1_load_from(1u, p));
  workgroupBarrier();

  var stride = G1_MSM_WG / 2u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g1_jac_wg[tid] = g1_add_jac(g1_jac_wg[tid], g1_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  if (tid == 0u) {
    g1_store(i, g1_jac_wg[0u]);
  }
}

// Window sum: one workgroup per (instance, window) tree-reduces the
// `groups_per_window` (at most WG) group sums of the window.
//   input_a    sum output: (instance * num_windows + win) * groups + g
//   output     one Jacobian point per (instance, window)
@compute @workgroup_size(64)
fn g1_msm_sum_windows_jac_main(
  @builtin(local_invocation_id) local_id: vec3<u32>,
  @builtin(workgroup_id) wg_id: vec3<u32>,
) {
  let i = wg_id.x;
  let tid = local_id.x;
  if (i >= params_count()) { return; }
  let groups = params_groups_per_window();
  var acc = g1_jac_infinity();
  if (tid < groups) {
    acc = g1_load_from(0u, i * groups + tid);
  }
  g1_jac_wg[tid] = acc;
  workgroupBarrier();

  var stride = G1_MSM_WG / 2u;
  loop {
    if (stride == 0u) { break; }
    if (tid < stride) {
      g1_jac_wg[tid] = g1_add_jac(g1_jac_wg[tid], g1_jac_wg[tid + stride]);
    }
    workgroupBarrier();
    stride = stride >> 1u;
  }
  if (tid == 0u) {
    g1_store(i, g1_jac_wg[0u]);
  }
}

// Combine: Horner evaluation over the window sums of one instance,
// normalized to affine (z = 1, or all zero for infinity). One thread per
// instance: the 256 doublings are an inherent serial chain.
//   input_a    sum_windows output: instance * num_windows + win
@compute @workgroup_size(64)
fn g1_msm_combine_jac_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let i = id.x;
  if (i >= params_count()) { return; }
  let num_windows = params_num_windows();
  let window = params_window();
  var acc = g1_jac_infinity();
  var win = num_windows;
  loop {
    if (win == 0u) { break; }
    win = win - 1u;
    if (win + 1u != num_windows) {
      for (var step = 0u; step < window; step = step + 1u) {
        acc = g1_double_jac(acc);
      }
    }
    acc = g1_add_jac(acc, g1_load_from(0u, i * num_windows + win));
  }
  g1_store(i, g1_jac_to_affine(acc));
}
