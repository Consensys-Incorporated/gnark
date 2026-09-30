// Signed-digit bucket assignment for the Pippenger MSM. Group independent:
// operates on regular little-endian 32-byte scalars and u32 metadata only.
//
// Digit recoding: a scalar is split into `num_windows` windows of `window`
// bits (the last one holds only the final carry); each digit is recoded to
// the signed range [-2^(window-1), 2^(window-1)] so only
// `bucket_count = 2^(window-1)` buckets per window are needed. A non-zero
// digit of absolute value v lands in bucket v-1; negative digits flag the
// base index with 0x80000000 so the bucket kernel negates the point.
//
// Slot s = (instance * num_windows + win) * bucket_count + (v - 1), for
// s in [0, slot_count).
//
// Pipeline (one dispatch each): count -> scan -> scatter, chunks. The
// `counters` buffer must be zeroed before `count`.
//
//   counters : [0, S) per-slot entry counts; [S, 2S) scatter cursors.
//   sort_meta: [0, S) per-slot entry offsets (exclusive prefix sum),
//              [S, 2S] per-slot chunk offsets (S + 1 entries, the last is
//              the total chunk count), [2S + 1] total entry count.
//   indices  : signed base indices, grouped by slot.
//   chunks   : per chunk (start, size) into `indices`; buckets with more than
//              `chunk_size` entries are split so no bucket thread runs long.
//   heavy    : slots with more than one chunk, for the fold stage of the
//              group shaders: [0] their number, slot ids from [1].

struct SortParams {
  term_count: u32,
  terms_per_instance: u32,
  window: u32,
  num_windows: u32,
  bucket_count: u32,
  chunk_size: u32,
  base_index_offset: u32,
  slot_count: u32,
}

@group(0) @binding(0) var<storage, read> scalars: array<u32>;
@group(0) @binding(1) var<uniform> sp: SortParams;
@group(0) @binding(2) var<storage, read_write> counters: array<atomic<u32>>;
@group(0) @binding(3) var<storage, read_write> sort_meta: array<u32>;
@group(0) @binding(4) var<storage, read_write> indices: array<u32>;
@group(0) @binding(5) var<storage, read_write> chunks: array<u32>;
@group(0) @binding(6) var<storage, read_write> heavy: array<atomic<u32>>;

const MSM_HEAVY_LIST_OFFSET: u32 = 1u;

const MSM_SORT_WG: u32 = 256u;
const MSM_SCALAR_WORDS: u32 = 8u;

// Unsigned `window`-bit digit `win` of scalar `term` (0 past the scalar end).
fn msm_window_digit(term: u32, win: u32) -> u32 {
  let w = sp.window;
  let bit = win * w;
  let word = bit >> 5u;
  if (word >= MSM_SCALAR_WORDS) {
    return 0u;
  }
  let shift = bit & 31u;
  let mask = (1u << w) - 1u;
  let base = term * MSM_SCALAR_WORDS;
  var v = scalars[base + word] >> shift;
  if (shift + w > 32u && word + 1u < MSM_SCALAR_WORDS) {
    v = v | (scalars[base + word + 1u] << (32u - shift));
  }
  return v & mask;
}

// Signed digit `win` of `term` given the incoming carry: returns
// (absolute value, negative flag, outgoing carry).
fn msm_signed_digit(term: u32, win: u32, carry: u32) -> vec3<u32> {
  let half = sp.bucket_count;
  var value = carry;
  if (win + 1u < sp.num_windows) {
    value = value + msm_window_digit(term, win);
  }
  if (value >= half) {
    value = (half << 1u) - value;
    return vec3<u32>(value, select(0u, 1u, value != 0u), 1u);
  }
  return vec3<u32>(value, 0u, 0u);
}

fn msm_slot(term: u32, win: u32, value: u32) -> u32 {
  let instance = term / sp.terms_per_instance;
  return (instance * sp.num_windows + win) * sp.bucket_count + value - 1u;
}

// 1. Histogram: one thread per term, one atomic increment per non-zero digit.
@compute @workgroup_size(256)
fn msm_sort_count_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let term = id.x;
  if (term >= sp.term_count) {
    return;
  }
  var carry = 0u;
  for (var win = 0u; win < sp.num_windows; win = win + 1u) {
    let d = msm_signed_digit(term, win, carry);
    carry = d.z;
    if (d.x != 0u) {
      atomicAdd(&counters[msm_slot(term, win, d.x)], 1u);
    }
  }
}

// 2. Exclusive prefix sums over the slot counts (entries and chunks). One
// workgroup: each thread owns a contiguous slot range, thread 0 scans the
// 256 partials, then every thread writes its range.
var<workgroup> scan_entries: array<u32, 256>;
var<workgroup> scan_chunks: array<u32, 256>;

@compute @workgroup_size(256)
fn msm_sort_scan_main(@builtin(local_invocation_id) local_id: vec3<u32>) {
  let tid = local_id.x;
  let s_count = sp.slot_count;
  let per = (s_count + MSM_SORT_WG - 1u) / MSM_SORT_WG;
  let begin = min(tid * per, s_count);
  let end = min(begin + per, s_count);
  let chunk = sp.chunk_size;

  var entries = 0u;
  var nchunks = 0u;
  for (var s = begin; s < end; s = s + 1u) {
    let c = atomicLoad(&counters[s]);
    entries = entries + c;
    nchunks = nchunks + (c + chunk - 1u) / chunk;
  }
  scan_entries[tid] = entries;
  scan_chunks[tid] = nchunks;
  workgroupBarrier();

  if (tid == 0u) {
    var e = 0u;
    var c = 0u;
    for (var t = 0u; t < MSM_SORT_WG; t = t + 1u) {
      let te = scan_entries[t];
      let tc = scan_chunks[t];
      scan_entries[t] = e;
      scan_chunks[t] = c;
      e = e + te;
      c = c + tc;
    }
    sort_meta[2u * s_count] = c;
    sort_meta[2u * s_count + 1u] = e;
    atomicStore(&heavy[0u], 0u);
  }
  workgroupBarrier();

  var entry_offset = scan_entries[tid];
  var chunk_offset = scan_chunks[tid];
  for (var s = begin; s < end; s = s + 1u) {
    let c = atomicLoad(&counters[s]);
    sort_meta[s] = entry_offset;
    sort_meta[s_count + s] = chunk_offset;
    atomicStore(&counters[s_count + s], entry_offset);
    entry_offset = entry_offset + c;
    chunk_offset = chunk_offset + (c + chunk - 1u) / chunk;
  }
}

// 3a. Scatter: one thread per term; each non-zero digit claims the next free
// entry of its slot. Entry order within a slot is therefore arbitrary, which
// the bucket sum does not depend on.
@compute @workgroup_size(256)
fn msm_sort_scatter_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let term = id.x;
  if (term >= sp.term_count) {
    return;
  }
  let index = term + sp.base_index_offset;
  var carry = 0u;
  for (var win = 0u; win < sp.num_windows; win = win + 1u) {
    let d = msm_signed_digit(term, win, carry);
    carry = d.z;
    if (d.x != 0u) {
      let pos = atomicAdd(&counters[sp.slot_count + msm_slot(term, win, d.x)], 1u);
      indices[pos] = select(index, index | 0x80000000u, d.y != 0u);
    }
  }
}

// 3b. Chunk descriptors: one thread per slot writes (start, size) for each
// chunk of at most `chunk_size` entries, and lists slots with several chunks
// for the fold stage.
@compute @workgroup_size(256)
fn msm_sort_chunks_main(@builtin(global_invocation_id) id: vec3<u32>) {
  let s = id.x;
  if (s >= sp.slot_count) {
    return;
  }
  let count = atomicLoad(&counters[s]);
  let start = sort_meta[s];
  var c = sort_meta[sp.slot_count + s];
  for (var done = 0u; done < count; done = done + sp.chunk_size) {
    chunks[2u * c] = start + done;
    chunks[2u * c + 1u] = min(sp.chunk_size, count - done);
    c = c + 1u;
  }
  if (count > sp.chunk_size) {
    let h = atomicAdd(&heavy[0u], 1u);
    atomicStore(&heavy[MSM_HEAVY_LIST_OFFSET + h], s);
  }
}
