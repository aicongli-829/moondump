// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! Stack walking: starting from a thread's CONTEXT, reconstruct the call chain as faithfully as
///! possible using only memory that has **already been captured into the file**.
///!
///! Two walking strategies are provided side by side, distinguished in the result by `kind`,
///! never blended into one category:
///! - `"context"`: the instruction pointer from the context; always the first frame (it is not
///!   read off the stack).
///! - `"fp"`: the frame-pointer chain. On x86 read `[EBP+4]`, on amd64 `[RBP+8]`, on arm64
///!   `[X29+8]`; this is what the compiler's standard `push rbp; mov rbp,rsp` prologue leaves
///!   behind, so it is the most trustworthy; but if any frame in between omitted the frame
///!   pointer (`/Oy-`, i.e. the default Release setting in VS), the chain breaks right there.
///! - `"scan"`: stack-window scanning. Slot by slot, at pointer-width granularity, look for
///!   values that "look like a return address"; this can recover frames beyond where the chain
///!   broke, at the cost that stale values left over in locals also get counted, so callers must
///!   treat frames according to `kind` and must not treat scan frames as a definite call chain.
///!   Consecutive slots holding the same value yield a single frame (the same return address
///!   written into several adjacent slots is not several nested levels of the same call); how
///!   many were merged is stated in the notes.
///!
///! **Not done** — and this is the most important point: this does not interpret x64
///! `UNWIND_INFO`, nor the `STACK CFI`/`STACK WIN` unwind rules in `.sym` files, so this is not
///! "precise unwinding"; when the chain breaks what you get is a scan approximation. The
///! semantics of these two rule sets have no authoritative source that can be checked offline
///! (see the top of `symbols.mbt`); per this project's rule of "no authority, no parser", it
///! prefers to approximate and annotate rather than guess semantics.
///!
///! All reads go through `MemoryMap`; when an address was not captured you get None instead of an
///! exception: walking off the end of the stack is routine, so "there is no memory here" must be
///! data, not an error.

///|
/// A frame. `address` is the instruction address; for every frame except the first, it is a
/// value read out of the stack slot `stack_address`.
#derive(Eq, Debug)
pub(all) struct StackFrame {
  /// Instruction address (a return address; for the first frame it is RIP/EIP/PC)
  address : UInt64
  /// The stack slot address it was read from; None for `"context"` frames (they do not come from the stack)
  stack_address : UInt64?
  /// `"context"` / `"fp"` / `"scan"`
  kind : String
  module_index : Int32?
  /// Name of the owning module; empty string when no module matches
  module_name : String
  /// `address - base_of_image`, i.e. the offset within the module; None when not inside any module
  offset : UInt64?
  /// Whether the function-table stream covers this address. None means "no function table to
  /// compare against"; only Some(false) means "a table exists, and that table says the address
  /// is not within its registered range".
  in_function_table : Bool?
  /// Circumstantial evidence about the return address, from a closed set of three values:
  /// `"call"` (the preceding bytes are exactly the most common `E8`/`FF /2,4` encodings),
  /// `"no_call"` (the preceding bytes were read, but are not either of those encodings — note
  /// this is **not** the same as "definitely not a return address"; longer call encodings such
  /// as `FF 15 disp32` fall into this bucket),
  /// `"unknown"` (those bytes were not captured, or the address is not in any module, so there
  /// is nothing to judge by).
  /// The first frame is not an address someone called back into; it is always `"unknown"`.
  return_site : String
}

///|
pub extend StackFrame with Debug::{to_repr}

///|
pub extend StackFrame with Eq::{equal, not_equal}

///|
/// Walk options. Both limits must be explicit: a real dump's stack window can be several MB.
#derive(Eq, Debug)
pub(all) struct StackWalkOptions {
  /// How many frames this stack may produce at most (not counting the context frame). Once the
  /// chain and the scan each hit their own limit, the merged result is passed through this same
  /// limit again, so `frames.length() - 1 <= max_frames` always holds.
  max_frames : Int32
  /// How many bytes the scan may walk at most
  max_scan_bytes : Int64
  /// With scanning off, only the frame-pointer chain remains and no `"scan"` frames appear in the result
  scan : Bool
}

///|
pub extend StackWalkOptions with Debug::{to_repr}

///|
pub extend StackWalkOptions with Eq::{equal, not_equal}

///|
/// Defaults are chosen so "it fits on one terminal screen and runs under wasm": 64 frames and a
/// 4 KB window (1024 slots).
pub fn stack_walk_options_default() -> StackWalkOptions {
  { max_frames: 64, max_scan_bytes: 4096L, scan: true, }
}

///|
/// The result of one stack walk.
#derive(Eq, Debug)
pub(all) struct StackWalk {
  thread_id : UInt32
  /// The field table **actually used** (`x86`/`amd64`/`arm64`/`undecoded`), not SystemInfo's
  /// architecture: in WOW64 dumps SystemInfo says amd64 while the thread context is a
  /// 716-byte x86 table and 4-byte pointers are stored on the stack, so the width must follow
  /// the field table.
  layout : String
  /// Pointer width; 0 when the field table is unrecognized, with `supported` false as well
  pointer_size : UInt32
  /// Whether the walk is actually possible (a trustworthy width and a captured stack window)
  supported : Bool
  /// Why the walk is not possible; empty string when it is
  reason : String
  /// The first frame is the context; the rest are ascending by `stack_address` (stack addresses
  /// from low to high are calls from inner to outer)
  frames : Array[StackFrame]
  /// Facts observed during the walk: where the chain broke, whether the scan hit its limit,
  /// whether the merged result was truncated by the total frame limit, and so on
  notes : Array[String]
  /// The number of frames in `frames` with `kind == "fp"` (recounted after merge-limit
  /// truncation, so it is always consistent with `frames`)
  fp_frames : Int32
  scanned_slots : Int64
  /// The scan did not finish the window (truncated by `max_frames`, or by `max_scan_bytes`)
  scan_limited : Bool
  /// The stack window that participated in the walk, from `Thread.stack`
  window_low : UInt64?
  window_high : UInt64?
}

///|
pub extend StackWalk with Debug::{to_repr}

///|
pub extend StackWalk with Eq::{equal, not_equal}

///|
/// The adopted field table determines the pointer width. `Undecoded` has no verified field
/// table, and hence no width.
pub fn context_pointer_size(ctx : Context) -> UInt32? {
  match ctx {
    X86(_) => Some(4U)
    Amd64(_) => Some(8U)
    Arm64(_) => Some(8U)
    Undecoded(_) => None
  }
}

///|
/// How far the frame-pointer chain is trusted, per architecture. x86/amd64 are covered by
/// synthetic-dump tests; arm64 is handled with the same "frame pointer and return address in
/// adjacent slots" shape, but there is no real arm64 dump offline to prove it — when the chain
/// cannot proceed, the result carries a corresponding note and never silently gives a wrong
/// call chain.
pub fn frame_chain_supported(ctx : Context) -> Bool {
  match ctx {
    Undecoded(_) => false
    _ => true
  }
}

///|
/// Read one pointer-width value by virtual address. The width can only be 4 or 8 (as given by `context_pointer_size`).
fn Dump::read_pointer_at(
  self : Dump,
  map : MemoryMap,
  address : UInt64,
  ps : UInt32,
) -> UInt64? raise ParseError {
  if ps == 4U {
    match self.read_uint32_at(map, address) {
      Some(v) => Some(v.to_uint64())
      None => None
    }
  } else if ps == 8U {
    self.read_uint64_at(map, address)
  } else {
    None
  }
}

///|
/// Round up. Stack slots must be aligned to the pointer width; unaligned "pointers" are almost always data.
fn align_up(value : UInt64, ps : UInt32) -> UInt64 {
  let w = ps.to_uint64()
  let rem = value % w
  if rem == 0UL {
    value
  } else {
    value + (w - rem)
  }
}

///|
/// What the function-table stream says about this frame. Only two things are checked: whether
/// the descriptor's `[MinimumAddress, MaximumAddress)` contains this virtual address, and
/// whether the inline-function entry's `[BeginAddress, EndAddress)` (an RVA relative to
/// `BaseAddress`) contains this module offset. Either condition counts as coverage.
///
/// **None** is returned (no comparable information) rather than Some(false) when the table has
/// no descriptor for this module: WER's function table registers only a handful of entries per
/// module, so `Some(false)` only means "not within the registered range", and never "this is
/// not code".
fn function_table_state(
  ft : FunctionTableInfo?,
  owner : (Int32, Module)?,
  address : UInt64,
) -> Bool? {
  match ft {
    None => None
    Some(info) =>
      if !info.layout_ok {
        // The layout failed the self-consistency check, so the extracted fields are untrusted;
        // no conclusion is drawn from them for anything
        None
      } else {
        match owner {
          None => None
          Some((_, m)) => {
            let mut known = false
            let mut hit = false
            for d in info.descriptors {
              if d.base_address == m.base_of_image {
                known = true
                if address >= d.minimum_address && address < d.maximum_address {
                  hit = true
                }
                match d.inline_entry {
                  Some((begin, end, _)) =>
                    if address >= m.base_of_image {
                      let rva = address - m.base_of_image
                      if rva >= begin.to_uint64() && rva < end.to_uint64() {
                        hit = true
                      }
                    }
                  None => ()
                }
              }
            }
            if known {
              Some(hit)
            } else {
              None
            }
          }
        }
      }
  }
}

///|
/// Does the instruction before a return address look like a call. Only the 8 bytes before
/// `address` are examined; if they cannot be read, the answer is `"unknown"`, with no guessing.
fn Dump::return_site_hint(
  self : Dump,
  map : MemoryMap,
  address : UInt64,
) -> String {
  if address < 8UL {
    "unknown"
  } else {
    let before = try self.read_memory_at(map, address - 8UL, 8) catch {
      _ => None
    } noraise {
      b => b
    }
    match before {
      None => "unknown"
      Some(bs) => {
        // bs[7] is address-1, so a 5-byte E8 starts at bs[3], and a 2-byte FF /2 starts at
        // bs[6] (modrm in bs[7]; the reg field decides whether it is a call/jmp)
        let e8 = bs[3] == 0xE8
        let reg = bs[7].to_int() / 8 % 8
        let ff_call = bs[6] == 0xFF && (reg == 2 || reg == 4)
        if e8 || ff_call {
          "call"
        } else {
          "no_call"
        }
      }
    }
  }
}

///|
/// Flatten an address into all the fields of a frame. Module ownership uses `find_module`
/// (the first match when ranges overlap).
fn Dump::frame_of(
  self : Dump,
  map : MemoryMap,
  modules : Array[Module],
  ft : FunctionTableInfo?,
  address : UInt64,
  stack_address : UInt64?,
  kind : String,
) -> StackFrame {
  let owner = find_module(modules, address)
  let (module_index, module_name, offset) = match owner {
    None => (None, "", None)
    Some((i, m)) => (Some(i), m.name, m.offset_of(address))
  }
  // The first frame is the current instruction, not an address someone called back into; do not
  // judge it for a call
  let site = if kind == "context" || offset is None {
    "unknown"
  } else {
    self.return_site_hint(map, address)
  }
  let frame : StackFrame = {
    address,
    stack_address,
    kind,
    module_index,
    module_name,
    offset,
    in_function_table: function_table_state(ft, owner, address),
    return_site: site,
  }
  frame
}

///|
/// Does the address "look like code": by preference it must fall within some module's image
/// range. When the module table is empty (a dump without a ModuleListStream) the rule degrades
/// to "non-zero and outside the stack window", and that fact is written into the notes rather
/// than pretending the original rule still applies.
fn looks_like_code(
  address : UInt64,
  modules : Array[Module],
  window_low : UInt64,
  window_high : UInt64,
) -> Bool {
  if address == 0UL {
    false
  } else if modules.length() > 0 {
    find_module(modules, address) is Some(_)
  } else {
    !(address >= window_low && address < window_high)
  }
}

///|
/// Is any part of the stack window captured. Judging only by `readable(low, 2)` would
/// misclassify "the slot at the low edge happens to fall between two regions" as the whole
/// window being uncaptured, so it asks once more whether any region intersects.
fn region_intersects(map : MemoryMap, low : UInt64, high : UInt64) -> Bool {
  let mut hit = false
  for r in map.regions {
    if !hit && r.start_address < high && r.end_address() > low {
      hit = true
    }
  }
  hit
}

///|
/// Sort key for stack frames: `None` (the context frame) sorts first, the rest by stack slot address.
fn key_of(f : StackFrame) -> UInt64 {
  match f.stack_address {
    None => 0UL
    Some(a) => a
  }
}

///|
/// In-place ascending sort by `stack_address`. Insertion sort: the frame cap is only a few
/// dozen, and the payoff is "no dependence on core's sort interface and a fully deterministic
/// order", which lets the tests assert exactly.
fn sort_by_stack_address(frames : Array[StackFrame]) -> Unit {
  let n = frames.length()
  let mut i = 1
  while i < n {
    let mut j = i
    while j > 0 && key_of(frames[j]) < key_of(frames[j - 1]) {
      let tmp = frames[j]
      frames[j] = frames[j - 1]
      frames[j - 1] = tmp
      j = j - 1
    }
    i = i + 1
  }
}

///|
/// The frame-pointer chain. Returns the frames read; `notes` explains why it stopped.
/// `covered` passes back the upper end of the range the chain actually read, which the scan
/// step relies on to avoid emitting duplicate frames over the same memory.
fn Dump::frame_chain(
  self : Dump,
  map : MemoryMap,
  modules : Array[Module],
  ft : FunctionTableInfo?,
  start : UInt64?,
  low : UInt64,
  high : UInt64,
  width : UInt32,
  max_frames : Int32,
  notes : Array[String],
) -> (Array[StackFrame], UInt64, UInt64) raise ParseError {
  let out : Array[StackFrame] = []
  let w = width.to_uint64()
  let mut cur = start
  let mut covered_low = 0UL
  let mut covered_high = 0UL
  let mut more = true
  while more {
    let f = match cur {
      Some(v) => v
      None => 0UL
    }
    if cur is None {
      more = false
      notes.push("no frame pointer in the context; scan only")
    } else if f % w != 0UL {
      more = false
      cur = None
      notes.push("frame pointer 0x" + f.to_string(radix=16) + " is unaligned")
    } else if f < low || add_saturating(f, 2UL * w) > high {
      more = false
      cur = None
      notes.push(
        "frame pointer 0x" +
        f.to_string(radix=16) +
        " is outside the stack window [0x" +
        low.to_string(radix=16) +
        ", 0x" +
        high.to_string(radix=16) +
        ")",
      )
    } else {
      // As long as this slot passes the alignment and window checks, the chain counts it as
      // "read" — even if the next step breaks. What the scan phase must avoid is emitting
      // frames twice over the same memory, regardless of whether the chain managed to continue.
      if covered_low == 0UL {
        covered_low = f
      }
      covered_high = add_saturating(f, 2UL * w)
      let next = self.read_pointer_at(map, f, width)
      let ret = self.read_pointer_at(map, add_saturating(f, w), width)
      let step : (UInt64, UInt64)? = match (next, ret) {
        (Some(nf), Some(ra)) => Some((nf, ra))
        _ => None
      }
      let usable = match step {
        Some((nf, ra)) =>
          looks_like_code(ra, modules, low, high) && nf > f && nf < high
        None => false
      }
      if usable {
        match step {
          Some((nf, ra)) => {
            out.push(
              self.frame_of(
                map,
                modules,
                ft,
                ra,
                Some(add_saturating(f, w)),
                "fp",
              ),
            )
            cur = Some(nf)
          }
          None => more = false
        }
        if more && out.length() >= max_frames {
          more = false
          cur = None
          notes.push(
            "frame-pointer chain truncated at " +
            max_frames.to_string() +
            " frames",
          )
        }
      } else {
        more = false
        cur = None
        let why = match step {
          None =>
            "frame-pointer chain broke: the two slots it needs were not captured"
          Some((nf, ra)) =>
            if !(nf > f && nf < high) {
              "frame-pointer chain broke: next frame pointer 0x" +
              nf.to_string(radix=16) +
              " is outside (0x" +
              f.to_string(radix=16) +
              ", 0x" +
              high.to_string(radix=16) +
              ")"
            } else {
              "frame-pointer chain broke: return address 0x" +
              ra.to_string(radix=16) +
              " does not look like code (see the rule noted above)"
            }
        }
        notes.push(why)
      }
    }
  }
  (out, covered_low, covered_high)
}

///|
/// Stack-window scan. Returns the candidate frames and the number of slots scanned; `limited`
/// says the window was not fully walked.
fn Dump::scan_stack(
  self : Dump,
  map : MemoryMap,
  modules : Array[Module],
  ft : FunctionTableInfo?,
  rsp : UInt64?,
  low : UInt64,
  high : UInt64,
  width : UInt32,
  max_frames : Int32,
  max_scan_bytes : Int64,
  covered_low : UInt64,
  covered_high : UInt64,
  notes : Array[String],
) -> (Array[StackFrame], Int64, Bool) raise ParseError {
  let out : Array[StackFrame] = []
  let w = width.to_uint64()
  let sp = match rsp {
    Some(v) => if v >= low && v < high { v } else { low }
    None => low
  }
  let start = align_up(sp, width)
  let budget = if max_scan_bytes > 0L {
    max_scan_bytes.reinterpret_as_uint64()
  } else {
    0UL
  }
  let byte_stop = add_saturating(start, budget)
  let stop_at = if byte_stop < high { byte_stop } else { high }
  let mut a = start
  let mut slots : Int64 = 0L
  let mut limited = false
  let mut running = true
  let mut dupes : Int32 = 0
  let mut last_value : UInt64? = None
  while running {
    if add_saturating(a, w) > stop_at {
      running = false
    } else if out.length() >= max_frames {
      running = false
      limited = true
      notes.push("scan truncated at " + max_frames.to_string() + " frames")
    } else if a >= covered_low && a < covered_high {
      // Where the chain has gone, the chain's word is final; no second verdict is emitted over
      // the same memory
      a = add_saturating(a, w)
      slots = slots + 1L
    } else {
      let v = self.read_pointer_at(map, a, width)
      match v {
        Some(value) =>
          if looks_like_code(value, modules, low, high) {
            // Consecutive slots holding the same value yield a single frame: the same return
            // address written into several adjacent slots (a compiler spilling arguments, or
            // stale stack contents just overwritten) is not several nested levels of the same
            // call. The comparison is against "the previously emitted frame's value"; an
            // intervening different value restarts the count, so merging never spans segments.
            if last_value == Some(value) {
              dupes = dupes + 1
            } else {
              out.push(self.frame_of(map, modules, ft, value, Some(a), "scan"))
              last_value = Some(value)
            }
          }
        None => ()
      }
      a = add_saturating(a, w)
      slots = slots + 1L
    }
  }
  if dupes > 0 {
    notes.push(
      "scan merged " +
      dupes.to_string() +
      " consecutive slots holding the previous frame's address (one frame emitted)",
    )
  }
  if stop_at < high {
    limited = true
    notes.push(
      "scan covered only " +
      max_scan_bytes.to_string() +
      " bytes; the stack window was not fully scanned",
    )
  }
  (out, slots, limited)
}

///|
/// Stack walk of one thread. The context and thread record are supplied by the caller
/// (`dump.threads` / `dump.read_context` / `dump.exception` can all produce them); the function
/// table may be passed in as corroboration; when it is not (or that stream is absent),
/// `in_function_table` is all None.
pub fn Dump::walk_thread_stack(
  self : Dump,
  map : MemoryMap,
  modules : Array[Module],
  ft : FunctionTableInfo?,
  thread : Thread,
  ctx : Context,
  opts : StackWalkOptions,
) -> StackWalk raise ParseError {
  let notes : Array[String] = []
  let ps = context_pointer_size(ctx)
  // The stack window comes from the thread record: StartOfMemoryRange is the low bound, and the
  // length is the declared capture size.
  let declared = thread.stack
  let has_window = declared.location.size > 0U
  let low = declared.start_address
  let high = if has_window {
    add_saturating(low, declared.location.size.to_uint64())
  } else {
    0UL
  }
  let reason = match ps {
    None =>
      "context did not parse under any known field table; no trustworthy pointer width"
    Some(_) =>
      if !has_window {
        "thread record declares no stack range (declared size 0)"
      } else if !region_intersects(map, low, high) {
        "stack window was not captured into the dump; this address range is absent from the memory stream"
      } else {
        ""
      }
  }
  let supported = reason.length() == 0
  let frames : Array[StackFrame] = []
  match ctx.instruction_pointer() {
    Some(ip) =>
      frames.push(self.frame_of(map, modules, ft, ip, None, "context"))
    None => notes.push("no instruction pointer in the context")
  }
  let mut fp_frames : Int32 = 0
  let mut scanned : Int64 = 0L
  let mut scan_limited = false
  if supported {
    let width = match ps {
      Some(v) => v
      None => 8U
    }
    let (chain, covered_low, covered_high) = self.frame_chain(
      map,
      modules,
      ft,
      ctx.frame_pointer(),
      low,
      high,
      width,
      opts.max_frames,
      notes,
    )
    fp_frames = chain.length()
    for f in chain {
      frames.push(f)
    }
    if opts.scan {
      let (found, slots, limited) = self.scan_stack(
        map,
        modules,
        ft,
        ctx.stack_pointer(),
        low,
        high,
        width,
        opts.max_frames,
        opts.max_scan_bytes,
        covered_low,
        covered_high,
        notes,
      )
      scanned = slots
      scan_limited = limited
      for f in found {
        frames.push(f)
      }
    } else {
      notes.push("scan disabled by option; frame-pointer chain only")
    }
    if modules.length() == 0 {
      notes.push(
        "no module list; \"looks like a return address\" is judged only as \"non-zero and outside the stack window\"",
      )
    }
  }
  sort_by_stack_address(frames)
  // `max_frames` means "how many frames this stack has in total" (the context frame is not
  // counted). The chain and the scan each have their own limit, and the combined result still
  // has to pass a total limit, otherwise asking for 8 could actually yield 16 frames,
  // contradicting what the option says. Truncation drops from the outermost end — the frames
  // with the highest stack addresses.
  let mut real : Int32 = 0
  for f in frames {
    if f.stack_address is Some(_) {
      real = real + 1
    }
  }
  if real > opts.max_frames {
    while real > opts.max_frames {
      match frames.pop() {
        Some(dropped) => if dropped.stack_address is Some(_) { real = real - 1 }
        None => ()
      }
    }
    notes.push(
      "this stack was truncated at " +
      opts.max_frames.to_string() +
      " frames after merging",
    )
    // The merge limit can eat frames the chain produced, so the chain frames that **remained**
    // are recounted here, keeping the count consistent with `frames`
    fp_frames = 0
    for f in frames {
      if f.kind == "fp" {
        fp_frames = fp_frames + 1
      }
    }
  }
  let walk : StackWalk = {
    thread_id: thread.id,
    layout: ctx.layout_name(),
    pointer_size: match ps {
      Some(v) => v
      None => 0U
    },
    supported,
    reason,
    frames,
    notes,
    fp_frames,
    scanned_slots: scanned,
    scan_limited,
    window_low: if has_window {
      Some(low)
    } else {
      None
    },
    window_high: if has_window {
      Some(high)
    } else {
      None
    },
  }
  walk
}

///|
/// The symbol resolution result for one frame. `status` is a closed set of values; callers must
/// use it to distinguish the causes of "no symbol":
/// - `"ok"`: a function or PUBLIC matched.
/// - `"unresolved"`: a symbol table exists, but this address falls in no FUNC/PUBLIC.
/// - `"ambiguous"`: multiple `.sym` files matched; the first is used and `candidates` gives the count.
/// - `"no_module"`: the address is not in any module, so the module offset cannot be computed.
/// - `"no_symbol_file"`: the symbol store has no `.sym` for this module.
/// - `"empty_store"`: the symbol store is empty (`--symbols` was not given).
#derive(Eq, Debug)
pub(all) struct SymbolTarget {
  name : String
  /// How the match was made: `"func"` / `"public"` / empty string
  kind : String
  /// The symbol's start (module-relative RVA)
  symbol_start : UInt64?
  /// `address - symbol_start`
  offset : UInt64?
  file : String
  line : Int64?
  /// The `.sym` source path the result was based on; empty string when no symbol table was used
  symbol_source : String
  /// Which matching route was used: `"debug_id"` / `"pdb_name"` / `"module_name"` / empty string
  matched_by : String
  status : String
  candidates : Int32
}

///|
pub extend SymbolTarget with Debug::{to_repr}

///|
pub extend SymbolTarget with Eq::{equal, not_equal}

///|
/// The fields of a `pub(all)` struct are immutable, so the failure branches must each construct
/// a whole value; this factory writes down once the fact that "everything except `status` is empty".
fn target_of(
  name : String,
  kind : String,
  symbol_start : UInt64?,
  offset : UInt64?,
  file : String,
  line : Int64?,
  symbol_source : String,
  matched_by : String,
  status : String,
  candidates : Int32,
) -> SymbolTarget {
  {
    name,
    kind,
    symbol_start,
    offset,
    file,
    line,
    symbol_source,
    matched_by,
    status,
    candidates,
  }
}

///|
/// Find the symbol table for a module: first an exact hit on the debug id, then fall back to
/// the PDB name (path stripped), then to the module file name. Each route also asks how many
/// files matched; when >1, the ambiguity is recorded in `candidates` instead of pretending the
/// right one was chosen.
fn module_symbol(
  store : SymbolStore,
  m : Module,
) -> ((String, SymbolFile)?, String, Int32) {
  let id = module_debug_id(m)
  let none : ((String, SymbolFile)?, String, Int32) = (None, "", 0)
  let by_id = symbol_store_find_with_source(store, id, "")
  if by_id is Some(_) {
    (by_id, "debug_id", symbol_store_match_count(store, id, ""))
  } else {
    let pdb = basename_of(m.code_view_pdb_name())
    let by_pdb = symbol_store_find_with_source(store, "", pdb)
    if by_pdb is Some(_) {
      (by_pdb, "pdb_name", symbol_store_match_count(store, "", pdb))
    } else {
      let file = basename_of(m.name)
      let by_file = symbol_store_find_with_source(store, "", file)
      if by_file is Some(_) {
        (by_file, "module_name", symbol_store_match_count(store, "", file))
      } else {
        none
      }
    }
  }
}

///|
/// Find symbols for one frame. Addresses in `.sym` are offsets relative to the image base, so
/// the address must fall inside a module before a query can be built; when `frame.offset` is
/// None (empty module table and the like), the result is `"no_module"` directly.
pub fn symbolize_frame(
  frame : StackFrame,
  modules : Array[Module],
  store : SymbolStore,
) -> SymbolTarget {
  if store.loaded.length() == 0 {
    target_of("", "", None, None, "", None, "", "", "empty_store", 0)
  } else {
    match frame.module_index {
      None => target_of("", "", None, None, "", None, "", "", "no_module", 0)
      Some(i) => {
        let bad = i < 0 || i >= modules.length()
        if bad {
          target_of("", "", None, None, "", None, "", "", "no_module", 0)
        } else {
          let m = modules[i]
          let (hit, matched_by, candidates) = module_symbol(store, m)
          match (hit, frame.offset) {
            (None, _) =>
              target_of(
                "",
                "",
                None,
                None,
                "",
                None,
                "",
                "",
                "no_symbol_file",
                candidates,
              )
            (Some((source, sf)), Some(rva)) => {
              let found = symbol_file_resolve(sf, rva)
              let miss = if candidates > 1 { "ambiguous" } else { "unresolved" }
              match found {
                None =>
                  target_of(
                    "",
                    "",
                    None,
                    None,
                    "",
                    None,
                    source,
                    matched_by,
                    miss,
                    candidates,
                  )
                Some(r) => {
                  let rel = if rva >= r.start {
                    Some(rva - r.start)
                  } else {
                    None
                  }
                  target_of(
                    r.name,
                    r.kind,
                    Some(r.start),
                    rel,
                    r.file,
                    r.line,
                    source,
                    matched_by,
                    "ok",
                    candidates,
                  )
                }
              }
            }
            (Some(_), None) =>
              target_of("", "", None, None, "", None, "", "", "no_module", 0)
          }
        }
      }
    }
  }
}

///|
/// One-line human-readable form of a `SymbolTarget`, shared by the CLI and the tests so the
/// format is written only once.
pub fn symbol_target_line(t : SymbolTarget) -> String {
  if t.status != "ok" {
    "(" + t.status + ")"
  } else {
    let off = match t.offset {
      None => ""
      Some(o) => "+0x" + o.to_string(radix=16)
    }
    let place = match t.line {
      None => ""
      Some(v) => {
        let f = if t.file.length() > 0 { t.file } else { "(unknown file)" }
        "  at " + f + ":" + v.to_string()
      }
    }
    t.name + " " + t.kind + off + place
  }
}

///|
/// The module's PDB name (empty string when there is no RSDS record). It lives here because
/// only symbol resolution uses it.
pub fn Module::code_view_pdb_name(self : Module) -> String {
  match self.code_view {
    Rsds(r) => r.pdb_name
    _ => ""
  }
}
