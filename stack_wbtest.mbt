// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! In-package tests: stack walking and symbol resolution.
///!
///! Synthetic dumps are used instead of public corpora because "which slot the chain breaks on,
///! what the scan recovers, and whether the bytes before a return address are a call" must all
///! be controllable: real samples cannot provide conditions like "I deliberately placed a value
///! pointing outside the stack in this slot". The constants of the synthetic layout are below;
///! read the cases by matching against the RVAs.

///|
let sk_threads = 80

///|
let sk_modules = 132

///|
let sk_mem64 = 352

///|
let sk_sysinfo = 400

///|
let sk_ctx = 512

///|
let sk_name_a = 1800

///|
let sk_cv_a = 1824

///|
let sk_name_b = 1864

///|
let sk_stack = 2048

///|
let sk_stack_len = 1024

///|
let sk_stack_low = 0x10_0000UL

///|
let sk_mod_a = 0x7ff00000_0000UL

///|
let sk_mod_b = 0x7ff10000_0000UL

///|
let sk_code_va = 0x7ff00000_1000UL

///|
/// The synthetic RSDS's GUID comes from `rsds_record` (the actual value for ntdll in test.dmp),
/// and age is 1, so the breakpad-style debug id is the 32 hex digits followed directly by "1".
let sk_id_a = "5A9832E5287241C1838ED98914E9B7FF1"

///|
/// One entry in the directory: type + declared length + RVA, 4 bytes each.
fn dir_entry(
  buf : Buffer,
  stream_type : UInt32,
  size : UInt32,
  rva : UInt32,
) -> Unit {
  buf.write_uint_le(stream_type)
  buf.write_uint_le(size)
  buf.write_uint_le(rva)
}

///|
/// Zero-pad up to a given file offset. The blob region relies on this to line up with the planned RVAs.
fn pad_to(buf : Buffer, target : Int32) -> Unit {
  while buf.length() < target {
    buf.write_byte(b'\x00')
  }
}

///|
/// A 1232-byte amd64 CONTEXT: only the three pointers the walker needs and ContextFlags are
/// filled in. Field offsets are taken from `read_context_amd64`, whose table has already been
/// checked byte by byte against real dumps.
fn ctx_amd64(rip : UInt64, rsp : UInt64, rbp : UInt64) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(zeros(48))
  buf.write_uint_le(0x10_001fU) // ContextFlags: CONTROL | INTEGER | SEGMENTS
  buf.write_bytes(zeros(100))
  buf.write_uint64_le(rsp)
  buf.write_uint64_le(rbp)
  buf.write_bytes(zeros(80))
  buf.write_uint64_le(rip)
  buf.write_bytes(zeros(976))
  buf.to_bytes()
}

///|
/// A 716-byte x86 CONTEXT. All pointers are 32 bits, so addresses passed in must fit.
fn ctx_x86(eip : UInt64, esp : UInt64, ebp : UInt64) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(0x10_001fU)
  buf.write_bytes(zeros(176))
  buf.write_uint_le(ebp.to_uint())
  buf.write_uint_le(eip.to_uint())
  buf.write_bytes(zeros(8))
  buf.write_uint_le(esp.to_uint())
  buf.write_bytes(zeros(516))
  buf.to_bytes()
}

///|
/// Stack contents: a fixed 1024 bytes; `slots` gives (byte offset within the stack, value) in
/// ascending offset order, with everything else filled as 0. The offset is "virtual address
/// minus the window start", so when writing cases you can take the low bits of a VA directly
/// as the offset.
fn stack_blob(ps : UInt32, slots : Array[(Int32, UInt64)]) -> Bytes {
  let buf = Buffer()
  let mut pos = 0
  let step = ps.reinterpret_as_int()
  for (off, v) in slots {
    if off > pos {
      pad_to(buf, off)
      pos = off
    }
    if ps == 4U {
      buf.write_uint_le(v.to_uint())
    } else {
      buf.write_uint64_le(v)
    }
    pos = pos + step
  }
  pad_to(buf, sk_stack_len)
  buf.to_bytes()
}

///|
/// The module's 32 code bytes (from virtual address 0x…1000): 0x1003 is `E8` (call rel32),
/// 0x100e is `FF D0` (call rax), and the rest are `0x90` (nop).
/// Used to cover all three `return_site` values in one go.
fn code_blob() -> Bytes {
  cat([
    b"\x90\x90\x90\xE8\x11\x11\x11\x11",
    b"\x90\x90\x90\x90\x90\x90\xFF\xD0",
    zeros(16),
  ])
}

///|
/// Assemble the whole synthetic dump. The three pointers come from the context; the stack
/// contents come from `slots`; `stack_declared` of 0 means "the thread record declares no stack
/// range", and a `mem_low` inconsistent with the stack window means "the window was not
/// captured into the dump".
fn synth(
  ip~ : UInt64,
  sp~ : UInt64,
  fp~ : UInt64,
  slots~ : Array[(Int32, UInt64)] = [],
  arch~ : UInt16 = 9,
  code~ : Bytes = zeros(32),
  stack_declared~ : UInt32 = 1024U,
  mem_low~ : UInt64 = sk_stack_low,
  base_a~ : UInt64 = sk_mod_a,
  base_b~ : UInt64 = sk_mod_b,
  code_va~ : UInt64 = sk_code_va,
) -> Dump raise ParseError {
  let ps : UInt32 = if arch == 9 { 8U } else { 4U }
  let ctx = if ps == 8U { ctx_amd64(ip, sp, fp) } else { ctx_x86(ip, sp, fp) }
  let stack = stack_blob(ps, slots)
  let cv = rsds_record("ntdll.pdb", 1U)
  let buf = Buffer()
  // --- Header: 4 streams, the directory immediately follows the header ---
  buf.write_uint_le(expected_signature)
  buf.write_uint_le(0x0007_a793U)
  buf.write_uint_le(4U)
  buf.write_uint_le(32U)
  buf.write_uint_le(0U) // checksum
  buf.write_uint_le(1_730_000_000U)
  buf.write_uint64_le(0x2UL) // MINIDUMP_TYPE
  dir_entry(buf, thread_list_stream, 52U, sk_threads.reinterpret_as_uint())
  dir_entry(buf, module_list_stream, 220U, sk_modules.reinterpret_as_uint())
  dir_entry(buf, memory_64_list_stream, 48U, sk_mem64.reinterpret_as_uint())
  dir_entry(buf, system_info_stream, 56U, sk_sysinfo.reinterpret_as_uint())
  // --- ThreadList: one 48-byte record ---
  buf.write_uint_le(1U)
  buf.write_uint_le(0x1234U) // ThreadId
  buf.write_uint_le(0U) // SuspendCount
  buf.write_uint_le(2U) // PriorityClass
  buf.write_uint_le(8U) // Priority
  buf.write_uint64_le(0x50_0000UL) // Teb
  buf.write_uint64_le(sk_stack_low) // Stack.StartOfMemoryRange
  buf.write_uint_le(stack_declared) // Stack.Memory.DataSize
  buf.write_uint_le(sk_stack.reinterpret_as_uint()) // Stack.Memory.Rva
  buf.write_uint_le(ctx.length().reinterpret_as_uint()) // ThreadContext.Size
  buf.write_uint_le(sk_ctx.reinterpret_as_uint()) // ThreadContext.Rva
  // --- ModuleList: A has RSDS, B has no debug info ---
  buf.write_uint_le(2U)
  buf.write_bytes(
    module_record(
      base_a,
      0x2000U,
      name_rva=sk_name_a.reinterpret_as_uint(),
      cv_rva=sk_cv_a.reinterpret_as_uint(),
      cv_size=cv.length().reinterpret_as_uint(),
    ),
  )
  buf.write_bytes(
    module_record(base_b, 0x1000U, name_rva=sk_name_b.reinterpret_as_uint()),
  )
  // --- Memory64List: the stack window + module code, both ranges laid consecutively in the blob area ---
  buf.write_uint64_le(2UL)
  buf.write_uint64_le(sk_stack.to_uint64()) // BaseRva: the first range starts right at 2048
  buf.write_uint64_le(mem_low)
  buf.write_uint64_le(sk_stack_len.to_uint64())
  buf.write_uint64_le(code_va)
  buf.write_uint64_le(32UL)
  // --- SystemInfo ---
  buf.write_bytes(fake_system_info(arch, zeros(24)))
  // --- Blob area ---
  pad_to(buf, sk_ctx)
  buf.write_bytes(ctx)
  pad_to(buf, sk_name_a)
  buf.write_bytes(minidump_string("ntdll.dll"))
  pad_to(buf, sk_cv_a)
  buf.write_bytes(cv)
  pad_to(buf, sk_name_b)
  buf.write_bytes(minidump_string("app.exe"))
  pad_to(buf, sk_stack)
  buf.write_bytes(stack)
  buf.write_bytes(code)
  open_dump(buf.to_bytes())
}

///|
/// Walk a synthetic dump: the thread list, context, memory index, and module list are all
/// fetched through the public API, guaranteeing that the backtrace consumes "what the parsing
/// layer would actually hand out", not structures the test assembled on its own.
fn synth_walk(
  d : Dump,
  arch~ : UInt16 = 9,
  ft~ : FunctionTableInfo? = None,
  opts~ : StackWalkOptions = stack_walk_options_default(),
) -> StackWalk raise ParseError {
  let entries = d.stream_directory()
  let threads = match d.threads(entries) {
    None => abort("synthetic dump has no thread list")
    Some(ts) => ts
  }
  let map = match d.memory_map(entries) {
    None => abort("synthetic dump has no memory stream")
    Some(m) => m
  }
  let modules = match d.modules(entries) {
    None => abort("synthetic dump has no module list")
    Some(ml) => ml.modules
  }
  let t = threads[0]
  let ctx = match d.read_context(arch, t.context) {
    None => abort("synthetic dump has no context")
    Some(c) => c
  }
  d.walk_thread_stack(map, modules, ft, t, ctx, opts)
}

///|
/// Module list.
fn synth_modules(d : Dump) -> Array[Module] raise ParseError {
  match d.modules(d.stream_directory()) {
    None => abort("synthetic dump has no module list")
    Some(ml) => ml.modules
  }
}

///|
/// Compact summary of one frame, letting a single assert_eq compare a whole chain:
/// `kind@stack-slot/module-index/offset/return_site`.
fn frame_probe(f : StackFrame) -> String {
  let sa = match f.stack_address {
    None => "-"
    Some(a) => "0x" + a.to_string(radix=16)
  }
  let mi = match f.module_index {
    None => "x"
    Some(i) => i.to_string()
  }
  let off = match f.offset {
    None => "-"
    Some(o) => "0x" + o.to_string(radix=16)
  }
  f.kind + "@" + sa + "/m" + mi + "/" + off + "/" + f.return_site
}

///|
fn walk_probe(w : StackWalk) -> String {
  let parts : Array[String] = []
  for f in w.frames {
    parts.push(frame_probe(f))
  }
  parts.join(" ")
}

///|
/// Build a function-table corroboration: only module A is registered, covering up to 0x…1100.
/// `ok` controls layout_ok, used to verify that "no verdict is given when the layout fails the
/// self-consistency check".
fn ft_info(ok : Bool) -> FunctionTableInfo {
  {
    descriptors: [
      {
        minimum_address: sk_mod_a,
        maximum_address: 0x7ff00000_1100UL,
        base_address: sk_mod_a,
        entry_count: 1U,
        inline_entry: Some((0x0U, 0x1100U, 0x1200U)),
      },
    ],
    size_of_descriptor: 32U,
    size_of_native_descriptor: 136U,
    size_of_function_entry: 12U,
    declared_header: 24U,
    size_of_align_pad: 4U,
    layout: InlineRecords,
    layout_ok: ok,
    record_width: 184UL,
    entries_rva: 0UL,
    total_entries: 1UL,
    entries_in_file: true,
  }
}

///|
/// Per-frame function-table corroboration values, compacted into a `kind:yes|no|none` string.
fn marks_of(w : StackWalk) -> Array[String] {
  let marks : Array[String] = []
  for f in w.frames {
    let v = match f.in_function_table {
      None => "none"
      Some(true) => "yes"
      Some(false) => "no"
    }
    marks.push(f.kind + ":" + v)
  }
  marks
}

///|
test "amd64: fp chain + scan backfill; intervals the chain covered do not emit twice" {
  let d = synth(
    ip=0x7ff00000_1040UL,
    sp=0x10_0100UL,
    fp=0x10_0200UL,
    slots=[
      (0x100, 0x1234UL), // not inside any module
      (0x108, 0UL), // empty slot
      (0x120, 0x7ff10000_0500UL), // scan hit outside the chain (module B)
      (0x128, 0x7ff00000_1f00UL), // scan hit outside the chain (module A, this code was not captured)
      (0x200, 0x10_0220UL), // [rbp]
      (0x208, 0x7ff00000_1008UL), // [rbp+8], preceded by E8
      (0x220, 0x10_0250UL),
      (0x228, 0x7ff00000_1010UL), // [rbp+8], preceded by FF D0
      (0x230, 0x7ff00000_1020UL), // memory the chain already touched: the scan must skip it
      (0x250, 0UL), // chain break: the next frame pointer is 0
      (0x258, 0x7ff00000_1f00UL), // also inside memory the chain touched
      (0x300, 0x7ff00000_1e00UL), // scan hit outside the chain
    ],
    code=code_blob(),
  )
  let w = synth_walk(d)
  assert_eq(w.supported, true)
  assert_eq(w.reason, "")
  assert_eq(w.layout, "amd64")
  assert_eq(w.pointer_size, 8U)
  assert_eq(w.fp_frames, 2)
  assert_eq(w.window_low, Some(sk_stack_low))
  assert_eq(w.window_high, Some(0x10_0400UL))
  // The context frame comes first, the rest in ascending stack-slot order (the stack grows from
  // low to high, so calls go from innermost to outermost)
  assert_eq(
    walk_probe(w),
    "context@-/m0/0x1040/unknown " +
    "scan@0x100120/m1/0x500/unknown " +
    "scan@0x100128/m0/0x1f00/unknown " +
    "fp@0x100208/m0/0x1008/call " +
    "fp@0x100228/m0/0x1010/call " +
    "scan@0x100300/m0/0x1e00/unknown",
  )
  assert_eq(w.notes, [
    "frame-pointer chain broke: next frame pointer 0x0 is outside (0x100250, 0x100400)",
  ])
  // Per-slot counting includes the slots in the skipped chain intervals: the window runs from
  // 0x100100 to 0x100400, one slot per 8 bytes
  assert_eq(w.scanned_slots, 96L)
  assert_eq(w.scan_limited, false)
}

///|
test "the three return_site values" {
  // 0x…1008 is preceded by E8, 0x…1010 by FF D0, 0x…1018 by nop,
  // and the bytes before 0x…1028 were never captured at all
  let d = synth(
    ip=0x7ff00000_1040UL,
    sp=0x10_0100UL,
    fp=0x10_0200UL,
    slots=[
      (0x200, 0x10_0220UL),
      (0x208, 0x7ff00000_1008UL),
      (0x220, 0x10_0250UL),
      (0x228, 0x7ff00000_1010UL),
      (0x300, 0x7ff00000_1018UL),
      (0x308, 0x7ff00000_1028UL),
      (0x310, 0UL),
    ],
    code=code_blob(),
  )
  let w = synth_walk(d)
  let sites : Array[String] = []
  for f in w.frames {
    sites.push(f.kind + ":" + f.return_site)
  }
  assert_eq(
    sites.join(" "),
    "context:unknown fp:call fp:call scan:no_call scan:unknown",
  )
}

///|
test "scan off: frame-pointer chain only" {
  let d = synth(ip=0x7ff00000_1040UL, sp=0x10_0100UL, fp=0x10_0200UL, slots=[
    (0x120, 0x7ff10000_0500UL),
    (0x200, 0x10_0220UL),
    (0x208, 0x7ff00000_1008UL),
    (0x220, 0UL),
  ])
  let opts : StackWalkOptions = {
    max_frames: 64,
    max_scan_bytes: 4096L,
    scan: false,
  }
  let w = synth_walk(d, opts~)
  assert_eq(w.frames.length(), 2)
  assert_eq(w.fp_frames, 1)
  assert_eq(w.scanned_slots, 0L)
  assert_eq(
    w.notes[w.notes.length() - 1],
    "scan disabled by option; frame-pointer chain only",
  )
}

///|
test "both limits report their own truncation" {
  let d = synth(ip=0x7ff00000_1040UL, sp=0x10_0100UL, fp=0x10_0200UL, slots=[
    (0x100, 0x7ff10000_0500UL),
    (0x108, 0x7ff10000_0600UL),
    (0x200, 0x10_0220UL),
    (0x208, 0x7ff00000_1008UL),
    (0x220, 0x10_0250UL),
    (0x228, 0x7ff00000_1010UL),
  ])
  let tight : StackWalkOptions = {
    max_frames: 1,
    max_scan_bytes: 16L,
    scan: true,
  }
  let w = synth_walk(d, opts=tight)
  assert_eq(w.scan_limited, true)
  // 1 chain frame + 1 scan frame + 1 context frame = 3 frames, over the "1 frame in total"
  // cap; frames are dropped from the outermost end
  assert_eq(w.frames.length(), 2)
  assert_eq(w.fp_frames, 0)
  assert_eq(
    walk_probe(w),
    "context@-/m0/0x1040/unknown scan@0x100100/m1/0x500/unknown",
  )
  // The chain's frame cap, the scan's frame cap, the scan's byte cap, and the merged total cap:
  // all four leave a note behind
  assert_eq(w.notes, [
    "frame-pointer chain truncated at 1 frames", "scan truncated at 1 frames", "scan covered only 16 bytes; the stack window was not fully scanned",
    "this stack was truncated at 1 frames after merging",
  ])
}

///|
test "x86 walks the chain with 4-byte pointers" {
  let d = synth(
    ip=0x7700_1040UL,
    sp=0x10_0100UL,
    fp=0x10_0200UL,
    arch=0,
    base_a=0x7700_0000UL,
    base_b=0x7800_0000UL,
    code_va=0x7700_1000UL,
    code=code_blob(),
    slots=[
      (0x100, 0x7800_0500UL), // scan hit (module B)
      (0x104, 0x1234UL), // not in any module
      (0x200, 0x10_0210UL), // [ebp]
      (0x204, 0x7700_1008UL), // [ebp+4], preceded by E8
      (0x210, 0UL), // chain break
    ],
  )
  let w = synth_walk(d, arch=0)
  assert_eq(w.layout, "x86")
  assert_eq(w.pointer_size, 4U)
  assert_eq(w.fp_frames, 1)
  assert_eq(
    walk_probe(w),
    "context@-/m0/0x1040/unknown " +
    "scan@0x100100/m1/0x500/unknown " +
    "fp@0x100204/m0/0x1008/call",
  )
  // One slot per 4 bytes: 0x100100 to 0x100400
  assert_eq(w.scanned_slots, 192L)
}

///|
test "no chain when window or field table is unavailable, and no fabricated frame" {
  // The thread record declares no stack size
  let no_size = synth(
    ip=0x7ff00000_1040UL,
    sp=0x10_0100UL,
    fp=0x10_0200UL,
    stack_declared=0U,
  )
  let w1 = synth_walk(no_size)
  assert_eq(w1.supported, false)
  assert_eq(
    w1.reason,
    "thread record declares no stack range (declared size 0)",
  )
  assert_eq(w1.window_low, None)
  assert_eq(w1.window_high, None)
  // When the walk is not supported, only the context frame remains and not a single memory slot
  // is read
  assert_eq(w1.frames.length(), 1)

  // The stack window was not captured into the dump: the memory stream points elsewhere
  let not_captured = synth(
    ip=0x7ff00000_1040UL,
    sp=0x10_0100UL,
    fp=0x10_0200UL,
    mem_low=0x20_0000UL,
  )
  let w2 = synth_walk(not_captured)
  assert_eq(w2.supported, false)
  assert_eq(
    w2.reason,
    "stack window was not captured into the dump; this address range is absent from the memory stream",
  )

  // The context matches no verified field table: there should not even be a pointer width
  let entries = no_size.stream_directory()
  let ts = match no_size.threads(entries) {
    None => abort("no thread list")
    Some(t) => t
  }
  let ctx = match no_size.read_context(6, ts[0].context) {
    // ia64: this project has no CONTEXT field table for it
    None => abort("no context")
    Some(c) => c
  }
  let map = match no_size.memory_map(entries) {
    None => abort("no memory stream")
    Some(m) => m
  }
  let w3 = no_size.walk_thread_stack(
    map,
    synth_modules(no_size),
    None,
    ts[0],
    ctx,
    stack_walk_options_default(),
  )
  assert_eq(w3.supported, false)
  assert_eq(w3.pointer_size, 0U)
  assert_eq(w3.layout, "undecoded")
  assert_eq(w3.frames.length(), 0)
  assert_eq(context_pointer_size(ctx), None)
  assert_eq(frame_chain_supported(ctx), false)
  assert_eq(
    w3.reason,
    "context did not parse under any known field table; no trustworthy pointer width",
  )
}

///|
test "function table only reports corroboration, never acts as a filter" {
  let d = synth(ip=0x7ff00000_1040UL, sp=0x10_0100UL, fp=0x10_0200UL, slots=[
    (0x120, 0x7ff10000_0500UL), // module B: the table has no descriptor for it
    (0x128, 0x7ff00000_1f00UL), // inside module A but outside the table's registered range
    (0x200, 0x10_0220UL),
    (0x208, 0x7ff00000_1008UL), // inside the table's registered range
    (0x220, 0UL),
  ])
  let w = synth_walk(d, ft=Some(ft_info(true)))
  assert_eq(marks_of(w), ["context:yes", "scan:none", "scan:no", "fp:yes"])
  // When the layout fails the self-consistency check everything is none: the extracted fields
  // are untrustworthy, so no verdict is given
  let w2 = synth_walk(d, ft=Some(ft_info(false)))
  assert_eq(marks_of(w2), ["context:none", "scan:none", "scan:none", "fp:none"])
  // When no function table is passed (the stream is absent) everything is none as well
  assert_eq(marks_of(synth_walk(d)), [
    "context:none", "scan:none", "scan:none", "fp:none",
  ])
}

///|
test "module_debug_id is exactly the breakpad scheme" {
  let d = synth(ip=0x7ff00000_1040UL, sp=0x10_0100UL, fp=0x10_0200UL)
  let mods = synth_modules(d)
  assert_eq(module_debug_id(mods[0]), sk_id_a)
  // A module without RSDS yields the empty string, never accidentally matching any symbol table
  assert_eq(module_debug_id(mods[1]), "")
  assert_eq(mods[0].code_view_pdb_name(), "ntdll.pdb")
  assert_eq(mods[1].code_view_pdb_name(), "")
  assert_eq(mods[0].name, "ntdll.dll")
  assert_eq(mods[1].name, "app.exe")
}

///|
/// A symbol table that matches synthetic module A: FUNC covers 0x1000..0x1100,
/// line numbers only cover 0x1040..0x1048, a PUBLIC sits at 0x1500, plus one unexplained
/// STACK CFI line.
fn sym_text(id : String, name : String) -> String {
  "MODULE windows amd64 " +
  id +
  " " +
  name +
  "\n" +
  "FILE 0 src/nt/pause.c\n" +
  "FILE 1 src/nt/other.c\n" +
  "FUNC 0 1000 100 ntdll!NtWaitForSingleObject\n" +
  "1040 8 7 0\n" +
  "PUBLIC 1 1500 0 ntdll!SomeExport\n" +
  "STACK CFI INIT 1000 100 .cfa: $rsp 8 +\n"
}

///|
test "symbolization: function with line numbers, PUBLIC fallback, unresolved when nothing covers" {
  let d = synth(ip=0x7ff00000_1040UL, sp=0x10_0100UL, fp=0x10_0200UL, slots=[
    (0x128, 0x7ff00000_1500UL), // covered by PUBLIC only
    (0x130, 0x7ff00000_0800UL), // has a symbol table, but the address precedes every record
    (0x200, 0x10_0220UL),
    (0x208, 0x7ff00000_1008UL), // inside FUNC, with no line-number coverage
    (0x220, 0UL),
  ])
  let mods = synth_modules(d)
  let store = symbol_store_new()
  let added = symbol_store_add(
    store,
    "ntdll.dll/" + sk_id_a + "/ntdll.pdb.sym",
    sym_text(sk_id_a, "ntdll.pdb"),
  )
  assert_eq(added, true)
  let w = synth_walk(d)
  assert_eq(w.frames.length(), 4)
  let statuses : Array[String] = []
  let lines : Array[String] = []
  for f in w.frames {
    let t = symbolize_frame(f, mods, store)
    statuses.push(t.status + "/" + t.matched_by)
    lines.push(symbol_target_line(t))
  }
  assert_eq(
    statuses.join(" "),
    "ok/debug_id ok/debug_id unresolved/debug_id ok/debug_id",
  )
  assert_eq(
    lines[0],
    "ntdll!NtWaitForSingleObject func+0x40  at src/nt/pause.c:7",
  )
  assert_eq(lines[1], "ntdll!SomeExport public+0x0")
  assert_eq(lines[2], "(unresolved)")
  assert_eq(lines[3], "ntdll!NtWaitForSingleObject func+0x8")
  // Symbol starts are RVAs relative to the image base; the report must reconcile them with the
  // offsets shown on the frame
  let t0 = symbolize_frame(w.frames[0], mods, store)
  assert_eq(t0.symbol_start, Some(0x1000UL))
  assert_eq(t0.symbol_source, "ntdll.dll/" + sk_id_a + "/ntdll.pdb.sym")
  assert_eq(t0.line, Some(7L))
}

///|
test "symbolization: fall back to the PDB name when the id mismatches, then to the module file name" {
  let d = synth(ip=0x7ff00000_1040UL, sp=0x10_0100UL, fp=0x10_0200UL, slots=[
    (0x130, 0x7ff00000_0800UL),
  ])
  let mods = synth_modules(d)
  let w = synth_walk(d)
  assert_eq(w.frames.length(), 2)

  // The symbol store is empty: report empty_store, not a vague "no symbols"
  let empty = symbol_store_new()
  assert_eq(symbolize_frame(w.frames[0], mods, empty).status, "empty_store")

  // The id was tampered with but the name still matches the PDB
  let by_pdb = symbol_store_new()
  ignore(
    symbol_store_add(
      by_pdb,
      "a.sym",
      sym_text("DEADBEEF0000000000000000000000000", "ntdll.pdb"),
    ),
  )
  let t1 = symbolize_frame(w.frames[0], mods, by_pdb)
  assert_eq(t1.status, "ok")
  assert_eq(t1.matched_by, "pdb_name")

  // Neither the id nor the PDB name matches, leaving only the module file name route: try it
  // with module B, which has no RSDS
  let by_file = symbol_store_new()
  ignore(
    symbol_store_add(
      by_file,
      "b.sym",
      "MODULE windows amd64 111111111111111111111111111111111 app.exe\n" +
      "PUBLIC 0 500 0 app!Entry\n",
    ),
  )
  let frame_b : StackFrame = {
    address: 0x7ff10000_0500UL,
    stack_address: Some(0x10_0140UL),
    kind: "scan",
    module_index: Some(1),
    module_name: mods[1].name,
    offset: Some(0x500UL),
    in_function_table: None,
    return_site: "unknown",
  }
  // The store only has ntdll symbols: module B matches on none of the three routes, so say
  // outright "no symbol file for this module"
  let t2 = symbolize_frame(frame_b, mods, by_pdb)
  assert_eq(t2.status, "no_symbol_file")
  let t3 = symbolize_frame(frame_b, mods, by_file)
  assert_eq(t3.status, "ok")
  assert_eq(t3.matched_by, "module_name")
  assert_eq(t3.name, "app!Entry")
  assert_eq(symbol_target_line(t3), "app!Entry public+0x0")

  // Both entries can match: the first one is used, and on a hit the status is still ok with the
  // ambiguity visible via candidates; on a miss the ambiguity surfaces directly in the status
  let dup = symbol_store_new()
  ignore(symbol_store_add(dup, "first.sym", sym_text(sk_id_a, "ntdll.pdb")))
  ignore(symbol_store_add(dup, "second.sym", sym_text(sk_id_a, "ntdll.pdb")))
  let t4 = symbolize_frame(w.frames[0], mods, dup)
  assert_eq(t4.candidates, 2)
  assert_eq(t4.status, "ok")
  assert_eq(t4.symbol_source, "first.sym")
  let t5 = symbolize_frame(w.frames[1], mods, dup)
  assert_eq(t5.status, "ambiguous")
  assert_eq(t5.candidates, 2)

  // A frame with no module attribution: not even an in-module offset can be constructed
  let loose : StackFrame = {
    address: 0x1234UL,
    stack_address: Some(0x10_0140UL),
    kind: "scan",
    module_index: None,
    module_name: "",
    offset: None,
    in_function_table: None,
    return_site: "unknown",
  }
  assert_eq(symbolize_frame(loose, mods, dup).status, "no_module")
}
