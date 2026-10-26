// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! Public entry point for reading the corpus. Fixture logic lives in a
///! non-test file so that the field-level assertions for every stream can
///! reuse the same loader.

///|
/// Files in the corpus directory. See `testdata/README.md` for provenance and licensing.
pub let fixtures : Array[String] = [
  "test.dmp", "simple-crashpad.dmp", "linux-mini.dmp", "invalid-parameter.dmp", "invalid-range.dmp",
  "invalid-record-count.dmp", "full-dump.dmp",
]

///|
/// The working directory of `moon test` varies with how it is invoked, so try the candidate paths in turn.
fn candidates(name : String) -> Array[String] {
  ["testdata/" + name, "../testdata/" + name, "../../testdata/" + name]
}

///|
/// Returns Some when found; None when every candidate fails to read (the caller decides how to report it).
pub fn find_fixture(name : String) -> Bytes? {
  let mut found : Bytes? = None
  for p in candidates(name) {
    if found is None {
      // x/fs's read_file_to_bytes is raise-style, not Result-returning
      try @fs.read_file_to_bytes(p) catch {
        _ => ()
      } noraise {
        bytes => found = Some(bytes)
      }
    }
  }
  found
}

///|
/// Read a corpus fixture; when it is missing, fail with a message pointing to testdata/README.md to fetch the public samples.
pub fn read_fixture(name : String) -> Bytes raise {
  match find_fixture(name) {
    Some(bytes) => bytes
    None =>
      fail(
        "cannot read corpus " +
        name +
        "; fetch the public fixtures per testdata/README.md",
      )
  }
}

///|
/// Open a corpus fixture and validate the signature and format version, for reuse by each stream's tests.
pub fn open_fixture(name : String) -> @lib.Dump raise {
  let dump = @lib.open_dump(read_fixture(name))
  assert_eq((name, dump.header.signature), (name, @lib.expected_signature))
  assert_true(@lib.header_format_version_is_known(dump.header.version))
  dump
}

///|
/// Include the corpus name in the assertion so a failure immediately shows which file it was.
pub fn assert_count(name : String, got : Int32, want : Int32) -> Unit raise {
  assert_eq((name, got), (name, want))
}

///|
pub fn assert_stream_present(
  name : String,
  entries : Array[@lib.StreamEntry],
  stream_type : UInt32,
) -> Unit raise {
  assert_eq(
    (name, @lib.get_stream(entries, stream_type) is Some(_)),
    (name, true),
  )
}

///|
/// Compress SystemInfo into a single line of fixed-order text:
/// arch|OS version|platform|processor count|product type|SuiteMask|CPUID vendor|family/model/stepping|CSD string
/// One assertion then pins every field at once, and a failing diff points straight at the field that changed.
pub fn system_info_line(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String raise {
  match @lib.get_stream(entries, @lib.system_info_stream) {
    None => "no-system-info"
    Some(e) => {
      let si = dump.read_system_info(e)
      let fms = @lib.x86_family_model_stepping(si)
      let vendor = match si.cpu_vendor {
        Some(v) => v
        None => "-"
      }
      let arch = @lib.architecture_name(si.processor_architecture)
      let ver = @lib.version_string(si)
      let platform = @lib.platform_id_name(si.platform_id)
      // Byte's Show prints b'\x01'-style output; the summary wants the decimal number
      let ncpu = si.number_of_processors.to_int().to_string()
      let prod = @lib.product_type_name(si.product_type)
      let suite = "0x" + si.suite_mask.to_string(radix=16)
      let model = fms.0.to_string() +
        "/" +
        fms.1.to_string() +
        "/" +
        fms.2.to_string()
      arch +
      "|" +
      ver +
      "|" +
      platform +
      "|" +
      ncpu +
      "|" +
      prod +
      "|" +
      suite +
      "|" +
      vendor +
      "|" +
      model +
      "|" +
      si.csd_version
    }
  }
}

///|
pub fn assert_system_info(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  want : String,
) -> Unit raise {
  assert_eq((name, system_info_line(dump, entries)), (name, want))
}

///|
/// Compress one module record into a single line of fixed-order text:
/// name|address range|image size|file version|product version|timestamp|checksum|debug info
/// Address, size, timestamp and checksum are lowercase hex; debug info takes one of four
/// forms: `RSDS:GUID/age:pdb`, `cv:0x..`, `none`, `corrupt`.
pub fn module_line(m : @lib.Module) -> String {
  let cv = match m.code_view {
    @lib.Rsds(r) =>
      "RSDS:" + r.debug_id + "/" + r.age.to_string() + ":" + r.pdb_name
    @lib.Unrecognized(k) => "cv:0x" + k.to_string(radix=16)
    @lib.Missing => "none"
    @lib.Corrupt => "corrupt"
  }
  let range = "0x" +
    m.base_of_image.to_string(radix=16) +
    "-0x" +
    m.end_address().to_string(radix=16)
  let head = m.name +
    "|" +
    range +
    "|" +
    "0x" +
    m.size_of_image.to_string(radix=16)
  let ver = head + "|" + m.file_version() + "|" + m.product_version()
  let tail = "0x" +
    m.time_date_stamp.to_string(radix=16) +
    "|" +
    "0x" +
    m.checksum.to_string(radix=16)
  ver + "|" + tail + "|" + cv
}

///|
/// Take a module by index and assert the whole line. An out-of-range index fails outright, so tests never skip silently.
pub fn assert_module(
  name : String,
  list : @lib.ModuleList,
  index : Int32,
  want : String,
) -> Unit raise {
  assert_true(
    index < list.modules.length(),
    msg=name + " module index " + index.to_string() + " out of range",
  )
  assert_eq((name, module_line(list.modules[index])), (name, want))
}

///|
/// `key=value` fragment: None (the Flags1 bit is off, or the version is too low) is always
/// written as `key=-`, so the corpus assertion pins two things at once: whether the value
/// is right and whether the gating is right.
fn opt_u32(key : String, v : UInt32?) -> String {
  match v {
    None => key + "=-"
    Some(x) => key + "=" + x.to_string()
  }
}

///|
fn opt_hex(key : String, v : UInt32?) -> String {
  match v {
    None => key + "=-"
    Some(x) => key + "=0x" + x.to_string(radix=16)
  }
}

///|
fn opt_i32(key : String, v : Int32?) -> String {
  match v {
    None => key + "=-"
    Some(x) => key + "=" + x.to_string()
  }
}

///|
fn opt_str(key : String, v : String?) -> String {
  match v {
    None => key + "=-"
    Some(x) => key + "=" + x
  }
}

///|
/// The time-zone segment is assembled separately: it is either present as a whole group or absent as a whole (both gated by MISC3_TIMEZONE).
fn tz_segment(mi : @lib.MiscInfo) -> String {
  match mi.time_zone {
    None =>
      "tz_id=-|tz_bias=-|tz_offset=-|tz_std_name=-|tz_std_rule=-|tz_std_bias=-|tz_dst_name=-|tz_dst_rule=-|tz_dst_bias=-"
    Some(t) => {
      let bias = opt_i32("tz_bias", Some(t.bias))
      let off = opt_str("tz_offset", Some(@lib.time_zone_offset_text(t.bias)))
      let id = opt_u32("tz_id", mi.time_zone_id)
      let std = opt_str("tz_std_name", Some(t.standard_name))
      let std_rule = opt_str("tz_std_rule", Some(t.standard_date.rule_text()))
      let std_bias = opt_i32("tz_std_bias", Some(t.standard_bias))
      let dst = opt_str("tz_dst_name", Some(t.daylight_name))
      let dst_rule = opt_str("tz_dst_rule", Some(t.daylight_date.rule_text()))
      let dst_bias = opt_i32("tz_dst_bias", Some(t.daylight_bias))
      id +
      "|" +
      bias +
      "|" +
      off +
      "|" +
      std +
      "|" +
      std_rule +
      "|" +
      std_bias +
      "|" +
      dst +
      "|" +
      dst_rule +
      "|" +
      dst_bias
    }
  }
}

///|
fn xstate_segment(mi : @lib.MiscInfo) -> String {
  match mi.xstate_config {
    None => "xstate_size=-|ctx_size=-|enabled=-"
    Some(x) => {
      let size = x.size_of_info.to_string()
      let ctx = x.context_size.to_string()
      let en = "0x" + x.enabled_features.to_string(radix=16)
      "xstate_size=" + size + "|ctx_size=" + ctx + "|enabled=" + en
    }
  }
}

///|
/// Compress the MiscInfo stream into one line of fixed-order key=value text; a single
/// assertion pins the whole stream. The order is fixed, missing values are always written
/// as `-`, and hex is always `0x`-prefixed, so every value in the golden can be checked
/// directly against the field table of `MINIDUMP_MISC_INFO` without guessing which field
/// sits at that position.
pub fn misc_info_line(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String raise {
  match @lib.get_stream(entries, @lib.misc_info_stream) {
    None => "no-misc-info"
    Some(e) => {
      let mi = dump.read_misc_info(e)
      let times = match mi.process_times {
        None => (None, None, None)
        Some(t) => (Some(t.create_time), Some(t.user_time), Some(t.kernel_time))
      }
      let power = match mi.processor_power_info {
        None => (None, None, None, None, None)
        Some(p) =>
          (
            Some(p.max_mhz),
            Some(p.current_mhz),
            Some(p.mhz_limit),
            Some(p.max_idle_state),
            Some(p.current_idle_state),
          )
      }
      let head = opt_u32("pid", mi.process_id) +
        "|" +
        opt_u32("create_time", times.0) +
        "|" +
        opt_u32("user_time", times.1) +
        "|" +
        opt_u32("kernel_time", times.2)
      let mid = opt_u32("max_mhz", power.0) +
        "|" +
        opt_u32("current_mhz", power.1) +
        "|" +
        opt_u32("mhz_limit", power.2) +
        "|" +
        opt_u32("max_idle_state", power.3) +
        "|" +
        opt_u32("current_idle_state", power.4) +
        "|" +
        opt_u32("integrity", mi.process_integrity_level) +
        "|" +
        opt_hex("exec_flags", mi.process_execute_flags) +
        "|" +
        opt_u32("protected", mi.protected_process)
      let tail = opt_str("build", mi.build_string) +
        "|" +
        opt_str("dbg", mi.dbg_build_string) +
        "|" +
        xstate_segment(mi) +
        "|" +
        opt_hex("cookie", mi.process_cookie)
      let version = "v=" +
        mi.info_version.to_string() +
        "|" +
        "size_of_info=" +
        mi.size_of_info.to_string() +
        "|" +
        "flags=0x" +
        mi.flags1.to_string(radix=16)
      version + "|" + head + "|" + mid + "|" + tz_segment(mi) + "|" + tail
    }
  }
}

///|
pub fn assert_misc_info(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  want : String,
) -> Unit raise {
  assert_eq((name, misc_info_line(dump, entries)), (name, want))
}

///|
/// Hex in the corpus summary lines is uniformly "0x + lowercase, no leading zeros", matching the oracle.
fn chex(value : UInt64) -> String {
  "0x" + value.to_string(radix=16)
}

///|
/// One MINIDUMP_MEMORY_DESCRIPTOR line: `0x<virtual address>+<size>@<RVA>`.
fn md_line(md : @lib.MemoryDescriptor) -> String {
  chex(md.start_address) +
  "+" +
  md.location.size.to_string() +
  "@" +
  md.location.rva.to_string()
}

///|
/// One LocationDescriptor line: `<size>@<RVA>`.
fn loc_line(loc : @lib.LocationDescriptor) -> String {
  loc.size.to_string() + "@" + loc.rva.to_string()
}

///|
/// One thread record: `id=..,sus=..,pcls=..,prio=..,teb=..,stk=..,ctx=..[,bs=..],w=..`
fn thread_line(t : @lib.Thread) -> String {
  let head = "id=" +
    t.id.to_string() +
    ",sus=" +
    t.suspend_count.to_string() +
    ",pcls=" +
    t.priority_class.to_string() +
    ",prio=" +
    t.priority.to_string()
  let mid = ",teb=" +
    chex(t.teb) +
    ",stk=" +
    md_line(t.stack) +
    ",ctx=" +
    loc_line(t.context)
  let bs = match t.backing_store {
    None => ""
    Some(md) => ",bs=" + md_line(md)
  }
  head + mid + bs + ",w=" + t.entry_size.to_string()
}

///|
/// One thread-table line: `no-threads` or `count=N <t0> ; <t1> ; …`.
/// Malformed records that fail to read collapse into `error:<kind>` here, so one bad
/// corpus file cannot drag down the whole assertion group.
pub fn thread_list_line(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String {
  try dump.threads(entries) catch {
    err => "error:" + @lib.error_kind(err)
  } noraise {
    list =>
      match list {
        None => "no-threads"
        Some(ts) => {
          let items : Array[String] = []
          for t in ts {
            items.push(thread_line(t))
          }
          "count=" + ts.length().to_string() + " " + items.join(" ; ")
        }
      }
  }
}

///|
/// SystemInfo's architecture number; use the "unknown" 0xffff when the stream is absent,
/// so contexts fall into Undecoded instead of guessing.
fn corpus_arch(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> UInt16 {
  try dump.system_info(entries) catch {
    _ => 0xffff
  } noraise {
    info =>
      match info {
        None => 0xffff
        Some(si) => si.processor_architecture
      }
  }
}

///|
/// SystemInfo's platform number; assume Windows (0) when absent, and the label tables follow EXCEPTION_*.
fn corpus_platform(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> UInt32 {
  try dump.system_info(entries) catch {
    _ => 0U
  } noraise {
    info =>
      match info {
        None => 0U
        Some(si) => si.platform_id
      }
  }
}

///|
/// One CONTEXT line. Unreadable ones are recorded as `error:<kind>`, absent ones as `none`.
fn context_line(
  dump : @lib.Dump,
  arch : UInt16,
  loc : @lib.LocationDescriptor,
) -> String {
  try dump.read_context(arch, loc) catch {
    err => "error:" + @lib.error_kind(err)
  } noraise {
    ctx =>
      match ctx {
        None => "none"
        Some(c) => @lib.context_summary(c)
      }
  }
}

///|
/// CONTEXT summaries of the first two threads: `0:<line> ; 1:<line>`.
/// Taking only two is deliberate—a full-memory dump can have hundreds of threads, and a
/// golden stuffed with registers makes the diff completely unreadable, while a shifted
/// field table already shows up on the first two.
pub fn thread_context_lines(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String raise {
  let arch = corpus_arch(dump, entries)
  let ts = match dump.threads(entries) {
    None => []
    Some(ts) => ts
  }
  let items : Array[String] = []
  let limit = if ts.length() < 2 { ts.length() } else { 2 }
  let mut i = 0
  while i < limit {
    items.push(i.to_string() + ":" + context_line(dump, arch, ts[i].context))
    i = i + 1
  }
  items.join(" ; ")
}

///|
/// Crash-site line: exception code + platform label + address attribution + parameter decoding + crash CONTEXT.
/// `kind/target/status` are only meaningful for ACCESS_VIOLATION / IN_PAGE_ERROR and are `-`
/// otherwise, so "this convention does not apply" and "the convention value is 0" never
/// get conflated in an assertion.
pub fn exception_line(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String raise {
  let platform = corpus_platform(dump, entries)
  let arch = corpus_arch(dump, entries)
  let modules : Array[@lib.Module] = match dump.modules(entries) {
    None => []
    Some(list) => list.modules
  }
  let ts : Array[@lib.Thread] = match dump.threads(entries) {
    None => []
    Some(list) => list
  }
  try dump.exception(entries) catch {
    err => "error:" + @lib.error_kind(err)
  } noraise {
    exc =>
      match exc {
        None => "no-exception"
        Some(e) => {
          let ps : Array[String] = []
          for p in e.parameters {
            ps.push(chex(p))
          }
          let flags = @lib.describe_exception_flags(e.flags)
          let thread_index = match @lib.find_thread_by_id(ts, e.thread_id) {
            None => "-"
            Some((i, _)) => i.to_string()
          }
          let kind = match @lib.memory_access_kind(e.code, e.parameters) {
            None => "-"
            Some(k) => k
          }
          let target = match e.fault_address() {
            None => "-"
            Some(a) => chex(a)
          }
          let status = match e.underlying_status() {
            None => "-"
            Some(s) => chex(s)
          }
          "tid=" +
          e.thread_id.to_string() +
          " code=0x" +
          e.code.to_string(radix=16) +
          "/" +
          @lib.exception_code_label(platform, e.code) +
          " flags=0x" +
          e.flags.to_string(radix=16) +
          "/" +
          (if flags.is_empty() { "-" } else { flags.join(",") }) +
          " addr=" +
          chex(e.address) +
          "@" +
          @lib.address_module_line(modules, e.address) +
          " nest=" +
          chex(e.nested_record_address) +
          " np=" +
          e.number_parameters.to_string() +
          " p=" +
          (if ps.is_empty() { "-" } else { ps.join(",") }) +
          " kind=" +
          kind +
          " target=" +
          target +
          " status=" +
          status +
          " ctx=" +
          loc_line(e.thread_context) +
          " thread=" +
          thread_index +
          " crash=" +
          context_line(dump, arch, e.thread_context)
        }
      }
  }
}

///|
/// One assertion pins the thread table, the crash CONTEXT, and the exception stream.
pub fn assert_threads_and_exception(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  want_threads : String,
  want_contexts : String,
  want_exception : String,
) -> Unit raise {
  assert_eq((name, thread_list_line(dump, entries)), (name, want_threads))
  assert_eq((name, thread_context_lines(dump, entries)), (name, want_contexts))
  assert_eq((name, exception_line(dump, entries)), (name, want_exception))
}

///|
/// One memory region line: `0x<virtual address>+<readable size>@<file location>`.
fn region_line(r : @lib.MemoryRegion) -> String {
  chex(r.start_address) +
  "+" +
  r.size.to_string() +
  "@" +
  r.file_rva.to_string()
}

///|
/// Memory index line: `n=<available regions> dropped=<dropped count> total=<readable bytes> head=[first 3 regions] tail=[last region]`.
/// Taking only the first 3 and the last 1 is deliberate: a full-memory dump has dozens to
/// hundreds of regions, and a golden stuffed with RVAs cannot be diffed, while the
/// sorting and truncation behaviors already show up in the first 3.
pub fn memory_map_line(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String raise {
  match dump.memory_map(entries) {
    None => "no-memory"
    Some(m) => {
      let rs = m.regions
      let head : Array[String] = []
      let mut i = 0
      while i < rs.length() && i < 3 {
        head.push(region_line(rs[i]))
        i = i + 1
      }
      let tail : Array[String] = []
      if rs.length() > 0 {
        tail.push(region_line(rs[rs.length() - 1]))
      }
      "n=" +
      rs.length().to_string() +
      " dropped=" +
      m.dropped.to_string() +
      " total=" +
      m.total_bytes().to_string() +
      " head=[" +
      head.join(" ") +
      "] tail=[" +
      tail.join(" ") +
      "]"
    }
  }
}

///|
/// Two-digit lowercase hex of a single byte.
fn byte_hex(b : Byte) -> String {
  let digits = "0123456789abcdef".to_array()
  let v = b.to_int()
  digits[v / 16].to_string() + digits[v % 16].to_string()
}

///|
fn bytes_hex(bs : Bytes?) -> String {
  match bs {
    None => "-"
    Some(body) => {
      let parts : Array[String] = []
      for b in body {
        parts.push(byte_hex(b))
      }
      parts.join("")
    }
  }
}

///|
/// A small "virtual address -> file location" segment: `0x<address>-><file offset>`, `-` when unmapped;
/// when the address itself is unavailable (no CONTEXT, or an unrecognized field table) the whole segment is `-`.
fn mapped_text(map : @lib.MemoryMap, address : UInt64?) -> String {
  match address {
    None => "-"
    Some(a) => {
      let file_pos = match map.file_rva_for(a, 1UL) {
        None => "-"
        Some(f) => f.to_string()
      }
      chex(a) + "->" + file_pos
    }
  }
}

///|
/// Take ip/sp from the CONTEXT. An unrecognized table or an unreadable one both count as (None, None),
/// so the assertion line shows `-` instead of the whole line disappearing.
fn context_pointers(
  dump : @lib.Dump,
  arch : UInt16,
  loc : @lib.LocationDescriptor,
) -> (UInt64?, UInt64?) {
  try dump.read_context(arch, loc) catch {
    _ => (None, None)
  } noraise {
    c =>
      match c {
        None => (None, None)
        Some(ctx) => (ctx.instruction_pointer(), ctx.stack_pointer())
      }
  }
}

///|
/// One line per thread: `TID <id> sp=<mapped> b16=<raw 16 bytes at sp> ip=<mapped> stk=<mapped>`.
/// This line is the end-to-end evidence of "read by virtual address": after an address maps
/// to a file location, the bytes at that location are printed verbatim, so what the diff
/// compares is **memory contents**, not my offsets.
///
/// The contents can be independently falsified, and the corpus has three places for it:
/// - full-dump.dmp (Memory64List, the stack RVAs in the thread records are all 0, so positions
///   can only be computed by accumulation): the first byte at ip is `cc` = int 3, which
///   exactly matches that dump's EXCEPTION_BREAKPOINT; at the other three threads the first
///   8 bytes at sp are values like 0x00007ffb60402dc7 falling inside ntdll's module range—
///   they are return addresses, and would be garbage if the accumulation rule were wrong.
/// - test.dmp (XP x86): the three dwords at sp, 0x7c90e9c0 / 0x7c8025cb / 0x7b8, all lie in
///   the ntdll range, and the file location stk maps to matches the 5689 the thread record
///   itself declares.
/// - linux-mini.dmp: at ip is `c7042545000000` = `movl $0x45,0x45`, exactly matching that
///   stream's "out-of-bounds write of 0x45", so the pointer-to-instruction mapping is
///   verified once by the instruction itself.
pub fn memory_read_lines(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> String raise {
  let arch = corpus_arch(dump, entries)
  match dump.memory_map(entries) {
    None => "no-memory"
    Some(map) =>
      match dump.threads(entries) {
        None => "no-threads"
        Some(ts) => {
          let lines : Array[String] = []
          for t in ts {
            let (ip, sp) = context_pointers(dump, arch, t.context)
            let sample = try
              dump.read_memory_at(map, sp_or_zero(sp), 16)
            catch {
              _ => None
            } noraise {
              b => b
            }
            lines.push(
              "TID " +
              t.id.to_string() +
              " sp=" +
              mapped_text(map, sp) +
              " b16=" +
              bytes_hex(sample) +
              " ip=" +
              mapped_text(map, ip) +
              " stk=" +
              mapped_text(map, Some(t.stack.start_address)),
            )
          }
          lines.join(" ; ")
        }
      }
  }
}

///|
/// Give 0 when `sp` is absent: read_memory_at returns None for unmapped addresses, which lands as `-`.
fn sp_or_zero(sp : UInt64?) -> UInt64 {
  match sp {
    None => 0UL
    Some(a) => a
  }
}

///|
/// One assertion pins both the memory index and "read by virtual address".
pub fn assert_memory(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  want_map : String,
  want_reads : String,
) -> Unit raise {
  assert_eq((name, memory_map_line(dump, entries)), (name, want_map))
  assert_eq((name, memory_read_lines(dump, entries)), (name, want_reads))
}

///|
/// Booleans are written y/n in summary lines so they cannot be confused with field-value texts like `true`/`false`.
fn yn(b : Bool) -> String {
  if b {
    "y"
  } else {
    "n"
  }
}

///|
/// Module table: a missing stream counts as an empty table, letting the stack walk itself write "no module table" into notes.
fn corpus_modules(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Array[@lib.Module] raise {
  match dump.modules(entries) {
    None => []
    Some(list) => list.modules
  }
}

///|
/// Function-table side evidence: a missing stream or an invalid layout collapses into None, without interrupting the whole assertion group here.
fn corpus_function_table(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> @lib.FunctionTableInfo? {
  try dump.function_table(entries) catch {
    _ => None
  } noraise {
    v => v
  }
}

///|
/// Short line for one frame: `<kind>@<instruction address> slot=<stack slot> mod=<module+offset> ft=<-/in/out> rs=<…>`.
/// The module base address is not printed—the module table's golden pins it separately,
/// and repeating it would only make the diff longer.
fn stack_frame_short(f : @lib.StackFrame) -> String {
  let slot = match f.stack_address {
    None => "-"
    Some(a) => chex(a)
  }
  let mod_text = match f.offset {
    Some(o) => f.module_name + "+" + chex(o)
    None => if f.module_name.length() > 0 { f.module_name } else { "-" }
  }
  let ft = match f.in_function_table {
    None => "-"
    Some(true) => "in"
    Some(false) => "out"
  }
  f.kind +
  "@" +
  chex(f.address) +
  " slot=" +
  slot +
  " mod=" +
  mod_text +
  " ft=" +
  ft +
  " rs=" +
  f.return_site
}

///|
/// One line per stack: first the statistics (layout, pointer width, walkable or not, window,
/// total frames, fp frames, slots scanned, whether it hit the limit), then the first `show`
/// frames, then the notes verbatim.
///
/// Printing only the first few frames is deliberate: the full table with the default 64-frame
/// cap would make the diff completely unreadable, and since the total frame count, fp frame
/// count, and scanned slot count all head the line, a few missing frames are visible at a
/// glance; whether every frame in the table is right is covered by the "independently
/// extracted slot table" and `assert_walk_invariants`.
pub fn stack_walk_line_of(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  thread : @lib.Thread,
  loc : @lib.LocationDescriptor,
  opts : @lib.StackWalkOptions,
  show : Int32,
) -> String raise {
  let arch = corpus_arch(dump, entries)
  let ctx = try dump.read_context(arch, loc) catch {
    _ => None
  } noraise {
    c => c
  }
  match (ctx, dump.memory_map(entries)) {
    (None, _) => "ctx-unreadable loc=" + loc_line(loc)
    (Some(_), None) => "no-memory"
    (Some(c), Some(m)) =>
      match
        try_walk(
          dump,
          m,
          corpus_modules(dump, entries),
          corpus_function_table(dump, entries),
          thread,
          c,
          opts,
        ) {
        (Some(w), _) => stack_walk_line_text(thread, w, show)
        (None, kind) => "walk-error:" + kind
      }
  }
}

///|
/// The walk itself. This function **deliberately does not raise**: only inside a function with no exposed error type
/// is the `err` bound by catch a ParseError rather than being widened to Error, which is what makes the category name available.
/// A stack walk throwing on the corpus is always an implementation bug; the caller sees the `walk-error:` prefix and fails.
fn try_walk(
  dump : @lib.Dump,
  map : @lib.MemoryMap,
  modules : Array[@lib.Module],
  ft : @lib.FunctionTableInfo?,
  thread : @lib.Thread,
  ctx : @lib.Context,
  opts : @lib.StackWalkOptions,
) -> (@lib.StackWalk?, String) {
  try dump.walk_thread_stack(map, modules, ft, thread, ctx, opts) catch {
    err => (None, @lib.error_kind(err))
  } noraise {
    w => (Some(w), "")
  }
}

///|
/// The text for one stack. Split out so that `try_walk` stays non-raising (see its comment).
fn stack_walk_line_text(
  thread : @lib.Thread,
  w : @lib.StackWalk,
  show : Int32,
) -> String {
  let items : Array[String] = []
  let mut i = 0
  while i < w.frames.length() && i < show {
    items.push(stack_frame_short(w.frames[i]))
    i = i + 1
  }
  let more = if w.frames.length() > show { " …" } else { "" }
  let window = match (w.window_low, w.window_high) {
    (Some(l), Some(h)) => chex(l) + "+" + (h - l).to_string()
    _ => "-"
  }
  let reason = if w.reason.is_empty() { "-" } else { w.reason }
  let notes = if w.notes.is_empty() { "-" } else { w.notes.join(" ;; ") }
  "tid=" +
  thread.id.to_string() +
  " layout=" +
  w.layout +
  " ps=" +
  w.pointer_size.to_string() +
  " supported=" +
  yn(w.supported) +
  " reason=" +
  reason +
  " window=" +
  window +
  " frames=" +
  w.frames.length().to_string() +
  " fp=" +
  w.fp_frames.to_string() +
  " slots=" +
  w.scanned_slots.to_string() +
  " limited=" +
  yn(w.scan_limited) +
  " [" +
  items.join(" ; ") +
  more +
  "] notes=[" +
  notes +
  "]"
}

///|
/// Which context the crash site should use: if the exception stream is present, use the CONTEXT it carries (that is
/// the moment of the crash); otherwise fall back to entry 0 of the thread table. Returns None when there is no thread
/// stream, or when the thread id written in the exception is not in the table.
fn crash_target(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> (String, @lib.Thread, @lib.LocationDescriptor)? raise {
  let ts : Array[@lib.Thread] = match dump.threads(entries) {
    None => []
    Some(list) => list
  }
  let exc = try dump.exception(entries) catch {
    _ => None
  } noraise {
    e => e
  }
  if ts.length() == 0 {
    None
  } else {
    match exc {
      None => Some(("thread0", ts[0], ts[0].context))
      Some(e) =>
        match @lib.find_thread_by_id(ts, e.thread_id) {
          None => None
          Some((_, t)) => Some(("exception", t, e.thread_context))
        }
    }
  }
}

///|
/// The line for the crash-site stack. `src=` marks which context was used, matching the registers in the
/// exception-stream golden's `thread=0 crash=` segment; for corpora where the two contexts' instruction pointers
/// differ (test.dmp), this line shows `src=exception` and the first frame's address equals the exception stream's eip.
pub fn crash_stack_walk_line(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  opts : @lib.StackWalkOptions,
  show : Int32,
) -> String raise {
  match crash_target(dump, entries) {
    None => "no-crash-target"
    Some((src, t, loc)) =>
      src + " " + stack_walk_line_of(dump, entries, t, loc, opts, show)
  }
}

///|
/// One assertion pins the crash-site stack: which context was used, whether it walked, how many frames it produced,
/// what the first few frames are, and what notes were given for a broken chain or truncation — all in this one line.
pub fn assert_crash_stack_walk(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  opts : @lib.StackWalkOptions,
  show : Int32,
  want : String,
) -> Unit raise {
  assert_eq(
    (name, crash_stack_walk_line(dump, entries, opts, show)),
    (name, want),
  )
}

///|
/// The symbolization result for each frame of the crash-site stack, frames separated by ` ; `; the leading `src=`
/// marks which context was used. When the walk fails it gives `walk-error:<kind>`, so the golden diff points straight at the cause.
fn symbol_frame_line(f : @lib.StackFrame, t : @lib.SymbolTarget) -> String {
  let line = match t.line {
    None => "-"
    Some(v) => v.to_string()
  }
  let off = match t.offset {
    None => "-"
    Some(v) => chex(v)
  }
  let by = if t.matched_by.is_empty() { "-" } else { t.matched_by }
  let kind = if t.kind.is_empty() { "-" } else { t.kind }
  let nm = if t.name.is_empty() { "-" } else { t.name }
  let file = if t.file.is_empty() { "-" } else { t.file }
  let source = if t.symbol_source.is_empty() { "-" } else { t.symbol_source }
  chex(f.address) +
  " " +
  t.status +
  "/" +
  by +
  "/" +
  kind +
  " name=" +
  nm +
  " at=" +
  file +
  ":" +
  line +
  " +sym=" +
  off +
  " src=" +
  source +
  " n=" +
  t.candidates.to_string() +
  " | " +
  @lib.symbol_target_line(t)
}

///|
/// The symbolization result for each frame of the crash-site stack, frames separated by ` ; `.
pub fn crash_symbol_lines(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  store : @lib.SymbolStore,
) -> String raise {
  let modules = corpus_modules(dump, entries)
  match crash_target(dump, entries) {
    None => "no-crash-target"
    Some((src, t, loc)) => {
      let ctx = try dump.read_context(corpus_arch(dump, entries), loc) catch {
        _ => None
      } noraise {
        c => c
      }
      match (ctx, dump.memory_map(entries)) {
        (Some(c), Some(m)) =>
          match
            try_walk(
              dump,
              m,
              modules,
              corpus_function_table(dump, entries),
              t,
              c,
              @lib.stack_walk_options_default(),
            ) {
            (Some(w), _) => {
              let items : Array[String] = []
              for f in w.frames {
                items.push(
                  symbol_frame_line(f, @lib.symbolize_frame(f, modules, store)),
                )
              }
              src + " " + items.join(" ; ")
            }
            (None, kind) => "walk-error:" + kind
          }
        _ => "no-context-or-memory"
      }
    }
  }
}

///|
/// A frame's module attribution must agree with the module table itself: the index is in range, the name matches,
/// the offset equals "address minus base", and the address really lies within [base, base + size).
fn assert_module_self_consistent(
  tag : String,
  modules : Array[@lib.Module],
  f : @lib.StackFrame,
) -> Unit raise {
  match f.module_index {
    None => {
      assert_eq((tag, f.module_name), (tag, ""))
      assert_eq((tag, f.offset), (tag, None))
    }
    Some(i) => {
      assert_true(
        i >= 0 && i < modules.length(),
        msg=tag + " module index out of range",
      )
      let m = modules[i]
      assert_eq((tag, f.module_name), (tag, m.name))
      match f.offset {
        None => fail(tag + " hit a module but got no offset")
        Some(o) => {
          assert_true(
            f.address >= m.base_of_image && f.address < m.end_address(),
            msg=tag +
              " attributed to a module but the address is outside its range",
          )
          assert_eq((tag, o), (tag, f.address - m.base_of_image))
        }
      }
    }
  }
}

///|
/// Structural invariants of the stack walk. Complementary to the per-frame golden: the golden moves whenever
/// the heuristics change, this group does not — it only requires the output to be self-consistent, and any
/// violated rule is an implementation bug.
pub fn assert_walk_invariants(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit raise {
  let arch = corpus_arch(dump, entries)
  let ts : Array[@lib.Thread] = match dump.threads(entries) {
    None => []
    Some(list) => list
  }
  let modules = corpus_modules(dump, entries)
  let map = dump.memory_map(entries)
  let ft = corpus_function_table(dump, entries)
  let cases : Array[@lib.StackWalkOptions] = [
    @lib.stack_walk_options_default(),
    { max_frames: 0, max_scan_bytes: 4096L, scan: true, },
    { max_frames: 3, max_scan_bytes: 64L, scan: true, },
    { max_frames: 64, max_scan_bytes: 4096L, scan: false, },
  ]
  let mut walked = 0
  let mut i = 0
  while i < ts.length() {
    let t = ts[i]
    let ctx = try dump.read_context(arch, t.context) catch {
      _ => None
    } noraise {
      c => c
    }
    let mut o = 0
    while o < cases.length() {
      let opts = cases[o]
      match (ctx, map) {
        (Some(c), Some(m)) => {
          let tag = name + " tid=" + t.id.to_string() + " opts=" + o.to_string()
          let w = match try_walk(dump, m, modules, ft, t, c, opts) {
            (Some(v), _) => v
            (None, kind) =>
              fail(tag + " stack walk should not throw, but threw " + kind)
          }
          walked = walked + 1
          assert_eq((tag, w.frames.length() >= 1), (tag, true))
          let first = w.frames[0]
          assert_eq((tag, first.kind), (tag, "context"))
          assert_eq((tag, first.stack_address), (tag, None))
          assert_eq((tag, first.return_site), (tag, "unknown"))
          assert_eq((tag, first.address), (tag, context_instruction_pointer(c)))
          let mut j = 1
          while j < w.frames.length() {
            let prev = slot_or_zero(w.frames[j - 1].stack_address)
            let cur = slot_or_zero(w.frames[j].stack_address)
            assert_eq((tag, prev < cur), (tag, true))
            let k = w.frames[j].kind
            assert_true(
              k == "fp" || k == "scan",
              msg=tag +
                " frame " +
                j.to_string() +
                " has an out-of-range kind: " +
                k,
            )
            let rs = w.frames[j].return_site
            assert_true(
              rs == "call" || rs == "no_call" || rs == "unknown",
              msg=tag + " return-site label out of range: " + rs,
            )
            assert_module_self_consistent(tag, modules, w.frames[j])
            j = j + 1
          }
          assert_eq(
            (tag, w.frames.length() - 1 <= opts.max_frames),
            (tag, true),
          )
          let mut fp = 0
          let mut scan_kind = 0
          for f in w.frames {
            if f.kind == "fp" {
              fp = fp + 1
            }
            if f.kind == "scan" {
              scan_kind = scan_kind + 1
            }
          }
          assert_eq((tag, w.fp_frames), (tag, fp))
          if !opts.scan {
            assert_eq((tag, scan_kind), (tag, 0))
          }
          if !w.supported {
            assert_eq((tag, w.frames.length()), (tag, 1))
            assert_eq((tag, w.reason.length() > 0), (tag, true))
          }
        }
        _ => ()
      }
      o = o + 1
    }
    i = i + 1
  }
  assert_true(
    if ts.length() == 0 {
      true
    } else {
      walked > 0
    },
    msg=name +
      " has no walkable stack at all; this assertion group would be a no-op",
  )
}

///|
/// The first frame's instruction pointer must equal the one in the CONTEXT verbatim; a table without a
/// pointer is treated as 0, and such a corpus leaves a "no instruction pointer in the context" note in the walk.
fn context_instruction_pointer(c : @lib.Context) -> UInt64 {
  match c.instruction_pointer() {
    Some(v) => v
    None => 0UL
  }
}

///|
fn slot_or_zero(a : UInt64?) -> UInt64 {
  match a {
    None => 0UL
    Some(v) => v
  }
}

///|
/// Fetch one of the long-tail streams: a missing stream must yield None, a thrown error fails outright —
/// no panicking and no inventing records. MoonBit has no way to write "accept a generic closure that
/// raises" covering these five different types, so each type is written out once; that reads more plainly
/// than building an abstraction.
pub fn assert_long_tail_absent(
  name : String,
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit raise {
  let types : Array[(String, UInt32)] = [
    ("UnloadedModuleListStream", @lib.unloaded_module_list_stream),
    ("HandleDataStream", @lib.handle_data_stream),
    ("FunctionTableStream", @lib.function_table_stream),
    ("ThreadInfoListStream", @lib.thread_info_list_stream),
    ("ThreadNamesStream", @lib.thread_names_stream),
  ]
  // None of these stream types exist anywhere in the corpus: the directory must not list them, which is what "the generator did not write them" means.
  for (label, stream_type) in types {
    assert_eq(
      (name, label, @lib.get_stream(entries, stream_type) is Some(_)),
      (name, label, false),
    )
  }
  let unloaded = try dump.unloaded_modules(entries) catch {
    err =>
      fail(
        name +
        " missing UnloadedModuleList should return None, but threw " +
        @lib.error_kind(err),
      )
  } noraise {
    result => result
  }
  assert_eq((name, unloaded is None), (name, true))
  let handles = try dump.handles(entries) catch {
    err =>
      fail(
        name +
        " missing HandleData should return None, but threw " +
        @lib.error_kind(err),
      )
  } noraise {
    result => result
  }
  assert_eq((name, handles is None), (name, true))
  let function_table = try dump.function_table(entries) catch {
    err =>
      fail(
        name +
        " missing FunctionTable should return None, but threw " +
        @lib.error_kind(err),
      )
  } noraise {
    result => result
  }
  assert_eq((name, function_table is None), (name, true))
  let thread_infos = try dump.thread_infos(entries) catch {
    err =>
      fail(
        name +
        " missing ThreadInfoList should return None, but threw " +
        @lib.error_kind(err),
      )
  } noraise {
    result => result
  }
  assert_eq((name, thread_infos is None), (name, true))
  let thread_names = try dump.thread_names(entries) catch {
    err =>
      fail(
        name +
        " missing ThreadNames should return None, but threw " +
        @lib.error_kind(err),
      )
  } noraise {
    result => result
  }
  assert_eq((name, thread_names is None), (name, true))
}
