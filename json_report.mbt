// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
/// JSON report layer: maps each already-parsed piece of data verbatim into a `Json` document.
///
/// This is **moondump's own schema** (`schema: "moondump/v1"`). It carries the same fields
/// as the CLI's human-readable output, batch for batch, just reshaped into a form a machine
/// can consume directly:
/// - every field is always present; when a value cannot be obtained it is `null` — absence
///   is never expressed by omitting a key;
/// - addresses are always hex strings (`"0x7ff6e7c40000"`), 64-bit lengths are always
///   decimal strings; only quantities that fit in 32 bits are JSON numbers — double
///   precision is exact only up to 2^53, and addresses must not take that risk;
/// - a section that fails to parse is written as `{"kind": "<kind>", "message": "<original text>"}`,
///   so one malformed stream never keeps the whole document from coming out. When even the
///   file cannot be read, `json_failure` is used: same shape, just attached to the top-level
///   `error`.
///
/// Offline there is no way to compare byte-for-byte against `minidump-stackwalk --json`,
/// so this layer **does not claim** field compatibility with it; what it does claim is:
/// this layer introduces no new heuristics, and every value comes from fields the format
/// layer has already computed.

///|
/// The schema number of this document. Any change to fields or their meaning means changing
/// this, so readers never have to guess.
let json_schema = "moondump/v1"

///|
/// Truncation cap for long lists. Memory regions, handles and the like can number in the tens
/// of thousands of records in a full dump; stuffing them all into one JSON document only keeps
/// readers from opening it. Truncation is stated explicitly in the document, never dropped silently.
let json_list_cap = 2000

///|
pub fn json_list_cap_value() -> Int32 {
  json_list_cap
}

///|
/// Switches for `report_json`.
pub(all) struct JsonOptions {
  /// Dump path, only so it can be written into `file.path`; the library itself knows no path, the CLI passes it in.
  path : String?
  /// When given, per-frame symbolication results go into `symbol`; otherwise it is `null`.
  symbols : SymbolStore?
  /// Stack-walk parameters, matching the CLI's `--max-frames` / `--no-scan`.
  walk : StackWalkOptions
  /// When `true`, every thread is walked; otherwise only the crash thread plus the first `thread_walk_limit` threads.
  all_threads : Bool
}

///|
/// Default per-thread walk cap, matching the CLI's default behavior.
pub let thread_walk_limit : Int32 = 8

///|
pub fn json_options_default() -> JsonOptions {
  {
    path: None,
    symbols: None,
    walk: stack_walk_options_default(),
    all_threads: false,
  }
}

///|
// The helpers below fold MoonBit values into Json; missing values uniformly become null.
fn jnull() -> Json {
  Json::null()
}

///|
fn jstr(s : String) -> Json {
  Json::string(s)
}

///|
fn jbool(b : Bool) -> Json {
  Json::boolean(b)
}

///|
fn ju32(v : UInt32) -> Json {
  Json::number(v.to_double())
}

///|
fn ju16(v : UInt16) -> Json {
  Json::number(v.to_uint().to_double())
}

///|
fn jbyte(v : Byte) -> Json {
  Json::number(v.to_double())
}

///|
fn ji32(v : Int32) -> Json {
  Json::number(v.to_double())
}

///|
fn ji64(v : Int64) -> Json {
  Json::number(v.to_double())
}

///|
/// Optional 32-bit quantity: a number when present, null when absent.
fn ju32_opt(v : UInt32?) -> Json {
  match v {
    None => jnull()
    Some(x) => ju32(x)
  }
}

///|
/// Also an optional 32-bit value, but it is inherently an identifier (process cookie and
/// the like), so it is emitted as a hex string rather than mixed into the numbers.
fn ju32_hex_opt(v : UInt32?) -> Json {
  match v {
    None => jnull()
    Some(x) => jhex(x.to_uint64())
  }
}

///|
/// Addresses: hex strings. 64-bit lengths also go through the string channel (`jdec`), never through a double.
fn jhex(v : UInt64) -> Json {
  jstr(hex_uint(v))
}

///|
fn jhex_opt(v : UInt64?) -> Json {
  match v {
    None => jnull()
    Some(x) => jhex(x)
  }
}

///|
fn jdec(v : UInt64) -> Json {
  jstr(v.to_string())
}

///|
fn jstr_opt(v : String?) -> Json {
  match v {
    None => jnull()
    Some(s) => jstr(s)
  }
}

///|
fn jbool_opt(v : Bool?) -> Json {
  match v {
    None => jnull()
    Some(b) => jbool(b)
  }
}

///|
fn ji64_opt(v : Int64?) -> Json {
  match v {
    None => jnull()
    Some(x) => ji64(x)
  }
}

///|
/// Builds objects in insertion order. `Json::object` takes a `Map[String, Json]`,
/// and MoonBit's Map preserves insertion order, so field order is exactly the order written here.
fn jobj(pairs : Array[(String, Json)]) -> Json {
  let m : Map[String, Json] = Map([])
  for (k, v) in pairs {
    m[k] = v
  }
  Json::object(m)
}

///|
fn jarr(items : Array[Json]) -> Json {
  Json::array(items)
}

///|
/// One failure section: a kind name plus the full text. What a catch binds in a non-raise
/// function is still a ParseError, so both values are retrievable (same pattern as the
/// `corpus` side).
/// When the whole document cannot be read out (the file cannot even be opened), the same
/// shape is used, see `json_failure`.
fn jerror(kind : String, text : String) -> Json {
  jobj([("kind", jstr(kind)), ("message", jstr(text))])
}

///|
/// Truncates to a cap, and reports whether truncation happened.
fn j_list(items : Array[Json], cap : Int32) -> Json {
  let out : Array[Json] = []
  let mut i = 0
  while i < items.length() && i < cap {
    out.push(items[i])
    i = i + 1
  }
  let truncated = if items.length() > cap { true } else { false }
  jobj([
    ("count", ji32(items.length())),
    ("truncated", jbool(truncated)),
    ("items", jarr(out)),
  ])
}

///|
/// A long run of hex parameters (exception parameters and raw CPU words have this shape).
fn j_hex_array(items : Array[UInt64]) -> Json {
  let out : Array[Json] = []
  for v in items {
    out.push(jhex(v))
  }
  jarr(out)
}

///|
/// Array of strings.
fn j_str_array(items : Array[String]) -> Json {
  let out : Array[Json] = []
  for s in items {
    out.push(jstr(s))
  }
  jarr(out)
}

///|
/// Address attribution: `{index,name,base,offset}` on a module hit, otherwise `null`.
fn j_module_at(modules : Array[Module], address : UInt64) -> Json {
  match find_module(modules, address) {
    None => jnull()
    Some((i, m)) =>
      jobj([
        ("index", ji32(i)),
        ("name", jstr(m.name)),
        ("base", jhex(m.base_of_image)),
        ("end", jhex(m.end_address())),
        ("offset", jhex(address - m.base_of_image)),
      ])
  }
}

///|
/// `MINIDUMP_MEMORY_DESCRIPTOR`: the stack and the context location both have this shape.
fn j_location(loc : LocationDescriptor) -> Json {
  jobj([("size", ju32(loc.size)), ("rva", jdec(loc.rva))])
}

///|
fn j_memory_descriptor(d : MemoryDescriptor) -> Json {
  jobj([
    ("start_address", jhex(d.start_address)),
    ("size", ju32(d.location.size)),
    ("rva", jdec(d.location.rva)),
  ])
}

///|
/// Context registers: what `Context::registers()` gives is "name → already-formatted text";
/// it is written verbatim into an object here, without assembling a second set of hex.
fn j_registers(ctx : Context) -> Json {
  let pairs : Array[(String, Json)] = []
  for (name, text) in ctx.registers() {
    pairs.push((name, jstr(text)))
  }
  pairs.push(("layout", jstr(ctx.layout_name())))
  let arch = ctx.flag_architecture()
  let flags = ctx.context_flags()
  let described = describe_context_flags(arch, flags)
  pairs.push(("context_flags", jhex(flags.to_uint64())))
  pairs.push(("context_flag_bits", j_str_array(described)))
  jobj(pairs)
}

///|
/// The SystemInfo section. `cpu` is the raw CPUID words, `cpu_vendor` is the vendor string
/// probed out of them, null when unavailable (Linux/Mac dumps usually lack it).
fn j_system_info(si : SystemInfo) -> Json {
  let fms = x86_family_model_stepping(si)
  let words : Array[Json] = []
  for w in si.cpu {
    words.push(jhex(w.to_uint64()))
  }
  jobj([
    ("processor_architecture", ju16(si.processor_architecture)),
    ("architecture", jstr(architecture_name(si.processor_architecture))),
    ("processor_level", ju16(si.processor_level)),
    ("processor_revision", ju16(si.processor_revision)),
    ("number_of_processors", jbyte(si.number_of_processors)),
    ("product_type", jbyte(si.product_type)),
    ("product_type_name", jstr(product_type_name(si.product_type))),
    ("major_version", ju32(si.major_version)),
    ("minor_version", ju32(si.minor_version)),
    ("build_number", ju32(si.build_number)),
    ("version", jstr(version_string(si))),
    ("platform_id", ju32(si.platform_id)),
    ("platform_name", jstr(platform_id_name(si.platform_id))),
    ("csd_version", jstr_opt(csd_or_null(si.csd_version))),
    ("suite_mask", ju16(si.suite_mask)),
    ("suite_mask_bits", j_str_array(describe_suite_mask(si.suite_mask))),
    ("cpu_vendor", jstr_opt(si.cpu_vendor)),
    ("family", ji32(fms.0)),
    ("model", ji32(fms.1)),
    ("stepping", ji32(fms.2)),
    ("cpu_raw", jarr(words)),
  ])
}

///|
/// An empty string reads better as null in JSON: upstream gives an empty string when `csd_version` is unset.
fn csd_or_null(s : String) -> String? {
  if s.length() == 0 {
    None
  } else {
    Some(s)
  }
}

///|
/// The optional blocks of each MiscInfo version. A whole group that was not provided is null,
/// not 0 — this matches the text output.
fn j_misc_info(mi : MiscInfo) -> Json {
  let times = match mi.process_times {
    None => jnull()
    Some(t) =>
      jobj([
        ("create_time", ju32(t.create_time)),
        ("user_time", ju32(t.user_time)),
        ("kernel_time", ju32(t.kernel_time)),
      ])
  }
  let power = match mi.processor_power_info {
    None => jnull()
    Some(p) =>
      jobj([
        ("max_mhz", ju32(p.max_mhz)),
        ("current_mhz", ju32(p.current_mhz)),
        ("mhz_limit", ju32(p.mhz_limit)),
        ("max_idle_state", ju32(p.max_idle_state)),
        ("current_idle_state", ju32(p.current_idle_state)),
      ])
  }
  let tz = match mi.time_zone {
    None => jnull()
    Some(z) =>
      jobj([
        ("bias", ji32(z.bias)),
        ("offset", jstr(time_zone_offset_text(z.bias))),
        ("standard_name", jstr(z.standard_name)),
        ("standard_bias", ji32(z.standard_bias)),
        ("standard_date", j_system_time(z.standard_date)),
        ("daylight_name", jstr(z.daylight_name)),
        ("daylight_bias", ji32(z.daylight_bias)),
        ("daylight_date", j_system_time(z.daylight_date)),
      ])
  }
  let xstate = match mi.xstate_config {
    None => jnull()
    Some(x) => {
      let feats : Array[Json] = []
      let mut fi : Int32 = 0
      while fi < x.features.length() {
        let f = x.features[fi]
        feats.push(
          jobj([
            ("index", ji32(fi)),
            ("enabled", jbool(x.enabled(fi))),
            ("size", ju32(f.size)),
            ("offset", ju32(f.offset)),
          ]),
        )
        fi = fi + 1
      }
      jobj([
        ("size_of_info", ju32(x.size_of_info)),
        ("context_size", ju32(x.context_size)),
        ("enabled_features", jdec(x.enabled_features)),
        ("features", j_list(feats, 64)),
      ])
    }
  }
  jobj([
    ("info_version", ju32(mi.info_version)),
    ("size_of_info", ju32(mi.size_of_info)),
    ("flags1", jhex(mi.flags1.to_uint64())),
    ("flags1_bits", j_str_array(describe_misc_flags(mi.flags1))),
    ("process_id", ju32_opt(mi.process_id)),
    ("process_times", times),
    ("processor_power_info", power),
    ("process_integrity_level", ju32_opt(mi.process_integrity_level)),
    ("process_execute_flags", ju32_opt(mi.process_execute_flags)),
    ("protected_process", ju32_opt(mi.protected_process)),
    ("time_zone_id", ju32_opt(mi.time_zone_id)),
    ("time_zone", tz),
    ("build_string", jstr_opt(mi.build_string)),
    ("dbg_build_string", jstr_opt(mi.dbg_build_string)),
    ("xstate_config", xstate),
    ("process_cookie", ju32_hex_opt(mi.process_cookie)),
  ])
}

///|
fn j_system_time(t : SystemTime) -> Json {
  jobj([
    ("year", ju16(t.year)),
    ("month", ju16(t.month)),
    ("day_of_week", ju16(t.day_of_week)),
    ("day", ju16(t.day)),
    ("hour", ju16(t.hour)),
    ("minute", ju16(t.minute)),
    ("second", ju16(t.second)),
    ("milliseconds", ju16(t.milliseconds)),
  ])
}

///|
/// Of the CodeView record only RSDS has real content; the rest are honestly split into three
/// cases: "magic recognized but content not understood" / "not written" / "written corrupt".
fn j_code_view(cv : CodeView) -> Json {
  match cv {
    Rsds(r) =>
      jobj([
        ("kind", jstr("rsds")),
        ("debug_id", jstr(r.debug_id)),
        ("age", ju32(r.age)),
        ("pdb_name", jstr(r.pdb_name)),
      ])
    Unrecognized(magic) =>
      jobj([
        ("kind", jstr("unrecognized")),
        ("magic", jhex(magic.to_uint64())),
        ("magic_text", jstr(code_view_magic_text(magic))),
      ])
    Missing => jobj([("kind", jstr("missing"))])
    Corrupt => jobj([("kind", jstr("corrupt"))])
  }
}

///|
/// ASCII reading of the magic (`RSDS`, `LEpB`, and the like). Stored little-endian, so it is
/// read starting from the low bytes; non-printable bytes become `.`, and the string is always
/// exactly 4 characters.
fn code_view_magic_text(magic : UInt32) -> String {
  let out : Array[String] = []
  let mut v = magic
  let mut n : Int32 = 0
  while n < 4 {
    let byte = (v % 256U).to_byte()
    v = v / 256U
    let c = byte.to_int()
    let text = if c >= 32 && c < 127 { byte.to_char().to_string() } else { "." }
    out.push(text)
    n = n + 1
  }
  out.join("")
}

///|
fn j_module(m : Module, index : Int32) -> Json {
  jobj([
    ("index", ji32(index)),
    ("name", jstr(m.name)),
    ("base_of_image", jhex(m.base_of_image)),
    ("size_of_image", ju32(m.size_of_image)),
    ("end_address", jhex(m.end_address())),
    ("time_date_stamp", ju32(m.time_date_stamp)),
    ("checksum", jhex(m.checksum.to_uint64())),
    ("file_version", jstr(m.file_version())),
    ("product_version", jstr(m.product_version())),
    ("debug_id", jstr(module_debug_id(m))),
    ("pdb_name", jstr(m.code_view_pdb_name())),
    ("code_view", j_code_view(m.code_view)),
    ("misc_record", j_location(m.misc_record)),
  ])
}

///|
fn j_exception(
  e : Exception,
  arch : UInt16,
  platform : UInt32,
  threads : Array[Thread],
  modules : Array[Module],
  ctx : Context?,
) -> Json {
  let who = match find_thread_by_id(threads, e.thread_id) {
    None => jnull()
    Some((i, _)) => ji32(i)
  }
  let access = memory_access_kind(e.code, e.parameters)
  let fault = e.fault_address()
  let status = e.underlying_status()
  let ctx_json = match ctx {
    None => jnull()
    Some(c) => j_registers(c)
  }
  jobj([
    ("thread_id", ju32(e.thread_id)),
    ("thread_index", who),
    ("code", jhex(e.code.to_uint64())),
    ("code_label", jstr(exception_code_label(platform, e.code))),
    ("code_name", jstr(exception_code_name(e.code))),
    ("flags", jhex(e.flags.to_uint64())),
    ("flags_bits", j_str_array(describe_exception_flags(e.flags))),
    ("address", jhex(e.address)),
    ("address_module", j_module_at(modules, e.address)),
    ("nested_record_address", jhex(e.nested_record_address)),
    ("number_parameters", ju32(e.number_parameters)),
    ("parameters", j_hex_array(e.parameters)),
    ("access_kind", jstr_opt(access)),
    ("fault_address", jhex_opt(fault)),
    ("fault_module", jopt_module_at(modules, fault)),
    ("underlying_status", jhex_opt(status)),
    ("thread_context", j_location(e.thread_context)),
    ("registers", ctx_json),
    ("architecture", jstr(architecture_name(arch))),
  ])
}

///|
/// "No target address" means null — the module table is not looked up with 0 (0 usually hits
/// nothing anyway, but semantically that is "unknown", not "address 0 landed elsewhere").
fn jopt_module_at(modules : Array[Module], address : UInt64?) -> Json {
  match address {
    None => jnull()
    Some(a) => j_module_at(modules, a)
  }
}

///|
fn j_thread(t : Thread, index : Int32, name : String?, ctx : Context?) -> Json {
  let ctx_json = match ctx {
    None => jnull()
    Some(c) => j_registers(c)
  }
  let bs = match t.backing_store {
    None => jnull()
    Some(b) => j_memory_descriptor(b)
  }
  jobj([
    ("index", ji32(index)),
    ("id", ju32(t.id)),
    ("name", jstr_opt(name)),
    ("suspend_count", ju32(t.suspend_count)),
    ("priority_class", ju32(t.priority_class)),
    ("priority", ju32(t.priority)),
    ("teb", jhex(t.teb)),
    ("stack", j_memory_descriptor(t.stack)),
    ("context", j_location(t.context)),
    ("backing_store", bs),
    ("entry_size", ju32(t.entry_size)),
    ("thread_ex", jbool(t.entry_size == thread_ex_size)),
    ("registers", ctx_json),
  ])
}

///|
fn ji32_opt(v : Int32?) -> Json {
  match v {
    None => jnull()
    Some(x) => ji32(x)
  }
}

///|
/// Module on a frame: the format layer only stores the name and index, and the name is an
/// empty string on a miss — normalized to null in JSON.
fn module_of(f : StackFrame) -> String? {
  if f.module_name.length() == 0 {
    None
  } else {
    Some(f.module_name)
  }
}

///|
fn j_symbol_target(t : SymbolTarget) -> Json {
  jobj([
    ("status", jstr(t.status)),
    ("matched_by", jstr_opt(empty_to_none(t.matched_by))),
    ("kind", jstr_opt(empty_to_none(t.kind))),
    ("name", jstr_opt(empty_to_none(t.name))),
    ("symbol_start", jhex_opt(t.symbol_start)),
    ("offset", jhex_opt(t.offset)),
    ("file", jstr_opt(empty_to_none(t.file))),
    ("line", ji64_opt(t.line)),
    ("symbol_source", jstr_opt(empty_to_none(t.symbol_source))),
    ("candidates", ji32(t.candidates)),
    ("line_text", jstr(symbol_target_line(t))),
  ])
}

///|
/// The symbol layer uses empty strings for "none"; null reads better in JSON.
fn empty_to_none(s : String) -> String? {
  if s.length() == 0 {
    None
  } else {
    Some(s)
  }
}

///|
fn j_window(low : UInt64?, high : UInt64?) -> Json {
  match (low, high) {
    (Some(l), Some(h)) =>
      jobj([("low", jhex(l)), ("high", jhex(h)), ("size", jdec(h - l))])
    _ => jnull()
  }
}

///|
/// Walk section with the module table. `modules` is only for symbolication (`symbolize_frame`
/// needs it to locate modules); each frame's module attribution was already computed in the
/// format layer.
fn j_stack_with_modules(
  w : StackWalk,
  store : SymbolStore?,
  modules : Array[Module],
  source : String,
) -> Json {
  let frames : Array[Json] = []
  let mut i : Int32 = 0
  while i < w.frames.length() {
    let f = w.frames[i]
    let sym = match store {
      None => jnull()
      Some(s) => j_symbol_target(symbolize_frame(f, modules, s))
    }
    frames.push(j_frame_out(f, i, sym))
    i = i + 1
  }
  jobj([
    ("thread_id", ju32(w.thread_id)),
    ("source", jstr(source)),
    ("layout", jstr(w.layout)),
    ("pointer_size", ju32(w.pointer_size)),
    ("supported", jbool(w.supported)),
    ("reason", jstr_opt(empty_to_none(w.reason))),
    ("window", j_window(w.window_low, w.window_high)),
    ("frame_count", ji32(w.frames.length())),
    ("fp_frames", ji32(w.fp_frames)),
    ("scanned_slots", ji64(w.scanned_slots)),
    ("scan_limited", jbool(w.scan_limited)),
    ("notes", j_str_array(w.notes)),
    ("frames", jarr(frames)),
  ])
}

///|
fn j_frame_out(f : StackFrame, index : Int32, sym : Json) -> Json {
  jobj([
    ("index", ji32(index)),
    ("ip", jhex(f.address)),
    ("kind", jstr(f.kind)),
    ("stack_slot", jhex_opt(f.stack_address)),
    ("module", jstr_opt(module_of(f))),
    ("module_index", ji32_opt(f.module_index)),
    ("offset", jhex_opt(f.offset)),
    ("function_table", jbool_opt(f.in_function_table)),
    ("return_site", jstr(f.return_site)),
    ("symbol", sym),
  ])
}

///|
/// One thread's walk. Unreadable context, missing memory map, or a walk that throws are each
/// written as `null` + `walk_error`; the section is never dropped wholesale.
fn j_walk_of(
  dump : Dump,
  map : MemoryMap?,
  modules : Array[Module],
  ft : FunctionTableInfo?,
  thread : Thread,
  arch : UInt16,
  loc : LocationDescriptor,
  opts : StackWalkOptions,
  store : SymbolStore?,
  source : String,
) -> Json {
  let ctx = try dump.read_context(arch, loc) catch {
    _ => None
  } noraise {
    c => c
  }
  match (ctx, map) {
    (None, _) =>
      jobj([
        ("thread_id", ju32(thread.id)),
        ("source", jstr(source)),
        ("walk_error", jstr("context-unreadable")),
      ])
    (Some(_), None) =>
      jobj([
        ("thread_id", ju32(thread.id)),
        ("source", jstr(source)),
        ("walk_error", jstr("no-memory-stream")),
      ])
    (Some(c), Some(m)) =>
      try dump.walk_thread_stack(m, modules, ft, thread, c, opts) catch {
        err =>
          jobj([
            ("thread_id", ju32(thread.id)),
            ("source", jstr(source)),
            ("walk_error", jerror(error_kind(err), describe_error(err))),
          ])
      } noraise {
        w => j_stack_with_modules(w, store, modules, source)
      }
  }
}

///|
fn j_memory_map(mm : MemoryMap) -> Json {
  let items : Array[Json] = []
  for r in mm.regions {
    items.push(
      jobj([
        ("start_address", jhex(r.start_address)),
        ("declared_size", jdec(r.declared_size)),
        ("size", jdec(r.size)),
        ("file_rva", jdec(r.file_rva)),
        ("clipped", jbool(r.size != r.declared_size)),
      ]),
    )
  }
  jobj([
    ("region_count", ji32(mm.region_count())),
    ("dropped", ju32(mm.dropped)),
    ("clipped", ju32(mm.clipped_count())),
    ("total_bytes", jdec(mm.total_bytes())),
    ("regions", j_list(items, json_list_cap)),
  ])
}

///|
fn j_memory_info(list : Array[MemoryInfo]) -> Json {
  let items : Array[Json] = []
  for mi in list {
    items.push(
      jobj([
        ("base_address", jhex(mi.base_address)),
        ("allocation_base", jhex(mi.allocation_base)),
        ("allocation_protect", jhex(mi.allocation_protect.to_uint64())),
        ("region_size", jdec(mi.region_size)),
        ("state", jhex(mi.state.to_uint64())),
        ("state_name", jstr(memory_state_name(mi.state))),
        ("protect", jhex(mi.protect.to_uint64())),
        ("protect_name", jstr(memory_protection_name(mi.protect))),
        ("type", jhex(mi.type_.to_uint64())),
        ("type_name", jstr(memory_type_name(mi.type_))),
      ]),
    )
  }
  jobj([
    ("count", ji32(list.length())),
    ("committed_bytes", jdec(memory_info_committed_bytes(list))),
    ("items", j_list(items, json_list_cap)),
  ])
}

///|
fn j_function_table(ft : FunctionTableInfo) -> Json {
  let items : Array[Json] = []
  for d in ft.descriptors {
    let inline = match d.inline_entry {
      None => jnull()
      Some((a, b, c)) =>
        jobj([
          ("function_rva", ju32(a)),
          ("entry_count", ju32(b)),
          ("parameter_size", ju32(c)),
        ])
    }
    items.push(
      jobj([
        ("minimum_address", jhex(d.minimum_address)),
        ("maximum_address", jhex(d.maximum_address)),
        ("base_address", jhex(d.base_address)),
        ("entry_count", ju32(d.entry_count)),
        ("inline_entry", inline),
      ]),
    )
  }
  jobj([
    ("layout", jstr(function_table_layout_name(ft.layout))),
    ("layout_ok", jbool(ft.layout_ok)),
    ("size_of_descriptor", ju32(ft.size_of_descriptor)),
    ("size_of_native_descriptor", ju32(ft.size_of_native_descriptor)),
    ("size_of_function_entry", ju32(ft.size_of_function_entry)),
    ("declared_header", ju32(ft.declared_header)),
    ("record_width", jdec(ft.record_width)),
    ("entries_rva", jdec(ft.entries_rva)),
    ("total_entries", jdec(ft.total_entries)),
    ("entries_in_file", jbool(ft.entries_in_file)),
    ("descriptor_count", ji32(ft.descriptors.length())),
    ("descriptors", j_list(items, 500)),
  ])
}

///|
fn j_handle(h : Handle) -> Json {
  jobj([
    ("handle", jhex(h.handle)),
    ("type_name", jstr(h.type_name)),
    ("object_name", jstr(h.object_name)),
    ("attributes", jhex(h.attributes.to_uint64())),
    ("granted_access", jhex(h.granted_access.to_uint64())),
    ("handle_count", ju32(h.handle_count)),
    ("pointer_count", ju32(h.pointer_count)),
    ("object_info_rva", jdec(h.object_info_rva)),
    ("descriptor_size", ju32(h.descriptor_size)),
  ])
}

///|
fn j_unloaded(m : UnloadedModule, index : Int32) -> Json {
  jobj([
    ("index", ji32(index)),
    ("name", jstr(m.name)),
    ("base_of_image", jhex(m.base_of_image)),
    ("size_of_image", ju32(m.size_of_image)),
    ("end_address", jhex(m.base_of_image + m.size_of_image.to_uint64())),
    ("time_date_stamp", ju32(m.time_date_stamp)),
    ("checksum", jhex(m.checksum.to_uint64())),
  ])
}

///|
/// `dump.report_json(opts)`: the complete structured report for one dump. It does not raise —
/// any section that fails to read falls back to `{"kind": ..., "message": ...}`, so the caller
/// always gets at least a parseable document.
/// Only when the stream directory itself is too malformed to list does `streams.error` say so;
/// every other section gives whatever it can, as usual.
pub fn Dump::report_json(self : Dump, opts : JsonOptions) -> Json {
  let entries = entries_or_empty(self)
  let (arch, platform) = arch_platform_json(self, entries)
  let modules = modules_array_json(self, entries)
  let threads = thread_array_json(self, entries)
  let names = thread_name_map_json(self, entries)
  let head : Array[(String, Json)] = [
    ("schema", jstr(json_schema)),
    ("generator", generator_json()),
    ("file", file_json(self, opts)),
    ("streams", streams_json(self)),
    ("system_info", section_system_info(self, entries)),
    ("misc_info", section_misc_info(self, entries)),
    ("modules", section_modules(self, entries)),
    ("unloaded_modules", section_unloaded_modules(self, entries)),
    ("threads", section_threads(self, entries, arch, names)),
    (
      "exception",
      section_exception(self, entries, arch, platform, threads, modules),
    ),
    (
      "stacks",
      section_stacks(
        self,
        entries,
        opts,
        arch,
        modules,
        ft_of(self, entries),
        threads,
      ),
    ),
    ("memory", section_memory(self, entries)),
    ("thread_names", section_thread_names(self, entries)),
    ("thread_infos", section_thread_infos(self, entries)),
    ("handles", section_handles(self, entries)),
    ("function_table", section_function_table(self, entries)),
    ("symbol_store", section_symbol_store(opts.symbols)),
  ]
  jobj(head)
}

///|
/// The document's provenance section. The version is the one in `moon.mod`; the schema number
/// is given separately, so when fields change later you touch `schema`, and readers never have
/// to guess.
fn generator_json() -> Json {
  jobj([
    ("name", jstr("moondump")),
    ("version", jstr("0.1.0")),
    (
      "note",
      jstr(
        "moondump's own JSON schema, not the output format of minidump-stackwalk",
      ),
    ),
  ])
}

///|
/// File section: the header verbatim plus generation parameters parsed out of the flags.
fn file_json(dump : Dump, opts : JsonOptions) -> Json {
  let h = dump.header
  let fmt = header_format_version(h.version)
  let known = header_format_version_is_known(h.version)
  jobj([
    ("path", jstr_opt(opts.path)),
    ("size", jdec(dump.data.length().to_uint64())),
    ("signature", jstr(signature_text(h.signature))),
    ("signature_raw", jhex(h.signature.to_uint64())),
    ("format_version", ju32(fmt)),
    ("format_version_known", jbool(known)),
    ("version_raw", jhex(h.version.to_uint64())),
    ("stream_directory_rva", jdec(h.stream_directory_rva)),
    ("number_of_streams", ju32(h.number_of_streams)),
    ("checksum", jhex(h.checksum.to_uint64())),
    ("time_date_stamp", ju32(h.time_date_stamp)),
    ("flags", jhex(h.flags)),
    ("minidump_type", j_str_array(describe_minidump_type(h.flags))),
  ])
}

///|
/// The stream directory gets its own section: when it cannot be listed, `{"error": ...}` is
/// written, and every other section still gives whatever it can.
fn streams_json(dump : Dump) -> Json {
  try dump.stream_directory() catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    entries => j_streams(dump, entries)
  }
}

///|
fn entries_or_empty(dump : Dump) -> Array[StreamEntry] {
  try dump.stream_directory() catch {
    _ => []
  } noraise {
    e => e
  }
}

///|
/// ASCII reading of the signature: `MDMP`; anything else is treated as non-printable and becomes `.`.
fn signature_text(signature : UInt32) -> String {
  code_view_magic_text(signature)
}

///|
fn j_streams(dump : Dump, entries : Array[StreamEntry]) -> Json {
  let items : Array[Json] = []
  for e in entries {
    let name = stream_type_name(e.stream_type)
    let fallback = "Stream(0x" + e.stream_type.to_string(radix=16) + ")"
    items.push(
      jobj([
        ("type", jhex(e.stream_type.to_uint64())),
        ("name", jstr(name)),
        ("recognized", jbool(name != fallback)),
        ("size", ju32(e.data_size)),
        ("rva", jdec(e.rva)),
        ("in_file", jbool(dump.range_in_file(e.rva, e.data_size.to_uint64()))),
      ]),
    )
  }
  jobj([("count", ji32(entries.length())), ("items", jarr(items))])
}

///|
fn arch_platform_json(
  dump : Dump,
  entries : Array[StreamEntry],
) -> (UInt16, UInt32) {
  try dump.system_info(entries) catch {
    _ => (0xffff, 0U)
  } noraise {
    info =>
      match info {
        None => (0xffff, 0U)
        Some(si) => (si.processor_architecture, si.platform_id)
      }
  }
}

///|
fn modules_array_json(
  dump : Dump,
  entries : Array[StreamEntry],
) -> Array[Module] {
  try dump.modules(entries) catch {
    _ => []
  } noraise {
    list =>
      match list {
        None => []
        Some(ml) => ml.modules
      }
  }
}

///|
fn thread_array_json(
  dump : Dump,
  entries : Array[StreamEntry],
) -> Array[Thread] {
  try dump.threads(entries) catch {
    _ => []
  } noraise {
    list =>
      match list {
        None => []
        Some(ts) => ts
      }
  }
}

///|
fn thread_name_map_json(
  dump : Dump,
  entries : Array[StreamEntry],
) -> Array[ThreadName] {
  try dump.thread_names(entries) catch {
    _ => []
  } noraise {
    list =>
      match list {
        None => []
        Some(ns) => ns
      }
  }
}

///|
fn ft_of(dump : Dump, entries : Array[StreamEntry]) -> FunctionTableInfo? {
  try dump.function_table(entries) catch {
    _ => None
  } noraise {
    v => v
  }
}

///|
fn section_system_info(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.system_info(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    info =>
      match info {
        None => jnull()
        Some(si) => j_system_info(si)
      }
  }
}

///|
fn section_misc_info(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.misc_info(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    info =>
      match info {
        None => jnull()
        Some(mi) => j_misc_info(mi)
      }
  }
}

///|
fn section_modules(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.modules(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    list =>
      match list {
        None => jnull()
        Some(ml) => {
          let items : Array[Json] = []
          let mut i : Int32 = 0
          while i < ml.modules.length() {
            items.push(j_module(ml.modules[i], i))
            i = i + 1
          }
          jobj([
            ("count", ji32(ml.modules.length())),
            ("skipped", ji32(ml.skipped)),
            ("items", j_list(items, json_list_cap)),
          ])
        }
      }
  }
}

///|
fn section_unloaded_modules(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.unloaded_modules(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    list =>
      match list {
        None => jnull()
        Some(ul) => {
          let items : Array[Json] = []
          let mut i : Int32 = 0
          while i < ul.modules.length() {
            items.push(j_unloaded(ul.modules[i], i))
            i = i + 1
          }
          jobj([
            ("count", ji32(ul.modules.length())),
            ("declared_count", jdec(ul.declared_count)),
            ("skipped", ju32(ul.skipped)),
            ("items", j_list(items, json_list_cap)),
          ])
        }
      }
  }
}

///|
/// Thread table. Registers are given for every thread (this is a machine-read format, not
/// the CLI's expand-only-first-8 approach); the thread whose context cannot be read gets null.
fn section_threads(
  dump : Dump,
  entries : Array[StreamEntry],
  arch : UInt16,
  names : Array[ThreadName],
) -> Json {
  try dump.threads(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    list =>
      match list {
        None => jnull()
        Some(ts) => {
          let items : Array[Json] = []
          let mut i : Int32 = 0
          while i < ts.length() {
            let ctx = try dump.read_context(arch, ts[i].context) catch {
              _ => None
            } noraise {
              c => c
            }
            items.push(
              j_thread(ts[i], i, thread_name_for(names, ts[i].id), ctx),
            )
            i = i + 1
          }
          jobj([
            ("count", ji32(ts.length())),
            ("architecture", jstr(architecture_name(arch))),
            ("items", j_list(items, json_list_cap)),
          ])
        }
      }
  }
}

///|
fn section_exception(
  dump : Dump,
  entries : Array[StreamEntry],
  arch : UInt16,
  platform : UInt32,
  threads : Array[Thread],
  modules : Array[Module],
) -> Json {
  try dump.exception(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    exc =>
      match exc {
        None => jnull()
        Some(e) => {
          let ctx = try dump.read_context(arch, e.thread_context) catch {
            _ => None
          } noraise {
            c => c
          }
          j_exception(e, arch, platform, threads, modules, ctx)
        }
      }
  }
}

///|
/// The set of walks matches the CLI: the crash thread always comes first, the rest follow
/// thread-table order. One deliberate difference in ordering: the CLI is for humans, so it
/// presents the thread-table context first and then adds a line saying "the next one is the
/// moment of the crash"; JSON is for machines, so `items[0]` is directly the crash-moment
/// walk and readers need not skip past a waiting stack first. Both contexts are present,
/// none missing.
/// The document's `walked` counts **walks** (the crash thread's two contexts each count as
/// one), not threads — `skipped_threads` is counted per thread; the units differ, and each
/// name states its own accounting. With `all_threads`, `skipped_threads` is never recorded.
fn section_stacks(
  dump : Dump,
  entries : Array[StreamEntry],
  opts : JsonOptions,
  arch : UInt16,
  modules : Array[Module],
  ft : FunctionTableInfo?,
  threads : Array[Thread],
) -> Json {
  let mm = try dump.memory_map(entries) catch {
    err => (None, Some(jerror(error_kind(err), describe_error(err))))
  } noraise {
    m => (m, None)
  }
  let map = mm.0
  let map_error = mm.1
  let exc = try dump.exception(entries) catch {
    _ => None
  } noraise {
    e => e
  }
  let crash_index : Int32? = match exc {
    None => None
    Some(e) =>
      match find_thread_by_id(threads, e.thread_id) {
        None => None
        Some((i, _)) => Some(i)
      }
  }
  let items : Array[Json] = []
  let store = opts.symbols
  let w = opts.walk
  match crash_index {
    Some(i) => {
      items.push(
        j_walk_of(
          dump,
          map,
          modules,
          ft,
          threads[i],
          arch,
          e_loc(exc),
          w,
          store,
          "exception_context",
        ),
      )
      // The crash thread has two contexts: the exception site (the moment of the crash) and
      // the one in the thread table (the moment the dump was written). If their instruction
      // pointers differ, an extra walk is emitted — the CLI walks both, and JSON must not
      // emit one fewer, otherwise the same dump would give different call chains on the
      // two output channels.
      let a = ip_of(dump, arch, threads[i].context)
      let b = ip_of(dump, arch, e_loc(exc))
      if a != b {
        items.push(
          j_walk_of(
            dump,
            map,
            modules,
            ft,
            threads[i],
            arch,
            threads[i].context,
            w,
            store,
            "thread_table_context",
          ),
        )
      }
    }
    None => ()
  }
  let mut skipped : Int32 = 0
  let mut other_walked : Int32 = 0
  let mut i : Int32 = 0
  while i < threads.length() {
    let is_crash = match crash_index {
      Some(c) => c == i
      None => false
    }
    if is_crash {
      i = i + 1
    } else if !opts.all_threads && other_walked >= thread_walk_limit {
      skipped = skipped + 1
      i = i + 1
    } else {
      other_walked = other_walked + 1
      items.push(
        j_walk_of(
          dump,
          map,
          modules,
          ft,
          threads[i],
          arch,
          threads[i].context,
          w,
          store,
          "thread_table_context",
        ),
      )
      i = i + 1
    }
  }
  // All three cases carry the same complete fields: `memory_map` is either "present",
  // "absent", or a {"kind", "message"} object — readers never have to guess the shape first.
  let map_state = match map {
    None =>
      match map_error {
        None => jstr("absent")
        Some(e) => e
      }
    Some(_) => jstr("present")
  }
  jobj([
    ("memory_map", map_state),
    ("max_frames", ji32(opts.walk.max_frames)),
    ("max_scan_bytes", ji64(opts.walk.max_scan_bytes)),
    ("scan", jbool(opts.walk.scan)),
    ("symbolicated", jbool(opts.symbols is Some(_))),
    ("walked", ji32(items.length())),
    ("skipped_threads", ji32(skipped)),
    ("items", j_list(items, json_list_cap)),
  ])
}

///|
/// The location of the crash-moment context. Never reached without an exception stream
/// (crash_index is None).
fn e_loc(exc : Exception?) -> LocationDescriptor {
  match exc {
    None => { size: 0U, rva: 0UL, }
    Some(e) => e.thread_context
  }
}

///|
/// The instruction pointer from a context, None when unreadable. Only used to decide "are
/// these two contexts the same site"; it never supplies any value — the same comparison as
/// on the CLI side.
fn ip_of(dump : Dump, arch : UInt16, loc : LocationDescriptor) -> UInt64? {
  try dump.read_context(arch, loc) catch {
    _ => None
  } noraise {
    ctx =>
      match ctx {
        None => None
        Some(c) => c.instruction_pointer()
      }
  }
}

///|
fn section_memory(dump : Dump, entries : Array[StreamEntry]) -> Json {
  let map = try dump.memory_map(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    m =>
      match m {
        None => jnull()
        Some(mm) => j_memory_map(mm)
      }
  }
  let info = try dump.memory_info_list(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    l =>
      match l {
        None => jnull()
        Some(list) => j_memory_info(list)
      }
  }
  let regions = try dump.memory_regions(entries) catch {
    _ => None
  } noraise {
    r => r
  }
  let raw_count : Int32 = match regions {
    None => 0
    Some(rs) => rs.length()
  }
  jobj([
    ("map", map),
    ("info_list", info),
    ("raw_region_count", ji32(raw_count)),
  ])
}

///|
fn section_thread_names(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.thread_names(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    list =>
      match list {
        None => jnull()
        Some(ns) => {
          let items : Array[Json] = []
          for n in ns {
            items.push(
              jobj([("thread_id", ju32(n.thread_id)), ("name", jstr(n.name))]),
            )
          }
          jobj([
            ("count", ji32(ns.length())),
            ("items", j_list(items, json_list_cap)),
          ])
        }
      }
  }
}

///|
fn section_thread_infos(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.thread_infos(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    list =>
      match list {
        None => jnull()
        Some(ts) => {
          let items : Array[Json] = []
          for t in ts {
            items.push(
              jobj([
                ("thread_id", ju32(t.thread_id)),
                ("dump_flags", jhex(t.dump_flags.to_uint64())),
                (
                  "dump_flags_names",
                  j_str_array(describe_thread_dump_flags(t.dump_flags)),
                ),
                ("dump_error", jhex(t.dump_error.to_uint64())),
                ("exit_status", jhex(t.exit_status.to_uint64())),
                ("create_time", jdec(t.create_time)),
                ("exit_time", jdec(t.exit_time)),
                ("kernel_time", jdec(t.kernel_time)),
                ("user_time", jdec(t.user_time)),
                ("start_address", jhex(t.start_address)),
                ("affinity", jdec(t.affinity)),
              ]),
            )
          }
          jobj([
            ("count", ji32(ts.length())),
            ("items", j_list(items, json_list_cap)),
          ])
        }
      }
  }
}

///|
fn section_handles(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.handles(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    list =>
      match list {
        None => jnull()
        Some(hs) => {
          let items : Array[Json] = []
          for h in hs {
            items.push(j_handle(h))
          }
          jobj([
            ("count", ji32(hs.length())),
            ("items", j_list(items, json_list_cap)),
          ])
        }
      }
  }
}

///|
fn section_function_table(dump : Dump, entries : Array[StreamEntry]) -> Json {
  try dump.function_table(entries) catch {
    err => jerror(error_kind(err), describe_error(err))
  } noraise {
    v =>
      match v {
        None => jnull()
        Some(ft) => j_function_table(ft)
      }
  }
}

///|
/// Symbol store status: with no directory given the whole section is null; with one given,
/// "how many were loaded, which files were rejected" is written out.
fn section_symbol_store(store : SymbolStore?) -> Json {
  match store {
    None => jnull()
    Some(s) => {
      let loaded : Array[Json] = []
      for (path, _) in s.loaded {
        loaded.push(jstr(path))
      }
      let rejected : Array[Json] = []
      for path in s.rejected {
        rejected.push(jstr(path))
      }
      jobj([
        ("loaded", ji32(s.loaded.length())),
        ("loaded_files", jarr(loaded)),
        ("rejected", ji32(s.rejected.length())),
        ("rejected_files", jarr(rejected)),
      ])
    }
  }
}

///|
/// One-line JSON report (indent 2). Both the CLI and the tests use it, so stringify is not
/// written out twice.
pub fn json_report_text(doc : Json) -> String {
  doc.stringify(indent=2)
}

///|
/// The error document used when the whole document cannot be produced (file unreadable,
/// arguments unusable).
///
/// Under `--json`, stdout is allowed exactly one JSON document: even errors must go into the
/// document — no explanatory line may be printed to stdout on the side, or the upstream
/// program would fail parsing on the very first byte. Section-level failures use the same
/// `{"kind", "message"}` shape, so readers only need to recognize one form.
pub fn json_failure(kind : String, message : String) -> Json {
  jobj([
    ("schema", jstr(json_schema)),
    ("generator", generator_json()),
    ("error", jerror(kind, message)),
  ])
}
