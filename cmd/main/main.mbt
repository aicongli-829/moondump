// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
/// Terminal display width: CJK and fullwidth punctuation count as 2 columns, everything else as 1.
/// Without this rule, labels mixing CJK and ASCII can never line up.
fn display_width(s : String) -> Int32 {
  let mut w : Int32 = 0
  for c in s.to_array() {
    let cp = c.to_int()
    let wide = (cp >= 0x1100 && cp <= 0x115f) ||
      (cp >= 0x2e80 && cp <= 0x303e) ||
      (cp >= 0x3041 && cp <= 0x33ff) ||
      (cp >= 0x3400 && cp <= 0x4dbf) ||
      (cp >= 0x4e00 && cp <= 0x9fff) ||
      (cp >= 0xa000 && cp <= 0xa4cf) ||
      (cp >= 0xac00 && cp <= 0xd7a3) ||
      (cp >= 0xf900 && cp <= 0xfaff) ||
      (cp >= 0xfe30 && cp <= 0xfe6f) ||
      (cp >= 0xff00 && cp <= 0xff60) ||
      (cp >= 0xffe0 && cp <= 0xffe6) ||
      (cp >= 0x20000 && cp <= 0x3fffd)
    w = w + (if wide { 2 } else { 1 })
  }
  w
}

///|
/// One aligned "label: value" line. 16 columns because the longest label is the stream name ExceptionStream.
fn kv(label : String, value : String) -> Unit {
  println(pad_right(label, 16) + ": " + value)
}

///|
/// Uniform display for "the dump writer did not provide this field"; it must stay
/// distinguishable from "the field is provided and its value is 0".
let absent = "not provided"

///|
/// Pad right with spaces, counted in display width.
fn pad_right(s : String, width : Int32) -> String {
  let mut out = s
  while display_width(out) < width {
    out = out + " "
  }
  out
}

///|
/// Command-line options. Defaults are chosen so the output fits on one terminal screen:
/// empty symbol store, walking only the crash thread plus the first few threads.
struct Options {
  mut path : String
  symbol_dirs : Array[String]
  mut max_frames : Int32
  mut scan : Bool
  mut all_stacks : Bool
  mut json : Bool
}

///|
/// How many non-crash threads' stacks are walked by default (the crash thread is counted
/// separately and always comes first).
let thread_walk_cap = 8

///|
let sym_file_cap = 2000

///|
let sym_depth_cap = 8

///|
/// Usage text. MoonBit has no multi-line strings, so one print per line.
fn print_usage() -> Unit {
  println("usage: moon run cmd/main -- <crash-dump.dmp> [options]")
  println(
    "  --symbols <dir>    recursively collect *.sym files under the dir for symbolization, may be given multiple times",
  )
  println("  --max-frames <n>   walk at most n frames per stack, default 64")
  println(
    "  --no-scan          follow frame-pointer chains only, no stack-window scanning: more conservative, more frames missing",
  )
  println(
    "  --all-stacks       walk the stack of every thread, default is the crash thread plus the first " +
    thread_walk_cap.to_string() +
    " threads",
  )
  println(
    "  --json             emit a machine-readable JSON report (schema moondump/v1)," +
    " no terminal-formatted text",
  )
  println("  --help             show only this help")
}

///|
/// Accepts only plain decimal non-negative integers; anything else yields None so the caller
/// can report "bad argument".
fn parse_count(s : String) -> Int32? {
  let cs = s.to_array()
  if cs.length() == 0 {
    None
  } else {
    let mut v : Int32 = 0
    let mut ok = true
    for c in cs {
      let d = c.to_int() - 48
      if d < 0 || d > 9 {
        ok = false
      } else if v > 10_000_000 {
        ok = false
      } else {
        v = v * 10 + d
      }
    }
    if ok {
      Some(v)
    } else {
      None
    }
  }
}

///|
/// Argument parsing. Returns (options, malformed usages, whether only usage was requested).
/// Only the first positional argument is taken as the dump path; extras are reported as
/// mistakes — one dump at a time, so outputs never interleave.
fn parse_args(argv : Array[String]) -> (Options, Array[String], Bool) {
  let o : Options = {
    path: "",
    symbol_dirs: [],
    max_frames: 64,
    scan: true,
    all_stacks: false,
    json: false,
  }
  let mut help = false
  let bad : Array[String] = []
  let mut i = 1
  while i < argv.length() {
    let a = argv[i]
    if a == "--symbols" || a == "-s" {
      if i + 1 < argv.length() {
        o.symbol_dirs.push(argv[i + 1])
        i = i + 2
      } else {
        bad.push("--symbols needs a directory after it")
        i = i + 1
      }
    } else if a == "--max-frames" {
      if i + 1 < argv.length() {
        let v = parse_count(argv[i + 1])
        match v {
          Some(n) => {
            o.max_frames = n
            i = i + 2
          }
          None => {
            bad.push(
              "--max-frames expects a decimal integer, got: " + argv[i + 1],
            )
            i = i + 2
          }
        }
      } else {
        bad.push("--max-frames needs a number after it")
        i = i + 1
      }
    } else if a == "--no-scan" {
      o.scan = false
      i = i + 1
    } else if a == "--all-stacks" {
      o.all_stacks = true
      i = i + 1
    } else if a == "--json" {
      o.json = true
      i = i + 1
    } else if a == "--help" || a == "-h" {
      help = true
      i = i + 1
    } else if a == "--" {
      i = i + 1
    } else if o.path.length() == 0 && !starts_with_dash(a) {
      o.path = a
      i = i + 1
    } else if starts_with_dash(a) {
      bad.push("unknown option: " + a)
      i = i + 1
    } else {
      bad.push("only one dump file is processed, extra ones ignored: " + a)
      i = i + 1
    }
  }
  (o, bad, help)
}

///|
/// Path join. The directory given on the command line may already end with a separator, or
/// use backslashes throughout; in both cases nothing more is appended.
fn join_path(dir : String, name : String) -> String {
  let cs = dir.to_array()
  if cs.length() == 0 {
    name
  } else {
    let last = cs[cs.length() - 1]
    if last == '/' || last == '\\' {
      dir + name
    } else {
      dir + "/" + name
    }
  }
}

///|
/// Checks only the `.sym` suffix, case-insensitively. Every vendor uses this extension for
/// breakpad symbol tables; reading other files (sources, dlls, the dump itself) is pure waste,
/// but the evidence is never silently dropped.
fn is_sym_file(name : String) -> Bool {
  let cs = name.to_array()
  let n = cs.length()
  // 46='.', 115='s', 121='y', 109='m'
  n >= 4 &&
  lower_code(cs[n - 4].to_int()) == 46 &&
  lower_code(cs[n - 3].to_int()) == 115 &&
  lower_code(cs[n - 2].to_int()) == 121 &&
  lower_code(cs[n - 1].to_int()) == 109
}

///|
/// Lowercase code point of an ASCII uppercase letter; everything else returned unchanged.
fn lower_code(i : Int32) -> Int32 {
  if i >= 65 && i <= 90 {
    i + 32
  } else {
    i
  }
}

///|
/// Anything starting with `-` is treated as an option, never as the dump path.
fn starts_with_dash(s : String) -> Bool {
  let cs = s.to_array()
  cs.length() > 0 && cs[0] == '-'
}

///|
fn read_text_file(path : String) -> String? {
  try @fs.read_file_to_string(path) catch {
    _ => None
  } noraise {
    text => Some(text)
  }
}

///|
/// Recursively collect `*.sym`. The symbol store is indexed by the debug id declared in each
/// file's `MODULE` line, so the directory layout does not matter — breakpad's
/// `<pdb>/<id>/<name>.sym>` is a convention, not a requirement.
/// Both depth and count are capped: symbol directories are often pointed at an entire drive.
fn collect_sym_files(
  dir : String,
  out : Array[String],
  notes : Array[String],
  depth : Int32,
) -> Unit {
  if out.length() >= sym_file_cap {
    notes.push(
      "hit the cap of " +
      sym_file_cap.to_string() +
      " symbol files, not scanning further from " +
      dir,
    )
  } else if depth > sym_depth_cap {
    notes.push(
      "deeper than " +
      sym_depth_cap.to_string() +
      " levels, not descending below " +
      dir,
    )
  } else {
    let items = try @fs.read_dir(dir) catch {
      _ => None
    } noraise {
      names => Some(names.to_owned())
    }
    match items {
      None => notes.push("cannot read directory: " + dir)
      Some(names) =>
        for name in names {
          if name != "." && name != ".." {
            let p = join_path(dir, name)
            let sub = try @fs.is_dir(p) catch {
              _ => false
            } noraise {
              b => b
            }
            if sub {
              collect_sym_files(p, out, notes, depth + 1)
            } else if is_sym_file(name) {
              out.push(p)
            }
          }
        }
    }
  }
}

///|
/// Read the symbol tables from each directory into the store, and accumulate a record of
/// "what happened during loading". No bad file is silently dropped: unreadable ones and ones
/// without a valid MODULE line each get their own note line.
fn load_symbols(dirs : Array[String]) -> (@lib.SymbolStore, Array[String]) {
  let store = @lib.symbol_store_new()
  let notes : Array[String] = []
  for d in dirs {
    let files : Array[String] = []
    if !@fs.path_exists(d) {
      notes.push("symbol directory does not exist: " + d)
    } else {
      collect_sym_files(d, files, notes, 0)
    }
    let mut accepted : Int32 = 0
    for f in files {
      match read_text_file(f) {
        None =>
          notes.push("cannot read as text (not UTF-8 or unreadable): " + f)
        Some(text) =>
          if @lib.symbol_store_add(store, f, text) {
            accepted = accepted + 1
          }
      }
    }
    notes.push(
      "symbol directory " +
      d +
      ": scanned " +
      files.length().to_string() +
      " .sym files, accepted " +
      accepted.to_string() +
      ", rejected " +
      (files.length() - accepted).to_string(),
    )
  }
  (store, notes)
}

///|
/// Usage: moon run cmd/main --target native -- <crash-dump.dmp> [options]
/// With `--json` a different path is taken: stdout carries only that one document, see `json_document`.
fn main {
  let argv = @env.args()
  let (opts, bad, help) = parse_args(argv)
  if help {
    print_usage()
    return ()
  }
  if opts.json {
    println(@lib.json_report_text(json_document(opts, bad)))
    return ()
  }
  for b in bad {
    println(b)
  }
  if opts.path.length() == 0 {
    if bad.length() == 0 {
      println("no dump file given")
    }
    print_usage()
    return ()
  }
  let (store, notes) = load_symbols(opts.symbol_dirs)
  try @fs.read_file_to_bytes(opts.path) catch {
    _ => println("failed to read file: " + opts.path)
  } noraise {
    bytes =>
      try @lib.open_dump(bytes) catch {
        err => println("parse failed: " + @lib.describe_error(err))
      } noraise {
        dump => print_summary(dump, store, notes, opts)
      }
  }
}

///|
/// The only exit of JSON mode: success or not, stdout carries exactly this one document.
///
/// Bad arguments, no file given, unreadable file, not an MDMP at all — every one of them
/// returns a `json_failure`, shaped the same as a per-section failure (`{"kind","message"}`).
/// Printing a human-language explanation line to stdout is the trap most easily swallowed by
/// upstream consumers: the very first byte would no longer be JSON.
fn json_document(opts : Options, bad : Array[String]) -> Json {
  if bad.length() > 0 {
    @lib.json_failure("arguments", bad.join(" ;; "))
  } else if opts.path.length() == 0 {
    @lib.json_failure("usage", "no dump file given")
  } else {
    // The per-directory statistics text exists for terminal layout; the document already
    // carries loaded_files/rejected_files, so the notes are dropped here. When --symbols is
    // not given the symbol store is written as null, so that "empty store" and "no store
    // used" do not look identical in the document.
    let (store, _) = load_symbols(opts.symbol_dirs)
    json_read_file(opts, store)
  }
}

///|
/// Report parameters for `--json`. `max_scan_bytes` is hardcoded to 4096 bytes, same as text mode.
fn json_options_for(
  opts : Options,
  store : @lib.SymbolStore,
) -> @lib.JsonOptions {
  let symbols = if opts.symbol_dirs.length() > 0 { Some(store) } else { None }
  {
    path: Some(opts.path),
    symbols,
    walk: {
      max_frames: opts.max_frames,
      max_scan_bytes: 4096L,
      scan: opts.scan,
    },
    all_threads: opts.all_stacks,
  }
}

///|
fn json_read_file(opts : Options, store : @lib.SymbolStore) -> Json {
  try @fs.read_file_to_bytes(opts.path) catch {
    _ => @lib.json_failure("read_file", "failed to read file: " + opts.path)
  } noraise {
    bytes => json_open_dump(opts, store, bytes)
  }
}

///|
fn json_open_dump(
  opts : Options,
  store : @lib.SymbolStore,
  bytes : Bytes,
) -> Json {
  try @lib.open_dump(bytes) catch {
    err =>
      @lib.json_failure(
        "open_dump",
        "parse failed: " + @lib.describe_error(err),
      )
  } noraise {
    dump => dump.report_json(json_options_for(opts, store))
  }
}

///|
fn print_summary(
  dump : @lib.Dump,
  store : @lib.SymbolStore,
  store_notes : Array[String],
  opts : Options,
) -> Unit {
  let h = dump.header
  kv("file", dump.data.length().to_string() + " bytes")
  kv("signature", "MDMP")
  let version = "0x" + h.version.to_string(radix=16)
  let fmt = @lib.header_format_version(h.version)
  let note = if @lib.header_format_version_is_known(h.version) {
    " (format version " + fmt.to_string() + ")"
  } else {
    " (format version 0x" +
    fmt.to_string(radix=16) +
    ", not the common 42899, parsing anyway)"
  }
  kv("version", version + note)
  kv("streams", h.number_of_streams.to_string())
  kv("directory RVA", h.stream_directory_rva.to_string())
  kv("timestamp", h.time_date_stamp.to_string() + " (Unix seconds)")
  kv("flags", "0x" + h.flags.to_string(radix=16))
  kv("generation flags", @lib.describe_minidump_type(h.flags).join(" | "))
  try dump.stream_directory() catch {
    err => println("malformed stream directory: " + @lib.describe_error(err))
  } noraise {
    entries => {
      println("")
      print_system_info(dump, entries)
      println("")
      print_misc_info(dump, entries)
      println("")
      print_modules(dump, entries)
      println("")
      print_threads(dump, entries)
      println("")
      print_crash(dump, entries)
      println("")
      print_stacks(dump, entries, store, store_notes, opts)
      println("")
      print_memory(dump, entries)
      println("")
      print_extra_streams(dump, entries)
      println("")
      println(
        pad_right("type", 26) + right("size", 12) + right("RVA", 12) + "  range",
      )
      for e in entries {
        let ok = dump.range_in_file(e.rva, e.data_size.to_uint64())
        let name = @lib.stream_type_name(e.stream_type)
        let sz = e.data_size.to_string()
        let rv = e.rva.to_string()
        let row = pad_right(name, 26) + right(sz, 12) + right(rv, 12)
        println(row + (if ok { "  ok" } else { "  out of range" }))
      }
    }
  }
}

///|
/// System information: the first thing triage looks at — which architecture, which CPU, which OS version.
fn print_system_info(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  try dump.system_info(entries) catch {
    err => kv("SystemInfo", "unreadable: " + @lib.describe_error(err))
  } noraise {
    info =>
      match info {
        None => kv("SystemInfo", "stream absent")
        Some(si) => {
          let csd = if si.csd_version.length() > 0 {
            " " + si.csd_version
          } else {
            ""
          }
          kv(
            "system",
            @lib.platform_id_name(si.platform_id) +
            " " +
            @lib.version_string(si) +
            csd,
          )
          let arch = @lib.architecture_name(si.processor_architecture)
          kv(
            "architecture",
            arch +
            " (" +
            si.number_of_processors.to_int().to_string() +
            " logical processors)",
          )
          kv("product type", @lib.product_type_name(si.product_type))
          let suite = @lib.describe_suite_mask(si.suite_mask)
          if suite.length() > 0 {
            let hex = si.suite_mask.to_string(radix=16)
            kv("SuiteMask", "0x" + hex + " " + suite.join("|"))
          }
          let fms = @lib.x86_family_model_stepping(si)
          let vendor = match si.cpu_vendor {
            Some(v) => v
            None => "?"
          }
          let f = fms.0.to_string()
          let m = fms.1.to_string()
          let s = fms.2.to_string()
          kv("CPU", vendor + " family " + f + " model " + m + " stepping " + s)
          let words : Array[String] = []
          for w in si.cpu {
            words.push("0x" + w.to_string(radix=16))
          }
          kv("CPU raw words", words.join(" "))
        }
      }
  }
}

///|
/// MiscInfo: process identity + machine environment. Answers triage's "which machine, which
/// process, which time zone, which build"; every field is gated by Flags1, and a bit that is
/// not set is always shown as «not provided».
fn print_misc_info(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  try dump.misc_info(entries) catch {
    err => kv("MiscInfo", "unreadable: " + @lib.describe_error(err))
  } noraise {
    info =>
      match info {
        None => kv("MiscInfo", "stream absent")
        Some(mi) => {
          let head = "v" +
            mi.info_version.to_string() +
            ", SizeOfInfo " +
            mi.size_of_info.to_string()
          kv("MiscInfo", head + " bytes")
          let hex = mi.flags1.to_string(radix=16)
          let names = @lib.describe_misc_flags(mi.flags1)
          kv("Flags1", "0x" + hex + "  " + names.join(" | "))
          match mi.process_id {
            Some(pid) => kv("process ID", pid.to_string())
            None => kv("process ID", absent)
          }
          match mi.process_times {
            Some(t) => {
              let c = t.create_time.to_string()
              let u = t.user_time.to_string()
              let k = t.kernel_time.to_string()
              kv(
                "process times",
                c + " (Unix seconds) user " + u + " kernel " + k,
              )
            }
            None => kv("process times", absent)
          }
          match mi.processor_power_info {
            Some(p) => {
              let cur = p.current_mhz.to_string()
              let max = p.max_mhz.to_string()
              let idle = p.current_idle_state.to_string()
              kv(
                "processor frequency",
                cur + " / max " + max + " MHz  idle " + idle,
              )
            }
            None => kv("processor frequency", absent)
          }
          match mi.process_integrity_level {
            Some(l) => kv("integrity level", "0x" + l.to_string(radix=16))
            None => kv("integrity level", absent)
          }
          // ProcessExecuteFlags is the raw value of NtQueryInformationProcess's 62nd info class.
          // The MEM_EXECUTE_OPTION_* bits are not defined in minidumpapiset.h,
          // so this implementation does not decode names and reports the raw bitmap only
          // (rust-minidump likewise returns it as-is).
          match mi.process_execute_flags {
            Some(f) => kv("execution policy", "0x" + f.to_string(radix=16))
            None => kv("execution policy", absent)
          }
          match mi.protected_process {
            Some(0U) => kv("protected process", "no")
            Some(_) => kv("protected process", "yes")
            None => kv("protected process", absent)
          }
          match mi.time_zone {
            Some(tz) => {
              let id = match mi.time_zone_id {
                Some(i) => i.to_string()
                None => "?"
              }
              let off = @lib.time_zone_offset_text(tz.bias)
              let bias = tz.bias.to_string()
              let std = tz.standard_name + "/" + tz.daylight_name
              kv(
                "time zone",
                "id " + id + "  UTC" + off + " (Bias " + bias + ")",
              )
              kv("time zone names", std)
              let s = tz.standard_date.rule_text()
              let d = tz.daylight_date.rule_text()
              kv("transition rules", "standard " + s + "  daylight " + d)
            }
            None => kv("time zone", absent)
          }
          match mi.build_string {
            Some(b) => kv("system build", b)
            None => kv("system build", absent)
          }
          match mi.dbg_build_string {
            Some(b) => kv("debugger", b)
            None => kv("debugger", absent)
          }
          match mi.xstate_config {
            Some(x) => {
              let total = x.features.length()
              let n = total.to_string()
              let cs = x.context_size.to_string()
              let en = "0x" + x.enabled_features.to_string(radix=16)
              kv(
                "XState",
                "ContextSize " +
                cs +
                "  enabled " +
                en +
                "  table " +
                n +
                " entries",
              )
              let shown : Array[String] = []
              let mut i : Int32 = 0
              while i < total && shown.length() < 8 {
                match x.feature(i) {
                  Some(f) =>
                    shown.push(
                      i.to_string() +
                      ":0x" +
                      f.offset.to_string(radix=16) +
                      "+0x" +
                      f.size.to_string(radix=16),
                    )
                  None => ()
                }
                i = i + 1
              }
              if shown.length() > 0 {
                kv("XState features", shown.join(" "))
              }
            }
            None => kv("XState", absent)
          }
          match mi.process_cookie {
            Some(c) => kv("process cookie", "0x" + c.to_string(radix=16))
            None => kv("process cookie", absent)
          }
        }
      }
  }
}

///|
/// Module list: the most-used table in crash triage — which module, which version, whether debug info is present.
fn print_modules(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  try dump.modules(entries) catch {
    err => kv("ModuleList", "unreadable: " + @lib.describe_error(err))
  } noraise {
    list =>
      match list {
        None => kv("ModuleList", "stream absent")
        Some(ml) => {
          let skipped = if ml.skipped > 0 {
            ", skipped " + ml.skipped.to_string() + " malformed records"
          } else {
            ""
          }
          kv(
            "modules",
            ml.modules.length().to_string() + " module(s)" + skipped,
          )
          for mo in ml.modules {
            let cv = match mo.code_view {
              @lib.Rsds(r) =>
                "RSDS " +
                r.debug_id +
                "/" +
                r.age.to_string() +
                "  " +
                r.pdb_name
              @lib.Unrecognized(k) =>
                "CodeView 0x" +
                k.to_string(radix=16) +
                " (this tool does not decode this record type yet)"
              @lib.Missing => "no debug info"
              @lib.Corrupt => "debug record out of range/corrupt"
            }
            let name = if mo.name.length() > 0 { mo.name } else { "(unnamed)" }
            let range = "0x" +
              mo.base_of_image.to_string(radix=16) +
              "-0x" +
              mo.end_address().to_string(radix=16)
            let size = "0x" + mo.size_of_image.to_string(radix=16)
            let ts = "0x" + mo.time_date_stamp.to_string(radix=16)
            let cs = "0x" + mo.checksum.to_string(radix=16)
            println("  " + name)
            println(
              "    range " +
              range +
              "  image " +
              size +
              "  timestamp " +
              ts +
              "  checksum " +
              cs,
            )
            println(
              "    version " +
              mo.file_version() +
              "  product " +
              mo.product_version(),
            )
            println("    " + cv)
          }
        }
      }
  }
}

///|
/// The "architecture + platform" pair for the overview. When SystemInfo is missing or
/// malformed a sentinel is returned, so the threads/exception sections still print —
/// with an unknown architecture, contexts are always shown as "unresolved".
fn arch_platform(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
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
/// Crash-address attribution needs the module table; that section reports ModuleList errors
/// itself, so here we only want the data.
fn module_array(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Array[@lib.Module] {
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
fn thread_array(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Array[@lib.Thread] {
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
/// One register row: fixed-width name + hex value, four per row.
fn print_registers(regs : Array[(String, String)]) -> Unit {
  let mut i = 0
  while i < regs.length() {
    let items : Array[String] = []
    let mut j = i
    while j < i + 4 && j < regs.length() {
      let (name, value) = regs[j]
      items.push(pad_right(name, 7) + "= " + value)
      j = j + 1
    }
    println("      " + items.join("   "))
    i = i + 4
  }
}

///|
/// One CONTEXT: first "which field layout applies + ContextFlags decoded", then the registers
/// laid out. When the architecture and the declared size disagree, the layout shown here is
/// the **actually adopted** one, so contradictions like WOW64 stand out at a glance. `label`
/// distinguishes the thread-table copy from the crash-site copy.
fn print_context(
  dump : @lib.Dump,
  arch : UInt16,
  loc : @lib.LocationDescriptor,
  label : String,
) -> Unit {
  let head = "      " + label
  if loc.size == 0U || loc.rva == 0UL {
    println(head + "  " + absent)
  } else {
    let size = loc.size.to_string()
    let at = loc.rva.to_string()
    try dump.read_context(arch, loc) catch {
      err =>
        println(
          head +
          "  " +
          size +
          " bytes @ " +
          at +
          ": unreadable " +
          @lib.describe_error(err),
        )
    } noraise {
      ctx =>
        match ctx {
          None => println(head + "  none")
          Some(c) => {
            let flags = c.context_flags()
            println(
              head +
              "  " +
              c.layout_name() +
              " layout, " +
              size +
              " bytes @ " +
              at,
            )
            if flags != 0U {
              let names = @lib.describe_context_flags(
                c.flag_architecture(),
                flags,
              )
              println(
                "      valid fields  0x" +
                flags.to_string(radix=16) +
                "  " +
                names.join("|"),
              )
            }
            print_registers(c.registers())
          }
        }
    }
  }
}

///|
/// Thread table: for each thread, the TEB, stack range, and context location, then the
/// registers laid out. There can be hundreds of threads and registers are long, so by default
/// only the first 8 threads get their contexts expanded.
fn print_threads(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  let (arch, _) = arch_platform(dump, entries)
  let names = thread_names_of(dump, entries)
  try dump.threads(entries) catch {
    err => kv("ThreadList", "unreadable: " + @lib.describe_error(err))
  } noraise {
    list =>
      match list {
        None => kv("ThreadList", "stream absent")
        Some(ts) => {
          kv("threads", ts.length().to_string() + " total")
          let total = ts.length()
          let mut i = 0
          while i < total {
            let t = ts[i]
            let range = "0x" +
              t.stack.start_address.to_string(radix=16) +
              " + " +
              t.stack.location.size.to_string() +
              " bytes @ " +
              t.stack.location.rva.to_string()
            let ctx = t.context.size.to_string() +
              " bytes @ " +
              t.context.rva.to_string()
            let width = if t.entry_size == @lib.thread_ex_size {
              " ThreadEx"
            } else {
              ""
            }
            println(
              "  #" +
              i.to_string() +
              "  thread " +
              t.id.to_string() +
              "  TEB " +
              @lib.hex_uint(t.teb) +
              width +
              thread_name_text(names, t.id),
            )
            println("      stack  " + range)
            let show_registers = if i < 8 { true } else { false }
            if show_registers {
              print_context(dump, arch, t.context, "context")
            } else {
              println("      context  " + ctx + " (not expanded)")
            }
            i = i + 1
          }
          if total > 8 {
            println(
              "  (registers expanded only for the first 8 of " +
              total.to_string() +
              " threads)",
            )
          }
        }
      }
  }
}

///|
/// Crash site: exception code + module attribution of the faulting address + the crash-site context.
/// Note that the crash-site context and the context of that thread in the thread table are two
/// different pieces of data: the thread-table copy is "at dump-writing time", while the
/// exception-stream copy is "at the moment of the exception".
fn print_crash(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  let (arch, platform) = arch_platform(dump, entries)
  let modules = module_array(dump, entries)
  let threads = thread_array(dump, entries)
  try dump.exception(entries) catch {
    err => kv("ExceptionStream", "unreadable: " + @lib.describe_error(err))
  } noraise {
    exc =>
      match exc {
        None =>
          kv(
            "ExceptionStream", "stream absent (not an exception-triggered dump)",
          )
        Some(e) => {
          println("crash site:")
          let who = match @lib.find_thread_by_id(threads, e.thread_id) {
            None => " (not in the thread table)"
            Some((i, _)) => " (thread table #" + i.to_string() + ")"
          }
          kv("thread", e.thread_id.to_string() + who)
          let label = @lib.exception_code_label(platform, e.code)
          kv("exception code", @lib.hex_uint(e.code.to_uint64()) + "  " + label)
          let flags = @lib.describe_exception_flags(e.flags)
          let flag_text = if flags.length() == 0 {
            "none"
          } else {
            flags.join("|")
          }
          kv(
            "exception flags",
            "0x" + e.flags.to_string(radix=16) + "  " + flag_text,
          )
          kv(
            "faulting address",
            @lib.hex_uint(e.address) +
            "  " +
            @lib.address_module_line(modules, e.address),
          )
          let nested = @lib.hex_uint(e.nested_record_address)
          let nest_note = if e.nested_record_address == 0UL {
            " (no nested exception)"
          } else {
            " (points into target-process memory, usually not captured in the dump)"
          }
          kv("previous exception", nested + nest_note)
          let ps : Array[String] = []
          for p in e.parameters {
            ps.push(@lib.hex_uint(p))
          }
          let declared = e.number_parameters.to_string()
          let got = e.parameters.length().to_string()
          let params = if ps.length() == 0 { "none" } else { ps.join(" ") }
          kv(
            "parameters",
            "declared " + declared + ", got " + got + "  " + params,
          )
          match @lib.memory_access_kind(e.code, e.parameters) {
            None => ()
            Some(k) => {
              kv("access type", k)
              match e.fault_address() {
                Some(a) =>
                  kv(
                    "accessed address",
                    @lib.hex_uint(a) +
                    "  " +
                    @lib.address_module_line(modules, a),
                  )
                None => ()
              }
            }
          }
          match e.underlying_status() {
            Some(s) => kv("page fault reason", @lib.hex_uint(s))
            None => ()
          }
          print_context(dump, arch, e.thread_context, "crash-site context")
        }
      }
  }
}

///|
/// The crash thread id + the location of the "crash-site context" from the exception stream.
/// An absent or unreadable exception stream gives (None, None).
fn crash_site(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> (UInt32?, @lib.LocationDescriptor?) {
  try dump.exception(entries) catch {
    _ => (None, None)
  } noraise {
    exc =>
      match exc {
        None => (None, None)
        Some(e) => (Some(e.thread_id), Some(e.thread_context))
      }
  }
}

///|
/// The order in which stacks are walked. The crash thread always comes first, the rest in
/// thread-table order; without `--all-stacks`, walking stops after `thread_walk_cap` further
/// threads, and "how many were left unwalked" is stated clearly.
fn threads_to_walk(
  threads : Array[@lib.Thread],
  crash_index : Int32?,
  all : Bool,
) -> (Array[(Int32, Bool)], Int32) {
  let order : Array[(Int32, Bool)] = []
  match crash_index {
    None => ()
    Some(i) => order.push((i, true))
  }
  let mut walked : Int32 = 0
  let mut skipped : Int32 = 0
  let n = threads.length()
  let mut i = 0
  while i < n {
    if crash_index is Some(c) && c == i {
      i = i + 1
    } else if !all && walked >= thread_walk_cap {
      skipped = skipped + 1
      i = i + 1
    } else {
      order.push((i, false))
      walked = walked + 1
      i = i + 1
    }
  }
  (order, skipped)
}

///|
/// One line of symbol-store status. When `--symbols` is not given, that must be stated too,
/// otherwise "every frame is (empty_store)" looks like a parse failure.
fn store_line(store : @lib.SymbolStore, notes : Array[String]) -> String {
  let head = store.loaded.length().to_string() + " symbol files"
  let tail = if notes.length() == 0 {
    " (0 when --symbols is not given)"
  } else {
    ", per-directory details below"
  }
  head + store_reject_text(store) + tail
}

///|
/// How many files the store holds and how many were rejected. An empty store must be stated
/// clearly, so it does not look like a parse failure.
fn store_reject_text(store : @lib.SymbolStore) -> String {
  if store.rejected.length() > 0 {
    ", rejected " + store.rejected.length().to_string() + " files"
  } else {
    ""
  }
}

///|
/// The per-frame "function table" corroboration. None and Some(false) must be kept apart:
/// the former means "no function table to compare against", the latter means "a table exists
/// and it says this address is not within any registered range".
fn ft_mark(v : Bool?) -> String {
  match v {
    None => "function table: none"
    Some(true) => "function table: inside"
    Some(false) => "function table: outside"
  }
}

///|
/// The per-frame "return site" corroboration. `no_call` does not mean "definitely not a return
/// address", only "the two preceding bytes are not the two most common call encodings"; the
/// wording must preserve that margin.
fn site_mark(v : String) -> String {
  if v == "call" {
    "return site call"
  } else if v == "no_call" {
    "return site not a common call encoding"
  } else {
    "return site undecidable"
  }
}

///|
/// One stack: first the adopted layout and window, then frame by frame with the symbol line
/// right after each frame, and finally the facts gathered during the walk.
fn print_walk(
  w : @lib.StackWalk,
  modules : Array[@lib.Module],
  store : @lib.SymbolStore,
) -> Unit {
  let win = match (w.window_low, w.window_high) {
    (Some(lo), Some(hi)) =>
      "  window 0x" + lo.to_string(radix=16) + "-0x" + hi.to_string(radix=16)
    _ => "  window none"
  }
  println(
    "      layout " +
    w.layout +
    "  pointer " +
    w.pointer_size.to_string() +
    " bytes" +
    win,
  )
  if !w.supported {
    println("      not walked: " + w.reason)
  }
  if w.frames.length() == 0 {
    println("      no frames")
  }
  let mut i : Int32 = 0
  for f in w.frames {
    let sa = match f.stack_address {
      None => "context"
      Some(a) => "slot 0x" + a.to_string(radix=16)
    }
    let t = @lib.symbolize_frame(f, modules, store)
    println(
      "      #" +
      i.to_string() +
      "  " +
      @lib.hex_uint(f.address) +
      "  " +
      f.kind +
      "  " +
      sa +
      "  " +
      @lib.address_module_line(modules, f.address),
    )
    println(
      "          " +
      @lib.symbol_target_line(t) +
      "  " +
      ft_mark(f.in_function_table) +
      "  " +
      site_mark(f.return_site),
    )
    if t.candidates > 1 {
      println(
        "          matched " +
        t.candidates.to_string() +
        " symbol files, using " +
        t.symbol_source,
      )
    }
    i = i + 1
  }
  for n in w.notes {
    println("      note  " + n)
  }
}

///|
/// The instruction pointer inside a context, None when unreadable. Used to check whether two
/// contexts are the same crash site.
fn context_ip(
  dump : @lib.Dump,
  arch : UInt16,
  loc : @lib.LocationDescriptor,
) -> UInt64? {
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
/// Walk one stack from one context; `label` says which copy is being walked.
/// An unreadable context and an error from the walk itself are each reported separately;
/// neither may degrade into "no stack".
fn walk_and_print(
  dump : @lib.Dump,
  map : @lib.MemoryMap,
  modules : Array[@lib.Module],
  ft : @lib.FunctionTableInfo?,
  store : @lib.SymbolStore,
  walk_opts : @lib.StackWalkOptions,
  t : @lib.Thread,
  loc : @lib.LocationDescriptor,
  arch : UInt16,
  label : String,
) -> Unit {
  if loc.size == 0U || loc.rva == 0UL {
    println("      " + label + "  " + absent)
  } else {
    let read = try dump.read_context(arch, loc) catch {
      err => (None, @lib.describe_error(err))
    } noraise {
      ctx => (ctx, "")
    }
    let (ctx, err_text) = read
    let why = if err_text.length() > 0 {
      ": " + err_text
    } else {
      ": no content"
    }
    match ctx {
      None => println("      " + label + "  unreadable" + why)
      Some(c) => {
        println("      " + label)
        try dump.walk_thread_stack(map, modules, ft, t, c, walk_opts) catch {
          err => println("        cannot walk: " + @lib.describe_error(err))
        } noraise {
          w => print_walk(w, modules, store)
        }
      }
    }
  }
}

///|
/// One thread's stack. The crash thread gets one extra step: the exception stream's "crash-site
/// context" and the thread-table copy are two different pieces of data, and when their
/// instruction pointers differ, both are walked and the difference explained — reporting only
/// the thread-table copy would present "dump-writing time" as the crash site; in the public
/// corpus test.dmp the two instruction pointers do differ.
fn print_thread_stack(
  dump : @lib.Dump,
  map : @lib.MemoryMap,
  modules : Array[@lib.Module],
  ft : @lib.FunctionTableInfo?,
  store : @lib.SymbolStore,
  arch : UInt16,
  walk_opts : @lib.StackWalkOptions,
  threads : Array[@lib.Thread],
  index : Int32,
  is_crash : Bool,
  site : @lib.LocationDescriptor?,
) -> Unit {
  let t = threads[index]
  let tag = if is_crash { " (crash thread)" } else { "" }
  println("  #" + index.to_string() + "  thread " + t.id.to_string() + tag)
  walk_and_print(
    dump,
    map,
    modules,
    ft,
    store,
    walk_opts,
    t,
    t.context,
    arch,
    "thread-table context",
  )
  match site {
    None => ()
    Some(s) =>
      if is_crash {
        let a = context_ip(dump, arch, t.context)
        let b = context_ip(dump, arch, s)
        if a != b {
          let ha = match a {
            None => "unreadable"
            Some(v) => @lib.hex_uint(v)
          }
          let hb = match b {
            None => "unreadable"
            Some(v) => @lib.hex_uint(v)
          }
          println(
            "      the two contexts have different instruction pointers: thread-table " +
            ha +
            ", exception-site " +
            hb +
            ". the former is from dump-writing time; the walk below is the crash moment",
          )
          walk_and_print(
            dump, map, modules, ft, store, walk_opts, t, s, arch, "exception-site context",
          )
        }
      }
  }
}

///|
/// The stack-walk section: a call chain can only be produced once the memory index, module
/// table, function table, and symbol store are all in place.
/// By default only the crash thread plus the first few threads are walked; `--all-stacks` walks all.
fn print_stacks(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  store : @lib.SymbolStore,
  store_notes : Array[String],
  opts : Options,
) -> Unit {
  println("stack walk:")
  kv("symbol store", store_line(store, store_notes))
  for n in store_notes {
    println("  " + n)
  }
  let walk_opts : @lib.StackWalkOptions = {
    max_frames: opts.max_frames,
    max_scan_bytes: 4096L,
    scan: opts.scan,
  }
  let scan_text = if opts.scan {
    "on (scan up to 4096 bytes per thread)"
  } else {
    "off (frame-pointer chain only)"
  }
  println(
    "  up to " +
    opts.max_frames.to_string() +
    " frames per thread  scan " +
    scan_text,
  )
  let (arch, _) = arch_platform(dump, entries)
  let modules = module_array(dump, entries)
  let threads = thread_array(dump, entries)
  if threads.length() == 0 {
    kv(
      "stack walk", "no thread table (ThreadList/ThreadExList), no threads to walk",
    )
  } else {
    let ft = try dump.function_table(entries) catch {
      _ => None
    } noraise {
      info => info
    }
    try dump.memory_map(entries) catch {
      err => println("  memory stream unreadable: " + @lib.describe_error(err))
    } noraise {
      map =>
        match map {
          None =>
            println(
              "  no memory stream (MemoryList/Memory64List), no frames can be read",
            )
          Some(m) => {
            let (crash_id, site) = crash_site(dump, entries)
            let crash_index = match crash_id {
              None => None
              Some(id) =>
                match @lib.find_thread_by_id(threads, id) {
                  None => None
                  Some((i, _)) => Some(i)
                }
            }
            let (order, skipped) = threads_to_walk(
              threads,
              crash_index,
              opts.all_stacks,
            )
            for (i, is_crash) in order {
              print_thread_stack(
                dump, m, modules, ft, store, arch, walk_opts, threads, i, is_crash,
                site,
              )
            }
            if skipped > 0 {
              println(
                "  (" +
                skipped.to_string() +
                " more threads not walked, pass --all-stacks to walk all)",
              )
            }
            println(
              "  note  kind: context is the instruction pointer from the context; fp is the frame-pointer chain;" +
              " scan is an approximation from stack-window scanning and may pick up stale values from local variables.",
            )
            println(
              "  note  x64 unwind info and .sym STACK CFI/STACK WIN are not interpreted;" +
              " after a broken chain the result is a scan approximation, not a precise unwind.",
            )
          }
        }
    }
  }
}

///|
/// Right-align with space padding, also counted in display width, so mixed CJK/ASCII rows still line up.
fn right(s : String, width : Int32) -> String {
  let mut pad = ""
  while display_width(pad + s) < width {
    pad = pad + " "
  }
  pad + s
}

///|
/// Whether the stream directory contains a stream of the given type.
fn has_stream(entries : Array[@lib.StreamEntry], stream_type : UInt32) -> Bool {
  let mut found = false
  for e in entries {
    if e.stream_type == stream_type {
      found = true
    }
  }
  found
}

///|
/// Human-readable byte count: a bare large decimal number does not show the dump size at a
/// glance. The raw byte count always follows; the rounded number cannot replace it.
fn human_bytes(n : UInt64) -> String {
  if n < 1024UL {
    n.to_string() + " bytes"
  } else if n < 1048576UL {
    let tenth = n % 1024UL * 10UL / 1024UL
    (n / 1024UL).to_string() +
    "." +
    tenth.to_string() +
    " KiB (" +
    n.to_string() +
    " bytes)"
  } else if n < 1073741824UL {
    let tenth = n % 1048576UL * 10UL / 1048576UL
    (n / 1048576UL).to_string() +
    "." +
    tenth.to_string() +
    " MiB (" +
    n.to_string() +
    " bytes)"
  } else {
    let tenth = n % 1073741824UL * 10UL / 1073741824UL
    (n / 1073741824UL).to_string() +
    "." +
    tenth.to_string() +
    " GiB (" +
    n.to_string() +
    " bytes)"
  }
}

///|
/// Two lowercase hex digits.
fn hex_byte(b : Byte) -> String {
  let digits = "0123456789abcdef".to_array()
  let v = b.to_int()
  digits[v / 16].to_string() + digits[v % 16].to_string()
}

///|
/// One memory region: `0x<virtual address> +<length> bytes -> file <offset>`; a clipped region
/// notes its originally declared length.
fn region_line(r : @lib.MemoryRegion) -> String {
  let clip = if r.was_clipped() {
    " (declared " + r.declared_size.to_string() + " bytes)"
  } else {
    ""
  }
  @lib.hex_uint(r.start_address) +
  " +" +
  r.size.to_string() +
  " bytes -> file " +
  r.file_rva.to_string() +
  clip
}

///|
/// Memory layer: three things — which virtual addresses were captured (the index), whether the
/// crash-relevant addresses can be read (accessibility), and what the bytes read back look like
/// (end-to-end verification).
///
/// The last one matters most: Memory64List's file position is "BaseRva + the sum of the declared
/// sizes of all preceding regions"; get that rule off by one and every region after it reads
/// back wrong, while the stream directory still looks perfectly normal.
/// Printing the 16 bytes at sp lets values such as return addresses and int 3 themselves
/// falsify the offset.
fn print_memory(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  let src : Array[String] = []
  if has_stream(entries, @lib.memory_list_stream) {
    src.push("MemoryList(5)")
  }
  if has_stream(entries, @lib.memory_64_list_stream) {
    src.push("Memory64List(9)")
  }
  try dump.memory_map(entries) catch {
    err => kv("memory", "unreadable: " + @lib.describe_error(err))
  } noraise {
    m =>
      match m {
        None => kv("memory", "no MemoryList/Memory64List stream")
        Some(map) => {
          println("memory index:")
          kv("sources", src.join(" + "))
          kv(
            "regions",
            map.region_count().to_string() +
            " region(s), " +
            human_bytes(map.total_bytes()),
          )
          if map.clipped_count() > 0U {
            kv(
              "clipped",
              map.clipped_count().to_string() +
              " region(s) declared past end of file, truncated to the file length",
            )
          }
          let rs = map.regions
          if rs.length() > 0 {
            kv("first region", region_line(rs[0]))
            kv("last region", region_line(rs[rs.length() - 1]))
            let mut biggest = rs[0]
            for r in rs {
              if r.size > biggest.size {
                biggest = r
              }
            }
            kv("largest region", region_line(biggest))
          }
          print_addresses(dump, entries, map)
        }
      }
  }
  println("")
  print_memory_layout(dump, entries)
}

///|
/// The faulting address + the crash site's instruction pointer / stack pointer: each mapped to
/// its file position, then the 16 bytes at that position printed as-is.
fn print_addresses(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
  map : @lib.MemoryMap,
) -> Unit {
  let (arch, _) = arch_platform(dump, entries)
  let modules = module_array(dump, entries)
  let exc = try dump.exception(entries) catch {
    _ => None
  } noraise {
    e => e
  }
  match exc {
    None => ()
    Some(e) => {
      show_address(dump, map, modules, "faulting address", Some(e.address))
      show_context_pointers(dump, map, modules, arch, e.thread_context)
    }
  }
}

///|
/// The instruction pointer and stack pointer lines. When the architecture's register table is
/// not recognized (returns None), say so explicitly instead of leaving a blank line.
fn show_context_pointers(
  dump : @lib.Dump,
  map : @lib.MemoryMap,
  modules : Array[@lib.Module],
  arch : UInt16,
  loc : @lib.LocationDescriptor,
) -> Unit {
  let ctx = try dump.read_context(arch, loc) catch {
    _ => None
  } noraise {
    c => c
  }
  match ctx {
    None =>
      kv(
        "instruction pointer",
        "context unreadable (register table for architecture 0x" +
        arch.to_string(radix=16) +
        " unsupported, or CONTEXT size unreasonable)",
      )
    Some(c) => {
      show_address(
        dump,
        map,
        modules,
        "instruction pointer",
        c.instruction_pointer(),
      )
      show_address(dump, map, modules, "stack pointer", c.stack_pointer())
    }
  }
}

///|
/// One virtual address: module attribution + whether it was captured, and if captured the 16
/// raw bytes follow. It is read only when the whole range lies within a single captured region
/// (read_memory_at's rule), so both "not captured" and "straddling two regions" display as
/// unreadable — that is intentional.
fn show_address(
  dump : @lib.Dump,
  map : @lib.MemoryMap,
  modules : Array[@lib.Module],
  label : String,
  address : UInt64?,
) -> Unit {
  match address {
    None => kv(label, "not present in the context")
    Some(a) => {
      let owner = @lib.address_module_line(modules, a)
      let reach = match map.file_rva_for(a, 1UL) {
        None => "not captured"
        Some(f) => "captured -> file " + f.to_string()
      }
      kv(label, @lib.hex_uint(a) + "  " + owner + "  " + reach)
      let sample = try dump.read_memory_at(map, a, 16) catch {
        _ => None
      } noraise {
        b => b
      }
      match sample {
        None => ()
        Some(bs) => {
          let parts : Array[String] = []
          for b in bs {
            parts.push(hex_byte(b))
          }
          println("                " + parts.join(" "))
        }
      }
    }
  }
}

///|
/// MemoryInfoList: the virtual memory layout. The question most often asked when analyzing a
/// sample is "is there executable memory outside any module", and this section answers it
/// directly; with an empty module table the check is skipped, so that the whole ntdll is not
/// listed as a suspicious region.
fn print_memory_layout(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  let modules = module_array(dump, entries)
  try dump.memory_info_list(entries) catch {
    err => kv("memory layout", "unreadable: " + @lib.describe_error(err))
  } noraise {
    list =>
      match list {
        None =>
          kv(
            "memory layout", "no MemoryInfoListStream (not written at dump time)",
          )
        Some(items) => {
          println("memory layout:")
          kv("entries", items.length().to_string() + " total")
          kv("committed", human_bytes(@lib.memory_info_committed_bytes(items)))
          let sus = @lib.memory_info_executable_outside_modules(items, modules)
          let note = if modules.length() == 0 {
            " (no module table, not checked)"
          } else {
            ""
          }
          kv(
            "executable outside modules",
            sus.length().to_string() + " region(s)" + note,
          )
          let mut i = 0
          while i < sus.length() && i < 8 {
            let m = sus[i]
            println(
              "  " +
              @lib.hex_uint(m.base_address) +
              " +" +
              m.region_size.to_string() +
              " bytes  " +
              @lib.memory_protection_name(m.protect) +
              "  " +
              @lib.memory_type_name(m.type_),
            )
            i = i + 1
          }
          if sus.length() > 8 {
            println(
              "  (showing first 8 of " + sus.length().to_string() + " total)",
            )
          }
        }
      }
  }
}

///|
/// Thread name table. Unreadable is treated as absent: the name at the end of a thread line is
/// supplementary information only and must not take the whole summary down with it — the
/// stream-directory section still explicitly reports this stream's presence and size.
fn thread_names_of(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Array[@lib.ThreadName] {
  try dump.thread_names(entries) catch {
    _ => []
  } noraise {
    names =>
      match names {
        None => []
        Some(list) => list
      }
  }
}

///|
/// The trailing segment of a thread line. With no record, nothing is appended; with a record
/// whose name is the empty string, it prints as `name ""` — "no such name" and "name is empty"
/// are two different facts.
fn thread_name_text(names : Array[@lib.ThreadName], id : UInt32) -> String {
  match @lib.thread_name_for(names, id) {
    None => ""
    Some(n) => "  name \"" + n + "\""
  }
}

///|
/// Long-tail streams: unloaded modules, handle table, function table, thread info. All four are
/// often entirely absent from real dumps, but "absent" and "present yet unreadable" are two
/// different things; both are reported, never silently skipped.
fn print_extra_streams(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  print_unloaded_modules(dump, entries)
  println("")
  print_handles(dump, entries)
  println("")
  print_function_table(dump, entries)
  println("")
  print_thread_infos(dump, entries)
}

///|
/// Unloaded modules: after injected code exits, this is all that remains, so "declared how
/// many, skipped how many" is reported alongside the entries.
fn print_unloaded_modules(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  if !has_stream(entries, @lib.unloaded_module_list_stream) {
    kv("UnloadedModuleList", "stream absent")
    return ()
  }
  try dump.unloaded_modules(entries) catch {
    err => kv("UnloadedModuleList", "unreadable: " + @lib.describe_error(err))
  } noraise {
    list =>
      match list {
        None => kv("UnloadedModuleList", "stream absent")
        Some(ul) => {
          let total = ul.modules.length()
          let skipped = if ul.skipped == 0U {
            ""
          } else {
            ", skipped " + ul.skipped.to_string() + " malformed records"
          }
          kv(
            "UnloadedModuleList",
            "declared " +
            ul.declared_count.to_string() +
            ", got " +
            total.to_string() +
            " entries" +
            skipped,
          )
          let mut i = 0
          while i < total && i < 20 {
            let m = ul.modules[i]
            let name = if m.name.length() == 0 { "(unnamed)" } else { m.name }
            println(
              "  " +
              @lib.hex_uint(m.base_of_image) +
              " - " +
              @lib.hex_uint(m.end_address()) +
              "  image " +
              m.size_of_image.to_string() +
              "  checksum 0x" +
              m.checksum.to_string(radix=16) +
              "  timestamp 0x" +
              m.time_date_stamp.to_string(radix=16) +
              "  " +
              name,
            )
            i = i + 1
          }
          if total > 20 {
            println("  (showing first 20 of " + total.to_string() + " total)")
          }
        }
      }
  }
}

///|
/// Handle table. Named objects are the cross-process-communication clues in sample analysis:
/// pipes, events, and shared memory are all tied together by names.
fn print_handles(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  if !has_stream(entries, @lib.handle_data_stream) {
    kv("HandleData", "stream absent")
    return ()
  }
  try dump.handles(entries) catch {
    err => kv("HandleData", "unreadable: " + @lib.describe_error(err))
  } noraise {
    hs =>
      match hs {
        None => kv("HandleData", "stream absent")
        Some(list) => {
          let mut named = 0
          for h in list {
            if h.object_name.length() > 0 {
              named = named + 1
            }
          }
          let width = if list.length() == 0 {
            "none"
          } else {
            list[0].descriptor_size.to_string() + " bytes"
          }
          kv(
            "HandleData",
            list.length().to_string() +
            " handle(s), named objects " +
            named.to_string() +
            ", descriptor " +
            width,
          )
          for row in top_counts(type_counts(list), 6L) {
            println("  " + right(row.0, 24) + " × " + row.1.to_string())
          }
          let mut shown = 0
          let mut i = 0
          while i < list.length() && shown < 12 {
            let h = list[i]
            i = i + 1
            if h.object_name.length() > 0 {
              let type_ = if h.type_name.length() == 0 {
                "(unnamed type)"
              } else {
                h.type_name
              }
              println(
                "  handle " +
                @lib.hex_uint(h.handle) +
                "  " +
                type_ +
                "  " +
                h.object_name +
                "  access 0x" +
                h.granted_access.to_string(radix=16),
              )
              shown = shown + 1
            }
          }
          if named > 12 {
            println(
              "  (showing first 12 named objects of " +
              named.to_string() +
              " total)",
            )
          }
        }
      }
  }
}

///|
/// Handles aggregated by type name. Unreadable type names (HandleObjectInfo missing, or a name
/// RVA pointing out of range) go into `(unnamed type)`, never mixed into a real type's bucket.
fn type_counts(hs : Array[@lib.Handle]) -> Array[(String, Int64)] {
  let out : Array[(String, Int64)] = []
  for h in hs {
    let key = if h.type_name.length() == 0 {
      "(unnamed type)"
    } else {
      h.type_name
    }
    let mut found = false
    let mut i = 0
    while i < out.length() {
      if out[i].0 == key {
        out[i] = (key, out[i].1 + 1)
        found = true
        i = out.length()
      } else {
        i = i + 1
      }
    }
    if !found {
      out.push((key, 1))
    }
  }
  out
}

///|
/// Take the top n buckets: larger counts first, and ties keep first-appearance order. Strings
/// are never compared, so the same dump prints its rows in the same order every time.
fn top_counts(
  counts : Array[(String, Int64)],
  n : Int64,
) -> Array[(String, Int64)] {
  let used : Array[Bool] = []
  let mut i = 0
  while i < counts.length() {
    used.push(false)
    i = i + 1
  }
  let out : Array[(String, Int64)] = []
  let mut taken : Int64 = 0
  let mut go = true
  while go {
    let mut best = -1
    let mut j = 0
    while j < counts.length() {
      if !used[j] && best < 0 {
        best = j
      } else if !used[j] && counts[j].1 > counts[best].1 {
        best = j
      }
      j = j + 1
    }
    if best < 0 || taken >= n {
      go = false
    } else {
      used[best] = true
      out.push(counts[best])
      taken = taken + 1
    }
  }
  out
}

///|
/// Function table: only the declared size and whether the entry region falls within the file
/// are reported. The entries themselves are platform-specific RUNTIME_FUNCTION/UNWIND_INFO;
/// parsing them requires the module base address and the PE alongside, which is the stack-walk
/// layer's job — the format layer does not decode them from memory.
fn print_function_table(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  if !has_stream(entries, @lib.function_table_stream) {
    kv("FunctionTable", "stream absent")
    return ()
  }
  try dump.function_table(entries) catch {
    err => kv("FunctionTable", "unreadable: " + @lib.describe_error(err))
  } noraise {
    info =>
      match info {
        None => kv("FunctionTable", "stream absent")
        Some(ft) => {
          let n = ft.descriptors.length()
          let note = if ft.layout_ok {
            ""
          } else {
            " -- neither layout is self-consistent, reading below with the declared stride, results are not trustworthy"
          }
          kv(
            "FunctionTable",
            @lib.function_table_layout_name(ft.layout) +
            ", " +
            n.to_string() +
            " table(s), declared " +
            ft.total_entries.to_string() +
            " function entries" +
            note,
          )
          println(
            "  stride  descriptor " +
            ft.size_of_descriptor.to_string() +
            "  native " +
            ft.size_of_native_descriptor.to_string() +
            "  entry " +
            ft.size_of_function_entry.to_string() +
            "  header " +
            ft.declared_header.to_string() +
            "  padding " +
            ft.size_of_align_pad.to_string() +
            "  record width " +
            ft.record_width.to_string(),
          )
          let inline_layout = match ft.layout {
            @lib.FunctionTableLayout::Declared => false
            @lib.FunctionTableLayout::InlineRecords => true
          }
          let body = if ft.total_entries == 0UL {
            "no function entries"
          } else if inline_layout && ft.entries_in_file {
            "function entries inlined in each record, no separate entry region"
          } else if inline_layout {
            "record region out of range, inline function entries incomplete"
          } else if ft.entries_in_file {
            "function entry region " +
            @lib.hex_uint(ft.entries_rva) +
            " within the file"
          } else {
            "function entry region " +
            @lib.hex_uint(ft.entries_rva) +
            " out of range, reporting descriptors only"
          }
          println("  " + body)
          let mut i = 0
          while i < n && i < 8 {
            let d = ft.descriptors[i]
            let inl = match d.inline_entry {
              None => ""
              Some(e) =>
                "  function entry 0x" +
                e.0.to_string(radix=16) +
                "-0x" +
                e.1.to_string(radix=16) +
                " unwind info 0x" +
                e.2.to_string(radix=16)
            }
            println(
              "  " +
              @lib.hex_uint(d.minimum_address) +
              " - " +
              @lib.hex_uint(d.maximum_address) +
              "  base " +
              @lib.hex_uint(d.base_address) +
              "  entries " +
              d.entry_count.to_string() +
              inl,
            )
            i = i + 1
          }
          if n > 8 {
            println("  (showing first 8 of " + n.to_string() + " total)")
          }
        }
      }
  }
}

///|
/// Thread info stream: each thread's error code, exit status, and entry address at dump-writing
/// time. An entry outside any module is a classic injection signal, so they are counted
/// separately and called out one by one.
fn print_thread_infos(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  if !has_stream(entries, @lib.thread_info_list_stream) {
    kv("ThreadInfoList", "stream absent")
    return ()
  }
  let modules = module_array(dump, entries)
  try dump.thread_infos(entries) catch {
    err => kv("ThreadInfoList", "unreadable: " + @lib.describe_error(err))
  } noraise {
    infos =>
      match infos {
        None => kv("ThreadInfoList", "stream absent")
        Some(list) => {
          let outside = @lib.thread_infos_started_outside_modules(list, modules)
          let mut flagged = 0
          for t in list {
            if t.dump_flags != 0U {
              flagged = flagged + 1
            }
          }
          kv(
            "ThreadInfoList",
            list.length().to_string() +
            " thread(s), " +
            flagged.to_string() +
            " with status flags, " +
            outside.length().to_string() +
            " with entry outside modules",
          )
          if modules.length() == 0 {
            println("  (no module table, entry outside modules not checked)")
          }
          let mut i = 0
          while i < list.length() && i < 8 {
            let t = list[i]
            println(
              "  thread " +
              t.thread_id.to_string() +
              "  " +
              @lib.thread_dump_flags_name(t.dump_flags) +
              "  error 0x" +
              t.dump_error.to_string(radix=16) +
              "  exit code 0x" +
              t.exit_status.to_string(radix=16) +
              "  entry " +
              @lib.hex_uint(t.start_address),
            )
            i = i + 1
          }
          if list.length() > 8 {
            println(
              "  (showing first 8 of " + list.length().to_string() + " total)",
            )
          }
          let mut k = 0
          while k < outside.length() && k < 8 {
            let t = outside[k]
            println(
              "  warning: thread " +
              t.thread_id.to_string() +
              " entry " +
              @lib.hex_uint(t.start_address) +
              " is not inside any module",
            )
            k = k + 1
          }
          if outside.length() > 8 {
            println(
              "  (showing first 8 of " +
              outside.length().to_string() +
              " total)",
            )
          }
        }
      }
  }
}
