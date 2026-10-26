// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! Corpus regression for the JSON report (`--json`).
///!
///! This deliberately goes down the full path: `report_json` builds the document → `stringify` turns it
///! into text → `@json.parse` reads the text **back in**, and fields are then taken from that parsed-back
///! document. Checking only the in-memory `Json` value cannot prove "this text is valid JSON and the
///! field names and nesting really are like this", while upstream consumers (scripts, CI, bulk triage)
///! get the text. This also pins "the parsed-back value equals the in-memory one" (the `round=y` in the digest).
///!
///! The value conventions match the stack-walk golden: a frame's `kind`/`ip`/`stack_slot`/module
///! attribution must be exactly what `assert_crash_stack_walk` reports; the two output channels
///! must never tell two different stories.

///|
/// Fetch a value by field name inside an object, yielding `Json::null()` when absent.
/// Iteration is used instead of `m[key]`: the `Map` subscript syntax changed implementation across
/// several core-library versions, while "iterate over key-value pairs" never did — in tests, a bit
/// of clumsiness is preferable.
fn get_key(m : Map[String, Json], key : String) -> Json {
  let mut out = Json::null()
  for k, v in m {
    if k == key {
      out = v
    }
  }
  out
}

///|
/// Walk down key by key. Hitting a non-object along the way or a missing field both return `Json::null()`:
/// tests do not throw; whatever cannot be fetched shows up as `-`, so the golden shows at a glance which cell came up empty.
fn at(node : Json, keys : Array[String]) -> Json {
  let mut cur = node
  let mut i = 0
  while i < keys.length() {
    let next = match cur {
      Json::Object(m) => get_key(m, keys[i])
      _ => Json::null()
    }
    cur = next
    i = i + 1
  }
  cur
}

///|
/// Array index. A non-array or an out-of-range index likewise yields null, keeping the same convention as `at`.
fn elem(node : Json, i : Int32) -> Json {
  match node {
    Json::Array(a) => if i >= 0 && i < a.length() { a[i] } else { Json::null() }
    _ => Json::null()
  }
}

///|
/// Take text: strings verbatim (addresses and 64-bit lengths go through here), null recorded as `-`,
/// numbers and booleans in JSON's own notation.
fn text(node : Json) -> String {
  match node {
    Json::String(s) => s
    Json::Null => "-"
    j => j.stringify()
  }
}

///|
fn ftext(node : Json, keys : Array[String]) -> String {
  text(at(node, keys))
}

///|
/// Top-level field names, in document order. `Json`'s objects are `Map`s and iteration order is insertion
/// order, so this one line pins both "all fields present" and "order is fixed".
fn top_keys(parsed : Json) -> String {
  let ks : Array[String] = []
  match parsed {
    Json::Object(m) =>
      for k, _ in m {
        ks.push(k)
      }
    _ => ()
  }
  ks.join(",")
}

///|
/// The 17 top-level fields, in a fixed order. The order itself is part of the schema: changing the order changes the schema.
let head_keys = "schema,generator,file,streams,system_info,misc_info,modules,unloaded_modules,threads,exception,stacks,memory,thread_names,thread_infos,handles,function_table,symbol_store"

///|
/// The cell of the skeleton digest representing the top-level fields: when the order is right it just
/// writes `17=y`; when it is not, the actual order is printed in full so the failure message has something to look at.
fn keys_note(parsed : Json) -> String {
  let ks = top_keys(parsed)
  if ks == head_keys {
    "keys=17/y"
  } else {
    "keys=" + ks
  }
}

///|
/// After walking "build → stringify → re-parse", hand over both the in-memory document and the parsed-back one.
fn report_of(name : String, opts : @lib.JsonOptions) -> (Json, Json) raise {
  let dump = @corpus.open_fixture(name)
  let doc = dump.report_json(opts)
  let parsed = @json.parse(@lib.json_report_text(doc))
  (doc, parsed)
}

///|
/// The report under default options: no path, no symbol store, plus the crashing thread's first stacks.
fn report_default(name : String) -> (Json, Json) raise {
  report_of(name, @lib.json_options_default())
}

///|
/// For cases where one dump must produce several reports: gives the "text parsed back" document directly.
fn parse_report(dump : @lib.Dump, opts : @lib.JsonOptions) -> Json raise {
  @json.parse(@lib.json_report_text(dump.report_json(opts)))
}

///|
/// Skeleton digest of one stack: which thread, which context was walked, what architecture, how many
/// frames, where the first frame stopped. The crashing thread's two stacks are told apart by this one
/// line — `thread_id` is the same; only `source` and the first frame's address differ. When an
/// out-of-range index fetches nothing the whole line is `-`, without throwing.
fn stack_digest(parsed : Json, i : Int32) -> String {
  let s = elem(at(parsed, ["stacks", "items", "items"]), i)
  let f0 = elem(at(s, ["frames"]), 0)
  [
    "t" + ftext(s, ["thread_id"]),
    ftext(s, ["source"]),
    ftext(s, ["layout"]),
    ftext(s, ["frame_count"]),
    "ip0=" + ftext(f0, ["ip"]),
    "mod0=" + ftext(f0, ["module"]) + "+" + ftext(f0, ["offset"]),
  ].join("/")
}

///|
/// Skeleton digest of one document. All corpora share the same shape, so this line pins:
/// not a single top-level field missing, in exactly the schema's 17-field order (`keys=17/y`), absent
/// sections present as `null` rather than omitted, the stack bookkeeping self-consistent (`book=ok` means
/// `stacks.walked` equals `stacks.items.count`), and `round=y` means the re-parsed text equals the in-memory document.
fn doc_digest(name : String, doc : Json, parsed : Json) -> String {
  let s0 = elem(at(parsed, ["stacks", "items", "items"]), 0)
  let walked = ftext(parsed, ["stacks", "walked"])
  let item_count = ftext(parsed, ["stacks", "items", "count"])
  let book = if walked == item_count { "ok" } else { "mismatch" }
  let round = if doc == parsed { "y" } else { "n" }
  let first : Array[String] = [
    ftext(s0, ["thread_id"]),
    ftext(s0, ["source"]),
    ftext(s0, ["layout"]),
    ftext(s0, ["frame_count"]),
  ]
  [
    name,
    keys_note(parsed),
    "round=" + round,
    "size=" + ftext(parsed, ["file", "size"]),
    "streams=" + ftext(parsed, ["streams", "count"]),
    "modules=" + ftext(parsed, ["modules", "count"]),
    "threads=" + ftext(parsed, ["threads", "count"]),
    "exception=" + ftext(parsed, ["exception", "code"]),
    "map=" + ftext(parsed, ["stacks", "memory_map"]),
    "scan=" + ftext(parsed, ["stacks", "scan"]),
    "symd=" + ftext(parsed, ["stacks", "symbolicated"]),
    "walked=" + walked,
    "count=" + item_count,
    "book=" + book,
    "skipped=" + ftext(parsed, ["stacks", "skipped_threads"]),
    "truncated=" + ftext(parsed, ["stacks", "items", "truncated"]),
    "store=" + ftext(parsed, ["symbol_store", "loaded"]),
    "first=" + first.join("/"),
  ].join(" ")
}

///|
/// Per-frame text for the crash-site stack.
fn frames_digest(parsed : Json) -> String {
  let s0 = elem(at(parsed, ["stacks", "items", "items"]), 0)
  let fs = at(s0, ["frames"])
  let n = match fs {
    Json::Array(a) => a.length()
    _ => 0
  }
  let out : Array[String] = []
  for i in 0..<n {
    let f = elem(fs, i)
    let one : Array[String] = [
      ftext(f, ["kind"]),
      ftext(f, ["ip"]),
      "slot=" + ftext(f, ["stack_slot"]),
      ftext(f, ["module"]) + "+" + ftext(f, ["offset"]),
      "ft=" + ftext(f, ["function_table"]),
      "rs=" + ftext(f, ["return_site"]),
      "sym=" + ftext(f, ["symbol", "status"]),
    ]
    out.push(one.join(" "))
  }
  out.join(" ; ")
}

///|
let fixtures : Array[String] = [
  "test.dmp", "simple-crashpad.dmp", "linux-mini.dmp", "invalid-parameter.dmp", "full-dump.dmp",
  "invalid-range.dmp", "invalid-record-count.dmp",
]

///|
/// Top-level shape: fields all present, order fixed; missing sections (e.g. a malformed dump with no
/// SystemInfo) are `null`, not "this key is gone". Addresses and 64-bit lengths must be strings —
/// double precision is only exact up to 2^53, and a 64-bit address must not take that risk.
test "JSON: top-level fields and order" {
  let (doc, parsed) = report_default("test.dmp")
  let got : Array[String] = [
    top_keys(parsed),
    ftext(parsed, ["generator", "name"]),
    ftext(parsed, ["generator", "version"]),
    ftext(parsed, ["stacks", "max_frames"]),
    ftext(parsed, ["stacks", "max_scan_bytes"]),
    // file.path is present only when the caller supplied it: the library does not know the path itself, so with default options it is null.
    ftext(parsed, ["file", "path"]),
    // symbol_store likewise: null when no symbol store was given, not an empty object.
    ftext(parsed, ["symbol_store"]),
  ]
  assert_eq(got, [head_keys, "moondump", "0.1.0", "64", "4096", "-", "-"])
  assert_true(doc == parsed)
  let shape : Array[String] = [
    ftext(parsed, ["file", "signature"]),
    ftext(parsed, ["file", "signature_raw"]),
    ftext(parsed, ["file", "checksum"]),
    ftext(parsed, ["file", "flags"]),
    ftext(parsed, ["file", "stream_directory_rva"]),
    ftext(parsed, ["file", "time_date_stamp"]),
    ftext(parsed, ["exception", "code"]),
    ftext(parsed, ["exception", "thread_context", "size"]),
    ftext(parsed, ["exception", "thread_context", "rva"]),
  ]
  assert_eq(shape, [
    "MDMP", "0x504d444d", "0x0", "0x0", "32", "1171480435", "0xc0000005", "716",
    "2760",
  ])
}

///|
/// All seven public corpora have the same shape: the two malformed ones must also produce a complete
/// document, with each section `null`, not a missing report.
/// `walked` is the number of stacks, not the thread count: when the crash thread's exception context and
/// thread-table context parked in different places (true for test.dmp and invalid-parameter.dmp), each
/// gets its own stack, so those two reports have `walked` one greater than `threads`.
test "JSON: skeleton of every fixture" {
  let lines : Array[String] = []
  for name in fixtures {
    let (doc, parsed) = report_default(name)
    lines.push(doc_digest(name, doc, parsed))
  }
  assert_eq(lines, [
    "test.dmp keys=17/y round=y size=11317 streams=9 modules=13 threads=2 exception=0xc0000005 map=present scan=true symd=false walked=3 count=3 book=ok skipped=0 truncated=false store=- first=3060/exception_context/x86/5",
    "simple-crashpad.dmp keys=17/y round=y size=18512 streams=7 modules=40 threads=1 exception=0x0 map=present scan=true symd=false walked=1 count=1 book=ok skipped=0 truncated=false store=- first=927532/exception_context/amd64/5",
    "linux-mini.dmp keys=17/y round=y size=27549 streams=14 modules=8 threads=1 exception=0xb map=present scan=true symd=false walked=1 count=1 book=ok skipped=0 truncated=false store=- first=1304/exception_context/amd64/16",
    "invalid-parameter.dmp keys=17/y round=y size=44629 streams=14 modules=31 threads=6 exception=0xc000000d map=present scan=true symd=false walked=7 count=7 book=ok skipped=0 truncated=false store=- first=5896/exception_context/amd64/28",
    "full-dump.dmp keys=17/y round=y size=8408702 streams=13 modules=6 threads=4 exception=0x80000003 map=present scan=true symd=false walked=4 count=4 book=ok skipped=0 truncated=false store=- first=8124/exception_context/amd64/24",
    "invalid-range.dmp keys=17/y round=y size=276 streams=4 modules=- threads=- exception=- map=absent scan=true symd=false walked=0 count=0 book=ok skipped=0 truncated=false store=- first=-/-/-/-",
    "invalid-record-count.dmp keys=17/y round=y size=235 streams=16 modules=- threads=- exception=- map=absent scan=true symd=false walked=0 count=0 book=ok skipped=0 truncated=false store=- first=-/-/-/-",
  ])
}

///|
/// The crash-site stack: both the stack's metadata and its per-frame values must match the
/// `assert_crash_stack_walk` golden (that one is frames=5 fp=3 slots=95, and the broken-chain note is the same one).
test "JSON: per-frame values match the stack-walk golden" {
  let (_, parsed) = report_default("test.dmp")
  let s0 = elem(at(parsed, ["stacks", "items", "items"]), 0)
  let meta : Array[String] = [
    ftext(s0, ["thread_id"]),
    ftext(s0, ["source"]),
    ftext(s0, ["layout"]),
    ftext(s0, ["pointer_size"]),
    ftext(s0, ["supported"]),
    ftext(s0, ["frame_count"]),
    ftext(s0, ["fp_frames"]),
    ftext(s0, ["scanned_slots"]),
    ftext(s0, ["scan_limited"]),
    ftext(s0, ["window", "low"]),
    ftext(s0, ["window", "high"]),
    ftext(s0, ["window", "size"]),
    text(elem(at(s0, ["notes"]), 0)),
  ]
  assert_eq(meta, [
    "3060", "exception_context", "x86", "4", "true", "5", "3", "95", "false", "0x12f31c",
    "0x130000", "3300", "frame-pointer chain broke: next frame pointer 0x0 is outside (0x12fff0, 0x130000)",
  ])
  assert_eq(
    frames_digest(parsed),
    "context 0x40429e slot=- c:\\test_app.exe+0x429e ft=- rs=unknown sym=- ; fp 0x404200 slot=0x12fe8c c:\\test_app.exe+0x4200 ft=- rs=unknown sym=- ; fp 0x4053ec slot=0x12ff74 c:\\test_app.exe+0x53ec ft=- rs=unknown sym=- ; fp 0x7c816fd7 slot=0x12ffc4 C:\\WINDOWS\\system32\\kernel32.dll+0x16fd7 ft=- rs=unknown sym=- ; scan 0x405443 slot=0x12fff8 c:\\test_app.exe+0x5443 ft=- rs=unknown sym=-",
  )
}

///|
/// The crash thread's **two contexts**: the one in the exception stream is the state at the moment of the
/// crash; the one in the thread table is the state when the dump was written. In test.dmp these two differ
/// greatly — the exception context is parked at test_app's 0x40429e, the thread-table context inside
/// kernel32. The text CLI walks both by default, so JSON must also have both by default, in the fixed
/// order "exception site first", and without needing `--all-stacks`: the same dump must give the same set
/// of call chains on both output channels, otherwise the machine-readable one shows less than the human one.
test "JSON: the crash thread's two contexts" {
  let (_, parsed) = report_default("test.dmp")
  let got : Array[String] = [
    "walked=" + ftext(parsed, ["stacks", "walked"]),
    "threads=" + ftext(parsed, ["threads", "count"]),
    stack_digest(parsed, 0),
    stack_digest(parsed, 1),
    stack_digest(parsed, 2),
    // An out-of-range index fetches nothing: the whole line is `-`, no throw.
    stack_digest(parsed, 3),
  ]
  assert_eq(got, [
    "walked=3", "threads=2", "t3060/exception_context/x86/5/ip0=0x40429e/mod0=c:\\test_app.exe+0x429e",
    "t3060/thread_table_context/x86/13/ip0=0x7c90eb94/mod0=C:\\WINDOWS\\system32\\ntdll.dll+0xeb94",
    "t4544/thread_table_context/x86/65/ip0=0x7c90eb94/mod0=C:\\WINDOWS\\system32\\ntdll.dll+0xeb94",
    "t-/-/-/-/ip0=-/mod0=-+-",
  ])
}

///|
/// Every CLI switch must leave a trace in the document: the path from `--json`, the symbol store from
/// `--symbols`, the frame pruning after `--no-scan`, the stack count walked by `--all-stacks`.
test "JSON: CLI flags recorded and symbolization" {
  let dump = @corpus.open_fixture("test.dmp")
  let store = @lib.symbol_store_new()
  let sym = "MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 c:\\test_app.pdb\n" +
    "FUNC 0 4280 40 test_app!crash_here\n"
  assert_true(@lib.symbol_store_add(store, "inline:test_app.sym", sym))
  let full : @lib.JsonOptions = {
    path: Some("testdata/test.dmp"),
    symbols: Some(store),
    walk: @lib.stack_walk_options_default(),
    all_threads: true,
  }
  let p_full = parse_report(dump, full)
  let s1 = elem(at(p_full, ["stacks", "items", "items"]), 1)
  let s2 = elem(at(p_full, ["stacks", "items", "items"]), 2)
  let head : Array[String] = [
    "path=" + ftext(p_full, ["file", "path"]),
    "symd=" + ftext(p_full, ["stacks", "symbolicated"]),
    "walked=" + ftext(p_full, ["stacks", "walked"]),
    "skipped=" + ftext(p_full, ["stacks", "skipped_threads"]),
    "store=" + ftext(p_full, ["symbol_store", "loaded"]),
    "file0=" + text(elem(at(p_full, ["symbol_store", "loaded_files"]), 0)),
    "t1=" + ftext(s1, ["thread_id"]),
    "src1=" + ftext(s1, ["source"]),
    "frames1=" + ftext(s1, ["frame_count"]),
    // items[2] is the second thread in the thread table (4544): both of the crash thread's stacks are listed ahead of it.
    "t2=" + ftext(s2, ["thread_id"]),
    "src2=" + ftext(s2, ["source"]),
    "frames2=" + ftext(s2, ["frame_count"]),
  ]
  // The per-frame result after symbolizing the crash thread's stack: only the sym= cell changes; not a single value moves.
  let sym_line = frames_digest(p_full)
  // --no-scan: only the context plus the frame-pointer chain remain, the scan frame is gone, and the slot count in the metadata changes with it.
  let p_noscan = parse_report(dump, {
    path: None,
    symbols: None,
    walk: { max_frames: 64, max_scan_bytes: 4096L, scan: false, },
    all_threads: false,
  })
  let s0_noscan = elem(at(p_noscan, ["stacks", "items", "items"]), 0)
  let noscan_line : Array[String] = [
    "scan=" + ftext(p_noscan, ["stacks", "scan"]),
    "symd=" + ftext(p_noscan, ["stacks", "symbolicated"]),
    "store=" + ftext(p_noscan, ["symbol_store"]),
    "frames=" + ftext(s0_noscan, ["frame_count"]),
    "slots=" + ftext(s0_noscan, ["scanned_slots"]),
    frames_digest(p_noscan),
  ]
  // --max-frames 2: the merged result is truncated to 2 frames the same way, and the note must say whether it was truncated or the chain broke.
  let p_two = parse_report(dump, {
    path: None,
    symbols: None,
    walk: { max_frames: 2, max_scan_bytes: 4096L, scan: true, },
    all_threads: false,
  })
  let s0_two = elem(at(p_two, ["stacks", "items", "items"]), 0)
  let two_line : Array[String] = [
    "max_frames=" + ftext(p_two, ["stacks", "max_frames"]),
    "frames=" + ftext(s0_two, ["frame_count"]),
    "note=" + text(elem(at(s0_two, ["notes"]), 0)),
    frames_digest(p_two),
  ]
  let got : Array[String] = [
    head.join(" "),
    sym_line,
    noscan_line.join(" "),
    two_line.join(" "),
  ]
  assert_eq(got, [
    "path=testdata/test.dmp symd=true walked=3 skipped=0 store=1 file0=inline:test_app.sym t1=3060 src1=thread_table_context frames1=13 t2=4544 src2=thread_table_context frames2=65",
    "context 0x40429e slot=- c:\\test_app.exe+0x429e ft=- rs=unknown sym=ok ; fp 0x404200 slot=0x12fe8c c:\\test_app.exe+0x4200 ft=- rs=unknown sym=unresolved ; fp 0x4053ec slot=0x12ff74 c:\\test_app.exe+0x53ec ft=- rs=unknown sym=unresolved ; fp 0x7c816fd7 slot=0x12ffc4 C:\\WINDOWS\\system32\\kernel32.dll+0x16fd7 ft=- rs=unknown sym=no_symbol_file ; scan 0x405443 slot=0x12fff8 c:\\test_app.exe+0x5443 ft=- rs=unknown sym=unresolved",
    "scan=false symd=false store=- frames=4 slots=0 context 0x40429e slot=- c:\\test_app.exe+0x429e ft=- rs=unknown sym=- ; fp 0x404200 slot=0x12fe8c c:\\test_app.exe+0x4200 ft=- rs=unknown sym=- ; fp 0x4053ec slot=0x12ff74 c:\\test_app.exe+0x53ec ft=- rs=unknown sym=- ; fp 0x7c816fd7 slot=0x12ffc4 C:\\WINDOWS\\system32\\kernel32.dll+0x16fd7 ft=- rs=unknown sym=-",
    "max_frames=2 frames=3 note=frame-pointer chain truncated at 2 frames context 0x40429e slot=- c:\\test_app.exe+0x429e ft=- rs=unknown sym=- ; fp 0x404200 slot=0x12fe8c c:\\test_app.exe+0x4200 ft=- rs=unknown sym=- ; fp 0x4053ec slot=0x12ff74 c:\\test_app.exe+0x53ec ft=- rs=unknown sym=-",
  ])
}
