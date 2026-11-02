# moondump

A Windows crash-dump (minidump, `.dmp`) parser library and command-line tool, written in MoonBit.

The intended use case is malware-sample triage and crash-site inspection: without Windows,
WinDbg, or DbgHelp, it reads a `.dmp` into structure — the stream directory, module list,
threads and their CONTEXT, the exception record, memory reads, a stack walk, Breakpad `.sym`
symbolization, and WER's long-tail extension streams. The same parsed data can also be handed
over as a machine-readable JSON document (`schema: "moondump/v1"`).

- Format sources: Microsoft `MINIDUMP_HEADER` / `MINIDUMP_STREAM_TYPE` (`minidumpapiset.h`),
  Google Crashpad `minidump_file_format.md`, Breakpad `minidump_format.h`.
- Behavioral reference: `rust-minidump` (MIT). Every offset and field was written against the
  local Windows SDK header, one by one — nothing from memory.
- License: Apache-2.0. The MIT/BSD-3 statements for the test corpus are in `testdata/README.md`.

## Usage

```bash
moon run cmd/main -- testdata/test.dmp                    # full text report
moon run cmd/main -- testdata/test.dmp --symbols ./sym    # symbolize from *.sym in a directory
moon run cmd/main -- testdata/test.dmp --json             # JSON document only
moon run examples -- testdata/test.dmp                    # minimal library-usage example
```

| Flag | Effect |
| --- | --- |
| `--symbols <dir>` | Recursively collect `*.sym` files for symbolization; may be given multiple times |
| `--max-frames <n>` | Walk at most n frames per stack (excluding the context frame), default 64 |
| `--no-scan` | Frame-pointer chain only, no stack-window scan: more conservative, more missing frames |
| `--all-stacks` | Walk the stack of every thread; default is the crash thread plus the first 8 |
| `--json` | Emit the machine-readable JSON report (`schema: "moondump/v1"`) instead of formatted text |
| `--help` | Print usage only |

Text output (excerpt; real output, not hand-drawn):

```text
file            : 11317 bytes
signature       : MDMP
version         : 0x5128a793 (format version 42899)
streams         : 9
flags           : 0x0
generation flags: Normal

system          : Win32NT 5.1.2600 Service Pack 2
architecture    : x86 (1 logical processors)
MiscInfo        : v1, SizeOfInfo 24 bytes
Flags1          : 0x3  ProcessId | ProcessTimes
process ID      : 3932

modules         : 13 module(s)
  c:\test_app.exe
    range 0x400000-0x42d000  image 0x2d000  timestamp 0x45d35f6c  checksum 0x0
    RSDS 5A9832E5-2872-41C1-838E-D98914E9B7FF/1  c:\test_app.pdb

crash site:
thread          : 3060 (thread table #0)
exception code  : 0xc0000005  EXCEPTION_ACCESS_VIOLATION
      flags  = 0x1003f   eip    = 0x40429e   esp    = 0x12fe84   ebp    = 0x12fe88

stack walk:
symbol store    : 0 symbol files (0 when --symbols is not given)
  up to 64 frames per thread  scan on (scan up to 4096 bytes per thread)
  #0  thread 3060 (crash thread)
      thread-table context
      layout x86  pointer 4 bytes  window 0x12f31c-0x130000
      #0  0x7c90eb94  context  context  C:\WINDOWS\system32\ntdll.dll+0xeb94
          (empty_store)  function table: none  return site undecidable
      #1  0x7c90e9c0  scan  slot 0x12f320  C:\WINDOWS\system32\ntdll.dll+0xe9c0
          … (this walk is "the moment the dump was written"; the thread was waiting in
          ntdll at that point, 13 frames in total)
      note  frame-pointer chain broke: next frame pointer 0x0 is outside (0x12fff0, 0x130000)
      the two contexts have different instruction pointers: thread-table 0x7c90eb94, exception-site 0x40429e. the former is from dump-writing time; the walk below is the crash moment
      exception-site context
      layout x86  pointer 4 bytes  window 0x12f31c-0x130000
      #0  0x40429e  context  context  c:\test_app.exe+0x429e
          (empty_store)  function table: none  return site undecidable
      #1  0x404200  fp  slot 0x12fe8c  c:\test_app.exe+0x4200
          (empty_store)  function table: none  return site undecidable
      #2  0x4053ec  fp  slot 0x12ff74  c:\test_app.exe+0x53ec
          (empty_store)  function table: none  return site undecidable
      #3  0x7c816fd7  fp  slot 0x12ffc4  C:\WINDOWS\system32\kernel32.dll+0x16fd7
          (empty_store)  function table: none  return site undecidable
      #4  0x405443  scan  slot 0x12fff8  c:\test_app.exe+0x5443
          (empty_store)  function table: none  return site undecidable
      note  frame-pointer chain broke: next frame pointer 0x0 is outside (0x12fff0, 0x130000)
  #1  thread 4544
      …
```

`moon run examples -- testdata/test.dmp` is the runnable minimal example; its stack-walk part
carries a symbol file inline (a `.sym` matching `test.dmp`'s own debug id, embedded in the
example — in real use, pass `--symbols <dir>`):

```text
symbol table: accepted the inline test_app.sym
stack walk: thread 3060 layout x86 pointer 4 bytes frames 5 fp frames 3
  #0  context  0x40429e  c:\test_app.exe+0x429e  (ok)  test_app!crash_here
  #1  fp  0x404200  c:\test_app.exe+0x4200  (unresolved)
  #2  fp  0x4053ec  c:\test_app.exe+0x53ec  (unresolved)
  #3  fp  0x7c816fd7  C:\WINDOWS\system32\kernel32.dll+0x16fd7  (no_symbol_file)
  #4  scan  0x405443  c:\test_app.exe+0x5443  (unresolved)
  note  frame-pointer chain broke: next frame pointer 0x0 is outside (0x12fff0, 0x130000)
```

Library usage:

```moonbit nocheck
// All of these are raise + Option: parse failures throw named errors, and a stream the
// generator never wrote returns None. "The stream is absent" and "the stream is there but
// the table is empty" are different situations, so callers handle both explicitly.

///|
fn inspect(bytes : Bytes) -> Unit raise {
  let dump = @moondump.open_dump(bytes) // validates signature and format version
  let entries = dump.stream_directory() // stream directory, 12 bytes per entry
  match dump.modules(entries) { // ModuleList + VS_FIXEDFILEINFO + CodeView
    None => println("no ModuleList in this dump")
    Some(mods) =>
      println(
        mods.modules.length().to_string() +
        " modules, skipped malformed records: " +
        mods.skipped.to_string(),
      )
  }
  match dump.exception(entries) { // exception code, access-violation address, crash CONTEXT
    None => println("no ExceptionStream in this dump")
    Some(exc) =>
      println(
        "thread " +
        exc.thread_id.to_string() +
        " crashed at 0x" +
        exc.address.to_string(radix=16),
      )
  }
  match dump.memory_map(entries) { // unified index over MemoryList / Memory64List
    None => println("this dump carries no memory stream")
    Some(map) =>
      // An unmapped address, or one straddling two ranges, reads back as None —
      // not as "read 0 bytes".
      match dump.read_memory_at(map, 0x12f31cUL, 16) {
        None => println("virtual address not captured")
        Some(data) => println("read " + data.length().to_string() + " bytes")
      }
  }
}
```

Stack walk + symbolization:

```moonbit nocheck
///|
fn inspect_stack(bytes : Bytes, sym_text : String) -> Unit raise {
  let dump = @moondump.open_dump(bytes)
  let entries = dump.stream_directory()
  // Frame-to-module attribution and module-relative offsets both come from the module list
  let mods = match dump.modules(entries) {
    None => []
    Some(m) => m.modules
  }
  // The function-table stream is corroboration only ("was this address ever registered"),
  // it never drives the walk
  let ft = dump.function_table(entries)
  // Architecture comes from SystemInfo; which register table actually applies is decided by
  // the CONTEXT itself (see the section below). With no SystemInfo, pass 0xffff:
  // read_context will not recognize the table and returns None instead of guessing.
  let arch : UInt16 = match dump.system_info(entries) {
    None => 0xffff
    Some(si) => si.processor_architecture
  }
  let store = @moondump.symbol_store_new()
  // Only files with a valid MODULE line are accepted; bad ones land in `rejected`,
  // never silently dropped
  let accepted = @moondump.symbol_store_add(store, "test_app.sym", sym_text)
  println(
    if accepted {
      "symbol file accepted"
    } else {
      "no valid MODULE line, recorded in rejected"
    },
  )
  match
    (dump.exception(entries), dump.threads(entries), dump.memory_map(entries)) {
    (Some(exc), Some(threads), Some(map)) =>
      match @moondump.find_thread_by_id(threads, exc.thread_id) {
        None =>
          println(
            "the thread named by the exception stream is not in the thread list",
          )
        Some((_, t)) =>
          match dump.read_context(arch, exc.thread_context) {
            None =>
              println(
                "context unreadable: register table unsupported or CONTEXT size unreasonable",
              )
            Some(ctx) => {
              let opts = @moondump.stack_walk_options_default()
              let w = dump.walk_thread_stack(map, mods, ft, t, ctx, opts)
              println(
                "layout " +
                w.layout +
                " frames " +
                w.frames.length().to_string(),
              )
              for f in w.frames {
                let sym = @moondump.symbolize_frame(f, mods, store)
                println(
                  f.kind +
                  " " +
                  @moondump.hex_uint(f.address) +
                  " " +
                  sym.status,
                )
              }
            }
          }
      }
    _ => println("missing exception / thread-list / memory stream; cannot walk")
  }
}
```

`examples/main.mbt` is the runnable version of these calls: `moon run examples -- testdata/test.dmp`.
Both snippets above have compile-checked copies in `examples/readme_check.mbt` — if the examples
drift from the API, `moon check` fails immediately instead of waiting for a reader to find out.

## Stream coverage

| Stream | Status |
| --- | --- |
| Header / StreamDirectory (unknown streams listed verbatim) | ✅ |
| SystemInfo (x86 / amd64 / arm / arm64 / ia64 platform detection) | ✅ |
| ModuleList (108-byte entries + VS_FIXEDFILEINFO + CodeView/Debug) | ✅ |
| MiscInfo v1–v5 (time zone, DST rules, XState table, Flags1 gating) | ✅ |
| ThreadList (48-byte entries + per-architecture CONTEXT tables) | ✅ |
| ExceptionStream (Windows exception codes / Linux signals / access-violation parameter conventions) | ✅ |
| MemoryList / Memory64List / MemoryInfoList (including reads by virtual address) | ✅ |
| UnloadedModuleList, HandleData, FunctionTable, ThreadInfoList, ThreadNames | ✅ format layer |
| Breakpad `.sym` symbols + stack walk + `--json` report | ✅ |
| Comment(A/W), SystemMemoryInfo, ProcessVmCounters, Crashpad/Breakpad extension streams | ⛔ listed, not parsed |

The last group is deliberate: no authoritative field layout for those streams is available
offline, and this project's rule is no parser without a checkable source — and no invented
field names.

## Stack walking and symbolization

Starting from a thread's CONTEXT, the walk reconstructs the call chain using only memory that
was **actually captured into the file**. Three frame kinds, distinguished by `kind`, never
mixed together:

- `"context"`: the instruction pointer from the CONTEXT, always the first frame — it was not
  read from the stack.
- `"fp"`: the frame-pointer chain. x86 reads `[EBP+4]`, amd64 reads `[RBP+8]`, arm64 reads
  `[X29+8]` — left behind by the standard prologue, the most trustworthy source. But if any
  frame in between omits the frame pointer (`/Oy-`, which is the VS Release default), the
  chain breaks right there, and the `ebp` value where it broke goes into `notes`.
- `"scan"`: stack-window scan. Walks slot by slot at pointer width looking for values that
  "look like return addresses"; it recovers frames after the chain breaks, at the cost of
  stale values left in local variables also counting as frames — so callers must treat frames
  by `kind` and never present scan frames as a confirmed call chain. Consecutive slots with
  the same value produce a single frame (the same return address written into several adjacent
  slots is not nested calls), with the merge noted in `notes`.

Each frame also carries two pieces of corroboration: `return_site` (`"call"` / `"no_call"` /
`"unknown"` — whether the bytes before this return address encode `E8` or `FF /2,4`) and
`in_function_table` (whether the function-table stream ever registered this address). Both are
evidence only — **neither decides whether the frame is kept**.

Pointer width follows **the field table the CONTEXT itself identifies** (`StackWalk.layout` is
its name), not an guess from the SystemInfo architecture: in a WOW64 dump, SystemInfo can say
amd64 while the same thread's context is a 716-byte x86 table whose stack slots hold 4-byte
pointers. When the field table cannot be identified, `supported = false` with a `reason`, and
not a single frame is fabricated. There is no WOW64 sample in the public corpus, so this rule
is a design decision based on field-table length, not a measured claim.

Symbolization uses Breakpad `.sym` files: `MODULE` / `FILE` / `FUNC` / line records directly
following a FUNC / `PUBLIC`. Module matching falls back in three steps — debug id → pdb name →
module name — with `matched_by` recording which step hit. `symbol.status` is a closed set that
separates the reasons "no symbol" can happen:

| status | Meaning |
| --- | --- |
| `ok` | Hit a FUNC or PUBLIC record |
| `unresolved` | A symbol file is loaded, but the address falls into no FUNC/PUBLIC |
| `ambiguous` | Multiple `.sym` files matched; the first is used, `candidates` gives the count |
| `no_module` | The address is in no module, so no module-relative offset can be computed |
| `no_symbol_file` | The symbol store has no `.sym` for this module |
| `empty_store` | The symbol store is empty (`--symbols` not given) |

**Not done** — and this is the most important limitation: no interpretation of x64
`UNWIND_INFO`, and no interpretation of the `STACK CFI INIT` / `STACK CFI` / `STACK WIN`
unwinding rules in `.sym` files (they are counted, never interpreted). So this is not precise
unwinding; where the chain breaks you get a scan approximation. There is no authoritative,
checkable source for those two rule sets in this offline environment, and per this project's
"no parser without authority" rule, an approximation that says so beats guessed semantics.

## JSON report (schema `moondump/v1`)

```bash
moon run cmd/main -- testdata/test.dmp --json
```

This is **moondump's own schema**, not the output format of `minidump-stackwalk --json`: with
no way to byte-compare against that tool offline, no field compatibility is claimed (the
document's `generator.note` says the same). What can be claimed: a stable shape, constant
fields, and a single source of truth with the text output — the same parse results in a
different arrangement, with no second set of heuristics.

Rules:

- The top level has **exactly 17 fields, always present, in fixed order**: `schema, generator,
  file, streams, system_info, misc_info, modules, unloaded_modules, threads, exception, stacks,
  memory, thread_names, thread_infos, handles, function_table, symbol_store`. A missing value is
  `null`, never an absent key; reordering the fields is a schema change and bumps the version.
- Addresses are always hex strings (`"0x7ff6e7c40000"`), 64-bit lengths are always decimal
  strings (`"8408702"`); only quantities that fit in 32 bits are JSON numbers — double precision
  is exact only up to 2^53, and addresses and file sizes do not get to gamble on that.
- A section that fails to parse becomes `{"kind": "...", "message": "..."}` and the document
  still ships; whole-document failures (bad arguments, unreadable file, invalid signature)
  produce only `{schema, generator, error}`.
- Long lists are wrapped as `{count, truncated, items}` with a cap of 2000 entries; truncation
  is stated in the document, never silent.

Excerpt (`--json`, indented by 2):

```json
{
  "schema": "moondump/v1",
  "generator": { "name": "moondump", "version": "0.1.0", "note": "..." },
  "file": {
    "path": "testdata/test.dmp", "size": "11317", "signature": "MDMP",
    "signature_raw": "0x504d444d", "format_version": 42899, "format_version_known": true,
    "number_of_streams": 9, "time_date_stamp": 1171480435, "minidump_type": ["Normal"]
  },
  "exception": {
    "thread_id": 3060, "code": "0xc0000005", "code_name": "EXCEPTION_ACCESS_VIOLATION",
    "parameters": ["0x1", "0x45"]
  },
  "stacks": {
    "memory_map": "present", "max_frames": 64, "max_scan_bytes": 4096, "scan": true,
    "symbolicated": false, "walked": 3, "skipped_threads": 0,
    "items": { "count": 3, "truncated": false, "items": [
      {
        "thread_id": 3060, "source": "exception_context", "layout": "x86",
        "pointer_size": 4, "supported": true,
        "window": { "low": "0x12f31c", "high": "0x130000", "size": "3300" },
        "frame_count": 5, "fp_frames": 3, "scanned_slots": 95, "scan_limited": false,
        "notes": ["frame-pointer chain broke: next frame pointer 0x0 is outside (0x12fff0, 0x130000)"],
        "frames": [
          {
            "index": 0, "ip": "0x40429e", "kind": "context", "stack_slot": null,
            "module": "c:\\test_app.exe", "module_index": 0, "offset": "0x429e",
            "function_table": null, "return_site": "unknown", "symbol": null
          }
        ]
      }
    ] }
  }
}
```

`stacks.items[i].source` says which CONTEXT this walk came from: `exception_context` (the
moment of the crash) or `thread_table_context` (the moment the dump was written). When the
crash thread's two contexts have different instruction pointers, both walks are emitted, and
`items[0]` is always the crash-site one; the text CLI also walks both, it just puts "the next
one is the crash moment" in front of the reader's eyes instead of in the ordering. The
remaining threads follow in thread-table order.

The library can hand you the `Json` value directly, no text in between:
`dump.report_json(opts)`; failed documents come from `@moondump.json_failure(kind, message)`;
printing uses `json_report_text`.

## Two findings from real dumps

Real WER dumps write the `FunctionTableStream` **in a layout that does not match the SDK's
declared strides**. The declared 32-byte stride leaves only 6 of 113 records self-consistent;
after sweeping every start offset against every record width, the only self-consistent layout
starts at `SizeOfHeader + SizeOfAlignPad` with record width
`SizeOfDescriptor + SizeOfNativeDescriptor + SizeOfFunctionEntry + SizeOfAlignPad`
(184 bytes) — i.e. "descriptor + native descriptor + **inline function entries** + padding",
with the x64 `IMAGE_FUNCTION_ENTRY` triple inlined into each record.

The implementation does not pick a side: both candidate layouts are checked against the
evidence, and the self-consistent one wins; if neither is consistent, the declared stride is
used and `layout_ok = false` is set, with the CLI printing "neither layout is self-consistent;
reading with the declared stride — do not trust these results".

The crash thread in `test.dmp` has **two contexts parked in completely different places**: the
exception stream's CONTEXT has instruction pointer `0x40429e`
(`c:\test_app.exe+0x429e` — the crash point itself), while the same thread's CONTEXT in the
thread table has `0x7c90eb94` (`ntdll.dll+0xeb94` — by the time the dump was written, the
thread was no longer at the crash site). Walking only the thread-table context never shows the
crash site; walking only the exception context never shows what the thread was waiting on. So
both are emitted. Details in `docs/proposal.md` §8 (Chinese), including how this finding once
cost the JSON output an entire stack.

## Robustness

- All RVA/length arithmetic uses saturating add and multiply; any out-of-bounds access becomes
  a named `ParseError` variant (`Truncated` / `RvaTooLarge` / `BadStreamCount` / `InvalidUtf16`
  etc.). Nothing panics.
- Malformed fixtures (directory RVA out of range, fabricated entry counts) are exercised in
  tests — see `corpus/corpus_test.mbt`.
- The UTF-16LE decoder rejects lone surrogates with `InvalidUtf16`; no silent replacement.
- Large files are never copied into memory wholesale: the reader maps ranges lazily.
- In `--json` mode, stdout carries exactly one document: MoonBit has no stderr channel in this
  toolchain, so bad arguments, file-read failures, and invalid signatures all become the
  document's `error` field. Callers get either a report that `JSON.parse`s or a well-formed
  failure report — never text mixed with logs.

## Testing and verification

```bash
moon test                  # wasm, 101 tests
moon test --target native  # native
moon fmt && moon check --deny-warn
moon info                  # regenerate pkg.generated.mbti (diff it to see API changes)
```

- **Public-corpus regression**: all seven rust-minidump fixtures run a full-field summary
  (stream count, module count, thread count, exception code, memory-stream state, stack
  counts, ...), and even the malformed dumps must produce a complete document — see
  `corpus/corpus_test.mbt`.
- **JSON goes through the full pipeline**: `report_json` → `stringify` → `@json.parse` reads
  the text **back**, then asserts the reparsed value equals the in-memory one
  (`corpus/json_corpus_test.mbt`). Checking only the in-memory `Json` proves nothing about
  whether the text is valid JSON with these field names and this nesting — and text is exactly
  what upstream scripts consume.
- **Both output channels share one source**: the JSON per-frame summaries and the text stack
  walk come from the same values; each frame's `kind`/address/slot/module attribution must
  agree.
- **An independent oracle for the stack walk**: `testdata/oracle/stack_oracle.js` reads the raw
  stack slot table and frame-pointer chain straight from the bytes per the SDK layout (no
  heuristics at all), and `stack_crosscheck.js` cross-checks the CLI's output frame by frame:
  apart from context frames, every frame's `(stack slot, instruction address)` pair must appear
  verbatim in the raw slot table, and module attribution is recomputed independently. The
  scripts share zero code with the implementation and can be re-run directly:

  ```bash
  node testdata/oracle/stack_oracle.js testdata/test.dmp > /tmp/golden.txt
  moon run cmd/main --target native -- testdata/test.dmp > /tmp/cli.txt
  node testdata/oracle/stack_crosscheck.js /tmp/golden.txt test.dmp /tmp/cli.txt
  ```

  The last line prints `checked=<frames matched> bad=<mismatched>`; `bad` must be 0. Latest
  run: `test.dmp` 80 frames, `invalid-parameter.dmp` 135 frames, `bad` 0 in both.
- **What is deliberately not claimed**: this machine has no `minidump-stackwalk` binary and no
  offline channel to byte-compare against it, so no field compatibility with its output is
  claimed; the only claims are the same-source, re-runnable checks above.
- **Real WER dumps** are run locally only (they contain process memory and user-name paths and
  never enter the repository); they are how layout-level mismatches like the `FunctionTableStream`
  one get found.

## Test corpus

`testdata/*.dmp` all come from [rust-minidump](https://github.com/rust-minidump/rust-minidump)'s
`testdata/` (MIT; the full license text ships alongside), with per-file coverage notes in
`testdata/README.md`. Real WER dumps generated on this machine contain process memory and
user-name paths, **never enter the repository**, and are used for local cross-checking only;
`.gitignore` blocks them via `*.dmp` + `testdata/local/` + `_scratch/`.

CI (`.github/workflows/ci.yml`) runs only the three steps that can be verified locally:
`moon fmt --check`, `moon check --deny-warn`, and `moon test` (wasm).

## Acknowledgement

- [rust-minidump](https://github.com/rust-minidump/rust-minidump) — MIT; test corpus and behavioral reference.
- [Google Breakpad](https://github.com/google/breakpad) / [Crashpad](https://github.com/google/crashpad) — format documentation and extension stream numbers.
- Microsoft Windows SDK `minidumpapiset.h` — the final authority on field offsets.
