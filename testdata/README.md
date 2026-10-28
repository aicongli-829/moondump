# Test corpus notes

Every `.dmp` here comes from a public project — **not** a real user's crash dump — and is
safe to commit to a public repository.

## Origin and license

- Location: `testdata/*.dmp`
- Upstream: the `testdata/` of [rust-minidump](https://github.com/rust-minidump/rust-minidump)
- License: MIT (full text in `LICENSE-rust-minidump.txt`; upstream copyright is
  "Copyright (c) 2015-2023 rust-minidump contributors")
- These files are also rust-minidump's own regression corpus. **This project does not claim
  field-for-field output parity with it** (`minidump-stackwalk` is not available offline);
  the crosscheck is done by the two independent scripts under `testdata/oracle/`, which read
  raw values out of the bytes per the SDK layout and share zero code with the implementation.

## What each file covers

| File | Size | Coverage |
| --- | --- | --- |
| `test.dmp` | 11 KB | Windows dump produced by breakpad-era tooling; 9 streams incl. ThreadList/ModuleList/MemoryList/Exception/SystemInfo/MiscInfo (v1, 24 bytes) plus a custom stream starting 0x4767 |
| `simple-crashpad.dmp` | 18 KB | Dump produced by **Crashpad**; stream order differs from the breakpad family, MiscInfo is 832 bytes (extended version) |
| `linux-mini.dmp` | 27 KB | breakpad dump from Linux; many extension streams (0x1000-range Linux streams, 0x4767-range Crashpad streams) — verifies "unknown streams must not error" |
| `invalid-parameter.dmp` | 45 KB | Misleading name; actually a **Windows dump carrying crash parameters**; includes Stream(21), SystemMemoryInfo and other newer streams |
| `invalid-range.dmp` | 276 B | Deliberately malformed: directory RVA=2, all stream RVAs out of range. Verifies no panic and that out-of-range is reported |
| `invalid-record-count.dmp` | 235 B | Deliberately malformed: entry count contradicts the record size, with garbage 0xffffffff RVA/size values |
| `full-dump.dmp` | 8.4 MB | Full-memory dump via **Memory64List**, verifies large files and the memory reader's lazy path (run the small files first if the download fails) |

Samples from `breakpad/src/processor/testdata` (BSD-3-Clause) may be added later; when that
happens their copyright and license notice go into `LICENSE-breakpad.txt`.

## Independent extraction scripts: `oracle/`

The two Node scripts under `oracle/` **read the corpus strictly by the SDK byte layout and
apply no heuristics**, providing an external check on the MoonBit side's conclusions —
especially for stack walking, where "which frames to report" is decided by the implementation:

- `stack_oracle.js <corpus.dmp>...`: lays out the raw material visible from each context —
  `CTX` (ip/sp/bp), `WINDOW` (the stack window declared by the thread record itself),
  `CHAIN` (the frame-pointer chain walked hard for 8 steps, each step showing `[bp]` and
  `[bp+ps]`), `SLOTS` (every aligned slot's value in the window, the module it hits, and the
  6 bytes before that address — used to separately verify corroboration such as "is the 5th
  byte before the return site `e8`").
- `stack_crosscheck.js <oracle output> <corpus name> <CLI output>`: takes every frame the CLI
  reports, looks up the same (stack slot, value) pair in `SLOTS`, requires the module
  attribution to match, and prints `checked=<frames matched> bad=<frames mismatched>`.

To reproduce (repo root, requires node):

```sh
node testdata/oracle/stack_oracle.js testdata/*.dmp > /tmp/golden.txt
moon run cmd/main --target native -- testdata/test.dmp > /tmp/cli.txt
node testdata/oracle/stack_crosscheck.js /tmp/golden.txt test.dmp /tmp/cli.txt
```

Across the 5 public corpora (including non-crashing threads), 266 frames matched verbatim
with `bad=0`. In other words, **the frames' values come from independent extraction; the
choice of which frames to report is pinned by the goldens in `corpus/`**.

## Real crash dumps

Files like `C:\Users\...\CrashDumps\*.dmp` on this machine contain process memory and
username paths and are **for local smoke testing only**; `.gitignore` already blocks them
via `*.dmp` and `testdata/local/`. Only public, sanitized corpora like the ones here are
allowed in the repository.
