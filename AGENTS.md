# Project Agents.md Guide

This is a [MoonBit](https://docs.moonbitlang.com) project.

You can browse and install extra skills here:
<https://github.com/moonbitlang/skills>

## Project Structure

- MoonBit packages are organized per directory; each directory contains a
  `moon.pkg` file listing its dependencies. Each package has its files and
  blackbox test files (ending in `_test.mbt`) and whitebox test files (ending in
  `_wbtest.mbt`).

- In the toplevel directory, there is a `moon.mod` file listing module
  metadata.

## Coding convention

- MoonBit code is organized in block style, each block is separated by `///|`,
  the order of each block is irrelevant. In some refactorings, you can process
  block by block independently.

- Try to keep deprecated blocks in file called `deprecated.mbt` in each
  directory.

## Tooling

- `moon fmt` is used to format your code properly.

- `moon ide` provides project navigation helpers like `peek-def`, `outline`, and
  `find-references`. See $moonbit-agent-guide for details.

- `moon info` is used to update the generated interface of the package, each
  package has a generated interface file `.mbti`, it is a brief formal
  description of the package. If nothing in `.mbti` changes, this means your
  change does not bring the visible changes to the external package users, it is
  typically a safe refactoring.

- In the last step, run `moon info && moon fmt` to update the interface and
  format the code. Check the diffs of `.mbti` file to see if the changes are
  expected.

- Run `moon test` to check tests pass. MoonBit supports snapshot testing; when
  changes affect outputs, run `moon test --update` to refresh snapshots.

- Prefer `assert_eq` or `assert_true(pattern is Pattern(...))` for results that
  are stable or very unlikely to change. For snapshot tests that record
  structured debugging output, derive `Debug` and use `debug_inspect`, rather
  than deriving `Show` for debugging. For solid, well-defined results (e.g.
  scientific computations), prefer assertion tests. You can use
  `moon coverage analyze > uncovered.log` to see which parts of your code are
  not covered by tests.

## Hard rules for this project (moondump)

These rules come from the nature of format parsing itself, not style preference. Violating
any of them turns the output into "plausible-looking wrong data".

1. **No offsets from memory.** Before adding a field, find the definition in the Windows SDK
   `10.0.26100.0\um\minidumpapiset.h` (or Crashpad `minidump_file_format.md`, Breakpad
   `minidump_format.h`) and write **the file and line number into a comment**. For streams
   the SDK gives no struct for (CommentStreamA/W, `AVRF_HANDLE_OPERATION`, SystemMemoryInfo,
   ProcessVmCounters, the Breakpad/Crashpad `0x4767…`/`0x4350…` extension series), never
   guess a parser — just list the type and length as-is in the stream directory.
2. **Goldens must not be generated from this implementation's output.** Every value in the
   corpus assertions must be independently extractable from the bytes by a script like
   `testdata/oracle/stack_oracle.js`; stack walking is accepted by `stack_crosscheck.js`
   matching every CLI frame back to the raw slot table (`bad` must be 0). Do not use
   `moon test --update` to "refresh" corpus assertions.
3. **Real `.dmp` files never enter the repository.** They contain process memory and username
   paths. Local verification files go in `testdata/local/`, intermediate artifacts in
   `_scratch/`, both covered by `.gitignore`; `*.dmp` is ignored by default and only the
   `!testdata/*.dmp` exception admits the public corpus. Committed corpus may only come from
   rust-minidump (MIT) / Breakpad (BSD-3-Clause), with the full license text kept alongside.
4. **When unsure, verify both candidates and hand over the trustworthiness verdict.** When a
   real file contradicts what the docs declare (the FunctionTable stream in section 7 of
   `docs/proposal.md` is exactly this case), pick the layout by self-consistency; if none
   wins, fall back to the declared stride and set `layout_ok = false` so callers get the verdict.
5. **No compatibility claims that cannot be verified.** There is no `minidump-stackwalk`
   binary on this machine and no offline channel for byte-level comparison, so the README,
   the JSON schema, and comments must not claim field compatibility with its output; the JSON
   is this project's own `moondump/v1`.
6. **The two output channels must come from one source.** The text CLI and `--json` must agree
   on the values for the same data; the crashing thread has two contexts (exception stream =
   the moment of the crash, thread table = the moment the dump was written) and when their
   instruction pointers differ, both stacks must be emitted. JSON assertions go through
   `report_json → stringify → @json.parse` and compare the parsed-back value; checking only
   the in-memory `Json` value does not count as verification.

## Pre-delivery checks (run in this order)

```bash
moon info && moon fmt && moon check --deny-warn && moon test
moon test --target native
node testdata/oracle/stack_oracle.js testdata/test.dmp > /tmp/golden.txt
moon run cmd/main --target native -- testdata/test.dmp > /tmp/cli.txt
node testdata/oracle/stack_crosscheck.js /tmp/golden.txt test.dmp /tmp/cli.txt
```

- It is `--deny-warn`, not `--deny-warnings`.
- The diff of `pkg.generated.mbti` is the list of external API changes; if it is unchanged,
  the change is invisible to consumers.
- `moon fmt` also formats ```moonbit``` code blocks inside `README.mbt.md`. The runnable
  example in the README has a compile-checked mirror in `examples/readme_check.mbt`
  (blocks marked `moonbit nocheck` are only formatted, not type-checked); **when you change
  the README examples, update the mirror too**.
- Alignment hex and address strings all go through `hex_uint`; 64-bit lengths are decimal
  strings in JSON (numbers are only exact up to 2^53).
- This toolchain has no stderr channel: under `--json`, every diagnostic (bad arguments, file
  read failure, invalid signature) must be written into the document's `error` field, and
  stdout may carry exactly one document.

