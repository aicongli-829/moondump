// Windows 崩溃转储（minidump，.dmp）解析库 + 命令行工具。
// 格式依据：minidumpapiset.h / Crashpad / Breakpad；行为参照 rust-minidump（MIT）。

name = "aicongli-829/moondump"

version = "0.1.0"

readme = "README.mbt.md"

// 公开仓库地址（GitHub ID：aicongli-829）。

repository = "https://github.com/aicongli-829/moondump"

license = "Apache-2.0"

keywords = [
  "minidump",
  "windows",
  "crash-dump",
  "dmp",
  "triage",
  "reverse-engineering",
]

preferred_target = "wasm"

description = "Windows minidump (.dmp) parser and CLI: streams, modules, threads, CONTEXT, exception, memory reads, stack walk with Breakpad .sym symbols, and a machine-readable JSON report."

import {
  "moonbitlang/x@0.5.7",
}
