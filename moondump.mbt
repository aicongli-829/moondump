// Copyright 2026 aicongli-829
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

///! Prototype parser for Windows minidump (crash dump) files.
///!
///! Ported from / references:
///! - rust-minidump (MIT)
///!   https://github.com/rust-minidump/rust-minidump
///! - Crashpad minidump file format
///!   https://chromium.googlesource.com/crashpad/crashpad/+/main/doc/minidump_file_format.md
///! - Microsoft MINIDUMP_HEADER / MINIDUMP_DIRECTORY documentation
///!   https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header

///|
/// Relative virtual address (RVA) within the file. minidump has no section
/// table, so an RVA numerically equals a file offset, but fields mix 32/64
/// bits (Memory64List uses 64-bit RVAs and sizes), so everything is carried
/// in UInt64 to avoid silent truncation on large dumps.
pub type Rva = UInt64

///|
/// Parse failure. All malformed/out-of-bounds input funnels here; panics are not allowed.
#derive(Debug)
pub(all) suberror ParseError {
  /// Signature is not "MDMP"
  InvalidSignature(UInt32)
  /// RVA exceeds this implementation's limit (2GB)
  RvaTooLarge(UInt64)
  /// Requested range runs past the end of the file: (rva, want, have)
  Truncated(UInt64, UInt64, UInt64)
  /// Malformed stream-directory entry count
  BadStreamCount(UInt32)
  /// Invalid UTF-16 surrogate/code point
  InvalidUtf16(UInt32)
  /// The stream's declared DataSize cannot hold the struct: (stream_type, want, have)
  StreamTooSmall(UInt32, UInt64, UInt64)
  /// Variable-length list stream's DataSize does not match its count: (stream_type, want, have)
  ListSizeMismatch(UInt32, UInt64, UInt64)
  /// CONTEXT declared length matches no verified field table: (architecture, declared, want)
  ContextSizeMismatch(UInt16, UInt32, UInt32)
}

// Explicitly publicize the derived methods instead of relying on implicit
// promotion (newer toolchains have deprecated that behavior).

///|
pub extend ParseError with Debug::{to_repr}

///|
/// Human-readable error descriptions for the CLI and tests.
pub fn describe_error(err : ParseError) -> String {
  match err {
    InvalidSignature(sig) =>
      "signature is not MDMP (read 0x" + sig.to_string(radix=16) + ")"
    RvaTooLarge(rva) => "RVA exceeds the 2GB limit: " + rva.to_string()
    Truncated(rva, want, have) => {
      let prefix = "need " +
        want.to_string() +
        " bytes at RVA " +
        rva.to_string()
      prefix + ", only " + have.to_string() + " bytes left in the file"
    }
    BadStreamCount(n) =>
      "malformed stream-directory entry count: " + n.to_string()
    InvalidUtf16(cp) => "invalid UTF-16 code point 0x" + cp.to_string(radix=16)
    StreamTooSmall(stream_type, want, have) => {
      let label = stream_type_name(stream_type)
      let size = " (" + stream_type.to_string() + ") needs " + want.to_string()
      label + size + " bytes, stream has only " + have.to_string() + " bytes"
    }
    ListSizeMismatch(stream_type, want, have) => {
      let label = stream_type_name(stream_type)
      let size = " (" +
        stream_type.to_string() +
        ") needs " +
        want.to_string() +
        " bytes for the declared entry count"
      label + size + ", stream declares " + have.to_string() + " bytes"
    }
    ContextSizeMismatch(arch, declared, want) => {
      let label = architecture_name(arch)
      let size = "CONTEXT for architecture " +
        label +
        " needs " +
        want.to_string()
      size + " bytes, only " + declared.to_string() + " declared"
    }
  }
}

///|
/// Error category name, for tests and the CLI.
pub fn error_kind(err : ParseError) -> String {
  match err {
    InvalidSignature(_) => "InvalidSignature"
    RvaTooLarge(_) => "RvaTooLarge"
    Truncated(_, _, _) => "Truncated"
    BadStreamCount(_) => "BadStreamCount"
    InvalidUtf16(_) => "InvalidUtf16"
    StreamTooSmall(_, _, _) => "StreamTooSmall"
    ListSizeMismatch(_, _, _) => "ListSizeMismatch"
    ContextSizeMismatch(_, _, _) => "ContextSizeMismatch"
  }
}

///|
/// MINIDUMP_HEADER, fixed 32 bytes.
#derive(Debug, Eq)
pub(all) struct Header {
  signature : UInt32
  version : UInt32
  number_of_streams : UInt32
  stream_directory_rva : Rva
  checksum : UInt32
  /// Dump creation time, Unix epoch seconds (UTC)
  time_date_stamp : UInt32
  /// 64-bit flags: the low half is MiniDumpType, the high half carries system/architecture info
  flags : UInt64
}

///|
pub extend Header with Debug::{to_repr}

///|
pub extend Header with Eq::{equal, not_equal}

///|
/// One entry of the stream directory. Both DataSize and RVA are 32-bit in the file.
#derive(Debug, Eq)
pub(all) struct StreamEntry {
  stream_type : UInt32
  data_size : UInt32
  rva : Rva
}

///|
pub extend StreamEntry with Debug::{to_repr}

///|
pub extend StreamEntry with Eq::{equal, not_equal}

///|
/// The value of the four bytes "MDMP" read little-endian.
pub let expected_signature : UInt32 = 0x504d444dU

///|
/// MINIDUMP_STREAM_TYPE. Numbers follow Microsoft `minidumpapiset.h` and
/// crashpad's `minidump_file_format.md`, cross-checked against rust-minidump's
/// `known_types`. Unlisted types pass through as-is; unknown streams are not an error.
pub let unused_stream : UInt32 = 0U

///|
pub let thread_list_stream : UInt32 = 3U

///|
pub let module_list_stream : UInt32 = 4U

///|
pub let memory_list_stream : UInt32 = 5U

///|
pub let exception_stream : UInt32 = 6U

///|
pub let system_info_stream : UInt32 = 7U

///|
pub let thread_ex_list_stream : UInt32 = 8U

///|
pub let memory_64_list_stream : UInt32 = 9U

///|
pub let comment_stream_a : UInt32 = 10U

///|
pub let comment_stream_w : UInt32 = 11U

///|
pub let handle_data_stream : UInt32 = 12U

///|
/// The SDK calls this number `MINIDUMP_FUNCTION_TABLE_STREAM` (function-table stream), not "function list".
pub let function_table_stream : UInt32 = 13U

///|
pub let unloaded_module_list_stream : UInt32 = 14U

///|
pub let misc_info_stream : UInt32 = 15U

///|
pub let memory_info_list_stream : UInt32 = 16U

///|
pub let thread_info_list_stream : UInt32 = 17U

///|
pub let handle_operation_list_stream : UInt32 = 18U

///|
pub let token_stream : UInt32 = 19U

///|
pub let system_memory_info_stream : UInt32 = 21U

///|
pub let process_vm_counters_stream : UInt32 = 22U

///|
pub let ipt_trace_stream : UInt32 = 23U

///|
pub let thread_names_stream : UInt32 = 24U

///|
/// 25/26 only appear in code blocks of the Microsoft docs (the
/// `CompressedMemoryStream` family); neither the constant table nor
/// rust-minidump/breakpad confirm their contents or bounds, so keep the
/// number but no name for now.
pub let compressed_memory_stream_unverified : UInt32 = 25U

///|
/// Crashpad's "CP" extension stream.
pub let crashpad_info_stream : UInt32 = 0x4350_0001U

///|
/// The first of breakpad's "Gg" extension streams. The Linux* stream family's
/// numbering differs across implementations; no name until verified.
pub let breakpad_info_stream : UInt32 = 0x4767_0001U

///|
pub let last_reserved_stream : UInt32 = 0xffffU

///|
/// Human-readable stream type names, for the CLI and tests. Unknown types
/// (including breakpad/crashpad's 0x1000-family and 0x4767-family extension
/// streams) are displayed as raw hex.
pub fn stream_type_name(stream_type : UInt32) -> String {
  let n = stream_type.reinterpret_as_int()
  match n {
    0 => "UnusedStream"
    3 => "ThreadListStream"
    4 => "ModuleListStream"
    5 => "MemoryListStream"
    6 => "ExceptionStream"
    7 => "SystemInfoStream"
    8 => "ThreadExListStream"
    9 => "Memory64ListStream"
    10 => "CommentStreamA"
    11 => "CommentStreamW"
    12 => "HandleDataStream"
    13 => "FunctionTableStream"
    14 => "UnloadedModuleListStream"
    15 => "MiscInfoStream"
    16 => "MemoryInfoListStream"
    17 => "ThreadInfoListStream"
    18 => "HandleOperationListStream"
    19 => "TokenStream"
    20 => "JavaScriptDataStream"
    21 => "SystemMemoryInfoStream"
    22 => "ProcessVmCountersStream"
    23 => "IptTraceStream"
    24 => "ThreadNamesStream"
    0x4350_0001 => "CrashpadInfoStream"
    0x4767_0001 => "BreakpadInfoStream"
    _ => "Stream(0x" + stream_type.to_string(radix=16) + ")"
  }
}

///|
/// The low 16 bits of MINIDUMP_HEADER.Version are the format version, commonly
/// 42899 (0xa793). In dumps generated by WER the high 16 bits were observed to
/// be generator-dependent (e.g. 0xa0f4); neither breakpad nor rust-minidump
/// rejects files over it, so this only offers a check and never blocks.
pub let known_format_version : UInt32 = 0xa793U

///|
/// Extract the low 16 bits of Version (the format version).
pub fn header_format_version(version : UInt32) -> UInt32 {
  version & 0xffffU
}

///|
pub fn header_format_version_is_known(version : UInt32) -> Bool {
  header_format_version(version) == known_format_version
}

///|
/// Bit table for MDMP_TYPE (MiniDumpWriteDump's uFlags), which decides which
/// streams a dump may contain. Values come from the Microsoft documentation
/// and are stable; unlisted bits are left to the caller as raw values.
pub let minidump_type_flags : Array[(UInt64, String)] = [
  (0x1UL, "WithDataSegs"),
  (0x2UL, "WithFullMemory"),
  (0x4UL, "WithHandleData"),
  (0x8UL, "FilterMemory"),
  (0x10UL, "ScanMemory"),
  (0x20UL, "WithUnloadedModules"),
  (0x40UL, "WithIndirectlyReferencedMemory"),
  (0x80UL, "FilterModulePaths"),
  (0x100UL, "WithProcessThreadData"),
  (0x200UL, "WithPrivateReadWriteMemory"),
  (0x400UL, "WithoutOptionalData"),
  (0x800UL, "WithFullMemoryInfo"),
  (0x1000UL, "WithThreadInfo"),
  (0x2000UL, "WithCodeSegs"),
  (0x4000UL, "WithoutAuxiliaryState"),
  (0x8000UL, "WithFullAuxiliaryState"),
  (0x10000UL, "WithPrivateWriteCopyMemory"),
  (0x20000UL, "IgnoreInaccessibleMemory"),
  (0x40000UL, "WithTokenInformation"),
  (0x80000UL, "WithModuleHeaders"),
  (0x100000UL, "FilterTriage"),
  (0x200000UL, "WithAvxXStateContext"),
  (0x400000UL, "WithIptTrace"),
  (0x800000UL, "ScanInaccessiblePartialPages"),
]

///|
/// Split the low half of header.flags into MDMP_TYPE names; any remaining
/// unrecognized bits end up as `Unknown(0x..)`, and 0 means MiniDumpNormal.
pub fn describe_minidump_type(flags : UInt64) -> Array[String] {
  let mut rest = flags & 0xffff_ffffUL
  let names : Array[String] = []
  for (bit, name) in minidump_type_flags {
    if (rest & bit) != 0UL {
      rest = rest ^ bit // the bit is confirmed set; XOR clears it exactly
      names.push(name)
    }
  }
  if rest != 0UL {
    names.push("Unknown(0x" + rest.to_string(radix=16) + ")")
  }
  if names.is_empty() {
    names.push("Normal")
  }
  names
}

///|
/// An opened dump: the whole byte block plus a validated header; streams are parsed lazily on demand.
pub(all) struct Dump {
  header : Header
  data : Bytes
}

///|
/// Open a dump from in-memory bytes, validating only the header.
pub fn open_dump(data : Bytes) -> Dump raise ParseError {
  if data.length() < 32 {
    raise ParseError::Truncated(0UL, 32UL, data.length().to_uint64())
  }
  let signature = data.unsafe_read_uint32_le(0)
  if signature != expected_signature {
    raise ParseError::InvalidSignature(signature)
  }
  let header : Header = {
    signature,
    version: data.unsafe_read_uint32_le(4),
    number_of_streams: data.unsafe_read_uint32_le(8),
    stream_directory_rva: data.unsafe_read_uint32_le(12).to_uint64(),
    checksum: data.unsafe_read_uint32_le(16),
    time_date_stamp: data.unsafe_read_uint32_le(20),
    flags: data.unsafe_read_uint64_le(24),
  }
  let dump : Dump = { header, data, }
  dump
}

///|
/// After bounds checks, convert an RVA into an Int32 offset safe for `unsafe_read_*`.
fn Dump::offset(self : Dump, rva : Rva, len : Int32) -> Int32 raise ParseError {
  if rva > 0x7fff_fff0UL {
    raise ParseError::RvaTooLarge(rva)
  }
  let off = rva.reinterpret_as_int64().to_int()
  let size = self.data.length()
  if off + len > size {
    raise ParseError::Truncated(rva, len.to_uint64(), size.to_uint64())
  }
  off
}

///|
/// Check whether [rva, rva+len) lies entirely within the file. Malformed dumps
/// often have stream RVAs pointing outside the file; a coarse check up front
/// makes failures easier to locate than erroring at read time.
pub fn Dump::range_in_file(self : Dump, rva : Rva, len : UInt64) -> Bool {
  let size = self.data.length().to_uint64()
  rva <= size && len <= size - rva
}

///|
/// Single-byte read. The toolchain's byte type is `Byte` and `Bytes::get`
/// returns `Byte?`; bounds checking reuses `offset`, and the remaining None
/// branch just collapses "already bounds-checked" into unreachable.
pub fn Dump::read_byte(self : Dump, rva : Rva) -> Byte raise ParseError {
  let have = self.data.length().to_uint64()
  match self.data.get(self.offset(rva, 1)) {
    Some(b) => b
    None => raise ParseError::Truncated(rva, 1UL, have)
  }
}

///|
pub fn Dump::read_uint16(self : Dump, rva : Rva) -> UInt16 raise ParseError {
  self.data.unsafe_read_uint16_le(self.offset(rva, 2))
}

///|
pub fn Dump::read_uint32(self : Dump, rva : Rva) -> UInt32 raise ParseError {
  self.data.unsafe_read_uint32_le(self.offset(rva, 4))
}

///|
pub fn Dump::read_uint64(self : Dump, rva : Rva) -> UInt64 raise ParseError {
  self.data.unsafe_read_uint64_le(self.offset(rva, 8))
}

///|
/// UTF-16 code point -> MoonBit Char; invalid code points funnel into ParseError.
fn code_point_to_char(cp : UInt32) -> Char raise ParseError {
  match cp.reinterpret_as_int().to_char() {
    Some(c) => c
    None => raise ParseError::InvalidUtf16(cp)
  }
}

///|
/// MINIDUMP_STRING: 4-byte length + UTF-16LE body.
/// The length is in bytes; unpaired surrogates are rejected as InvalidUtf16,
/// no silent replacement.
///
/// Do not strip a trailing NUL, because observation shows there is nothing to
/// strip: in real local WER dumps and the public corpus, the module paths,
/// PDB names, and thread names of all four generators (WER, breakpad
/// Windows/Linux, crashpad) end in a normal character one by one
/// (`e`/`l`/`y`/`b`/`o` and the like), i.e. these writers' Length field does
/// **not** include a trailing NUL. Since no observed sample supports it,
/// "defensive NUL stripping" is not added — it would silently eat characters
/// that are really there.
pub fn Dump::read_string(self : Dump, rva : Rva) -> String raise ParseError {
  let byte_len = self.read_uint32(rva).reinterpret_as_int()
  let start = self.offset(rva + 4UL, byte_len)
  self.decode_utf16(start, byte_len)
}

///|
/// UTF-16LE decoding core. `start` is an **absolute byte index** into
/// `self.data` (not an RVA); the caller must have bounds-checked it with
/// `offset`. Both MINIDUMP_STRING and fixed-length WCHAR arrays go through
/// here, so the surrogate rules live in exactly one place.
/// Note: Buffer is a byte buffer and its to_string does not "interpret the
/// bytes as UTF-8"; use StringBuilder to build strings.
fn Dump::decode_utf16(
  self : Dump,
  start : Int32,
  byte_len : Int32,
) -> String raise ParseError {
  let out = StringBuilder()
  let mut i : Int32 = 0
  while i < byte_len {
    let unit = self.data.unsafe_read_uint16_le(start + i)
    if unit.is_leading_surrogate() {
      // a high surrogate must pair with a low surrogate, otherwise malformed
      if i + 4 > byte_len {
        raise ParseError::InvalidUtf16(unit.to_uint())
      }
      let low = self.data.unsafe_read_uint16_le(start + i + 2)
      if !low.is_trailing_surrogate() {
        raise ParseError::InvalidUtf16(low.to_uint())
      }
      let full = 0x10000U +
        ((unit.to_uint() - 0xd800U) << 10) +
        (low.to_uint() - 0xdc00U)
      out.write_char(code_point_to_char(full))
      i = i + 4
    } else if unit.is_surrogate() {
      // reaching here leaves only the unpaired-low-surrogate case
      raise ParseError::InvalidUtf16(unit.to_uint())
    } else {
      out.write_char(code_point_to_char(unit.to_uint()))
      i = i + 2
    }
  }
  out.to_string()
}

///|
/// The stream directory. A malformed entry count is rejected here rather than
/// left to overflow when the streams are read.
pub fn Dump::stream_directory(
  self : Dump,
) -> Array[StreamEntry] raise ParseError {
  let n = self.header.number_of_streams
  if n > 4096U {
    raise ParseError::BadStreamCount(n)
  }
  let entries : Array[StreamEntry] = []
  let mut i : UInt32 = 0U
  while i < n {
    let base = self.header.stream_directory_rva + 12UL * i.to_uint64()
    let entry : StreamEntry = {
      stream_type: self.read_uint32(base),
      data_size: self.read_uint32(base + 4UL),
      rva: self.read_uint32(base + 8UL).to_uint64(),
    }
    entries.push(entry)
    i = i + 1U
  }
  entries
}

///|
/// Look up an entry by stream type in the directory. When a type appears more
/// than once, take the **last** one: rust-minidump builds a per-type map where
/// later entries overwrite earlier ones (with a warn); match that so
/// field-by-field cross-checks line up.
pub fn get_stream(
  entries : Array[StreamEntry],
  stream_type : UInt32,
) -> StreamEntry? {
  let mut found : StreamEntry? = None
  for e in entries {
    if e.stream_type == stream_type {
      found = Some(e)
    }
  }
  found
}

///|
/// Lenient read for optional strings: RVA 0 means "the generator did not write
/// this field"; a string body out of bounds or with malformed surrogates
/// degrades to an empty string without dragging down the rest of the stream.
/// A triage tool should not lose the system version because of one bad path name.
fn Dump::read_optional_string(self : Dump, rva : Rva) -> String {
  if rva == 0UL {
    ""
  } else {
    try self.read_string(rva) catch {
      _ => ""
    } noraise {
      s => s
    }
  }
}

///|
/// Fixed-length WCHAR arrays (TIME_ZONE_INFORMATION.StandardName,
/// MINIDUMP_MISC_INFO_4.BuildString and the like): read up to the NUL; the
/// rest is padding. `byte_len` is the size of the **entire array** in bytes;
/// out-of-bounds still raises.
fn Dump::read_wchar_fixed(
  self : Dump,
  base : Rva,
  byte_len : Int32,
) -> String raise ParseError {
  let start = self.offset(base, byte_len)
  let mut end : Int32 = 0
  let mut found_nul = false
  while end < byte_len && !found_nul {
    found_nul = self.data.unsafe_read_uint16_le(start + end) == 0
    if !found_nul {
      end = end + 2
    }
  }
  self.decode_utf16(start, end)
}

///|
/// Lenient version: a broken embedded string is treated as unwritten, without
/// dragging down the numeric fields in the same struct. ProcessId and the
/// time-zone offsets matter far more than triage-facing build strings.
fn Dump::read_wchar_fixed_or_empty(
  self : Dump,
  base : Rva,
  byte_len : Int32,
) -> String {
  try self.read_wchar_fixed(base, byte_len) catch {
    _ => ""
  } noraise {
    s => s
  }
}

///|
/// MINIDUMP_SYSTEM_INFO, fixed 56 bytes.
///
/// The layout of the first 32 bytes was verified byte-by-byte against 5 real
/// dumps under testdata/ (Windows x86/XP, Windows x64, Crashpad macOS,
/// breakpad Linux, Windows x64 full memory): versions read back as
/// 5.1.2600 + "Service Pack 2" and 10.0.19042, and suite_mask reads back as
/// valid VER_SUITE bitmaps like 0x0100/0x0300 — which places SuiteMask at 28,
/// not 30.
///
/// Bytes 32..56 are the CPU_INFORMATION union, fixed at 24 bytes, with
/// contents varying by architecture/generator: x86 and amd64 are
/// vendor_id[3]@32 + version_information@44 + feature_information@48 +
/// amd_extended_cpu_features@52; the ARM family is cpuid@32 + elf_hwcaps@36;
/// everything else is 2 u64s of processor_features. So this keeps the 6 raw
/// 32-bit words, and only surfaces a vendor when it actually looks like a
/// vendor string.
#derive(Debug, Eq)
pub(all) struct SystemInfo {
  processor_architecture : UInt16
  /// In x86 semantics this is family
  processor_level : UInt16
  /// In x86 semantics the high byte is model and the low byte is stepping
  processor_revision : UInt16
  /// Number of logical processors
  number_of_processors : Byte
  /// VER_NT_WORKSTATION / _DOMAIN_CONTROLLER / _SERVER
  product_type : Byte
  major_version : UInt32
  minor_version : UInt32
  build_number : UInt32
  /// Windows dumps use VER_PLATFORM_* (2 = Win32 NT); non-Windows generators
  /// write breakpad's MDOSPlatform here (observed macOS 0x8101, Linux 0x8201),
  /// so display only, never block.
  platform_id : UInt32
  /// CSD version string: "Service Pack 3" and the like on Windows, the full
  /// kernel version string on Linux.
  csd_version : String
  suite_mask : UInt16
  reserved2 : UInt16
  /// The 6 raw 32-bit words of bytes 32..56.
  cpu : Array[UInt32]
  /// For x86-family architectures bytes 32..44 are the CPUID vendor string
  /// ("GenuineIntel"/"AuthenticAMD"). x64 dumps generated by Windows itself
  /// often stuff a feature mask into this stretch that reads back as
  /// non-printable ASCII; in that case give None (rust-minidump likewise only
  /// accepts fully valid CPUID).
  cpu_vendor : String?
}

///|
pub extend SystemInfo with Debug::{to_repr}

///|
pub extend SystemInfo with Eq::{equal, not_equal}

///|
/// wProcessorArchitecture values and display names.
///
/// Names align with rust-minidump's `cpu_arch` output (x86/amd64/arm/arm64/…)
/// so future JSON cross-checks won't differ on this field. Two easy-to-miss
/// points: ARM64 is **12** (not 11) — 11 is undefined in MS/breakpad/
/// rust-minidump; breakpad's old ARM64 encoding uses 0x8003 and coexists with
/// MS's 12.
pub let architecture_names : Array[(UInt16, String)] = [
  (0, "x86"),
  (1, "mips"),
  (2, "alpha"),
  (3, "ppc"),
  (4, "shx"),
  (5, "arm"),
  (6, "ia64"),
  (7, "alpha64"),
  (8, "msil"),
  (9, "amd64"),
  (10, "x86"),
  (12, "arm64"),
  (0x8001, "sparc"),
  (0x8002, "ppc64"),
  (0x8003, "arm64"),
  (0x8004, "mips64"),
  (0xffff, "unknown"),
]

///|
/// Architecture name; unknown numbers display as-is.
pub fn architecture_name(arch : UInt16) -> String {
  let mut name : String? = None
  for (n, s) in architecture_names {
    if n == arch && name is None {
      name = Some(s)
    }
  }
  match name {
    Some(s) => s
    None => "Arch(0x" + arch.to_string(radix=16) + ")"
  }
}

///|
/// The x86-family numbers (INTEL / AMD64 / x86-on-64); only these have the
/// CPUID vendor string at 32..44.
fn architecture_is_x86(arch : UInt16) -> Bool {
  arch == 0 || arch == 9 || arch == 10
}

///|
/// Read bytes 32..44 (12 bytes) and interpret them as a CPUID vendor string;
/// stop at 0, treat any non-printable byte as invalid.
fn Dump::read_cpu_vendor(
  self : Dump,
  base : Rva,
  arch : UInt16,
) -> String? raise ParseError {
  if !architecture_is_x86(arch) {
    None
  } else {
    let out = StringBuilder()
    let mut valid = true
    let mut emitted : Int32 = 0
    let mut i : Int32 = 0
    while i < 12 {
      let byte = self.read_byte(base + 32UL + i.to_uint64())
      // 0 is the truncation terminator for vendor strings; stop appending after it
      if byte == 0 {
        i = 12
      } else if byte.to_int() >= 0x20 && byte.to_int() < 0x7f {
        out.write_char(byte.to_char())
        emitted = emitted + 1
        i = i + 1
      } else {
        valid = false
        i = 12
      }
    }
    // an all-zero segment (no CPU info stored) does not count as a vendor string
    if valid && emitted > 0 {
      Some(out.to_string())
    } else {
      None
    }
  }
}

///|
/// x86/amd64 family/model/stepping.
///
/// family comes straight from processor_level, model/stepping from the
/// high/low bytes of processor_revision; this rule matches the corpus
/// (test.dmp is a family 6 model 13 stepping 8 Pentium M). When family is
/// 0xf, real CPUID decoding would combine version_information into extended
/// model/stepping; that decode is unverified, so no guessing here.
pub fn x86_family_model_stepping(info : SystemInfo) -> (Int32, Int32, Int32) {
  let rev = info.processor_revision.to_int()
  (info.processor_level.to_int(), rev / 256 % 256, rev % 256)
}

///|
/// ProductType (VER_NT_*).
pub fn product_type_name(product_type : Byte) -> String {
  // Byte's Show prints b'\x01'-style; we want the decimal number here
  let n = product_type.to_int()
  match n {
    1 => "Workstation"
    2 => "DomainController"
    3 => "Server"
    _ => "ProductType(" + n.to_string() + ")"
  }
}

///|
/// PlatformId: the Windows side uses MS's VER_PLATFORM_*, the non-Windows side
/// breakpad's MDOSPlatform (0x81xx/0x82xx); the two numbering schemes overlap
/// on 0..3. rust-minidump's internal enum is shifted by +1 overall, but
/// observable behavior in cross-checks does not depend on that offset.
pub fn platform_id_name(platform_id : UInt32) -> String {
  match platform_id {
    0U => "Win32s"
    1U => "Win32Windows"
    2U => "Win32NT"
    3U => "WinCE"
    0x8000U => "Unix"
    0x8101U => "MacOS"
    0x8102U => "IOS"
    0x8201U => "Linux"
    0x8202U => "Solaris"
    0x8203U => "Android"
    0x8204U => "PS3"
    0x8205U => "NaCl"
    0x8206U => "Fuchsia"
    _ => "Platform(0x" + platform_id.to_string(radix=16) + ")"
  }
}

///|
/// Bit table for VER_SUITE_* (GetVersionEx's wSuiteMask; values are stable over time).
pub let suite_mask_bits : Array[(UInt16, String)] = [
  (0x1, "SmallBusiness"),
  (0x2, "Enterprise"),
  (0x4, "BackOffice"),
  (0x8, "Communications"),
  (0x10, "Terminal"),
  (0x20, "SmallBusinessRestricted"),
  (0x40, "EmbeddedNT"),
  (0x80, "DataCenter"),
  (0x100, "SingleUserTS"),
  (0x200, "Personal"),
  (0x400, "Blade"),
  (0x800, "SecurityAppliance"),
  (0x1000, "StorageServer"),
  (0x2000, "ComputeServer"),
]

///|
/// Split suite_mask; returns an empty array when no bit is set, unrecognized
/// bits end up as Unknown(0x..).
pub fn describe_suite_mask(suite_mask : UInt16) -> Array[String] {
  let mut rest = suite_mask
  let names : Array[String] = []
  for (bit, name) in suite_mask_bits {
    if (rest & bit) != 0 {
      rest = rest ^ bit
      names.push(name)
    }
  }
  if rest != 0 {
    names.push("Unknown(0x" + rest.to_string(radix=16) + ")")
  }
  names
}

///|
/// System version in "10.0.19042" form.
pub fn version_string(info : SystemInfo) -> String {
  let head = info.major_version.to_string() +
    "." +
    info.minor_version.to_string()
  head + "." + info.build_number.to_string()
}

///|
/// Full record length of MINIDUMP_SYSTEM_INFO.
pub let system_info_size : UInt32 = 56U

///|
/// Parse a SystemInfo stream.
///
/// Length requirements follow rust-minidump: fewer than 56 bytes is an error,
/// extra bytes are ignored. All 5 dumps in the corpus have DataSize exactly 56.
pub fn Dump::read_system_info(
  self : Dump,
  entry : StreamEntry,
) -> SystemInfo raise ParseError {
  if entry.data_size < system_info_size {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      system_info_size.to_uint64(),
      entry.data_size.to_uint64(),
    )
  }
  let base = entry.rva
  let arch = self.read_uint16(base)
  let csd_rva = self.read_uint32(base + 24UL).to_uint64()
  let vendor = self.read_cpu_vendor(base, arch)
  let words : Array[UInt32] = []
  let mut off = 32UL
  while off < 56UL {
    words.push(self.read_uint32(base + off))
    off = off + 4UL
  }
  let info : SystemInfo = {
    processor_architecture: arch,
    processor_level: self.read_uint16(base + 2UL),
    processor_revision: self.read_uint16(base + 4UL),
    number_of_processors: self.read_byte(base + 6UL),
    product_type: self.read_byte(base + 7UL),
    major_version: self.read_uint32(base + 8UL),
    minor_version: self.read_uint32(base + 12UL),
    build_number: self.read_uint32(base + 16UL),
    platform_id: self.read_uint32(base + 20UL),
    csd_version: self.read_optional_string(csd_rva),
    suite_mask: self.read_uint16(base + 28UL),
    reserved2: self.read_uint16(base + 30UL),
    cpu: words,
    cpu_vendor: vendor,
  }
  info
}

///|
/// Fetch the SystemInfoStream via the directory; returns None if the stream is absent.
pub fn Dump::system_info(
  self : Dump,
  entries : Array[StreamEntry],
) -> SystemInfo? raise ParseError {
  match get_stream(entries, system_info_stream) {
    None => None
    Some(entry) => Some(self.read_system_info(entry))
  }
}

///|
/// MINIDUMP_LOCATION_DESCRIPTOR: a (size, RVA) pair. Reused in many places
/// (a module's CvRecord / MiscRecord, the later UnloadedModuleList, etc.).
/// RVA 0 means the generator did not write it.
///
/// The field order in the file is **DataSize first, then Rva** (matching the
/// MS header), which is easy to get backwards from memory: in test.dmp the
/// first module has 0x28 (40) at +76 and 4908 at +80, and 4908 is exactly the
/// position of the first "RSDS" magic in the file — confirming that the
/// smaller value is the length and the larger is the offset.
#derive(Debug, Eq)
pub(all) struct LocationDescriptor {
  size : UInt32
  rva : Rva
}

///|
pub extend LocationDescriptor with Debug::{to_repr}

///|
pub extend LocationDescriptor with Eq::{equal, not_equal}

///|
fn Dump::read_location(
  self : Dump,
  base : Rva,
) -> LocationDescriptor raise ParseError {
  let loc : LocationDescriptor = {
    size: self.read_uint32(base),
    rva: self.read_uint32(base + 4UL).to_uint64(),
  }
  loc
}

///|
/// The valid signature of VS_FIXEDFILEINFO.
///
/// Note: this value must **not** be used for validation. In the observed
/// corpus the main program module ("c:\\test_app.exe") writes 0, and only
/// system modules write 0xfeef04bd; rust-minidump never validates it either.
/// The field is kept for display only.
pub let fixed_file_info_signature : UInt32 = 0xfeef_04bdU

///|
/// Module version info, fixed at 13 32-bit words / 52 bytes.
///
/// In minidump this struct uses the 52-byte layout from breakpad's
/// `minidump_format.h` (the file_os / file_type / file_subType trio), not the
/// 40-byte VS_FIXEDFILEINFO from Windows `winver.h`. This was derived and
/// confirmed from the corpus: test.dmp's ModuleListStream has DataSize=1408,
/// exactly 4 + 13*108, and only with 52-byte records does CvRecord land on
/// the RSDS magic. Field names follow breakpad (file_sub_type corresponds to
/// breakpad's file_subType).
#derive(Debug, Eq)
pub(all) struct FixedFileInfo {
  signature : UInt32
  struct_version : UInt32
  file_version_hi : UInt32
  file_version_lo : UInt32
  product_version_hi : UInt32
  product_version_lo : UInt32
  file_flags_mask : UInt32
  file_flags : UInt32
  file_os : UInt32
  file_type : UInt32
  file_sub_type : UInt32
  file_date_hi : UInt32
  file_date_lo : UInt32
}

///|
pub extend FixedFileInfo with Debug::{to_repr}

///|
pub extend FixedFileInfo with Eq::{equal, not_equal}

///|
/// Combine the (hi, lo) pair of 32-bit words into a four-part "5.1.2600.2180" version.
///
/// MS defines hi = (major<<16)|minor and lo = (build<<16)|patch. Division and
/// modulo instead of shifts, to avoid width pitfalls when shifting UInt32.
pub fn quad_version(hi : UInt32, lo : UInt32) -> String {
  let major = hi / 65536U
  let minor = hi % 65536U
  let build = lo / 65536U
  let patch = lo % 65536U
  let head = major.to_string() +
    "." +
    minor.to_string() +
    "." +
    build.to_string()
  head + "." + patch.to_string()
}

///|
/// Read the 13 words per the breakpad layout.
fn Dump::read_fixed_file_info(
  self : Dump,
  base : Rva,
) -> FixedFileInfo raise ParseError {
  let info : FixedFileInfo = {
    signature: self.read_uint32(base),
    struct_version: self.read_uint32(base + 4UL),
    file_version_hi: self.read_uint32(base + 8UL),
    file_version_lo: self.read_uint32(base + 12UL),
    product_version_hi: self.read_uint32(base + 16UL),
    product_version_lo: self.read_uint32(base + 20UL),
    file_flags_mask: self.read_uint32(base + 24UL),
    file_flags: self.read_uint32(base + 28UL),
    file_os: self.read_uint32(base + 32UL),
    file_type: self.read_uint32(base + 36UL),
    file_sub_type: self.read_uint32(base + 40UL),
    file_date_hi: self.read_uint32(base + 44UL),
    file_date_lo: self.read_uint32(base + 48UL),
  }
  info
}

///|
/// The RSDS (PDB 7.0) magic of a CodeView record, i.e. ASCII "RSDS".
pub let code_view_rsds_signature : UInt32 = 0x5344_5352U

///|
/// The three items decoded from an RSDS (PDB 7.0) record.
///
/// This toolchain's enum variants only accept named types as payloads, no
/// inline field lists, so the RSDS data gets its own struct.
#derive(Debug, Eq)
pub(all) struct CodeViewRsds {
  /// Mixed-endian GUID, like `5A9832E5-2872-41C1-838E-D98914E9B7FF`
  debug_id : String
  /// PDB revision number; symbol servers locate the PDB by GUID+age
  age : UInt32
  /// PDB path (raw bytes as written, NUL-terminated)
  pdb_name : String
}

///|
pub extend CodeViewRsds with Debug::{to_repr}

///|
pub extend CodeViewRsds with Eq::{equal, not_equal}

///|
/// Module debug info (CodeView).
///
/// Only RSDS is decoded for now: every CvRecord in the Windows corpus is
/// RSDS. Other magics are reported as the raw 4 bytes, with no unverified
/// decoding — the known case is `0x4270454c` ("LEpB") written by breakpad on
/// Linux (a build-id record; all 8 modules in linux-mini.dmp use it). Its
/// field layout will be filled in once multi-language corpus confirms it.
#derive(Debug, Eq)
pub(all) enum CodeView {
  /// PDB 7.0
  Rsds(CodeViewRsds)
  /// The magic is not RSDS; the 4 bytes read are given as-is
  Unrecognized(UInt32)
  /// The CvRecord is empty (RVA or size is 0)
  Missing
  /// The CvRecord points outside the file or its declared length is too small to read
  Corrupt
}

///|
pub extend CodeView with Debug::{to_repr}

///|
pub extend CodeView with Eq::{equal, not_equal}

///|
/// Uppercase byte hex, always two digits.
fn hex_byte(b : Byte) -> String {
  let digits : Array[String] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F",
  ]
  let v = b.to_int()
  digits[v / 16] + digits[v % 16]
}

///|
/// Format the 16-byte CV identifier the way breakpad/rust-minidump display it:
/// `5A9832E5-2872-41C1-838E-D98914E9B7FF`.
///
/// The first 4 bytes (Data1), next 2 bytes (Data2), and next 2 bytes (Data3)
/// are stored little-endian; the final 8 bytes (Data4) are output in file
/// order as-is. This mixed endianness is the easiest thing to copy wrong, so
/// the bytes are rearranged through a byte array first and then hex-encoded
/// one byte at a time — no shifts.
fn Dump::read_cv_guid(self : Dump, base : Rva) -> String raise ParseError {
  // display order -> in-file offset
  let order : Array[Int32] = [
    3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15,
  ]
  let out = StringBuilder()
  for i in 0..<16 {
    if i == 4 || i == 6 || i == 8 || i == 10 {
      out.write_char('-')
    }
    let b = self.read_byte(base + order[i].to_uint64())
    out.write_string(hex_byte(b))
  }
  out.to_string()
}

///|
/// Read a NUL-terminated byte string, at most `max_bytes` bytes.
///
/// Writers occasionally emit a LOC size off by one byte from the actual
/// content (the corpus contains a 40-byte LOC holding a 16-character path),
/// so read "up to the first NUL" and treat the declared length only as an
/// upper bound. Non-ASCII bytes are presented byte-by-byte as Latin-1:
/// observed PDB paths are all ASCII, rust-minidump does lossy UTF-8, and
/// alignment waits for multi-language corpus.
fn Dump::read_nul_terminated(
  self : Dump,
  base : Rva,
  max_bytes : Int32,
) -> String raise ParseError {
  let out = StringBuilder()
  let mut i : Int32 = 0
  let mut stop = false
  while !stop && i < max_bytes {
    let b = self.read_byte(base + i.to_uint64())
    if b == 0 {
      stop = true
    } else {
      out.write_char(b.to_char())
    }
    i = i + 1
  }
  out.to_string()
}

///|
/// Actually decode the CvRecord; raise on out-of-bounds, and the caller
/// collapses it into CodeView::Corrupt.
fn Dump::parse_code_view(
  self : Dump,
  loc : LocationDescriptor,
) -> CodeView raise ParseError {
  let kind = self.read_uint32(loc.rva)
  if kind != code_view_rsds_signature {
    CodeView::Unrecognized(kind)
  } else {
    let debug_id = self.read_cv_guid(loc.rva + 4UL)
    let age = self.read_uint32(loc.rva + 20UL)
    // 24 = magic(4) + GUID(16) + age(4)
    let name_room = if loc.size > 24U {
      loc.size.reinterpret_as_int() - 24
    } else {
      0
    }
    let pdb_name = self.read_nul_terminated(loc.rva + 24UL, name_room)
    CodeView::Rsds({ debug_id, age, pdb_name, })
  }
}

///|
/// CvRecord -> CodeView. Empty records give Missing, unreadable ones give
/// Corrupt: one bad debug record must not take the whole module table down.
fn Dump::read_code_view(self : Dump, loc : LocationDescriptor) -> CodeView {
  if loc.rva == 0UL || loc.size < 4U {
    CodeView::Missing
  } else {
    try self.parse_code_view(loc) catch {
      _ => CodeView::Corrupt
    } noraise {
      cv => cv
    }
  }
}

///|
/// Per-record length of MINIDUMP_MODULE. 108 = 8+4+4+4+4+52+8+8+8+8.
pub let module_size : UInt32 = 108U

///|
/// Module (image) record.
#derive(Debug, Eq)
pub(all) struct Module {
  /// Load base address
  base_of_image : UInt64
  /// Image size; together with the base it forms the address range [base, base+size)
  size_of_image : UInt32
  checksum : UInt32
  /// TimeDateStamp from the PE header; unrelated to the dump creation time
  time_date_stamp : UInt32
  /// MINIDUMP_STRING module path; degrades to an empty string when out of bounds or malformed
  name : String
  version_info : FixedFileInfo
  code_view : CodeView
  /// MiscRecord: VS_VERSION_INFO or crashpad extra info, not yet decoded; the raw LOC is kept
  misc_record : LocationDescriptor
  reserved0 : UInt64
  reserved1 : UInt64
}

///|
pub extend Module with Debug::{to_repr}

///|
pub extend Module with Eq::{equal, not_equal}

///|
/// The end address (exclusive) occupied by the module.
pub fn Module::end_address(self : Module) -> UInt64 {
  self.base_of_image + self.size_of_image.to_uint64()
}

///|
/// Whether an address falls within this module. Stack walking relies on it to
/// attribute return addresses to modules.
pub fn Module::contains(self : Module, address : UInt64) -> Bool {
  address >= self.base_of_image && address < self.end_address()
}

///|
/// File version, in "5.1.2600.2180" form.
pub fn Module::file_version(self : Module) -> String {
  quad_version(
    self.version_info.file_version_hi,
    self.version_info.file_version_lo,
  )
}

///|
/// Product version.
pub fn Module::product_version(self : Module) -> String {
  quad_version(
    self.version_info.product_version_hi,
    self.version_info.product_version_lo,
  )
}

///|
/// What comes out of reading a module list.
#derive(Debug, Eq)
pub(all) struct ModuleList {
  modules : Array[Module]
  /// Number of dropped entries; see the skip rules in `read_module_list`
  skipped : Int32
}

///|
pub extend ModuleList with Debug::{to_repr}

///|
pub extend ModuleList with Eq::{equal, not_equal}

///|
/// Read one module record (offsets per the 108-byte verification at the top of this file).
fn Dump::read_module(self : Dump, base : Rva) -> Module raise ParseError {
  let name_rva = self.read_uint32(base + 20UL).to_uint64()
  let cv_record = self.read_location(base + 76UL)
  let misc_record = self.read_location(base + 84UL)
  let m : Module = {
    base_of_image: self.read_uint64(base),
    size_of_image: self.read_uint32(base + 8UL),
    checksum: self.read_uint32(base + 12UL),
    time_date_stamp: self.read_uint32(base + 16UL),
    name: self.read_optional_string(name_rva),
    version_info: self.read_fixed_file_info(base + 24UL),
    code_view: self.read_code_view(cv_record),
    misc_record,
    reserved0: self.read_uint64(base + 92UL),
    reserved1: self.read_uint64(base + 100UL),
  }
  m
}

///|
/// Parse ModuleListStream.
///
/// Length validation aligns with rust-minidump: `DataSize` must equal
/// 4 + count*108, with the single known writer leniency of "exactly 4 extra
/// bytes" also accepted; everything else raises ListSizeMismatch. Entries are
/// skipped per the rules (and counted in skipped): `size_of_image == 0`, or
/// base+size overflows (meaning the record's addresses are untrustworthy and
/// would attribute frames to the wrong module).
pub fn Dump::read_module_list(
  self : Dump,
  entry : StreamEntry,
) -> ModuleList raise ParseError {
  let count = self.read_uint32(entry.rva).to_uint64()
  let needed = 4UL + count * module_size.to_uint64()
  let have = entry.data_size.to_uint64()
  if have != needed && have != needed + 4UL {
    raise ParseError::ListSizeMismatch(entry.stream_type, needed, have)
  }
  let file_len = self.data.length().to_uint64()
  // the declared length may be fine, but a truncated file must still be
  // reported; cannot rely on a later out-of-bounds read to catch it
  if !self.range_in_file(entry.rva, needed) {
    raise ParseError::Truncated(entry.rva, needed, file_len)
  }
  let modules : Array[Module] = []
  let mut skipped : Int32 = 0
  let mut i : UInt64 = 0UL
  while i < count {
    let m = self.read_module(entry.rva + 4UL + i * module_size.to_uint64())
    if m.size_of_image == 0U || m.end_address() < m.base_of_image {
      skipped = skipped + 1
    } else {
      modules.push(m)
    }
    i = i + 1UL
  }
  let list : ModuleList = { modules, skipped, }
  list
}

///|
/// Fetch the ModuleListStream via the directory.
pub fn Dump::modules(
  self : Dump,
  entries : Array[StreamEntry],
) -> ModuleList? raise ParseError {
  match get_stream(entries, module_list_stream) {
    None => None
    Some(entry) => Some(self.read_module_list(entry))
  }
}

///|
/// The **struct size** (bytes) of each version in the MINIDUMP_MISC_INFO family.
///
/// The numbers come from the field declarations in the local SDK header
/// `minidumpapiset.h` (Windows Kits 10.0.26100.0), computed under C alignment
/// rules — not copied folklore:
/// - v1 = 6 u32s = 24
/// - v2 = v1 + 5 u32s = 44
/// - v3 = v2 + 4 u32s + TIME_ZONE_INFORMATION(172) = 232
///   (172 = Bias4 + StandardName64 + StandardDate16 + StandardBias4
///          + DaylightName64 + DaylightDate16 + DaylightBias4)
/// - v4 = v3 + WCHAR[MAX_PATH](520) + WCHAR[40](80) = 832
/// - v5 = v4 + XSTATE_CONFIG_FEATURE_MSC_INFO(528) + u32 = 1364
///   (528 = 4 + 4 + 8 + 64*8; the start at 832 is already 8-aligned, no padding)
/// These five thresholds match the numbers rust-minidump uses for version
/// detection, so they can be cross-checked.
pub let misc_info_v1_size : UInt32 = 24U

///|
pub let misc_info_v2_size : UInt32 = 44U

///|
pub let misc_info_v3_size : UInt32 = 232U

///|
pub let misc_info_v4_size : UInt32 = 832U

///|
pub let misc_info_v5_size : UInt32 = 1364U

///|
/// The stream's declared DataSize -> struct version: the largest version that
/// fits completely. Sizes below v1 also return 1; the read site's
/// StreamTooSmall does the rejecting, so callers need no second check.
pub fn misc_info_version(data_size : UInt32) -> UInt32 {
  if data_size >= misc_info_v5_size {
    5U
  } else if data_size >= misc_info_v4_size {
    4U
  } else if data_size >= misc_info_v3_size {
    3U
  } else if data_size >= misc_info_v2_size {
    2U
  } else {
    1U
  }
}

///|
/// Bits of Flags1. The header file's lines 577–585 say verbatim:
/// "A member is valid if it's within the available size and its corresponding
/// bit is set." — so this implementation surfaces a field only when both
/// "version is sufficient" and "the bit is set" hold.
pub let misc1_process_id : UInt32 = 0x0000_0001U

///|
pub let misc1_process_times : UInt32 = 0x0000_0002U

///|
pub let misc1_processor_power_info : UInt32 = 0x0000_0004U

///|
pub let misc3_process_integrity : UInt32 = 0x0000_0010U

///|
pub let misc3_process_execute_flags : UInt32 = 0x0000_0020U

///|
pub let misc3_timezone : UInt32 = 0x0000_0040U

///|
pub let misc3_protected_process : UInt32 = 0x0000_0080U

///|
pub let misc4_buildstring : UInt32 = 0x0000_0100U

///|
pub let misc5_process_cookie : UInt32 = 0x0000_0200U

///|
pub let misc_info_flag_bits : Array[(UInt32, String)] = [
  (misc1_process_id, "ProcessId"),
  (misc1_process_times, "ProcessTimes"),
  (misc1_processor_power_info, "ProcessorPowerInfo"),
  (misc3_process_integrity, "ProcessIntegrity"),
  (misc3_process_execute_flags, "ProcessExecuteFlags"),
  (misc3_timezone, "TimeZone"),
  (misc3_protected_process, "ProtectedProcess"),
  (misc4_buildstring, "BuildString"),
  (misc5_process_cookie, "ProcessCookie"),
]

///|
/// Split Flags1 into a name list; undefined bits go into a single Unknown
/// entry, never silently dropped.
pub fn describe_misc_flags(flags : UInt32) -> Array[String] {
  let mut rest = flags
  let names : Array[String] = []
  for (bit, name) in misc_info_flag_bits {
    if (rest & bit) != 0U {
      rest = rest ^ bit
      names.push(name)
    }
  }
  if rest != 0U {
    names.push("Unknown(0x" + rest.to_string(radix=16) + ")")
  }
  names
}

///|
/// The PROCESS_TIMES group of times, in seconds (one each for kernel/user CPU time).
#derive(Debug, Eq)
pub(all) struct ProcessTimes {
  create_time : UInt32
  user_time : UInt32
  kernel_time : UInt32
}

///|
pub extend ProcessTimes with Debug::{to_repr}

///|
pub extend ProcessTimes with Eq::{equal, not_equal}

///|
/// The PROCESSOR_POWER_INFO group of frequencies/idle states.
#derive(Debug, Eq)
pub(all) struct ProcessorPowerInfo {
  max_mhz : UInt32
  current_mhz : UInt32
  mhz_limit : UInt32
  max_idle_state : UInt32
  current_idle_state : UInt32
}

///|
pub extend ProcessorPowerInfo with Debug::{to_repr}

///|
pub extend ProcessorPowerInfo with Eq::{equal, not_equal}

///|
/// SYSTEMTIME, fixed 16 bytes (minwinbase.h:90).
/// Note this holds a **time-zone transition rule** (which week/day/hour), not
/// an absolute moment; on machines that ignore DST the whole block is 0, so
/// is_empty is the norm, not malformation.
#derive(Debug, Eq)
pub(all) struct SystemTime {
  year : UInt16
  month : UInt16
  day_of_week : UInt16
  day : UInt16
  hour : UInt16
  minute : UInt16
  second : UInt16
  milliseconds : UInt16
}

///|
pub extend SystemTime with Debug::{to_repr}

///|
pub extend SystemTime with Eq::{equal, not_equal}

///|
pub fn SystemTime::is_empty(self : SystemTime) -> Bool {
  self.year == 0 &&
  self.month == 0 &&
  self.day_of_week == 0 &&
  self.day == 0 &&
  self.hour == 0 &&
  self.minute == 0 &&
  self.second == 0 &&
  self.milliseconds == 0
}

///|
fn pad_num(v : UInt16, width : Int32) -> String {
  let mut s = v.to_int().to_string()
  while s.length() < width {
    s = "0" + s
  }
  s
}

///|
/// Compress a "DST transition rule" into one fixed-width text line.
/// Deliberately not formatted as a date: wYear is 0 throughout the corpus;
/// the value expresses a rule like "switch on the first Sunday of November at
/// 02:00" (day_of_week + day together mean "the Nth weekday"), and dressing
/// it up as an absolute date would only mislead report readers.
pub fn SystemTime::rule_text(self : SystemTime) -> String {
  if self.is_empty() {
    "-"
  } else {
    let ymd = "y=" +
      self.year.to_int().to_string() +
      " m=" +
      self.month.to_int().to_string() +
      " dow=" +
      self.day_of_week.to_int().to_string() +
      " d=" +
      self.day.to_int().to_string()
    let hms = pad_num(self.hour, 2) +
      ":" +
      pad_num(self.minute, 2) +
      ":" +
      pad_num(self.second, 2)
    ymd + " " + hms
  }
}

///|
/// TIME_ZONE_INFORMATION, fixed 172 bytes (timezoneapi.h:35).
/// Bias is the minutes such that "local time + Bias = UTC", so its sign is the
/// **opposite** of the UTC offset: in the corpus US Eastern writes 300
/// (= UTC-05:00) and Beijing writes -480 (= UTC+08:00).
#derive(Debug, Eq)
pub(all) struct TimeZoneInformation {
  bias : Int32
  standard_name : String
  standard_date : SystemTime
  standard_bias : Int32
  daylight_name : String
  daylight_date : SystemTime
  daylight_bias : Int32
}

///|
pub extend TimeZoneInformation with Debug::{to_repr}

///|
pub extend TimeZoneInformation with Eq::{equal, not_equal}

///|
/// Format a Bias in minutes as a readable offset like "+08:00" (the caller
/// adds the "UTC" prefix itself). Bias's sign is opposite to the UTC offset
/// (Beijing writes -480, US Eastern writes 300), so flip the sign first.
pub fn time_zone_offset_text(bias : Int32) -> String {
  let sign = if bias <= 0 { "+" } else { "-" }
  let abs = if bias < 0 { 0 - bias } else { bias }
  sign + pad_two(abs / 60) + ":" + pad_two(abs % 60)
}

///|
/// Zero-pad to two decimal digits (small fields like hours/minutes); the sign is the caller's job.
fn pad_two(v : Int32) -> String {
  if v < 10 {
    "0" + v.to_string()
  } else {
    v.to_string()
  }
}

///|
/// XSTATE_FEATURE (winnt.h:14412): { Offset, Size }, 8 bytes.
#derive(Debug, Eq)
pub(all) struct XStateFeature {
  offset : UInt32
  size : UInt32
}

///|
pub extend XStateFeature with Debug::{to_repr}

///|
pub extend XStateFeature with Eq::{equal, not_equal}

///|
/// XSTATE_CONFIG_FEATURE_MSC_INFO (minidumpapiset.h:562), 528 bytes.
/// `context_size` is the total size of the extended CONTEXT; AVX stack
/// walking needs it to determine the read length. Bit i of
/// `enabled_features` corresponds to `features[i]`.
#derive(Debug, Eq)
pub(all) struct XStateConfig {
  size_of_info : UInt32
  context_size : UInt32
  enabled_features : UInt64
  features : Array[XStateFeature]
}

///|
pub extend XStateConfig with Debug::{to_repr}

///|
pub extend XStateConfig with Eq::{equal, not_equal}

///|
pub fn XStateConfig::enabled(self : XStateConfig, index : Int32) -> Bool {
  if index < 0 || index >= 64 {
    false
  } else {
    // not `1UL << index`: the shift's right side wants Int; avoids type
    // ping-pong here
    let mut bit : UInt64 = 1UL
    let mut i : Int32 = 0
    while i < index {
      bit = bit << 1
      i = i + 1
    }
    (self.enabled_features & bit) != 0UL
  }
}

///|
/// Get XState feature number index (None when out of range or not enabled).
pub fn XStateConfig::feature(
  self : XStateConfig,
  index : Int32,
) -> XStateFeature? {
  if !self.enabled(index) || index >= self.features.length() {
    None
  } else {
    Some(self.features[index])
  }
}

///|
/// The MINIDUMP_MISC_INFO stream. Everything except SizeOfInfo/Flags1 is
/// gated on "version sufficient + bit set"; when not satisfied the value is
/// None (not 0) — the two semantics must stay distinguishable: 0 is a value
/// the generator wrote, None means "this dump simply does not provide it".
///
/// `size_of_info` keeps the raw field: MS says it equals the struct length,
/// but writers have been observed writing other numbers (Crashpad often
/// differs by 4 bytes), so it is displayed only — not validated, and not used
/// for version detection.
#derive(Debug, Eq)
pub(all) struct MiscInfo {
  info_version : UInt32
  size_of_info : UInt32
  flags1 : UInt32
  process_id : UInt32?
  process_times : ProcessTimes?
  processor_power_info : ProcessorPowerInfo?
  process_integrity_level : UInt32?
  process_execute_flags : UInt32?
  protected_process : UInt32?
  time_zone_id : UInt32?
  time_zone : TimeZoneInformation?
  build_string : String?
  dbg_build_string : String?
  xstate_config : XStateConfig?
  process_cookie : UInt32?
}

///|
pub extend MiscInfo with Debug::{to_repr}

///|
pub extend MiscInfo with Eq::{equal, not_equal}

///|
fn Dump::read_system_time(
  self : Dump,
  base : Rva,
) -> SystemTime raise ParseError {
  let t : SystemTime = {
    year: self.read_uint16(base),
    month: self.read_uint16(base + 2UL),
    day_of_week: self.read_uint16(base + 4UL),
    day: self.read_uint16(base + 6UL),
    hour: self.read_uint16(base + 8UL),
    minute: self.read_uint16(base + 10UL),
    second: self.read_uint16(base + 12UL),
    milliseconds: self.read_uint16(base + 14UL),
  }
  t
}

///|
/// The TIME_ZONE_INFORMATION embedded at offset 60.
fn Dump::read_time_zone(
  self : Dump,
  base : Rva,
) -> TimeZoneInformation raise ParseError {
  let tz : TimeZoneInformation = {
    bias: self.read_uint32(base).reinterpret_as_int(),
    standard_name: self.read_wchar_fixed_or_empty(base + 4UL, 64),
    standard_date: self.read_system_time(base + 68UL),
    standard_bias: self.read_uint32(base + 84UL).reinterpret_as_int(),
    daylight_name: self.read_wchar_fixed_or_empty(base + 88UL, 64),
    daylight_date: self.read_system_time(base + 152UL),
    daylight_bias: self.read_uint32(base + 168UL).reinterpret_as_int(),
  }
  tz
}

///|
/// The XSTATE_CONFIG_FEATURE_MSC_INFO embedded at offset 832.
/// The Features table is fixed at 64 entries (MAXIMUM_XSTATE_FEATURES,
/// winnt.h:14266).
fn Dump::read_xstate_config(
  self : Dump,
  base : Rva,
) -> XStateConfig raise ParseError {
  let features : Array[XStateFeature] = []
  let mut i : UInt64 = 0UL
  while i < 64UL {
    let at = base + 16UL + i * 8UL
    let f : XStateFeature = {
      offset: self.read_uint32(at),
      size: self.read_uint32(at + 4UL),
    }
    features.push(f)
    i = i + 1UL
  }
  let cfg : XStateConfig = {
    size_of_info: self.read_uint32(base),
    context_size: self.read_uint32(base + 4UL),
    enabled_features: self.read_uint64(base + 8UL),
    features,
  }
  cfg
}

///|
/// Parse a MiscInfo stream (stream type is always 15; Linux/breakpad dumps
/// also write it).
pub fn Dump::read_misc_info(
  self : Dump,
  entry : StreamEntry,
) -> MiscInfo raise ParseError {
  let have = entry.data_size.to_uint64()
  if have < misc_info_v1_size.to_uint64() {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      misc_info_v1_size.to_uint64(),
      have,
    )
  }
  let version = misc_info_version(entry.data_size)
  let at = entry.rva
  let flags1 = self.read_uint32(at + 4UL)
  fn has(flag : UInt32) -> Bool {
    (flags1 & flag) != 0U
  }
  let process_id : UInt32? = if has(misc1_process_id) {
    Some(self.read_uint32(at + 8UL))
  } else {
    None
  }
  let process_times : ProcessTimes? = if has(misc1_process_times) {
    Some({
      create_time: self.read_uint32(at + 12UL),
      user_time: self.read_uint32(at + 16UL),
      kernel_time: self.read_uint32(at + 20UL),
    })
  } else {
    None
  }
  let power : ProcessorPowerInfo? = if version >= 2U &&
    has(misc1_processor_power_info) {
    Some({
      max_mhz: self.read_uint32(at + 24UL),
      current_mhz: self.read_uint32(at + 28UL),
      mhz_limit: self.read_uint32(at + 32UL),
      max_idle_state: self.read_uint32(at + 36UL),
      current_idle_state: self.read_uint32(at + 40UL),
    })
  } else {
    None
  }
  let integrity : UInt32? = if version >= 3U && has(misc3_process_integrity) {
    Some(self.read_uint32(at + 44UL))
  } else {
    None
  }
  let execute_flags : UInt32? = if version >= 3U &&
    has(misc3_process_execute_flags) {
    Some(self.read_uint32(at + 48UL))
  } else {
    None
  }
  let protected_value : UInt32? = if version >= 3U &&
    has(misc3_protected_process) {
    Some(self.read_uint32(at + 52UL))
  } else {
    None
  }
  // Both TimeZoneId and TIME_ZONE_INFORMATION are governed by the single
  // MISC3_TIMEZONE bit: the header provides no other time-zone-related bit.
  let mut time_zone_id : UInt32? = None
  let mut time_zone : TimeZoneInformation? = None
  if version >= 3U && has(misc3_timezone) {
    time_zone_id = Some(self.read_uint32(at + 56UL))
    time_zone = Some(self.read_time_zone(at + 60UL))
  }
  let build_string : String? = if version >= 4U && has(misc4_buildstring) {
    Some(self.read_wchar_fixed_or_empty(at + 232UL, 520))
  } else {
    None
  }
  let dbg_build_string : String? = if version >= 4U && has(misc4_buildstring) {
    Some(self.read_wchar_fixed_or_empty(at + 752UL, 80))
  } else {
    None
  }
  // XStateData has no corresponding flags bit (MS gates it on struct version only)
  let xstate : XStateConfig? = if version >= 5U {
    Some(self.read_xstate_config(at + 832UL))
  } else {
    None
  }
  let process_cookie : UInt32? = if version >= 5U && has(misc5_process_cookie) {
    Some(self.read_uint32(at + 1360UL))
  } else {
    None
  }
  let info : MiscInfo = {
    info_version: version,
    size_of_info: self.read_uint32(at),
    flags1,
    process_id,
    process_times,
    processor_power_info: power,
    process_integrity_level: integrity,
    process_execute_flags: execute_flags,
    protected_process: protected_value,
    time_zone_id,
    time_zone,
    build_string,
    dbg_build_string,
    xstate_config: xstate,
    process_cookie,
  }
  info
}

///|
/// Fetch the MiscInfoStream via the directory.
pub fn Dump::misc_info(
  self : Dump,
  entries : Array[StreamEntry],
) -> MiscInfo? raise ParseError {
  match get_stream(entries, misc_info_stream) {
    None => None
    Some(entry) => Some(self.read_misc_info(entry))
  }
}

///|
/// MINIDUMP_MEMORY_DESCRIPTOR: where a virtual-address range lives in the dump
/// file.
///
/// The C layout is `DWORD64 StartOfMemoryRange` followed by a
/// `MINIDUMP_LOCATION_DESCRIPTOR` (DataSize 4 + Rva 4), **16 bytes total**.
/// Thread stacks, ThreadEx's BackingStore, and MemoryListStream entries all
/// use this struct.
#derive(Debug, Eq)
pub(all) struct MemoryDescriptor {
  start_address : UInt64
  location : LocationDescriptor
}

///|
pub extend MemoryDescriptor with Debug::{to_repr}

///|
pub extend MemoryDescriptor with Eq::{equal, not_equal}

///|
fn Dump::read_memory_descriptor(
  self : Dump,
  base : Rva,
) -> MemoryDescriptor raise ParseError {
  let d : MemoryDescriptor = {
    start_address: self.read_uint64(base),
    location: self.read_location(base + 8UL),
  }
  d
}

///|
/// Record length of MINIDUMP_THREAD.
///
/// Computed from the field declarations in the local SDK header
/// `minidumpapiset.h`:
/// ThreadId4 + SuspendCount4 + PriorityClass4 + Priority4 + Teb8
/// + Stack(8 + 4 + 4 = 16) + ThreadContext(4 + 4 = 8) = **48**.
///
/// Corpus cross-check: test.dmp's ThreadListStream is DataSize=100 / count=2,
/// full-dump.dmp 196 / 4, invalid-parameter.dmp 292 / 6,
/// simple-crashpad.dmp and linux-mini.dmp both 52 / 1 — all exactly
/// 4 + 48*count.
pub let thread_size : UInt32 = 48U

///|
/// MINIDUMP_THREAD_EX = MINIDUMP_THREAD(48) + BackingStore(16) = **64**.
pub let thread_ex_size : UInt32 = 64U

///|
/// One thread record.
///
/// Thread and ThreadEx share one type: the only difference is `backing_store`,
/// which is present only for 64-byte records. Splitting into two types would
/// add a pointless extra match to the most common use, iterating threads.
#derive(Debug, Eq)
pub(all) struct Thread {
  id : UInt32
  suspend_count : UInt32
  priority_class : UInt32
  priority : UInt32
  /// The TEB's **virtual address** (not an RVA).
  teb : UInt64
  /// The stack range: StartOfMemoryRange is one of the boundaries toward the
  /// stack top; location gives this stack's position and length in the file.
  stack : MemoryDescriptor
  /// The CONTEXT's position in the file and its declared length.
  context : LocationDescriptor
  /// ThreadEx only: the thread stack's full reserved range (location may be 0,
  /// meaning unwritten).
  backing_store : MemoryDescriptor?
  /// The width this record was actually parsed at (48 / 64), keeping "parsed
  /// as ThreadEx" in the data.
  entry_size : UInt32
}

///|
pub extend Thread with Debug::{to_repr}

///|
pub extend Thread with Eq::{equal, not_equal}

///|
fn Dump::read_thread(
  self : Dump,
  base : Rva,
  ex : Bool,
) -> Thread raise ParseError {
  let backing : MemoryDescriptor? = if ex {
    Some(self.read_memory_descriptor(base + 48UL))
  } else {
    None
  }
  let t : Thread = {
    id: self.read_uint32(base),
    suspend_count: self.read_uint32(base + 4UL),
    priority_class: self.read_uint32(base + 8UL),
    priority: self.read_uint32(base + 12UL),
    teb: self.read_uint64(base + 16UL),
    stack: self.read_memory_descriptor(base + 24UL),
    context: self.read_location(base + 40UL),
    backing_store: backing,
    entry_size: if ex {
      thread_ex_size
    } else {
      thread_size
    },
  }
  t
}

///|
/// Determine the thread-table entry width.
///
/// Although the directory has ThreadExListStream=8 as a type, in practice
/// 64-byte entries mostly still live in ThreadListStream=3 (the writer just
/// copied MINIDUMP_THREAD_EX), so the width is inferred from the declared
/// length rather than from the type alone. Length validation keeps
/// ModuleList's leniency: only "exactly 4 extra bytes" is additionally accepted.
fn thread_entry_size(
  entry : StreamEntry,
  count : UInt64,
) -> UInt32 raise ParseError {
  let have = entry.data_size.to_uint64()
  let need48 = 4UL + count * thread_size.to_uint64()
  let need64 = 4UL + count * thread_ex_size.to_uint64()
  if entry.stream_type == thread_ex_list_stream {
    if have == need64 {
      thread_ex_size
    } else {
      raise ParseError::ListSizeMismatch(entry.stream_type, need64, have)
    }
  } else if have == need48 || have == need48 + 4UL {
    thread_size
  } else if have == need64 || have == need64 + 4UL {
    thread_ex_size
  } else {
    raise ParseError::ListSizeMismatch(entry.stream_type, need48, have)
  }
}

///|
/// Parse ThreadListStream / ThreadExListStream.
///
/// Only the thread records themselves are read here, **not the CONTEXTs**:
/// one malformed context must not take the whole thread table down. Fetch
/// contexts separately with `Dump::read_context`.
pub fn Dump::read_thread_list(
  self : Dump,
  entry : StreamEntry,
) -> Array[Thread] raise ParseError {
  let count = self.read_uint32(entry.rva).to_uint64()
  if count == 0UL {
    // empty table: many writers also set DataSize to 0; nothing to validate
    return []
  }
  let width = thread_entry_size(entry, count)
  let needed = 4UL + count * width.to_uint64()
  if !self.range_in_file(entry.rva, needed) {
    raise ParseError::Truncated(
      entry.rva,
      needed,
      self.data.length().to_uint64(),
    )
  }
  let threads : Array[Thread] = []
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva + 4UL + i * width.to_uint64()
    threads.push(self.read_thread(base, width == thread_ex_size))
    i = i + 1UL
  }
  threads
}

///|
/// Fetch the thread table via the directory: ThreadListStream first, then
/// ThreadExListStream.
pub fn Dump::threads(
  self : Dump,
  entries : Array[StreamEntry],
) -> Array[Thread]? raise ParseError {
  match get_stream(entries, thread_list_stream) {
    Some(entry) => Some(self.read_thread_list(entry))
    None =>
      match get_stream(entries, thread_ex_list_stream) {
        None => None
        Some(entry) => Some(self.read_thread_list(entry))
      }
  }
}

///|
/// Find a thread by ID in the thread table. The exception stream gives only
/// the ID, not the index.
pub fn find_thread_by_id(
  threads : Array[Thread],
  id : UInt32,
) -> (Int32, Thread)? {
  let n = threads.length()
  let mut i = 0
  let mut found : (Int32, Thread)? = None
  while i < n && found is None {
    if threads[i].id == id {
      found = Some((i, threads[i]))
    }
    i = i + 1
  }
  found
}

///|
/// The **canonical lengths** (bytes) of the CONTEXT for each architecture.
///
/// - x86: `_CONTEXT` from `um\winnt.h:8506` (pshpack4) — ContextFlags@0,
///   Dr0..Dr7@4..24, FLOATING_SAVE_AREA(112)@28, SegGs/Fs/Es/Ds@140..152,
///   Edi..Eax@156..176, Ebp@180 Eip@184 SegCs@188 EFlags@192 Esp@196 SegSs@200,
///   ExtendedRegisters[512]@204 → 204+512 = **716**.
///   test.dmp (XP x86) has ContextSize exactly 716, and reading with this
///   table yields SegCs=0x1b, SegSs=0x23, EFlags=0x246, and an Esp inside the
///   thread's declared stack range — four independent invariants all line up,
///   so these offsets have both header and corpus backing.
/// - amd64: `_CONTEXT` from `um\winnt.h:4304` (DECLSPEC_ALIGN(16)) → **1232**;
///   see the offset constants below. All 4 amd64 dumps in the corpus have
///   ContextSize 1232, with Rsp inside each thread's stack range and Rip
///   inside some module's image.
/// - arm64: `_ARM64_NT_CONTEXT` from `um\winnt.h:6796`, whose header comments
///   carry the offsets; the last field `/* +0x390 */` → **912**
///   (ARM64_MAX_BREAKPOINTS=8, ARM64_MAX_WATCHPOINTS=2, see winnt.h:6733).
///   The corpus has no arm64 dump, so this tier has header backing only.
pub let context_x86_size : UInt32 = 716U

///|
pub let context_amd64_size : UInt32 = 1232U

///|
pub let context_arm64_size : UInt32 = 912U

///|
/// Whether the architecture has a verified CONTEXT field table.
///
/// 32-bit ARM (number 5) is **deliberately absent from this table**: the local
/// SDK's ARM `_CONTEXT` (winnt.h:5287, computed 416 bytes) is not the same
/// layout breakpad/rust-minidump use for minidumps, and the corpus has no ARM
/// dump to prove otherwise. Per the "no guessed offsets" rule, such
/// architectures go through `Context::Undecoded`, reporting only the declared
/// length.
pub fn context_expected_size(architecture : UInt16) -> UInt32? {
  match architecture.to_int() {
    0 => Some(context_x86_size)
    9 => Some(context_amd64_size)
    10 => Some(context_x86_size)
    12 => Some(context_arm64_size)
    0x8003 => Some(context_arm64_size)
    _ => None
  }
}

///|
/// Infer the architecture from the declared length (cross-checking only; see `Dump::read_context`).
pub fn context_arch_by_size(size : UInt32) -> UInt16? {
  if size == context_x86_size {
    Some(0)
  } else if size == context_amd64_size {
    Some(9)
  } else if size == context_arm64_size {
    Some(12)
  } else {
    None
  }
}

///|
/// Registers decoded from the x86 (32-bit) CONTEXT.
///
/// SegCs / SegSs are declared as **DWORD** in the C header (winnt.h:8577/8580),
/// not WORD, so they stay UInt32 here; amd64's two are real WORDs, using
/// UInt16. FloatSave and ExtendedRegisters are floating-point/SIMD state,
/// useless for crash triage; this implementation skips them by offset rather
/// than pretending they are "decoded".
#derive(Debug, Eq)
pub(all) struct ContextX86 {
  context_flags : UInt32
  dr0 : UInt32
  dr1 : UInt32
  dr2 : UInt32
  dr3 : UInt32
  dr6 : UInt32
  dr7 : UInt32
  seg_gs : UInt32
  seg_fs : UInt32
  seg_es : UInt32
  seg_ds : UInt32
  edi : UInt32
  esi : UInt32
  ebx : UInt32
  edx : UInt32
  ecx : UInt32
  eax : UInt32
  ebp : UInt32
  eip : UInt32
  seg_cs : UInt32
  eflags : UInt32
  esp : UInt32
  seg_ss : UInt32
}

///|
pub extend ContextX86 with Debug::{to_repr}

///|
pub extend ContextX86 with Eq::{equal, not_equal}

///|
/// Integer/control registers of the amd64 CONTEXT. Floating point (FltSave@256,
/// 512 bytes) and VectorRegister@768 are left for future XState-related
/// handling; not decoded here.
#derive(Debug, Eq)
pub(all) struct ContextAmd64 {
  context_flags : UInt32
  mx_csr : UInt32
  seg_cs : UInt16
  seg_ds : UInt16
  seg_es : UInt16
  seg_fs : UInt16
  seg_gs : UInt16
  seg_ss : UInt16
  eflags : UInt32
  dr0 : UInt64
  dr1 : UInt64
  dr2 : UInt64
  dr3 : UInt64
  dr6 : UInt64
  dr7 : UInt64
  rax : UInt64
  rcx : UInt64
  rdx : UInt64
  rbx : UInt64
  rsp : UInt64
  rbp : UInt64
  rsi : UInt64
  rdi : UInt64
  r8 : UInt64
  r9 : UInt64
  r10 : UInt64
  r11 : UInt64
  r12 : UInt64
  r13 : UInt64
  r14 : UInt64
  r15 : UInt64
  rip : UInt64
}

///|
pub extend ContextAmd64 with Debug::{to_repr}

///|
pub extend ContextAmd64 with Eq::{equal, not_equal}

///|
/// Integer/control and debug registers of the arm64 CONTEXT.
/// `x` holds X0..X28 plus Fp(X29) and Lr(X30), 31 entries total (the two
/// halves of that union in winnt.h).
#derive(Debug, Eq)
pub(all) struct ContextArm64 {
  context_flags : UInt32
  cpsr : UInt32
  x : Array[UInt64]
  sp : UInt64
  pc : UInt64
  fpcr : UInt32
  fpsr : UInt32
  bcr : Array[UInt32]
  bvr : Array[UInt64]
  wcr : Array[UInt32]
  wvr : Array[UInt64]
}

///|
pub extend ContextArm64 with Debug::{to_repr}

///|
pub extend ContextArm64 with Eq::{equal, not_equal}

///|
/// A CONTEXT that could not be decoded against a field table: keeps the
/// architecture and declared length, and says why decoding failed.
#derive(Debug, Eq)
pub(all) struct ContextUndecoded {
  architecture : UInt16
  declared_size : UInt32
  reason : String
}

///|
pub extend ContextUndecoded with Debug::{to_repr}

///|
pub extend ContextUndecoded with Eq::{equal, not_equal}

///|
/// Thread context. The variant name is the **field table actually used**, not
/// the SystemInfo architecture: in WOW64-style dumps SystemInfo says amd64
/// while the thread context is a 716-byte x86 layout; the decoded result is
/// then `X86`, making the contradiction visible at a glance.
#derive(Debug, Eq)
pub(all) enum Context {
  X86(ContextX86)
  Amd64(ContextAmd64)
  Arm64(ContextArm64)
  Undecoded(ContextUndecoded)
}

///|
pub extend Context with Debug::{to_repr}

///|
pub extend Context with Eq::{equal, not_equal}

///|
fn Dump::read_context_x86(self : Dump, at : Rva) -> ContextX86 raise ParseError {
  let c : ContextX86 = {
    context_flags: self.read_uint32(at),
    dr0: self.read_uint32(at + 4UL),
    dr1: self.read_uint32(at + 8UL),
    dr2: self.read_uint32(at + 12UL),
    dr3: self.read_uint32(at + 16UL),
    dr6: self.read_uint32(at + 20UL),
    dr7: self.read_uint32(at + 24UL),
    seg_gs: self.read_uint32(at + 140UL),
    seg_fs: self.read_uint32(at + 144UL),
    seg_es: self.read_uint32(at + 148UL),
    seg_ds: self.read_uint32(at + 152UL),
    edi: self.read_uint32(at + 156UL),
    esi: self.read_uint32(at + 160UL),
    ebx: self.read_uint32(at + 164UL),
    edx: self.read_uint32(at + 168UL),
    ecx: self.read_uint32(at + 172UL),
    eax: self.read_uint32(at + 176UL),
    ebp: self.read_uint32(at + 180UL),
    eip: self.read_uint32(at + 184UL),
    seg_cs: self.read_uint32(at + 188UL),
    eflags: self.read_uint32(at + 192UL),
    esp: self.read_uint32(at + 196UL),
    seg_ss: self.read_uint32(at + 200UL),
  }
  c
}

///|
/// The offset table comes from `um\winnt.h:4304-4421`, checked item by item:
/// home registers 0..40 skipped, ContextFlags@48, MxCsr@52, six segment
/// registers 56..66, EFlags@68, Dr0..Dr7@72..112, Rax@120 onward ordered as
/// Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8..R15 up to 240, Rip@248.
fn Dump::read_context_amd64(
  self : Dump,
  at : Rva,
) -> ContextAmd64 raise ParseError {
  let c : ContextAmd64 = {
    context_flags: self.read_uint32(at + 48UL),
    mx_csr: self.read_uint32(at + 52UL),
    seg_cs: self.read_uint16(at + 56UL),
    seg_ds: self.read_uint16(at + 58UL),
    seg_es: self.read_uint16(at + 60UL),
    seg_fs: self.read_uint16(at + 62UL),
    seg_gs: self.read_uint16(at + 64UL),
    seg_ss: self.read_uint16(at + 66UL),
    eflags: self.read_uint32(at + 68UL),
    dr0: self.read_uint64(at + 72UL),
    dr1: self.read_uint64(at + 80UL),
    dr2: self.read_uint64(at + 88UL),
    dr3: self.read_uint64(at + 96UL),
    dr6: self.read_uint64(at + 104UL),
    dr7: self.read_uint64(at + 112UL),
    rax: self.read_uint64(at + 120UL),
    rcx: self.read_uint64(at + 128UL),
    rdx: self.read_uint64(at + 136UL),
    rbx: self.read_uint64(at + 144UL),
    rsp: self.read_uint64(at + 152UL),
    rbp: self.read_uint64(at + 160UL),
    rsi: self.read_uint64(at + 168UL),
    rdi: self.read_uint64(at + 176UL),
    r8: self.read_uint64(at + 184UL),
    r9: self.read_uint64(at + 192UL),
    r10: self.read_uint64(at + 200UL),
    r11: self.read_uint64(at + 208UL),
    r12: self.read_uint64(at + 216UL),
    r13: self.read_uint64(at + 224UL),
    r14: self.read_uint64(at + 232UL),
    r15: self.read_uint64(at + 240UL),
    rip: self.read_uint64(at + 248UL),
  }
  c
}

///|
/// Offsets likewise copied straight from the inline comments in
/// `um\winnt.h:6796`:
/// ContextFlags@0x0, Cpsr@0x4, X0@0x8 (stride 8, X28@0xe8), Fp@0xf0, Lr@0xf8,
/// Sp@0x100, Pc@0x108, V[32]@0x110 (skipped), Fpcr@0x310, Fpsr@0x314,
/// Bcr[8]@0x318, Bvr[8]@0x338, Wcr[2]@0x378, Wvr[2]@0x380.
fn Dump::read_context_arm64(
  self : Dump,
  at : Rva,
) -> ContextArm64 raise ParseError {
  let x : Array[UInt64] = []
  let mut i : UInt32 = 0U
  while i < 31U {
    x.push(self.read_uint64(at + 8UL + i.to_uint64() * 8UL))
    i = i + 1U
  }
  let bcr : Array[UInt32] = []
  let bvr : Array[UInt64] = []
  let mut j : UInt32 = 0U
  while j < 8U {
    bcr.push(self.read_uint32(at + 0x318UL + j.to_uint64() * 4UL))
    bvr.push(self.read_uint64(at + 0x338UL + j.to_uint64() * 8UL))
    j = j + 1U
  }
  let wcr : Array[UInt32] = []
  let wvr : Array[UInt64] = []
  let mut k : UInt32 = 0U
  while k < 2U {
    wcr.push(self.read_uint32(at + 0x378UL + k.to_uint64() * 4UL))
    wvr.push(self.read_uint64(at + 0x380UL + k.to_uint64() * 8UL))
    k = k + 1U
  }
  let c : ContextArm64 = {
    context_flags: self.read_uint32(at),
    cpsr: self.read_uint32(at + 4UL),
    x,
    sp: self.read_uint64(at + 0x100UL),
    pc: self.read_uint64(at + 0x108UL),
    fpcr: self.read_uint32(at + 0x310UL),
    fpsr: self.read_uint32(at + 0x314UL),
    bcr,
    bvr,
    wcr,
    wvr,
  }
  c
}

///|
/// Parse a CONTEXT.
///
/// Order of field-table selection (never guess; prefer reporting undecoded):
/// 1. `size == 0` or `rva == 0` → `None`: the generator wrote no context at all;
/// 2. no verified table for the architecture → `Undecoded`, reporting only the
///    architecture and declared length;
/// 3. the declared length **exactly equals** the canonical length of another
///    verified layout and not this architecture's → switch tables by length.
///    Length is an exact signature, harder evidence than SystemInfo's
///    architecture field: both WOW64's "amd64 system info + 716-byte context"
///    and the reverse are covered;
/// 4. the declared length fits this architecture's table → decode per the
///    architecture (extra bytes are not guessed at);
/// 5. nothing matches → `ContextSizeMismatch` (truncated, or an unverified
///    layout like old ARM64).
pub fn Dump::read_context(
  self : Dump,
  architecture : UInt16,
  context : LocationDescriptor,
) -> Context? raise ParseError {
  if context.size == 0U || context.rva == 0UL {
    None
  } else {
    let at = context.rva
    let declared = context.size
    match context_expected_size(architecture) {
      None => {
        let u : ContextUndecoded = {
          architecture,
          declared_size: declared,
          reason: "no verified CONTEXT field table for this architecture",
        }
        Some(Undecoded(u))
      }
      Some(want) =>
        if declared != want {
          match context_arch_by_size(declared) {
            Some(a) => Some(self.read_context_by(a, at, declared))
            None =>
              if declared > want {
                Some(self.read_context_by(architecture, at, declared))
              } else {
                raise ParseError::ContextSizeMismatch(
                  architecture, declared, want,
                )
              }
          }
        } else {
          Some(self.read_context_by(architecture, at, declared))
        }
    }
  }
}

///|
/// Actually fetch values using the selected field table. The declared length
/// must already have been checked to be sufficient. The final `_` branch is
/// unreachable in this code (callers only pass architectures that
/// `context_expected_size` recognizes); it stays so that "no table" has
/// exactly one expression.
fn Dump::read_context_by(
  self : Dump,
  architecture : UInt16,
  at : Rva,
  declared : UInt32,
) -> Context raise ParseError {
  match architecture.to_int() {
    0 | 10 => X86(self.read_context_x86(at))
    9 => Amd64(self.read_context_amd64(at))
    12 | 0x8003 => Arm64(self.read_context_arm64(at))
    _ => {
      let u : ContextUndecoded = {
        architecture,
        declared_size: declared,
        reason: "internal error: no field table for this architecture",
      }
      Undecoded(u)
    }
  }
}

///|
/// Name of the field table actually used.
pub fn Context::layout_name(self : Context) -> String {
  match self {
    X86(_) => "x86"
    Amd64(_) => "amd64"
    Arm64(_) => "arm64"
    Undecoded(_) => "undecoded"
  }
}

///|
/// The raw ContextFlags. `Undecoded` has no trustworthy field table, so
/// always 0 — preventing callers from mistaking "failed to decode" for
/// "no fields set".
pub fn Context::context_flags(self : Context) -> UInt32 {
  match self {
    X86(c) => c.context_flags
    Amd64(c) => c.context_flags
    Arm64(c) => c.context_flags
    Undecoded(_) => 0U
  }
}

///|
/// Which tier of ContextFlags bit table to split names with — follows the
/// **field table actually used**, not SystemInfo: with WOW64's amd64 system
/// info paired with a 716-byte x86 context, the bits in that 0x1003f carry
/// x86 semantics.
pub fn Context::flag_architecture(self : Context) -> UInt16 {
  match self {
    X86(_) => 0
    Amd64(_) => 9
    Arm64(_) => 12
    Undecoded(_) => 0xffff
  }
}

///|
pub fn hex_uint(value : UInt64) -> String {
  "0x" + value.to_string(radix=16)
}

///|
/// Flatten the decoded registers into (name, hex value) pairs; CLI and tests
/// share one ordering. Undecoded architectures return an empty array.
pub fn Context::registers(self : Context) -> Array[(String, String)] {
  match self {
    X86(c) => {
      let f = c.context_flags.to_uint64()
      [
        ("flags", hex_uint(f)),
        ("eip", hex_uint(c.eip.to_uint64())),
        ("esp", hex_uint(c.esp.to_uint64())),
        ("ebp", hex_uint(c.ebp.to_uint64())),
        ("eax", hex_uint(c.eax.to_uint64())),
        ("ebx", hex_uint(c.ebx.to_uint64())),
        ("ecx", hex_uint(c.ecx.to_uint64())),
        ("edx", hex_uint(c.edx.to_uint64())),
        ("esi", hex_uint(c.esi.to_uint64())),
        ("edi", hex_uint(c.edi.to_uint64())),
        ("eflags", hex_uint(c.eflags.to_uint64())),
        ("cs", hex_uint(c.seg_cs.to_uint64())),
        ("ss", hex_uint(c.seg_ss.to_uint64())),
        ("ds", hex_uint(c.seg_ds.to_uint64())),
        ("es", hex_uint(c.seg_es.to_uint64())),
        ("fs", hex_uint(c.seg_fs.to_uint64())),
        ("gs", hex_uint(c.seg_gs.to_uint64())),
        ("dr0", hex_uint(c.dr0.to_uint64())),
        ("dr1", hex_uint(c.dr1.to_uint64())),
        ("dr2", hex_uint(c.dr2.to_uint64())),
        ("dr3", hex_uint(c.dr3.to_uint64())),
        ("dr6", hex_uint(c.dr6.to_uint64())),
        ("dr7", hex_uint(c.dr7.to_uint64())),
      ]
    }
    Amd64(c) => {
      let head = [
        ("flags", hex_uint(c.context_flags.to_uint64())),
        ("rip", hex_uint(c.rip)),
        ("rsp", hex_uint(c.rsp)),
        ("rbp", hex_uint(c.rbp)),
        ("rax", hex_uint(c.rax)),
        ("rbx", hex_uint(c.rbx)),
        ("rcx", hex_uint(c.rcx)),
        ("rdx", hex_uint(c.rdx)),
        ("rsi", hex_uint(c.rsi)),
        ("rdi", hex_uint(c.rdi)),
      ]
      let tail = [
        ("r8", hex_uint(c.r8)),
        ("r9", hex_uint(c.r9)),
        ("r10", hex_uint(c.r10)),
        ("r11", hex_uint(c.r11)),
        ("r12", hex_uint(c.r12)),
        ("r13", hex_uint(c.r13)),
        ("r14", hex_uint(c.r14)),
        ("r15", hex_uint(c.r15)),
        ("eflags", hex_uint(c.eflags.to_uint64())),
        ("cs", hex_uint(c.seg_cs.to_uint().to_uint64())),
        ("ss", hex_uint(c.seg_ss.to_uint().to_uint64())),
        ("ds", hex_uint(c.seg_ds.to_uint().to_uint64())),
        ("es", hex_uint(c.seg_es.to_uint().to_uint64())),
        ("fs", hex_uint(c.seg_fs.to_uint().to_uint64())),
        ("gs", hex_uint(c.seg_gs.to_uint().to_uint64())),
        ("mxcsr", hex_uint(c.mx_csr.to_uint64())),
        ("dr0", hex_uint(c.dr0)),
        ("dr1", hex_uint(c.dr1)),
        ("dr2", hex_uint(c.dr2)),
        ("dr3", hex_uint(c.dr3)),
        ("dr6", hex_uint(c.dr6)),
        ("dr7", hex_uint(c.dr7)),
      ]
      head + tail
    }
    Arm64(c) => {
      let regs : Array[(String, String)] = [
        ("flags", hex_uint(c.context_flags.to_uint64())),
        ("pc", hex_uint(c.pc)),
        ("sp", hex_uint(c.sp)),
        ("fp", hex_uint(c.x[29])),
        ("lr", hex_uint(c.x[30])),
        ("cpsr", hex_uint(c.cpsr.to_uint64())),
      ]
      let out = regs
      let n = c.x.length()
      let mut i = 0
      while i < n && i < 29 {
        out.push(("x" + i.to_string(), hex_uint(c.x[i])))
        i = i + 1
      }
      out
    }
    Undecoded(_) => []
  }
}

///|
/// Instruction pointer / stack pointer / frame pointer — the three stack
/// walking (W4) needs.
pub fn Context::instruction_pointer(self : Context) -> UInt64? {
  match self {
    X86(c) => Some(c.eip.to_uint64())
    Amd64(c) => Some(c.rip)
    Arm64(c) => Some(c.pc)
    Undecoded(_) => None
  }
}

///|
pub fn Context::stack_pointer(self : Context) -> UInt64? {
  match self {
    X86(c) => Some(c.esp.to_uint64())
    Amd64(c) => Some(c.rsp)
    Arm64(c) => Some(c.sp)
    Undecoded(_) => None
  }
}

///|
pub fn Context::frame_pointer(self : Context) -> UInt64? {
  match self {
    X86(c) => Some(c.ebp.to_uint64())
    Amd64(c) => Some(c.rbp)
    // arm64's frame pointer is X29, already in the x array
    Arm64(c) => Some(c.x[29])
    Undecoded(_) => None
  }
}

///|
/// One-line summary for test corpus and CLI overview: `amd64/0x10001f rip=0x.. rsp=0x..`.
pub fn context_summary(ctx : Context) -> String {
  let head = match ctx {
    Undecoded(u) =>
      "undecoded arch=0x" +
      u.architecture.to_string(radix=16) +
      " size=" +
      u.declared_size.to_string()
    _ => ctx.layout_name()
  }
  let parts : Array[String] = []
  for (name, value) in ctx.registers() {
    parts.push(name + "=" + value)
  }
  if parts.is_empty() {
    head
  } else {
    head + " " + parts.join(" ")
  }
}

///|
/// The low bits of a CONTEXT's `ContextFlags`: which fields the writer
/// actually filled. Numbers come from `um\winnt.h` (x86: lines 8440-8454;
/// amd64: the comment block at 4273-4290). arm64's bit semantics have not
/// been independently verified, so it just gets raw hex.
pub fn context_flag_bits(architecture : UInt16) -> Array[(UInt32, String)] {
  match architecture.to_int() {
    0 | 10 =>
      [
        (0x1U, "CONTROL"),
        (0x2U, "INTEGER"),
        (0x4U, "SEGMENTS"),
        (0x8U, "FLOATING_POINT"),
        (0x10U, "DEBUG_REGISTERS"),
        (0x20U, "EXTENDED_REGISTERS"),
        (0x40U, "XSTATE"),
      ]
    9 =>
      [
        (0x1U, "CONTROL"),
        (0x2U, "INTEGER"),
        (0x4U, "SEGMENTS"),
        (0x8U, "FLOATING_POINT"),
        (0x10U, "DEBUG_REGISTERS"),
        (0x40U, "XSTATE"),
        (0x80U, "KERNEL_CET"),
      ]
    _ => []
  }
}

///|
/// Split ContextFlags: the architecture base bit (x86=0x10000, amd64=0x100000)
/// is confirmed separately; the rest are split by bit name, with leftovers
/// going into Unknown(0x..).
pub fn describe_context_flags(
  architecture : UInt16,
  flags : UInt32,
) -> Array[String] {
  let base = match architecture.to_int() {
    0 | 10 => 0x10000U
    9 => 0x100000U
    12 => 0x400000U
    _ => 0U
  }
  let names : Array[String] = []
  let mut rest = flags
  if base != 0U && (rest & base) == base {
    rest = rest ^ base
    names.push("ARCH_BASE(0x" + base.to_string(radix=16) + ")")
  } else if base != 0U {
    names.push("MissingArchBase(0x" + base.to_string(radix=16) + ")")
  }
  for (bit, name) in context_flag_bits(architecture) {
    if (rest & bit) != 0U {
      rest = rest ^ bit
      names.push(name)
    }
  }
  if rest != 0U {
    names.push("Unknown(0x" + rest.to_string(radix=16) + ")")
  }
  names
}

///|
/// The body length of MINIDUMP_EXCEPTION (same as EXCEPTION_RECORD64):
/// ExceptionCode4 + ExceptionFlags4 + ExceptionRecord8 + ExceptionAddress8
/// + NumberParameters4 + __unusedAlignment4 + ExceptionInformation[15]*8 = **152**.
/// The parameter cap of 15 comes from EXCEPTION_MAXIMUM_PARAMETERS at
/// `um\winnt.h:10080`.
pub let exception_record_size : UInt32 = 152U

///|
/// MINIDUMP_EXCEPTION_STREAM = ThreadId4 + __alignment4 + ExceptionRecord(152)
/// + ThreadContext(8) = **168**.
/// All 4 dumps in the corpus that carry an exception stream have DataSize 168,
/// matching the header-derived value.
pub let exception_stream_size : UInt32 = 168U

///|
pub let exception_maximum_parameters : UInt32 = 15U

///|
/// One unhandled/dump-triggering exception record.
#derive(Debug, Eq)
pub(all) struct Exception {
  thread_id : UInt32
  code : UInt32
  flags : UInt32
  /// ExceptionRecord: the address, in the **target process's virtual address
  /// space**, of the previous nested exception.
  /// It is not an RVA and dumps generally do not carry that memory, so only
  /// the number is reported; the chain is not followed.
  nested_record_address : UInt64
  /// The instruction address (virtual) that triggered the exception.
  address : UInt64
  /// The parameter count the generator declared, which can exceed 15 when
  /// malformed; `parameters` takes at most 15.
  number_parameters : UInt32
  parameters : Array[UInt64]
  /// The CONTEXT at the moment of the exception. Note it is **not the same
  /// RVA** as that thread's context in the thread table (in full-dump.dmp the
  /// exception stream has 1232@4530 while the thread table has 1232@5762);
  /// the crash site must read this one.
  thread_context : LocationDescriptor
}

///|
pub extend Exception with Debug::{to_repr}

///|
pub extend Exception with Eq::{equal, not_equal}

///|
/// Parse ExceptionStream. Fewer than 168 bytes is an immediate error: the
/// exception stream has exactly one layout, there is no "shorter legal
/// version" of it.
pub fn Dump::read_exception(
  self : Dump,
  entry : StreamEntry,
) -> Exception raise ParseError {
  let have = entry.data_size.to_uint64()
  if have < exception_stream_size.to_uint64() {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      exception_stream_size.to_uint64(),
      have,
    )
  }
  let at = entry.rva
  let declared = self.read_uint32(at + 32UL)
  let n = if declared > exception_maximum_parameters {
    exception_maximum_parameters
  } else {
    declared
  }
  let parameters : Array[UInt64] = []
  let mut i : UInt32 = 0U
  while i < n {
    parameters.push(self.read_uint64(at + 40UL + i.to_uint64() * 8UL))
    i = i + 1U
  }
  let e : Exception = {
    thread_id: self.read_uint32(at),
    code: self.read_uint32(at + 8UL),
    flags: self.read_uint32(at + 12UL),
    nested_record_address: self.read_uint64(at + 16UL),
    address: self.read_uint64(at + 24UL),
    number_parameters: declared,
    parameters,
    thread_context: self.read_location(at + 160UL),
  }
  e
}

///|
/// Fetch the ExceptionStream (the crash site) via the directory; returns None if absent.
pub fn Dump::exception(
  self : Dump,
  entries : Array[StreamEntry],
) -> Exception? raise ParseError {
  match get_stream(entries, exception_stream) {
    None => None
    Some(entry) => Some(self.read_exception(entry))
  }
}

///|
/// Windows exception code table. Every entry in the left column was verified
/// against the local SDK: `um\minwinbase.h:401-424` gives the EXCEPTION_* →
/// STATUS_* aliasing, and `shared\ntstatus.h` gives the values (orderings like
/// 0xC000008D being DENORMAL and 0x8E being DIVIDE_BY_ZERO can only be looked
/// up, not memorized).
/// The three entries beyond the EXCEPTION_* ones have no minwinbase.h alias
/// but are codes genuinely readable in minidumps; their values likewise come
/// from ntstatus.h.
pub let exception_code_names : Array[(UInt32, String)] = [
  (0x8000_0001U, "EXCEPTION_GUARD_PAGE"),
  (0x8000_0002U, "EXCEPTION_DATATYPE_MISALIGNMENT"),
  (0x8000_0003U, "EXCEPTION_BREAKPOINT"),
  (0x8000_0004U, "EXCEPTION_SINGLE_STEP"),
  (0xC000_0005U, "EXCEPTION_ACCESS_VIOLATION"),
  (0xC000_0006U, "EXCEPTION_IN_PAGE_ERROR"),
  (0xC000_0008U, "EXCEPTION_INVALID_HANDLE"),
  (0xC000_001DU, "EXCEPTION_ILLEGAL_INSTRUCTION"),
  (0xC000_0025U, "EXCEPTION_NONCONTINUABLE_EXCEPTION"),
  (0xC000_0026U, "EXCEPTION_INVALID_DISPOSITION"),
  (0xC000_008CU, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"),
  (0xC000_008DU, "EXCEPTION_FLT_DENORMAL_OPERAND"),
  (0xC000_008EU, "EXCEPTION_FLT_DIVIDE_BY_ZERO"),
  (0xC000_008FU, "EXCEPTION_FLT_INEXACT_RESULT"),
  (0xC000_0090U, "EXCEPTION_FLT_INVALID_OPERATION"),
  (0xC000_0091U, "EXCEPTION_FLT_OVERFLOW"),
  (0xC000_0092U, "EXCEPTION_FLT_STACK_CHECK"),
  (0xC000_0093U, "EXCEPTION_FLT_UNDERFLOW"),
  (0xC000_0094U, "EXCEPTION_INT_DIVIDE_BY_ZERO"),
  (0xC000_0095U, "EXCEPTION_INT_OVERFLOW"),
  (0xC000_0096U, "EXCEPTION_PRIV_INSTRUCTION"),
  (0xC000_00FDU, "EXCEPTION_STACK_OVERFLOW"),
  (0xC000_013AU, "STATUS_CONTROL_C_EXIT"),
  (0xC000_0194U, "EXCEPTION_POSSIBLE_DEADLOCK"),
  (0xC000_0374U, "STATUS_HEAP_CORRUPTION"),
  (0xC000_0409U, "STATUS_STACK_BUFFER_OVERRUN"),
  (0xC000_0420U, "STATUS_ASSERTION_FAILURE"),
]

///|
/// Exception code name; falls back to raw hex when not found.
pub fn exception_code_name(code : UInt32) -> String {
  let mut found : String? = None
  for (c, name) in exception_code_names {
    if c == code && found is None {
      found = Some(name)
    }
  }
  match found {
    Some(n) => n
    None => "Unknown(0x" + code.to_string(radix=16) + ")"
  }
}

///|
/// Linux-family signal numbers. breakpad/crashpad write the signal number
/// into ExceptionCode on non-Windows platforms; the 0xb in linux-mini.dmp is
/// the corpus proof (SIGSEGV). The remaining numbers are common POSIX values
/// not covered by this repo's corpus; defer to the Linux headers when
/// cross-checking.
pub let linux_signal_names : Array[(UInt32, String)] = [
  (1U, "SIGHUP"),
  (2U, "SIGINT"),
  (3U, "SIGQUIT"),
  (4U, "SIGILL"),
  (5U, "SIGTRAP"),
  (6U, "SIGABRT"),
  (7U, "SIGBUS"),
  (8U, "SIGFPE"),
  (9U, "SIGKILL"),
  (10U, "SIGUSR1"),
  (11U, "SIGSEGV"),
  (12U, "SIGUSR2"),
  (13U, "SIGPIPE"),
  (14U, "SIGALRM"),
  (15U, "SIGTERM"),
  (31U, "SIGSYS"),
]

///|
/// Should this platform's ExceptionCode be read as a signal number?
/// macOS (0x8101) and iOS (0x8102) write Mach exception style, not covered here.
pub fn platform_uses_signals(platform_id : UInt32) -> Bool {
  match platform_id {
    0x8000U | 0x8201U | 0x8203U | 0x8204U | 0x8205U | 0x8206U => true
    _ => false
  }
}

///|
/// Signal name; returns None for numbers not in the table.
pub fn signal_name(code : UInt32) -> String? {
  let mut found : String? = None
  for (c, name) in linux_signal_names {
    if c == code && found is None {
      found = Some(name)
    }
  }
  found
}

///|
/// Exception code label: Windows looks up the EXCEPTION_* table, Linux-family
/// tries the signal table first; on a miss fall back to the Windows table's
/// Unknown form (the number always stays visible).
pub fn exception_code_label(platform_id : UInt32, code : UInt32) -> String {
  if platform_uses_signals(platform_id) {
    match signal_name(code) {
      Some(n) => n
      None => "Signal(0x" + code.to_string(radix=16) + ")"
    }
  } else {
    exception_code_name(code)
  }
}

///|
/// EXCEPTION_RECORD's Flags: currently only "noncontinuable" is a public bit
/// (value 1, see minwinbase.h's EXCEPTION_NONCONTINUABLE_EXCEPTION). The MS
/// docs only say the remaining bits are reserved, so they are left as-is.
pub fn describe_exception_flags(flags : UInt32) -> Array[String] {
  let names : Array[String] = []
  let mut rest = flags
  if (rest & 0x1U) != 0U {
    rest = rest ^ 0x1U
    names.push("NONCONTINUABLE")
  }
  if rest != 0U {
    names.push("Reserved(0x" + rest.to_string(radix=16) + ")")
  }
  names
}

///|
/// The two exception codes carrying the "ExceptionInformation[0]=access type,
/// [1]=accessed address" convention.
fn is_memory_access_code(code : UInt32) -> Bool {
  code == 0xC000_0005U || code == 0xC000_0006U
}

///|
pub fn Exception::is_memory_access(self : Exception) -> Bool {
  is_memory_access_code(self.code)
}

///|
/// ACCESS_VIOLATION / IN_PAGE_ERROR's `ExceptionInformation[0]`:
/// 0=read, 1=write, 8=hit user-mode DEP (executed a non-executable page).
/// Source: MS Learn's EXCEPTION_RECORD struct documentation on
/// ExceptionInformation. Other codes have no such convention; returns None.
pub fn memory_access_kind(code : UInt32, parameters : Array[UInt64]) -> String? {
  if !is_memory_access_code(code) || parameters.is_empty() {
    None
  } else {
    match parameters[0] {
      0UL => Some("read")
      1UL => Some("write")
      8UL => Some("dep-execute")
      v => Some("Unknown(0x" + v.to_string(radix=16) + ")")
    }
  }
}

///|
/// The "accessed address" beyond the faulting instruction: likewise only
/// meaningful for ACCESS_VIOLATION / IN_PAGE_ERROR (ExceptionInformation[1]).
pub fn Exception::fault_address(self : Exception) -> UInt64? {
  if self.is_memory_access() && self.parameters.length() >= 2 {
    Some(self.parameters[1])
  } else {
    None
  }
}

///|
/// IN_PAGE_ERROR's `ExceptionInformation[2]`: the real NTSTATUS behind the failed page read.
pub fn Exception::underlying_status(self : Exception) -> UInt64? {
  if self.code == 0xC000_0006U && self.parameters.length() >= 3 {
    Some(self.parameters[2])
  } else {
    None
  }
}

///|
/// The offset within the module when the address falls inside it.
pub fn Module::offset_of(self : Module, address : UInt64) -> UInt64? {
  if self.contains(address) {
    Some(address - self.base_of_image)
  } else {
    None
  }
}

///|
/// Find a module by virtual address. On multiple hits (malformed dumps with
/// overlapping module ranges), take the **first** — matching rust-minidump's
/// module list behavior.
pub fn find_module(
  modules : Array[Module],
  address : UInt64,
) -> (Int32, Module)? {
  let n = modules.length()
  let mut i = 0
  let mut found : (Int32, Module)? = None
  while i < n && found is None {
    if modules[i].contains(address) {
      found = Some((i, modules[i]))
    }
    i = i + 1
  }
  found
}

///|
/// Crash address attribution: on a hit, "module name+offset"; otherwise state
/// explicitly that it is in no module (dumps with a zero address or addresses
/// outside all modules are common, and worth distinguishing).
pub fn address_module_line(modules : Array[Module], address : UInt64) -> String {
  if address == 0UL {
    "address is 0"
  } else {
    match find_module(modules, address) {
      None => "not inside any module"
      Some((index, m)) => {
        let tail = match m.offset_of(address) {
          None => ""
          Some(o) => "+0x" + o.to_string(radix=16)
        }
        let name = if m.name == "" {
          "module#" + index.to_string()
        } else {
          m.name
        }
        name + tail
      }
    }
  }
}

///|
/// One memory region.
///
/// Three lengths that must not be conflated:
/// - `declared_size`: the raw length written in the stream.
/// - `size`: the length **actually readable** after clipping to the end of the
///   file. In real dumps the last Memory64List segment often sits exactly on
///   the file end, and some writers overstate the length by tens of bytes;
///   storing both makes the malformation visible instead of turning into an
///   out-of-bounds read.
/// - `file_rva`: where this memory lives **in the file**. MemoryList(5) gives
///   it directly; Memory64List(9) does not — it accumulates as `BaseRva + the
///   sum of all preceding segments' declared lengths`, per the SDK comment
///   verbatim ("the RVA is the base RVA plus the sum of the preceeding
///   data blocks", `um\minidumpapiset.h:66`).
#derive(Debug, Eq)
pub(all) struct MemoryRegion {
  start_address : UInt64
  declared_size : UInt64
  size : UInt64
  file_rva : UInt64
}

///|
pub extend MemoryRegion with Debug::{to_repr}

///|
pub extend MemoryRegion with Eq::{equal, not_equal}

///|
/// Right boundary (exclusive).
pub fn MemoryRegion::end_address(self : MemoryRegion) -> UInt64 {
  self.start_address + self.size
}

///|
/// Whether the address falls within the readable range.
pub fn MemoryRegion::contains(self : MemoryRegion, address : UInt64) -> Bool {
  address >= self.start_address && address < self.end_address()
}

///|
/// Whether `[address, address+len)` lies **entirely** within this memory.
/// Reading an 8-byte pointer requires full coverage; otherwise the value is
/// stitched together, which is more dangerous than not reading at all.
pub fn MemoryRegion::covers(
  self : MemoryRegion,
  address : UInt64,
  len : UInt64,
) -> Bool {
  address >= self.start_address &&
  len <= self.size &&
  address - self.start_address <= self.size - len
}

///|
/// Was clipped (declared length differs from readable length).
pub fn MemoryRegion::was_clipped(self : MemoryRegion) -> Bool {
  self.declared_size != self.size
}

///|
/// In-region address -> file RVA. The caller guarantees the address is in the region.
fn MemoryRegion::file_offset(self : MemoryRegion, address : UInt64) -> UInt64 {
  self.file_rva + (address - self.start_address)
}

///|
/// Width of MINIDUMP_MEMORY_DESCRIPTOR: StartOfMemoryRange(8) +
/// MINIDUMP_LOCATION_DESCRIPTOR(DataSize4 + Rva4) = **16**.
pub let memory_descriptor_size : UInt32 = 16U

///|
/// The MINIDUMP_MEMORY_LIST header is a single ULONG32 NumberOfMemoryRanges.
pub let memory_list_header_size : UInt32 = 4U

///|
/// MINIDUMP_MEMORY64_LIST header: NumberOfMemoryRanges(8) + BaseRva(8) = **16**;
/// entries are MINIDUMP_MEMORY_DESCRIPTOR64 = StartOfMemoryRange(8) + DataSize(8).
pub let memory_64_header_size : UInt32 = 16U

///|
/// Length validation for variable-length list streams: **trailing slack is
/// allowed**, but the entries themselves must fit. Unlike ModuleList/
/// ThreadList's "exact or 4 extra bytes", memory streams routinely run to
/// thousands of entries and writers appending alignment tails after the count
/// is common; this only blocks "the declared entry count exceeds what the
/// stream can actually hold".
fn check_list_room(
  stream_type : UInt32,
  have : UInt32,
  need : UInt64,
) -> Unit raise ParseError {
  if have.to_uint64() < need {
    raise ParseError::ListSizeMismatch(stream_type, need, have.to_uint64())
  }
}

///|
/// The UInt64 maximum, used by the two saturating operations below.
let uint64_max : UInt64 = 0xffff_ffff_ffff_ffffUL

///|
/// Saturating UInt64 addition. This toolchain version lacks `saturating_add`,
/// and overflow here is not optional: Memory64List's entry count is 64-bit and
/// a malformed one can be large enough that `count * 16` wraps to a small
/// value, making the length check "pass" before the while loop runs into the
/// end of the file. Saturating at the maximum guarantees the check fails, and
/// the error shows the number was bogus.
fn add_saturating(a : UInt64, b : UInt64) -> UInt64 {
  if b > uint64_max - a {
    uint64_max
  } else {
    a + b
  }
}

///|
fn mul_saturating(a : UInt64, b : UInt64) -> UInt64 {
  if a != 0UL && b > uint64_max / a {
    uint64_max
  } else {
    a * b
  }
}

///|
/// Bytes needed by a list stream: `header + count * width`, overflow-safe.
fn list_need(count : UInt64, width : UInt32, header : UInt32) -> UInt64 {
  add_saturating(header.to_uint64(), mul_saturating(count, width.to_uint64()))
}

///|
/// MINIDUMP_MEMORY_LIST (stream 5): each entry independently carries
/// {start address, length, RVA}, so segments may be unordered and overlapping.
///
/// Corpus: test.dmp 3 segments / linux-mini.dmp 2 / simple-crashpad.dmp 1 /
/// invalid-parameter.dmp 10, all with DataSize exactly 4 + 16*count.
pub fn Dump::read_memory_list(
  self : Dump,
  entry : StreamEntry,
) -> Array[MemoryRegion] raise ParseError {
  let count = self.read_uint32(entry.rva).to_uint64()
  if count == 0UL {
    return []
  }
  let need = list_need(count, memory_descriptor_size, memory_list_header_size)
  check_list_room(entry.stream_type, entry.data_size, need)
  if !self.range_in_file(entry.rva, need) {
    raise ParseError::Truncated(entry.rva, need, self.data.length().to_uint64())
  }
  let regions : Array[MemoryRegion] = []
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva +
      memory_list_header_size.to_uint64() +
      i * memory_descriptor_size.to_uint64()
    let declared = self.read_uint32(base + 8UL).to_uint64()
    let r : MemoryRegion = {
      start_address: self.read_uint64(base),
      declared_size: declared,
      // copy the declared value for now; clipping is done uniformly in
      // memory_map, shared by both streams
      size: declared,
      file_rva: self.read_uint32(base + 12UL).to_uint64(),
    }
    regions.push(r)
    i = i + 1UL
  }
  regions
}

///|
/// MINIDUMP_MEMORY64_LIST (stream 9): memory is laid out **contiguously after
/// BaseRva**; each entry gives only {start address, length}, with the position
/// computed by accumulation.
///
/// Corpus cross-check: full-dump.dmp is MiniDumpWithFullMemory with 54
/// segments and BaseRva=11902; accumulating to the end lands exactly on
/// 8408702, equal to the file length, byte for byte.
pub fn Dump::read_memory_64_list(
  self : Dump,
  entry : StreamEntry,
) -> Array[MemoryRegion] raise ParseError {
  let count = self.read_uint64(entry.rva)
  let base_rva = self.read_uint64(entry.rva + 8UL)
  if count == 0UL {
    return []
  }
  // the entry count is 64-bit and can be malformed into the hundreds of
  // trillions; compute the needed byte count (overflow-safe) first to block
  // it before the while loop runs into the end of the file.
  let need = list_need(count, memory_descriptor_size, memory_64_header_size)
  check_list_room(entry.stream_type, entry.data_size, need)
  if !self.range_in_file(entry.rva, need) {
    raise ParseError::Truncated(entry.rva, need, self.data.length().to_uint64())
  }
  let regions : Array[MemoryRegion] = []
  let mut i : UInt64 = 0UL
  let mut cur = base_rva
  while i < count {
    let at = entry.rva +
      memory_64_header_size.to_uint64() +
      i * memory_descriptor_size.to_uint64()
    let size = self.read_uint64(at + 8UL)
    let r : MemoryRegion = {
      start_address: self.read_uint64(at),
      declared_size: size,
      size,
      file_rva: cur,
    }
    regions.push(r)
    cur = add_saturating(cur, size)
    i = i + 1UL
  }
  regions
}

///|
/// The **raw** declared table merged from both memory streams (unsorted,
/// unclipped). Use it to faithfully answer "what memory does this dump
/// declare"; to read memory, go through `Dump::memory_map`.
pub fn Dump::memory_regions(
  self : Dump,
  entries : Array[StreamEntry],
) -> Array[MemoryRegion]? raise ParseError {
  let out : Array[MemoryRegion] = []
  let mut found = false
  match get_stream(entries, memory_list_stream) {
    None => ()
    Some(entry) => {
      out.append(self.read_memory_list(entry))
      found = true
    }
  }
  match get_stream(entries, memory_64_list_stream) {
    None => ()
    Some(entry) => {
      out.append(self.read_memory_64_list(entry))
      found = true
    }
  }
  if found {
    Some(out)
  } else {
    None
  }
}

///|
/// Merge two halves by ascending start_address (stable: on ties take the left first).
fn merge_regions(
  left : Array[MemoryRegion],
  right : Array[MemoryRegion],
) -> Array[MemoryRegion] {
  let out : Array[MemoryRegion] = []
  let mut i = 0
  let mut j = 0
  while i < left.length() && j < right.length() {
    if right[j].start_address < left[i].start_address {
      out.push(right[j])
      j = j + 1
    } else {
      out.push(left[i])
      i = i + 1
    }
  }
  while i < left.length() {
    out.push(left[i])
    i = i + 1
  }
  while j < right.length() {
    out.push(right[j])
    j = j + 1
  }
  out
}

///|
/// Merge sort. Hand-rolled instead of pulling in `@compare`: the format layer
/// stays dependency-free, and there is exactly one sort key (start address) —
/// not worth introducing a trait. Recursion depth is log2(segment count); even
/// thousands of segments means a dozen-odd splits.
fn sort_regions(regions : Array[MemoryRegion]) -> Array[MemoryRegion] {
  let n = regions.length()
  if n <= 1 {
    regions
  } else {
    let mid = n / 2
    let left : Array[MemoryRegion] = []
    let mut i = 0
    while i < mid {
      left.push(regions[i])
      i = i + 1
    }
    let right : Array[MemoryRegion] = []
    while i < n {
      right.push(regions[i])
      i = i + 1
    }
    merge_regions(sort_regions(left), sort_regions(right))
  }
}

///|
/// Clip declared lengths down to what actually remains in the file. Regions
/// entirely outside the file or with a declared length of 0 are dropped
/// outright, yielding only a dropped count — "memory longer than the file" is
/// the most common form of a malformed dump, and this number must stay visible.
fn clip_regions(
  regions : Array[MemoryRegion],
  file_size : UInt64,
) -> (Array[MemoryRegion], UInt32) {
  let out : Array[MemoryRegion] = []
  let mut dropped : UInt32 = 0U
  for r in regions {
    if r.declared_size == 0UL || r.file_rva >= file_size {
      dropped = dropped + 1U
    } else {
      let room = file_size - r.file_rva
      let size = if r.declared_size <= room { r.declared_size } else { room }
      let c : MemoryRegion = {
        start_address: r.start_address,
        declared_size: r.declared_size,
        size,
        file_rva: r.file_rva,
      }
      out.push(c)
    }
  }
  (out, dropped)
}

///|
/// The "read memory by virtual address" view: both memory streams merged,
/// sorted, and clipped to the file end. Stack walking, memory search, and
/// crash-site forensics all read from here.
#derive(Debug, Eq)
pub(all) struct MemoryMap {
  /// Ascending by `start_address`; ties keep the streams' original order
  /// (stable sort).
  regions : Array[MemoryRegion]
  /// Count of declared but unusable segments (zero length or entirely outside
  /// the file).
  dropped : UInt32
}

///|
pub extend MemoryMap with Debug::{to_repr}

///|
pub extend MemoryMap with Eq::{equal, not_equal}

///|
/// Build the index: merge -> sort -> clip. Returns None when the directory
/// has neither memory stream.
pub fn Dump::memory_map(
  self : Dump,
  entries : Array[StreamEntry],
) -> MemoryMap? raise ParseError {
  match self.memory_regions(entries) {
    None => None
    Some(raw) => {
      let (clipped, dropped) = clip_regions(
        sort_regions(raw),
        self.data.length().to_uint64(),
      )
      let m : MemoryMap = { regions: clipped, dropped, }
      Some(m)
    }
  }
}

///|
/// Find the memory segment fully covering `[address, address+len)`.
///
/// Binary-search for "the last start_address <= address", then walk backward;
/// the backward walk carries a `max_end` pruning: if all earlier segments'
/// right boundaries are <= address, nothing further can match, so stop.
/// Normal dumps have non-overlapping ranges and hit on the first check; on
/// overlap take the segment with the **largest start address** (the most
/// specific one).
pub fn MemoryMap::region_for(
  self : MemoryMap,
  address : UInt64,
  len : UInt64,
) -> MemoryRegion? {
  let n = self.regions.length()
  if n == 0 {
    return None
  }
  let mut lo = 0
  let mut hi = n
  while lo < hi {
    let mid = (lo + hi) / 2
    if self.regions[mid].start_address <= address {
      lo = mid + 1
    } else {
      hi = mid
    }
  }
  let mut i = lo - 1
  let mut max_end = 0UL
  let mut found : MemoryRegion? = None
  while i >= 0 && found is None {
    let r = self.regions[i]
    if r.covers(address, len) {
      found = Some(r)
    }
    if r.end_address() > max_end {
      max_end = r.end_address()
    }
    if max_end <= address {
      i = -1
    } else {
      i = i - 1
    }
  }
  found
}

///|
/// Only asks "is this address itself present in the dump".
pub fn MemoryMap::region_at(
  self : MemoryMap,
  address : UInt64,
) -> MemoryRegion? {
  self.region_for(address, 1UL)
}

///|
/// Address -> file RVA. With it, the existing `read_uint32`/`read_uint64` can be used directly.
pub fn MemoryMap::file_rva_for(
  self : MemoryMap,
  address : UInt64,
  len : UInt64,
) -> UInt64? {
  match self.region_for(address, len) {
    None => None
    Some(r) => Some(r.file_offset(address))
  }
}

///|
/// Whether an address range is readable (fully covered and genuinely inside the file).
pub fn MemoryMap::readable(
  self : MemoryMap,
  address : UInt64,
  len : UInt64,
) -> Bool {
  match self.file_rva_for(address, len) {
    Some(_) => true
    None => false
  }
}

///|
pub fn MemoryMap::region_count(self : MemoryMap) -> Int32 {
  self.regions.length()
}

///|
/// Total readable bytes (by clipped lengths).
pub fn MemoryMap::total_bytes(self : MemoryMap) -> UInt64 {
  let mut total = 0UL
  for r in self.regions {
    total = total + r.size
  }
  total
}

///|
/// Number of clipped segments: those whose declared length differs from their readable length.
pub fn MemoryMap::clipped_count(self : MemoryMap) -> UInt32 {
  let mut n : UInt32 = 0U
  for r in self.regions {
    if r.was_clipped() {
      n = n + 1U
    }
  }
  n
}

///|
/// Read a stretch of memory by virtual address. Returns **None rather than
/// erroring** when the address is not covered: walking off the stack is normal
/// during stack traversal, and callers must distinguish "no memory here" from
/// "the file is broken". Reads byte-by-byte, suitable for sampling tens of
/// bytes; for a large whole-segment buffer, slice it yourself via
/// `file_rva_for`.
pub fn Dump::read_memory_at(
  self : Dump,
  map : MemoryMap,
  address : UInt64,
  len : Int32,
) -> Bytes? raise ParseError {
  match map.file_rva_for(address, len.to_uint64()) {
    None => None
    Some(rva) => {
      let buf = Buffer()
      let mut i = 0
      while i < len {
        buf.write_byte(self.read_byte(rva + i.to_uint64()))
        i = i + 1
      }
      Some(buf.to_bytes())
    }
  }
}

///|
/// Read one pointer width by virtual address. None when the address is
/// uncovered or fewer than 8 bytes remain in the segment.
pub fn Dump::read_uint64_at(
  self : Dump,
  map : MemoryMap,
  address : UInt64,
) -> UInt64? raise ParseError {
  match map.file_rva_for(address, 8UL) {
    None => None
    Some(rva) => Some(self.read_uint64(rva))
  }
}

///|
pub fn Dump::read_uint32_at(
  self : Dump,
  map : MemoryMap,
  address : UInt64,
) -> UInt32? raise ParseError {
  match map.file_rva_for(address, 4UL) {
    None => None
    Some(rva) => Some(self.read_uint32(rva))
  }
}

///|
/// MINIDUMP_MEMORY_INFO: describes the virtual-address **layout**, not content
/// (which addresses are committed, their protection attributes, image vs
/// private memory), from `um\minidumpapiset.h:690`.
/// 48 bytes: BaseAddress8 + AllocationBase8 + AllocationProtect4 + padding4
/// + RegionSize8 + State4 + Protect4 + Type4 + padding4.
#derive(Debug, Eq)
pub(all) struct MemoryInfo {
  base_address : UInt64
  allocation_base : UInt64
  allocation_protect : UInt32
  region_size : UInt64
  state : UInt32
  protect : UInt32
  type_ : UInt32
}

///|
pub extend MemoryInfo with Debug::{to_repr}

///|
pub extend MemoryInfo with Eq::{equal, not_equal}

///|
/// Record length of MINIDUMP_MEMORY_INFO.
pub let memory_info_size : UInt32 = 48U

///|
/// MINIDUMP_MEMORY_INFO_LIST header: SizeOfHeader4 + SizeOfEntry4 +
/// NumberOfEntries(8) = **16** (`um\minidumpapiset.h:708`; the header has no
/// fields beyond the count).
pub let memory_info_list_header_size : UInt32 = 16U

///|
pub fn MemoryInfo::end_address(self : MemoryInfo) -> UInt64 {
  self.base_address + self.region_size
}

///|
/// Parse MemoryInfoListStream. The stride is the **SizeOfEntry declared in
/// the file**, not a hardcoded 48: future _EX variants can only grow, and
/// walking by the declared stride keeps the first 48 bytes readable.
pub fn Dump::read_memory_info_list(
  self : Dump,
  entry : StreamEntry,
) -> Array[MemoryInfo] raise ParseError {
  let declared_header = self.read_uint32(entry.rva)
  let width = self.read_uint32(entry.rva + 4UL)
  let count = self.read_uint64(entry.rva + 8UL)
  // a declared header smaller than 16 cannot yield a trustworthy stride; fall
  // back to the SDK's 16. A stride below 48 cannot even hold one
  // MINIDUMP_MEMORY_INFO, so reject outright.
  let header = if declared_header < memory_info_list_header_size {
    memory_info_list_header_size
  } else {
    declared_header
  }
  if width < memory_info_size {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      memory_info_size.to_uint64(),
      width.to_uint64(),
    )
  }
  if count == 0UL {
    return []
  }
  let need = list_need(count, width, header)
  check_list_room(entry.stream_type, entry.data_size, need)
  if !self.range_in_file(entry.rva, need) {
    raise ParseError::Truncated(entry.rva, need, self.data.length().to_uint64())
  }
  let items : Array[MemoryInfo] = []
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva + header.to_uint64() + i * width.to_uint64()
    let m : MemoryInfo = {
      base_address: self.read_uint64(base),
      allocation_base: self.read_uint64(base + 8UL),
      allocation_protect: self.read_uint32(base + 16UL),
      region_size: self.read_uint64(base + 24UL),
      state: self.read_uint32(base + 32UL),
      protect: self.read_uint32(base + 36UL),
      type_: self.read_uint32(base + 40UL),
    }
    items.push(m)
    i = i + 1UL
  }
  items
}

///|
pub fn Dump::memory_info_list(
  self : Dump,
  entries : Array[StreamEntry],
) -> Array[MemoryInfo]? raise ParseError {
  match get_stream(entries, memory_info_list_stream) {
    None => None
    Some(entry) => Some(self.read_memory_info_list(entry))
  }
}

///|
/// The three values of MEMORY_BASIC_INFORMATION.State (`um\winnt.h:14606`).
pub let memory_state_names : Array[(UInt32, String)] = [
  (0x1000U, "MEM_COMMIT"),
  (0x2000U, "MEM_RESERVE"),
  (0x10000U, "MEM_FREE"),
]

///|
/// The three values of Type (`um\winnt.h:14712`).
pub let memory_type_names : Array[(UInt32, String)] = [
  (0x20000U, "MEM_PRIVATE"),
  (0x40000U, "MEM_MAPPED"),
  (0x1000000U, "MEM_IMAGE"),
]

///|
/// The low byte of Protect: the access rights proper (`um\winnt.h:14578`).
pub let memory_protection_bases : Array[(UInt32, String)] = [
  (0x01U, "PAGE_NOACCESS"),
  (0x02U, "PAGE_READONLY"),
  (0x04U, "PAGE_READWRITE"),
  (0x08U, "PAGE_WRITECOPY"),
  (0x10U, "PAGE_EXECUTE"),
  (0x20U, "PAGE_EXECUTE_READ"),
  (0x40U, "PAGE_EXECUTE_READWRITE"),
  (0x80U, "PAGE_EXECUTE_WRITECOPY"),
]

///|
/// The high-bit attributes of Protect. 0x40000000 and 0x80000000 each have two
/// same-valued macros (PAGE_TARGETS_INVALID/PAGE_TARGETS_NO_UPDATE,
/// PAGE_REVERT_TO_FILE_MAP/PAGE_ENCLAVE_THREAD_CONTROL); a single integer
/// cannot distinguish them, so the names are listed side by side.
/// PAGE_GRAPHICS_* and PAGE_ENCLAVE_* are not in the table and appear as
/// Unknown(0x..) — seeing them in a user-mode crash dump is itself noteworthy.
pub let memory_protection_flags : Array[(UInt32, String)] = [
  (0x100U, "PAGE_GUARD"),
  (0x200U, "PAGE_NOCACHE"),
  (0x400U, "PAGE_WRITECOMBINE"),
  (0x2000_0000U, "PAGE_ENCLAVE_UNVALIDATED"),
  (0x4000_0000U, "PAGE_TARGETS_INVALID|PAGE_TARGETS_NO_UPDATE"),
  (0x8000_0000U, "PAGE_REVERT_TO_FILE_MAP|PAGE_ENCLAVE_THREAD_CONTROL"),
]

///|
/// Look up an integer in a name table; falls back to `Unknown(0x..)`.
fn named_value(table : Array[(UInt32, String)], value : UInt32) -> String {
  let mut name : String? = None
  for (bit, text) in table {
    if bit == value && name is None {
      name = Some(text)
    }
  }
  match name {
    None => "Unknown(0x" + value.to_string(radix=16) + ")"
    Some(n) => n
  }
}

///|
pub fn memory_state_name(state : UInt32) -> String {
  named_value(memory_state_names, state)
}

///|
pub fn memory_type_name(type_ : UInt32) -> String {
  named_value(memory_type_names, type_)
}

///|
/// Split Protect into a name list of "access rights + attributes". The low
/// byte and high bits are handled separately, so
/// PAGE_EXECUTE_READWRITE|PAGE_GUARD(0x104) splits into two entries, while
/// 0x100 alone yields only the attribute name.
pub fn memory_protection_bits(protect : UInt32) -> Array[String] {
  let out : Array[String] = []
  let mut rest = protect
  let low = rest & 0xffU
  if low != 0U {
    rest = rest ^ low
    out.push(named_value(memory_protection_bases, low))
  }
  for (bit, name) in memory_protection_flags {
    if (rest & bit) != 0U {
      rest = rest ^ bit
      out.push(name)
    }
  }
  if rest != 0U {
    out.push("Unknown(0x" + rest.to_string(radix=16) + ")")
  }
  out
}

///|
/// One-line readable form of Protect; 0 renders as `0` (no protection bits
/// set), not Unknown(0x0).
pub fn memory_protection_name(protect : UInt32) -> String {
  let bits = memory_protection_bits(protect)
  if bits.length() == 0 {
    "0"
  } else {
    bits.join("|")
  }
}

///|
/// Layout statistic: committed memory bytes. Feeds the CLI's one-liner
/// "X bytes committed". Uses saturating addition: in a malformed dump a pile
/// of entries with RegionSize all 1 must not wrap the total back down to a
/// small number — "3 bytes committed" is a more deceptive conclusion than a
/// straight error.
pub fn memory_info_committed_bytes(items : Array[MemoryInfo]) -> UInt64 {
  let mut total = 0UL
  for m in items {
    if m.state == 0x1000U {
      total = add_saturating(total, m.region_size)
    }
  }
  total
}

///|
/// Executable bit: the low byte's PAGE_EXECUTE / _EXECUTE_READ /
/// _EXECUTE_READWRITE / _EXECUTE_WRITECOPY land on the four bits of 0xf0;
/// high-bit attributes (GUARD, NOCACHE, ...) do not participate.
pub fn memory_protection_is_executable(protect : UInt32) -> Bool {
  (protect & 0xf0U) != 0U
}

///|
/// Writable: the four bits PAGE_READWRITE(0x04) / PAGE_WRITECOPY(0x08) /
/// PAGE_EXECUTE_READWRITE(0x40) / PAGE_EXECUTE_WRITECOPY(0x80) of the low
/// byte, mask 0xcc. Note the executable variants' two write rights sit in the
/// upper half (0x40/0x80); checking only 0x0c would classify
/// PAGE_EXECUTE_READWRITE as "not writable" — this one was forced out by a test.
pub fn memory_protection_is_writable(protect : UInt32) -> Bool {
  (protect & 0xccU) != 0U
}

///|
/// Layout entries falling within a given module.
/// Malware-sample analysis commonly uses this to check "do code regions all
/// come from loaded modules".
pub fn memory_info_for_module(
  items : Array[MemoryInfo],
  target : Module,
) -> Array[MemoryInfo] {
  let out : Array[MemoryInfo] = []
  for m in items {
    if m.base_address >= target.base_of_image &&
      m.base_address < target.end_address() {
      out.push(m)
    }
  }
  out
}

///|
/// Committed regions that are in no module yet carry the execute bit.
/// A normal process's code regions are MEM_IMAGE and inside module ranges, so
/// "executable but outside any image" is one of the most stable signals for
/// packers, injected stubs, RWX heap code, and the like. When `modules` is
/// empty (module table not parsed), no judgment is made and an empty array is
/// returned — better to report nothing than to flag all of ntdll as suspect.
pub fn memory_info_executable_outside_modules(
  items : Array[MemoryInfo],
  modules : Array[Module],
) -> Array[MemoryInfo] {
  let out : Array[MemoryInfo] = []
  if modules.length() == 0 {
    out
  } else {
    for m in items {
      if m.state == 0x1000U &&
        memory_protection_is_executable(m.protect) &&
        find_module(modules, m.base_address) is None {
        out.push(m)
      }
    }
    out
  }
}
