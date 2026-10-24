// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! Validates the parsing skeleton with synthetic dumps: header checks, RVA
///! bounds, stream directory, UTF-16 strings. Regression tests against real
///! .dmp corpus live in `corpus/`; `--json` uses this project's own schema
///! and does not align field names with upstream tools that are unavailable
///! here (see the end of section 3 of `docs/proposal.md`).
fn u16(text : String) -> Bytes {
  let buf = Buffer()
  for c in text.to_array() {
    buf.write_char_utf16le(c)
  }
  buf.to_bytes()
}

///|
/// Builds a minimal dump in [header][directory][strings] order; all offsets computed on the fly, no magic numbers.
fn build_dump(entries : Array[(UInt32, Bytes)]) -> Bytes {
  build_dump_with_signature(@moondump.expected_signature, entries)
}

///|
fn build_dump_with_signature(
  sig : UInt32,
  entries : Array[(UInt32, Bytes)],
) -> Bytes {
  let n = entries.length()
  let rvas : Array[Int32] = []
  let mut next = 32 + n * 12
  for i in 0..<n {
    rvas.push(next)
    next = next + 4 + entries[i].1.length()
  }
  let buf = Buffer()
  buf.write_uint_le(sig) // signature
  buf.write_uint_le(0x0007_a793U) // version: high 16 bits = 7 is the signature, low 16 bits = 42899
  buf.write_uint_le(n.reinterpret_as_uint()) // number_of_streams
  buf.write_uint_le(32U) // stream_directory_rva
  buf.write_uint_le(0U) // checksum
  buf.write_uint_le(1_730_000_000U) // time_date_stamp
  buf.write_uint64_le(0x0000_0011_0000_0000UL) // flags
  for i in 0..<n {
    buf.write_uint_le(entries[i].0)
    buf.write_uint_le((4 + entries[i].1.length()).reinterpret_as_uint())
    buf.write_uint_le(rvas[i].reinterpret_as_uint())
  }
  for i in 0..<n {
    buf.write_uint_le(entries[i].1.length().reinterpret_as_uint())
    buf.write_bytes(entries[i].1)
  }
  buf.to_bytes()
}

///|
/// n zero bytes (n should be a multiple of 4)
fn zeros(n : Int32) -> Bytes {
  let buf = Buffer()
  for _ in 0..<(n / 4) {
    buf.write_uint_le(0U)
  }
  buf.to_bytes()
}

///|
/// Returns the error kind name on open failure, "Ok" on success.
fn outcome_of_open(data : Bytes) -> String {
  try @moondump.open_dump(data) catch {
    err => @moondump.error_kind(err)
  } noraise {
    _ => "Ok"
  }
}

///|
/// Reads the MINIDUMP_STRING pointed to by the given stream; returns the error kind name on failure.
fn read_stream_string(
  dump : @moondump.Dump,
  entries : Array[@moondump.StreamEntry],
  stream_type : UInt32,
) -> String {
  match @moondump.get_stream(entries, stream_type) {
    Some(e) =>
      try dump.read_string(e.rva) catch {
        err => @moondump.error_kind(err)
      } noraise {
        s => s
      }
    None => "NoStream"
  }
}

///|
test "synthetic dump: header, stream directory, UTF-16 strings" {
  let dump = @moondump.open_dump(
    build_dump([
      (@moondump.comment_stream_w, u16("崩溃样本💥x")),
      (@moondump.module_list_stream, u16("ntdll.dll")),
    ]),
  )
  assert_eq(dump.header.signature, @moondump.expected_signature)
  assert_eq(dump.header.number_of_streams, 2U)
  assert_eq(dump.header.stream_directory_rva, 32UL)
  assert_eq(dump.header.time_date_stamp, 1_730_000_000U)
  assert_eq(dump.header.flags, 0x0000_0011_0000_0000UL)

  let entries = dump.stream_directory()
  assert_eq(entries.length(), 2)
  assert_eq(entries[0].stream_type, @moondump.comment_stream_w)
  assert_eq(entries[1].stream_type, @moondump.module_list_stream)
  assert_eq(
    read_stream_string(dump, entries, @moondump.comment_stream_w),
    "崩溃样本💥x",
  )
  assert_eq(
    read_stream_string(dump, entries, @moondump.module_list_stream),
    "ntdll.dll",
  )
  assert_eq(
    read_stream_string(dump, entries, @moondump.system_info_stream),
    "NoStream",
  )
}

///|
test "malformed input always errors, never panics" {
  // file shorter than the header
  assert_eq(outcome_of_open(zeros(20)), "Truncated")
  // length is sufficient but the signature is wrong
  assert_eq(
    outcome_of_open(build_dump_with_signature(0x42424242U, [])),
    "InvalidSignature",
  )
  // a valid header + empty directory is allowed
  assert_eq(outcome_of_open(build_dump([])), "Ok")
  let empty = @moondump.open_dump(build_dump([]))
  assert_eq(empty.stream_directory().length(), 0)
  // read past the end of the file
  let dump = @moondump.open_dump(
    build_dump([(@moondump.comment_stream_w, u16("x"))]),
  )
  let tail = dump.data.length().to_uint64()
  try dump.read_uint64(tail - 4UL) catch {
    err => assert_eq(@moondump.error_kind(err), "Truncated")
  } noraise {
    _ => assert_eq("out-of-range read should error", "")
  }
}

///|
test "lone surrogate rejected as invalid UTF-16" {
  let malformed = {
    let b = Buffer()
    b.write_uint16_le(0x0041) // 'A'
    b.write_uint16_le(0xd83d) // high surrogate, no low surrogate follows
    b.write_uint16_le(0x0042)
    b.to_bytes()
  }
  let dump = @moondump.open_dump(
    build_dump([(@moondump.comment_stream_w, malformed)]),
  )
  let entries = dump.stream_directory()
  assert_eq(
    read_stream_string(dump, entries, @moondump.comment_stream_w),
    "InvalidUtf16",
  )
}

///|
/// Stream type names are aligned with the documentation to guard against mistyped constants.
test "stream type constant names" {
  assert_eq(
    @moondump.stream_type_name(@moondump.memory_list_stream),
    "MemoryListStream",
  )
  assert_eq(
    @moondump.stream_type_name(@moondump.memory_64_list_stream),
    "Memory64ListStream",
  )
  assert_eq(
    @moondump.stream_type_name(@moondump.system_info_stream),
    "SystemInfoStream",
  )
  assert_eq(
    @moondump.stream_type_name(@moondump.comment_stream_w),
    "CommentStreamW",
  )
  assert_eq(@moondump.stream_type_name(0xffffU), "Stream(0xffff)")
  // only the low 16 bits are the format version; a WER dump measured in the wild has high 16 bits 0xa0f4 and is still valid
  assert_eq(@moondump.header_format_version(0xa0f4_a793U), 0xa793U)
  assert_eq(@moondump.header_format_version_is_known(0xa0f4_a793U), true)
  assert_eq(@moondump.header_format_version_is_known(0x0007_1234U), false)
}

///|
/// A WER dump measured in the wild has flags 0x200121, and its directory does
/// contain UnloadedModuleListStream, so the decomposed names must line up with the stream directory.
test "flags decomposed into MDMP_TYPE names" {
  assert_eq(
    @moondump.describe_minidump_type(0x200121UL).join("|"),
    "WithDataSegs|WithUnloadedModules|WithProcessThreadData|WithAvxXStateContext",
  )
  assert_eq(@moondump.describe_minidump_type(0UL).join("|"), "Normal")
  assert_eq(
    @moondump.describe_minidump_type(0x2UL | 0x4UL).join("|"),
    "WithFullMemory|WithHandleData",
  )
  // only the low 32 bits are recognized; the high bits (system info) take no part in decomposition
  assert_eq(
    @moondump.describe_minidump_type(0x100_0000_0000UL).join("|"),
    "Normal",
  )
  // unrecognized low bits must surface, not be silently swallowed
  assert_eq(
    @moondump.describe_minidump_type(0x1000_0000UL).join("|"),
    "Unknown(0x10000000)",
  )
  // there are bits above MiniDumpValidTypeFlags that the docs leave undocumented; each name must match
  assert_eq(
    @moondump.describe_minidump_type(0xf80000UL).join("|"),
    "WithModuleHeaders|FilterTriage|WithAvxXStateContext|WithIptTrace|ScanInaccessiblePartialPages",
  )
}

///|
/// Streams 20-24 are easy to shift by one slot as a whole: SystemMemoryInfo is
/// 21 not 22, ThreadNames is 24, and none of the three implementations has
/// confirmed the content of 25 (the CompressedMemory family).
test "newer stream type number names" {
  assert_eq(
    @moondump.stream_type_name(@moondump.system_memory_info_stream),
    "SystemMemoryInfoStream",
  )
  assert_eq(
    @moondump.stream_type_name(@moondump.process_vm_counters_stream),
    "ProcessVmCountersStream",
  )
  assert_eq(@moondump.stream_type_name(20U), "JavaScriptDataStream")
  assert_eq(@moondump.stream_type_name(23U), "IptTraceStream")
  assert_eq(@moondump.stream_type_name(24U), "ThreadNamesStream")
  // 25 has no trustworthy name and is displayed as-is as an unknown stream
  assert_eq(@moondump.stream_type_name(25U), "Stream(0x19)")
  assert_eq(
    @moondump.stream_type_name(@moondump.crashpad_info_stream),
    "CrashpadInfoStream",
  )
  assert_eq(
    @moondump.stream_type_name(@moondump.breakpad_info_stream),
    "BreakpadInfoStream",
  )
}

///|
/// When the same type appears more than once, the last entry wins, matching rust-minidump's directory map behavior.
test "get_stream: duplicate stream types keep the last entry" {
  let dump = @moondump.open_dump(
    build_dump([
      (@moondump.comment_stream_w, u16("first")),
      (@moondump.comment_stream_w, u16("last")),
    ]),
  )
  let entries = dump.stream_directory()
  assert_eq(entries.length(), 2)
  match @moondump.get_stream(entries, @moondump.comment_stream_w) {
    None => assert_eq("stream should be found", "None")
    Some(e) => assert_eq(dump.read_string(e.rva), "last")
  }
}
