// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! Package-internal tests: memory streams (MemoryList / Memory64List / MemoryInfoList) and reading by virtual address.

///|
/// A single little-endian 64-bit word.
fn qword(v : UInt64) -> Bytes {
  let buf = Buffer()
  buf.write_uint64_le(v)
  buf.to_bytes()
}

///|
/// 32 bytes of "memory content": four 8-byte pointers with values 1/2/3/4.
/// It sits at the pre position of `one_stream_dump`, i.e. starting at file RVA 44,
/// so "virtual address 0x1000+off" and "file RVA 44+off" map one to one, which makes checking easy.
fn memory_content() -> Bytes {
  cat([qword(1UL), qword(2UL), qword(3UL), qword(4UL)])
}

///|
/// 16-byte MINIDUMP_MEMORY_DESCRIPTOR64: StartOfMemoryRange + DataSize, both 64-bit.
fn memory_descriptor_64(start : UInt64, size : UInt64) -> Bytes {
  cat([qword(start), qword(size)])
}

///|
/// MemoryList(5): content first, table after. `count` can be given a value that
/// disagrees with the number of entries, to build malformed "lying count" inputs;
/// `declared` = 0 means use the table's real length.
fn memory_list_dump(
  content : Bytes,
  items : Array[Bytes],
  count~ : UInt32? = None,
  declared~ : UInt32 = 0U,
) -> Dump raise ParseError {
  let table = cat(
    [
      word(
        match count {
          None => items.length().reinterpret_as_uint()
          Some(c) => c
        },
      ),
    ] +
    items,
  )
  let size = if declared == 0U {
    table.length().reinterpret_as_uint()
  } else {
    declared
  }
  one_stream_dump(memory_list_stream, size, content, table)
}

///|
/// Memory64List(9): the header is count(8) + BaseRva(8). `base_rva` defaults to 44, exactly where the content sits,
/// so segment i's file RVA = 44 + the sum of the declared sizes of the preceding segments.
fn memory_64_dump(
  content : Bytes,
  count : UInt64,
  items : Array[Bytes],
  base_rva~ : UInt64 = 44UL,
  declared~ : UInt32 = 0U,
) -> Dump raise ParseError {
  let table = cat([qword(count), qword(base_rva)] + items)
  let size = if declared == 0U {
    table.length().reinterpret_as_uint()
  } else {
    declared
  }
  one_stream_dump(memory_64_list_stream, size, content, table)
}

///|
/// MemoryInfoList(16): the header is SizeOfHeader(4) + SizeOfEntry(4) + count(8).
/// Giving `width` a value greater than 48 builds a "future variant with wider entries"; the implementation must follow the declared stride.
fn memory_info_dump(
  items : Array[Bytes],
  count~ : UInt64? = None,
  header~ : UInt32 = 16U,
  width~ : UInt32 = 48U,
  declared~ : UInt32 = 0U,
) -> Dump raise ParseError {
  let table = cat(
    [
      word(header),
      word(width),
      qword(
        match count {
          None => items.length().to_uint64()
          Some(c) => c
        },
      ),
    ] +
    items,
  )
  let size = if declared == 0U {
    table.length().reinterpret_as_uint()
  } else {
    declared
  }
  one_stream_dump(memory_info_list_stream, size, zeros(0), table)
}

///|
/// One MINIDUMP_MEMORY_INFO (48 bytes). Offsets per minidumpapiset.h:690:
/// Base@0 AllocBase@8 AllocProtect@16 padding@20 RegionSize@24 State@32
/// Protect@36 Type@40 padding@44.
fn memory_info_record(
  base : UInt64,
  allocation_base : UInt64,
  allocation_protect : UInt32,
  region_size : UInt64,
  state : UInt32,
  protect : UInt32,
  type_ : UInt32,
  width~ : UInt32 = 48U,
) -> Bytes {
  let body = cat([
    qword(base),
    qword(allocation_base),
    word(allocation_protect),
    word(0U),
    qword(region_size),
    word(state),
    word(protect),
    word(type_),
    word(0U),
  ])
  if width > 48U {
    cat([body, zeros(width.reinterpret_as_int() - 48)])
  } else {
    body
  }
}

///|
/// One line of the declared memory table: `0xstart+declared_size@file_position`.
fn memory_line(regions : Array[MemoryRegion]) -> String {
  let parts : Array[String] = []
  for r in regions {
    parts.push(
      hex_uint(r.start_address) +
      "+" +
      r.declared_size.to_string() +
      "@" +
      r.file_rva.to_string(),
    )
  }
  parts.join(" ")
}

///|
/// One line of the built map: the size is the **clipped** readable length, and clipped regions carry the declared value in parentheses;
/// the tail always ends with "dropped N", making "declared but unusable" explicit.
fn map_line(m : MemoryMap) -> String {
  let parts : Array[String] = []
  for r in m.regions {
    let tail = if r.was_clipped() {
      "(" + r.declared_size.to_string() + ")"
    } else {
      ""
    }
    parts.push(
      hex_uint(r.start_address) +
      "+" +
      r.size.to_string() +
      tail +
      "@" +
      r.file_rva.to_string(),
    )
  }
  let head = parts.join(" ")
  if head == "" {
    "dropped" + m.dropped.to_string()
  } else {
    head + " dropped" + m.dropped.to_string()
  }
}

///|
/// The raw declared table; on failure, the error kind name.
fn regions_line(dump : Dump) -> String {
  try dump.memory_regions(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    regions =>
      match regions {
        None => "no-stream"
        Some(list) => memory_line(list)
      }
  }
}

///|
/// The built map; on failure, the error kind name.
fn map_line_of(dump : Dump) -> String {
  try dump.memory_map(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    m =>
      match m {
        None => "no-stream"
        Some(map) => map_line(map)
      }
  }
}

///|
/// The 16-byte entries of MemoryList, plus the rule that "length validation only errors when the entries cannot fit".
/// In the corpus, the DataSize of all four streams in test.dmp / linux-mini / simple-crashpad / invalid-parameter
/// is exactly 4 + 16*count, so the focus here is on slack and malformed boundary cases.
test "MemoryList: entry fields, tail slack, short declaration and out-of-range" {
  let one = memory_descriptor(0x1000UL, 32U, 44U)
  assert_eq(
    regions_line(memory_list_dump(memory_content(), [one])),
    "0x1000+32@44",
  )
  // Table needs 20 bytes, 24 declared: the extra trailing zeros do not count as malformed
  assert_eq(
    regions_line(memory_list_dump(memory_content(), [one], declared=24U)),
    "0x1000+32@44",
  )
  // One byte short and the entry no longer fits
  assert_eq(
    regions_line(memory_list_dump(memory_content(), [one], declared=19U)),
    "ListSizeMismatch",
  )
  // An empty table is legal; the summary is the empty string
  assert_eq(regions_line(memory_list_dump(zeros(4), [])), "")
  // The count claims 5 entries, the table holds 1: it passes the length check first, then gets stopped by the file boundary.
  // The order must be "is the declaration sufficient -> does the file hold it -> only then read entry by entry"
  assert_eq(
    regions_line(
      memory_list_dump(memory_content(), [one], count=Some(5U), declared=84U),
    ),
    "Truncated",
  )
  // No memory stream
  assert_eq(
    regions_line(fixed_stream_dump(system_info_stream, zeros(56))),
    "no-stream",
  )
}

///|
/// Memory64List provides no RVA; positions come entirely from accumulation. The only real-world evidence for this rule is in the corpus:
/// full-dump.dmp has 54 segments with BaseRva=11902, and the accumulated end lands exactly on the file length 8408702.
test "Memory64List: RVA accumulates the declared sizes of preceding segments" {
  let items = [
    memory_descriptor_64(0x1000UL, 8UL),
    memory_descriptor_64(0x2000UL, 8UL),
    memory_descriptor_64(0x3000UL, 16UL),
  ]
  assert_eq(
    regions_line(memory_64_dump(memory_content(), 3UL, items)),
    "0x1000+8@44 0x2000+8@52 0x3000+16@60",
  )
  // The entry count is 64-bit; a malformed 2^60 makes count*16 wrap around to exactly 0.
  // Without overflow protection the check would "pass" here, and then the loop would run headlong into the end of the file.
  assert_eq(
    regions_line(
      memory_64_dump(
        memory_content(),
        0x1000_0000_0000_0000UL,
        [],
        declared=32U,
      ),
    ),
    "ListSizeMismatch",
  )
  // count=0 is a legal empty table
  assert_eq(regions_line(memory_64_dump(memory_content(), 0UL, [])), "")
  // BaseRva outside the file: the declarations still parse, but no segment is usable
  assert_eq(
    map_line_of(
      memory_64_dump(memory_content(), 2UL, items, base_rva=999_999UL),
    ),
    "dropped2",
  )
}

///|
/// The three things the indexing step does: sorting, clipping at the end of the file, and keeping the dropped-segment count in the data.
test "MemoryMap: sorting, clipping and dropped count" {
  // Three segments given out of order; the last one declares 4096 but only 68 bytes remain in the file.
  // Total file length = 44(header+directory) + 32(content) + 4(count) + 48(three entries) = 128
  let items = [
    memory_descriptor(0x3000UL, 4096U, 60U),
    memory_descriptor(0x1000UL, 32U, 44U),
    memory_descriptor(0x2000UL, 0U, 52U),
  ]
  let dump = memory_list_dump(memory_content(), items)
  assert_eq(map_line_of(dump), "0x1000+32@44 0x3000+68(4096)@60 dropped1")
  let m = match dump.memory_map(dump.stream_directory()) {
    None => []
    Some(map) => map.regions
  }
  assert_eq(m.length(), 2)
  assert_eq(m[0].was_clipped(), false)
  assert_eq(m[1].was_clipped(), true)
  assert_eq(m[1].end_address(), 0x3044UL)
  assert_eq(m[1].contains(0x3043UL), true)
  assert_eq(m[1].contains(0x3044UL), false)
}

///|
/// The read layer's core promise: **data is only returned when the whole range is covered**.
/// When reading a pointer width, it is better to return None than to stitch in bytes from outside the memory and use them as a pointer.
test "MemoryMap: read by virtual address, no read without full coverage" {
  let dump = memory_list_dump(memory_content(), [
    memory_descriptor(0x1000UL, 32U, 44U),
  ])
  match dump.memory_map(dump.stream_directory()) {
    None => assert_eq("should not be None", "none")
    Some(m) => {
      assert_eq(dump.read_uint64_at(m, 0x1000UL), Some(1UL))
      assert_eq(dump.read_uint64_at(m, 0x1018UL), Some(4UL))
      // Only 4 bytes remain at the end of the segment: an 8-byte read must fail, not treat the bytes that follow in the file as memory
      assert_eq(dump.read_uint64_at(m, 0x101FUL), None)
      assert_eq(dump.read_uint32_at(m, 0x1018UL), Some(4U))
      assert_eq(dump.read_uint32_at(m, 0x1020UL), None)
      assert_eq(
        dump.read_memory_at(m, 0x1008UL, 16),
        Some(cat([qword(2UL), qword(3UL)])),
      )
      assert_eq(dump.read_memory_at(m, 0x1020UL, 1), None)
      assert_eq(m.readable(0x1000UL, 32UL), true)
      assert_eq(m.readable(0x1000UL, 33UL), false)
      assert_eq(m.region_count(), 1)
      assert_eq(m.total_bytes(), 32UL)
      assert_eq(m.clipped_count(), 0U)
      match m.region_at(0x0FFFUL) {
        Some(_) => assert_eq("should not hit", "hit")
        None => ()
      }
    }
  }
}

///|
/// How overlapping ranges are resolved: the region with the largest start address (the most specific one);
/// when start addresses are equal, the later one in the stream wins.
test "MemoryMap: overlapping ranges pick the most specific region" {
  // Large region 0x1000+32@44, small region 0x1010+8@52
  let dump = memory_list_dump(memory_content(), [
    memory_descriptor(0x1000UL, 32U, 44U),
    memory_descriptor(0x1010UL, 8U, 52U),
  ])
  match dump.memory_map(dump.stream_directory()) {
    None => assert_eq("should not be None", "none")
    Some(m) => {
      match m.region_at(0x1010UL) {
        None => assert_eq("should hit the small region", "none")
        Some(r) => assert_eq(r.file_rva, 52UL)
      }
      // The small region only reaches 0x1018, so it cannot cover a 16-byte read and it falls back to the large region
      match m.region_for(0x1010UL, 16UL) {
        None => assert_eq("should fall back to the large region", "none")
        Some(r) => assert_eq(r.file_rva, 44UL)
      }
    }
  }
  // Same start address: the later entry wins (writers often patch in a small region first and provide the full region later)
  let same = memory_list_dump(memory_content(), [
    memory_descriptor(0x1000UL, 8U, 44U),
    memory_descriptor(0x1000UL, 8U, 52U),
  ])
  match same.memory_map(same.stream_directory()) {
    None => assert_eq("should not be None", "none")
    Some(s) =>
      match s.region_at(0x1000UL) {
        None => assert_eq("should hit", "none")
        Some(r) => assert_eq(r.file_rva, 52UL)
      }
  }
}

///|
/// When both memory streams exist, all of them are merged (Windows may provide both MemoryList and Memory64List).
test "MemoryMap: streams 5 and 9 merged" {
  let merged = two_stream_dump(
    (memory_list_stream, cat([word(1U), memory_descriptor(0x1000UL, 8U, 44U)])),
    (
      memory_64_list_stream,
      cat([qword(1UL), qword(80UL), memory_descriptor_64(0x2000UL, 8UL)]),
    ),
  )
  assert_eq(regions_line(merged), "0x1000+8@44 0x2000+8@80")
}

///|
/// MemoryInfoList describes the address layout, not the content: entries are 48 bytes, and the stride is taken from the value declared in the file.
test "MemoryInfoList: fields, stride and malformed input" {
  let a = memory_info_record(
    0x1000UL, 0x1000UL, 4U, 0x1000UL, 0x1000U, 0x40U, 0x1000000U,
  )
  let b = memory_info_record(
    0x2000UL, 0x1000UL, 4U, 0x2000UL, 0x2000U, 0x2U, 0x40000U,
  )
  let table_dump = memory_info_dump([a, b])
  let items = match table_dump.memory_info_list(table_dump.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(items.length(), 2)
  assert_eq(items[0].base_address, 0x1000UL)
  assert_eq(items[0].allocation_base, 0x1000UL)
  assert_eq(items[0].allocation_protect, 4U)
  assert_eq(items[0].region_size, 0x1000UL)
  assert_eq(items[0].state, 0x1000U)
  assert_eq(items[0].protect, 0x40U)
  assert_eq(items[0].type_, 0x1000000U)
  assert_eq(items[1].end_address(), 0x4000UL)
  assert_eq(memory_state_name(items[1].state), "MEM_RESERVE")
  assert_eq(memory_protection_name(items[0].protect), "PAGE_EXECUTE_READWRITE")
  assert_eq(memory_type_name(items[1].type_), "MEM_MAPPED")
  // Only committed memory is counted: of 0x1000 + 0x2000, only the former
  assert_eq(memory_info_committed_bytes(items), 0x1000UL)
  // Stride 56: a wider future variant; the first 48 bytes are still read per the table and the tail is simply skipped
  let wide = memory_info_dump(
    [
      memory_info_record(
        0x1000UL,
        0UL,
        0U,
        0x100UL,
        0x1000U,
        0x4U,
        0x20000U,
        width=56U,
      ),
      memory_info_record(
        0x2000UL,
        0UL,
        0U,
        0x200UL,
        0x1000U,
        0x4U,
        0x20000U,
        width=56U,
      ),
    ],
    width=56U,
  )
  let ws = match wide.memory_info_list(wide.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(ws.length(), 2)
  assert_eq(ws[1].base_address, 0x2000UL)
  assert_eq(ws[1].region_size, 0x200UL)
  // Stride smaller than 48: not even one structure fits, so reject outright
  let narrow = memory_info_dump([a], width=40U)
  assert_eq(
    try narrow.memory_info_list(narrow.stream_directory()) catch {
      err => error_kind(err)
    } noraise {
      _ => "ok"
    },
    "StreamTooSmall",
  )
  // Count larger than the number of entries, and the stream cannot hold them: ListSizeMismatch
  let short = memory_info_dump([a], count=Some(2UL))
  assert_eq(
    try short.memory_info_list(short.stream_directory()) catch {
      err => error_kind(err)
    } noraise {
      _ => "ok"
    },
    "ListSizeMismatch",
  )
  // A declared header size of 0 cannot be trusted; fall back to the SDK's 16
  let zh_dump = memory_info_dump([a], header=0U)
  let zh = match zh_dump.memory_info_list(zh_dump.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(zh.length(), 1)
  // count=0 is a legal empty table
  let empty = memory_info_dump([], count=Some(0UL), declared=16U)
  let es = match empty.memory_info_list(empty.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(es.length(), 0)
}

///|
/// Splitting protection bits, state and type into names. The low byte and the high bits are handled separately, so 0x104 yields two entries.
test "MemoryInfo: protection/state/type naming" {
  assert_eq(
    memory_protection_bits(0x104U).join("|"),
    "PAGE_READWRITE|PAGE_GUARD",
  )
  assert_eq(memory_protection_bits(0U).length(), 0)
  assert_eq(memory_protection_name(0U), "0")
  assert_eq(memory_protection_name(0x80U), "PAGE_EXECUTE_WRITECOPY")
  assert_eq(
    memory_protection_name(0x4000_0404U),
    "PAGE_READWRITE|PAGE_WRITECOMBINE|PAGE_TARGETS_INVALID|PAGE_TARGETS_NO_UPDATE",
  )
  // 0x1000 is the MEM_COMMIT bit, but it is not part of the PAGE_* low byte, so it is honestly reported as unreadable
  assert_eq(memory_protection_name(0x1000U), "Unknown(0x1000)")
  assert_eq(
    memory_protection_name(0x8000_0100U),
    "PAGE_GUARD|PAGE_REVERT_TO_FILE_MAP|PAGE_ENCLAVE_THREAD_CONTROL",
  )
  assert_eq(memory_state_name(0x1000U), "MEM_COMMIT")
  assert_eq(memory_state_name(0x10000U), "MEM_FREE")
  assert_eq(memory_state_name(0x1234U), "Unknown(0x1234)")
  assert_eq(memory_type_name(0x20000U), "MEM_PRIVATE")
  assert_eq(memory_type_name(0U), "Unknown(0x0)")
}

///|
/// Filtering layout entries by module ownership — a one-shot check for "do all code regions come from loaded modules".
test "MemoryInfo: filter layout entries by module" {
  let dump = module_table_dump([module_record(0x1000UL, 0x2000U)], None)
  let mods = match dump.modules(dump.stream_directory()) {
    None => []
    Some(list) => list.modules
  }
  let layout = memory_info_dump([
    memory_info_record(0x1000UL, 0UL, 0U, 0x100UL, 0x1000U, 0x20U, 0x1000000U),
    memory_info_record(0x9000UL, 0UL, 0U, 0x100UL, 0x1000U, 0x20U, 0x1000000U),
  ])
  let items = match layout.memory_info_list(layout.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(items.length(), 2)
  let hit = memory_info_for_module(items, mods[0])
  assert_eq(hit.length(), 1)
  assert_eq(hit[0].base_address, 0x1000UL)
}

///|
/// Deciding the executable/writable bits: only the permission bits of the low byte count; high-bit attributes do not participate.
/// 0x100 (PAGE_GUARD only) must not count as executable, and neither must 0x4000_0404.
test "MemoryInfo: executable and writable bits" {
  assert_true(memory_protection_is_executable(0x10U))
  assert_true(memory_protection_is_executable(0x20U))
  assert_true(memory_protection_is_executable(0x40U))
  assert_true(memory_protection_is_executable(0x80U))
  assert_true(!memory_protection_is_executable(0x104U))
  assert_true(!memory_protection_is_executable(0x100U))
  assert_true(!memory_protection_is_executable(0x4000_0404U))
  assert_true(!memory_protection_is_executable(0U))
  assert_true(memory_protection_is_writable(0x04U))
  assert_true(memory_protection_is_writable(0x08U))
  assert_true(memory_protection_is_writable(0x40U))
  assert_true(memory_protection_is_writable(0x80U))
  assert_true(!memory_protection_is_writable(0x20U))
  assert_true(!memory_protection_is_writable(0x10U))
  assert_true(!memory_protection_is_writable(0x02U))
  // 0x104 = READWRITE|GUARD: writable but not executable — exactly what "a data page with the guard bit set" looks like.
  assert_true(memory_protection_is_writable(0x104U))
  // High-bit attributes on their own must not count as writable: 0x100 is GUARD only, 0x200 is NOCACHE only.
  assert_true(!memory_protection_is_writable(0x100U))
  assert_true(!memory_protection_is_writable(0x200U))
  // 0x4000_0004 = READWRITE|PAGE_TARGETS_*: the attribute bits must not mask out the permission bits underneath.
  assert_true(memory_protection_is_writable(0x4000_0004U))
}

///|
/// "Executable committed regions outside modules": the filter for signals like injected stubs and RWX heap code.
/// All three exclusion conditions must hold — inside a module, non-executable, and uncommitted (MEM_RESERVE) all do not count;
/// when the module table is empty, nothing is reported at all, so the whole ntdll is not treated as a suspicious region.
test "MemoryInfo: executable regions outside modules" {
  let dump = module_table_dump([module_record(0x1000UL, 0x2000U)], None)
  let mods = match dump.modules(dump.stream_directory()) {
    None => []
    Some(list) => list.modules
  }
  let layout = memory_info_dump([
    // Code region inside a module: normal.
    memory_info_record(0x1000UL, 0x1000UL, 0x20U, 0x100UL, 0x1000U, 0x20U, 16U),
    // RX outside a module: report it.
    memory_info_record(
      0x9000UL, 0x9000UL, 0x20U, 0x100UL, 0x1000U, 0x20U, 0x20000U,
    ),
    // RWX outside a module: also reported (executability takes priority; the type does not matter).
    memory_info_record(
      0xa000UL, 0xa000UL, 0x40U, 0x100UL, 0x1000U, 0x40U, 0x20000U,
    ),
    // Pure data outside a module: not reported.
    memory_info_record(
      0xb000UL, 0xb000UL, 0x4U, 0x100UL, 0x1000U, 0x4U, 0x20000U,
    ),
    // Outside a module and executable, but still MEM_RESERVE: uncommitted does not count as running code.
    memory_info_record(
      0xc000UL, 0xc000UL, 0x20U, 0x100UL, 0x2000U, 0x20U, 0x20000U,
    ),
  ])
  let items = match layout.memory_info_list(layout.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(items.length(), 5)
  let hits = memory_info_executable_outside_modules(items, mods)
  assert_eq(hits.map(m => m.base_address), [0x9000UL, 0xa000UL])
  // Empty module table -> no judgment.
  assert_eq(memory_info_executable_outside_modules(items, []).length(), 0)
  // Committed bytes: 4 of the 5 entries are MEM_COMMIT (the 0xc000 one is still MEM_RESERVE),
  // 0x100 each -> 0x400.
  assert_eq(memory_info_committed_bytes(items), 0x400UL)
}

///|
/// Committed bytes use saturating addition: two malformed entries with RegionSize all-1s still add up to "all 1s",
/// never wrapping back to some small number after 0x1ff… — otherwise the CLI would print "0 committed bytes".
test "MemoryInfo: committed bytes do not wrap around" {
  let huge = 0xffff_ffff_ffff_ffffUL
  let layout = memory_info_dump([
    memory_info_record(0x1000UL, 0x1000UL, 0U, huge, 0x1000U, 0x40U, 0x20000U),
    memory_info_record(0x2000UL, 0x2000UL, 0U, huge, 0x1000U, 0x40U, 0x20000U),
    memory_info_record(
      0x3000UL, 0x3000UL, 0U, 0x100UL, 0x1000U, 0x40U, 0x20000U,
    ),
  ])
  let items = match layout.memory_info_list(layout.stream_directory()) {
    None => []
    Some(list) => list
  }
  assert_eq(memory_info_committed_bytes(items), huge)
  // All are executable regions: all three would be filtered out (with no module table, the "no judgment" path returns empty).
  assert_eq(memory_info_executable_outside_modules(items, []).length(), 0)
}
