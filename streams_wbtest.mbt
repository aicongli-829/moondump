// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! In-package tests: the long-tail streams (ThreadNames / UnloadedModuleList / HandleData /
///! FunctionTable / ThreadInfoList). Offsets follow the SDK structs; malformed input must raise
///! an error rather than silently produce a pile of plausible-looking wrong data.

///|
/// Lay out several strings **before** the stream data (the "pre" area) and return the pre bytes
/// plus each string's file RVA. A string RVA is an absolute file offset, so the length of pre
/// must be known before it can be computed; 44 here is where the data area starts in
/// `one_stream_dump`.
fn string_pool(names : Array[String]) -> (Bytes, Array[UInt32]) {
  let buf = Buffer()
  let rvas : Array[UInt32] = []
  let mut off = 44
  for s in names {
    rvas.push(off.reinterpret_as_uint())
    let body = minidump_string(s)
    buf.write_bytes(body)
    off = off + body.length()
  }
  (buf.to_bytes(), rvas)
}

///|
fn thread_name_record(id : UInt32, name_rva : UInt64) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(id)
  // RVA64: the ThreadName name pointer is 64 bits; writing 32 bits would leave 4 extra zero
  // bytes. With little-endian writes the first 8 bytes agree for both widths, so this simply
  // writes as u64.
  buf.write_uint64_le(name_rva)
  buf.to_bytes()
}

///|
fn unloaded_module_record(
  base : UInt64,
  size : UInt32,
  checksum : UInt32,
  timestamp : UInt32,
  name_rva : UInt32,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint64_le(base)
  buf.write_uint_le(size)
  buf.write_uint_le(checksum)
  buf.write_uint_le(timestamp)
  buf.write_uint_le(name_rva)
  buf.to_bytes()
}

///|
/// Passing `object_info_rva~` produces a 40-byte v2 descriptor; omitting it gives the 32-byte
/// v1.
fn handle_record(
  handle : UInt64,
  type_rva : UInt32,
  object_rva : UInt32,
  attributes : UInt32,
  granted_access : UInt32,
  handle_count : UInt32,
  pointer_count : UInt32,
  width~ : UInt32 = 32U,
  object_info_rva~ : UInt32 = 0U,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint64_le(handle)
  buf.write_uint_le(type_rva)
  buf.write_uint_le(object_rva)
  buf.write_uint_le(attributes)
  buf.write_uint_le(granted_access)
  buf.write_uint_le(handle_count)
  buf.write_uint_le(pointer_count)
  if width >= 40U {
    buf.write_uint_le(object_info_rva)
    buf.write_uint_le(0U) // Reserved0
  }
  if width > 40U {
    buf.write_bytes(zeros(width.reinterpret_as_int() - 40))
  }
  buf.to_bytes()
}

///|
fn function_descriptor(
  minimum : UInt64,
  maximum : UInt64,
  base : UInt64,
  entry_count : UInt32,
  width~ : UInt32 = 32U,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint64_le(minimum)
  buf.write_uint64_le(maximum)
  buf.write_uint64_le(base)
  buf.write_uint_le(entry_count)
  buf.write_uint_le(0U) // SizeOfAlignPad
  if width > 32U {
    buf.write_bytes(zeros(width.reinterpret_as_int() - 32))
  }
  buf.to_bytes()
}

///|
/// Header of FunctionTableStream: 6 u32s.
fn function_table_header(
  size_of_header~ : UInt32 = 24U,
  size_of_descriptor~ : UInt32 = 32U,
  size_of_native_descriptor~ : UInt32 = 0U,
  size_of_function_entry~ : UInt32 = 12U,
  number_of_descriptors~ : UInt32 = 0U,
  size_of_align_pad~ : UInt32 = 0U,
) -> Bytes {
  cat([
    word(size_of_header),
    word(size_of_descriptor),
    word(size_of_native_descriptor),
    word(size_of_function_entry),
    word(number_of_descriptors),
    word(size_of_align_pad),
  ])
}

///|
/// One record in the inline layout observed in a real WER dump:
/// descriptor(32) + native descriptor(136) + one function entry(12) + padding(4) = 184 bytes.
fn inline_function_record(
  minimum : UInt64,
  maximum : UInt64,
  base : UInt64,
  begin : UInt32,
  last : UInt32,
  unwind : UInt32,
  entry_count~ : UInt32 = 1U,
) -> Bytes {
  cat([
    function_descriptor(minimum, maximum, base, entry_count),
    zeros(136),
    word(begin),
    word(last),
    word(unwind),
    word(0U),
  ])
}

///|
/// MINIDUMP_THREAD_INFO: 64 bytes.
fn thread_info_record(
  id : UInt32,
  dump_flags : UInt32,
  dump_error : UInt32,
  exit_status : UInt32,
  create_time : UInt64,
  exit_time : UInt64,
  kernel_time : UInt64,
  user_time : UInt64,
  start_address : UInt64,
  affinity : UInt64,
  width~ : UInt32 = 64U,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(id)
  buf.write_uint_le(dump_flags)
  buf.write_uint_le(dump_error)
  buf.write_uint_le(exit_status)
  buf.write_uint64_le(create_time)
  buf.write_uint64_le(exit_time)
  buf.write_uint64_le(kernel_time)
  buf.write_uint64_le(user_time)
  buf.write_uint64_le(start_address)
  buf.write_uint64_le(affinity)
  if width > 64U {
    buf.write_bytes(zeros(width.reinterpret_as_int() - 64))
  }
  buf.to_bytes()
}

///|
/// The 12- or 16-byte header shared by ThreadInfoList / UnloadedModuleList / HandleData.
fn sized_header(
  size_of_header : UInt32,
  size_of_entry : UInt32,
  count : UInt32,
  extra~ : UInt32 = 0U,
) -> Bytes {
  if extra == 0U {
    cat([word(size_of_header), word(size_of_entry), word(count)])
  } else {
    cat([word(size_of_header), word(size_of_entry), word(count), word(extra)])
  }
}

///|
fn thread_names_line(dump : Dump) -> String {
  try dump.thread_names(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    names =>
      match names {
        None => "no-stream"
        Some(list) => {
          let parts : Array[String] = []
          for n in list {
            parts.push(n.thread_id.to_string() + "=\"" + n.name + "\"")
          }
          parts.join(" ")
        }
      }
  }
}

///|
fn unloaded_line(dump : Dump) -> String {
  try dump.unloaded_modules(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    list =>
      match list {
        None => "no-stream"
        Some(l) =>
          "declared " +
          l.declared_count.to_string() +
          " skipped " +
          l.skipped.to_string() +
          " got " +
          l.modules.length().to_string() +
          " " +
          l.modules
          .map(m => {
            hex_uint(m.base_of_image) +
            "+" +
            m.size_of_image.to_string() +
            "=\"" +
            m.name +
            "\"@" +
            m.end_address().to_string()
          })
          .join(",")
      }
  }
}

///|
fn handles_line(dump : Dump) -> String {
  try dump.handles(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    list =>
      match list {
        None => "no-stream"
        Some(hs) =>
          hs
          .map(h => {
            hex_uint(h.handle) +
            " t=" +
            h.type_name +
            " o=" +
            h.object_name +
            " g=" +
            h.granted_access.to_string(radix=16) +
            " n=" +
            h.handle_count.to_string() +
            "/" +
            h.pointer_count.to_string() +
            " w=" +
            h.descriptor_size.to_string() +
            " i=" +
            hex_uint(h.object_info_rva)
          })
          .join(" ; ")
      }
  }
}

///|
fn function_table_line(dump : Dump) -> String {
  try dump.function_table(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    info =>
      match info {
        None => "no-stream"
        Some(f) => {
          let bad = if f.layout_ok { "" } else { "(inconsistent)" }
          let layout_text = function_table_layout_name(f.layout) + bad
          "layout=" +
          layout_text +
          " w=" +
          f.size_of_descriptor.to_string() +
          " width=" +
          f.record_width.to_string() +
          " fn=" +
          f.size_of_function_entry.to_string() +
          " n=" +
          f.descriptors.length().to_string() +
          " entries=" +
          f.total_entries.to_string() +
          " entry-area=" +
          hex_uint(f.entries_rva) +
          (if f.entries_in_file { "in-file" } else { "out-of-range" }) +
          " [" +
          f.descriptors
          .map(d => {
            let inl = match d.inline_entry {
              None => ""
              Some(e) =>
                "/0x" +
                e.0.to_string(radix=16) +
                ",0x" +
                e.1.to_string(radix=16) +
                ",0x" +
                e.2.to_string(radix=16)
            }
            hex_uint(d.minimum_address) +
            ".." +
            hex_uint(d.maximum_address) +
            "@" +
            hex_uint(d.base_address) +
            "x" +
            d.entry_count.to_string() +
            inl
          })
          .join(",") +
          "]"
        }
      }
  }
}

///|
fn thread_infos_line(dump : Dump) -> String {
  try dump.thread_infos(dump.stream_directory()) catch {
    err => error_kind(err)
  } noraise {
    list =>
      match list {
        None => "no-stream"
        Some(ts) =>
          ts
          .map(t => {
            t.thread_id.to_string() +
            " " +
            thread_dump_flags_name(t.dump_flags) +
            " err=" +
            t.dump_error.to_string() +
            " exit=" +
            t.exit_status.to_string() +
            " ct=" +
            t.create_time.to_string() +
            " st=" +
            t.start_address.to_string()
          })
          .join(" ; ")
      }
  }
}

///|
/// ThreadNames(24): the 12-byte compact stride, decoding of the name strings, the distinction
/// between "absent" and "empty name" in `thread_name_for`, and the error raised when the
/// declared length is too short.
test "ThreadNames: stride, strings and malformed input" {
  let (pre, rvas) = string_pool(["worker-1", ""])
  let body = cat([
    word(2U),
    thread_name_record(100U, rvas[0].to_uint64()),
    thread_name_record(200U, rvas[1].to_uint64()),
  ])
  let dump = one_stream_dump(
    thread_names_stream,
    body.length().reinterpret_as_uint(),
    pre,
    body,
  )
  assert_eq(thread_names_line(dump), "100=\"worker-1\" 200=\"\"")
  let names = match dump.thread_names(dump.stream_directory()) {
    None => []
    Some(list) => list
  }
  // An empty name is Some(""); only an id that is not found gives None.
  assert_eq(thread_name_for(names, 200U), Some(""))
  assert_eq(thread_name_for(names, 999U), None)
  // The declared length cannot fit two records: ListSizeMismatch.
  let tight = one_stream_dump(
    thread_names_stream,
    (4 + 12).reinterpret_as_uint(),
    pre,
    body,
  )
  assert_eq(thread_names_line(tight), "ListSizeMismatch")
  // The entry count exceeds what the stream declares: also ListSizeMismatch (not a silent
  // short read).
  let over = one_stream_dump(
    thread_names_stream,
    body.length().reinterpret_as_uint(),
    pre,
    cat([
      word(9U),
      thread_name_record(100U, rvas[0].to_uint64()),
      thread_name_record(200U, rvas[1].to_uint64()),
    ]),
  )
  assert_eq(thread_names_line(over), "ListSizeMismatch")
  // The name RVA points outside the file: read_optional_string catches it and yields an empty
  // string instead of failing wholesale.
  let dangling = one_stream_dump(
    thread_names_stream,
    (4 + 12).reinterpret_as_uint(),
    pre,
    cat([word(1U), thread_name_record(7U, 0x7fff_ffffUL)]),
  )
  assert_eq(thread_names_line(dangling), "7=\"\"")
  // A name RVA of 0: by convention "not provided", also yielding an empty string.
  let zero = one_stream_dump(
    thread_names_stream,
    (4 + 12).reinterpret_as_uint(),
    pre,
    cat([word(1U), thread_name_record(8U, 0UL)]),
  )
  assert_eq(thread_names_line(zero), "8=\"\"")
  // When the stream is absent the result is None, rendered as no-stream.
  assert_eq(
    thread_names_line(single_module_dump("a.pdb", "a.dll")),
    "no-stream",
  )
}

///|
/// UnloadedModuleList(14): the stride is the SizeOfEntry declared in the file; extra trailing
/// fields are handled by still reading only the first 24 bytes; `size_of_image == 0` and
/// wrap-around entries are skipped and counted under the same rules as the module table.
test "UnloadedModuleList: fields, stride and skipping" {
  let (pre, rvas) = string_pool(["old.dll", "gone.exe"])
  let body = cat([
    sized_header(12U, 24U, 2U),
    unloaded_module_record(0x1000UL, 0x2000U, 0xabcdU, 0x45d35f6cU, rvas[0]),
    unloaded_module_record(0x20000UL, 0x1000U, 0U, 0U, rvas[1]),
  ])
  let dump = one_stream_dump(
    unloaded_module_list_stream,
    body.length().reinterpret_as_uint(),
    pre,
    body,
  )
  assert_eq(
    unloaded_line(dump),
    "declared 2 skipped 0 got 2 0x1000+8192=\"old.dll\"@12288,0x20000+4096=\"gone.exe\"@135168",
  )
  // A declared stride of 32 (a future variant): only the first 24 bytes are read, the entry
  // count is honored as-is.
  let wide = cat([
    sized_header(12U, 32U, 2U),
    unloaded_module_record(0x1000UL, 0x2000U, 0U, 0U, rvas[0]),
    zeros(8),
    unloaded_module_record(0x20000UL, 0x1000U, 0U, 0U, rvas[1]),
    zeros(8),
  ])
  let wide_dump = one_stream_dump(
    unloaded_module_list_stream,
    wide.length().reinterpret_as_uint(),
    pre,
    wide,
  )
  assert_eq(
    unloaded_line(wide_dump),
    "declared 2 skipped 0 got 2 0x1000+8192=\"old.dll\"@12288,0x20000+4096=\"gone.exe\"@135168",
  )
  // One skipped entry each for size_of_image=0 and for wrap-around.
  let bad = cat([
    sized_header(12U, 24U, 3U),
    unloaded_module_record(0x1000UL, 0U, 0U, 0U, rvas[0]),
    unloaded_module_record(0xffff_ffff_ffff_ff00UL, 0x2000U, 0U, 0U, rvas[0]),
    unloaded_module_record(0x3000UL, 0x100U, 0U, 0U, rvas[1]),
  ])
  let bad_dump = one_stream_dump(
    unloaded_module_list_stream,
    bad.length().reinterpret_as_uint(),
    pre,
    bad,
  )
  assert_eq(
    unloaded_line(bad_dump),
    "declared 3 skipped 2 got 1 0x3000+256=\"gone.exe\"@12544",
  )
  // A stride smaller than 24: cannot fit even a single record.
  let thin = one_stream_dump(
    unloaded_module_list_stream,
    (12 + 24).reinterpret_as_uint(),
    pre,
    cat([sized_header(12U, 20U, 1U), zeros(24)]),
  )
  assert_eq(unloaded_line(thin), "StreamTooSmall")
  // A declared count of 0: an empty table, not an error.
  let empty = one_stream_dump(
    unloaded_module_list_stream,
    12,
    pre,
    sized_header(12U, 24U, 0U),
  )
  assert_eq(unloaded_line(empty), "declared 0 skipped 0 got 0 ")
}

///|
/// HandleData(12): v1 is 32 bytes / v2 is 40 bytes; the type name and object name must decode
/// into strings, and v1's object_info_rva is fixed at 0.
test "HandleData: v1/v2 descriptors and named objects" {
  let (pre, rvas) = string_pool(["Mutant", "\\BaseNamedObjects\\demo"])
  let body = cat([
    sized_header(16U, 32U, 2U, extra=1U),
    handle_record(0x1234UL, rvas[0], rvas[1], 0U, 0x1f0001U, 1U, 2U),
    handle_record(0x5678UL, rvas[0], 0U, 0x42U, 0x10U, 3U, 4U),
  ])
  let dump = one_stream_dump(
    handle_data_stream,
    body.length().reinterpret_as_uint(),
    pre,
    body,
  )
  assert_eq(
    handles_line(dump),
    "0x1234 t=Mutant o=\\BaseNamedObjects\\demo g=1f0001 n=1/2 w=32 i=0x0 ; 0x5678 t=Mutant o= g=10 n=3/4 w=32 i=0x0",
  )
  // v2: the extra ObjectInfoRva is read out and Reserved0 is ignored.
  let v2 = cat([
    sized_header(16U, 40U, 1U, extra=1U),
    handle_record(
      0x99UL,
      rvas[0],
      rvas[1],
      0U,
      0x2U,
      1U,
      1U,
      width=40U,
      object_info_rva=rvas[1],
    ),
  ])
  let v2_dump = one_stream_dump(
    handle_data_stream,
    v2.length().reinterpret_as_uint(),
    pre,
    v2,
  )
  assert_eq(
    handles_line(v2_dump),
    "0x99 t=Mutant o=\\BaseNamedObjects\\demo g=2 n=1/1 w=40 i=0x" +
    rvas[1].to_string(radix=16),
  )
  // A declared stride smaller than v1's: rejected.
  let thin = one_stream_dump(
    handle_data_stream,
    (16 + 32).reinterpret_as_uint(),
    pre,
    cat([sized_header(16U, 24U, 1U, extra=1U), zeros(32)]),
  )
  assert_eq(handles_line(thin), "StreamTooSmall")
  // The declared count cannot fit: ListSizeMismatch.
  let short = one_stream_dump(
    handle_data_stream,
    (16 + 32).reinterpret_as_uint(),
    pre,
    cat([sized_header(16U, 32U, 3U, extra=1U), zeros(32)]),
  )
  assert_eq(handles_line(short), "ListSizeMismatch")
  // 0 entries: an empty array.
  let none = one_stream_dump(
    handle_data_stream,
    16,
    pre,
    sized_header(16U, 32U, 0U, extra=1U),
  )
  assert_eq(handles_line(none), "")
  assert_eq(handles_line(single_module_dump("a.pdb", "a.dll")), "no-stream")
}

///|
/// FunctionTable(13): the function-entry bodies immediately follow the descriptors; this layer
/// only reports the position of the entry area and whether it falls entirely inside the file.
/// A `SizeOfFunctionEntry` of 0, or entries that cannot be read, both count as out-of-range.
test "FunctionTable: descriptors and entry area" {
  let descs = cat([
    function_descriptor(0x1000UL, 0x2000UL, 0x1000UL, 3U),
    function_descriptor(0x3000UL, 0x3400UL, 0x3000UL, 2U),
  ])
  let body = cat([
    function_table_header(number_of_descriptors=2U),
    descs,
    zeros(5 * 12),
  ])
  let dump = one_stream_dump(
    function_table_stream,
    body.length().reinterpret_as_uint(),
    zeros(0),
    body,
  )
  let stream_rva = 44
  assert_eq(
    function_table_line(dump),
    "layout=Declared w=32 width=32 fn=12 n=2 entries=5 entry-area=0x" +
    (stream_rva + 24 + 64).to_string(radix=16) +
    "in-file [0x1000..0x2000@0x1000x3,0x3000..0x3400@0x3000x2]",
  )
  // The entry area extends past the end of the file: no error is raised, but
  // entries_in_file=false.
  let clipped = one_stream_dump(
    function_table_stream,
    (24 + 64).reinterpret_as_uint(),
    zeros(0),
    cat([function_table_header(number_of_descriptors=2U), descs]),
  )
  assert_eq(
    function_table_line(clipped),
    "layout=Declared w=32 width=32 fn=12 n=2 entries=5 entry-area=0x84out-of-range [0x1000..0x2000@0x1000x3,0x3000..0x3400@0x3000x2]",
  )
  // SizeOfFunctionEntry=0: the entries exist but cannot be located, so this also counts as
  // out-of-range.
  let zero_width = one_stream_dump(
    function_table_stream,
    body.length().reinterpret_as_uint(),
    zeros(0),
    cat([
      function_table_header(number_of_descriptors=2U, size_of_function_entry=0U),
      descs,
      zeros(60),
    ]),
  )
  assert_eq(function_table_line(zero_width).contains("out-of-range"), true)
  // 0 descriptors: 0 entries, and the area counts as "in file".
  let empty = one_stream_dump(
    function_table_stream,
    24,
    zeros(0),
    function_table_header(),
  )
  assert_eq(function_table_line(empty).contains("entries=0"), true)
  // A descriptor stride smaller than 32: rejected.
  let thin = one_stream_dump(
    function_table_stream,
    (24 + 32).reinterpret_as_uint(),
    zeros(0),
    cat([
      function_table_header(size_of_descriptor=24U, number_of_descriptors=1U),
      zeros(32),
    ]),
  )
  assert_eq(function_table_line(thin), "StreamTooSmall")
  // The declared count cannot fit: ListSizeMismatch.
  let over = one_stream_dump(
    function_table_stream,
    (24 + 32).reinterpret_as_uint(),
    zeros(0),
    cat([
      function_table_header(number_of_descriptors=9U),
      function_descriptor(0UL, 0UL, 0UL, 1U),
    ]),
  )
  assert_eq(function_table_line(over), "ListSizeMismatch")
  // An enormous entry count: the entry total uses saturating addition and does not wrap around
  // into a small number.
  let huge = one_stream_dump(
    function_table_stream,
    (24 + 32).reinterpret_as_uint(),
    zeros(0),
    cat([
      function_table_header(number_of_descriptors=1U),
      function_descriptor(0UL, 0UL, 0UL, 0xffff_ffffU),
    ]),
  )
  assert_eq(function_table_line(huge).contains("entries=4294967295"), true)
  assert_eq(
    function_table_line(single_module_dump("a.pdb", "a.dll")),
    "no-stream",
  )
}

///|
/// FunctionTable(13): the layout where the writer inlines the function entries into each record
/// (observed in a local WER dump). Reading with the SDK-declared stride yields a pile of
/// "addresses" wider than 48 bits, so the layout must be switched to "the array starts at
/// header + SizeOfAlignPad, and each record occupies descriptor + native + entries + padding",
/// and the chosen layout must be reported — the caller can see that this slot is inferred, not
/// documentation-guaranteed.
test "FunctionTable: inline layout read by record width, with per-record function entries" {
  let recs = cat([
    inline_function_record(
      0x7fffa9bdc000UL, 0x7fffa9bdd000UL, 0x7fffa9bdc000UL, 0U, 0x280U, 0x298U,
    ),
    inline_function_record(
      0x7fffa862b000UL, 0x7fffa862c000UL, 0x7fffa862b000UL, 0U, 0x280U, 0x298U,
    ),
  ])
  // Header 24 + leading padding 4 + two 184-byte records.
  assert_eq(recs.length(), 368)
  let body = cat([
    function_table_header(
      size_of_native_descriptor=136U,
      number_of_descriptors=2U,
      size_of_align_pad=4U,
    ),
    zeros(4),
    recs,
  ])
  let dump = one_stream_dump(
    function_table_stream,
    body.length().reinterpret_as_uint(),
    zeros(0),
    body,
  )
  assert_eq(
    function_table_line(dump),
    "layout=InlineRecords w=32 width=184 fn=12 n=2 entries=2 entry-area=0x1b8in-file " +
    "[0x7fffa9bdc000..0x7fffa9bdd000@0x7fffa9bdc000x1/0x0,0x280,0x298," +
    "0x7fffa862b000..0x7fffa862c000@0x7fffa862b000x1/0x0,0x280,0x298]",
  )
  // EntryCount=0: this record has no function entries, so no inline slots are given — never
  // mistake the padding bytes for entries.
  let empty_body = cat([
    function_table_header(
      size_of_native_descriptor=136U,
      number_of_descriptors=1U,
      size_of_align_pad=4U,
    ),
    zeros(4),
    inline_function_record(
      0x7fffa9bdc000UL,
      0x7fffa9bdd000UL,
      0x7fffa9bdc000UL,
      0U,
      0x280U,
      0x298U,
      entry_count=0U,
    ),
  ])
  let empty = one_stream_dump(
    function_table_stream,
    empty_body.length().reinterpret_as_uint(),
    zeros(0),
    empty_body,
  )
  assert_eq(
    function_table_line(empty),
    "layout=InlineRecords w=32 width=184 fn=12 n=1 entries=0 entry-area=0x100in-file " +
    "[0x7fffa9bdc000..0x7fffa9bdd000@0x7fffa9bdc000x0]",
  )
  // Neither layout is self-consistent: fall back to the declared stride and flag the output as
  // "inconsistent" instead of pretending the read succeeded.
  let both_bad = one_stream_dump(
    function_table_stream,
    (24 + 32).reinterpret_as_uint(),
    zeros(0),
    cat([
      function_table_header(number_of_descriptors=1U),
      function_descriptor(0UL, 0x2000UL, 0UL, 1U),
    ]),
  )
  assert_eq(
    function_table_line(both_bad).contains("layout=Declared(inconsistent)"),
    true,
  )
}

///|
/// ThreadInfoList(17): the entry count here is 32 bits (unlike MemoryInfoList's 64 bits);
/// flag naming, a stride that may be wider, and start-address attribution.
test "ThreadInfoList: fields, flags and start-address attribution" {
  let body = cat([
    sized_header(12U, 64U, 2U),
    thread_info_record(
      100U, 0U, 0U, 0U, 0x1000UL, 0UL, 1UL, 2UL, 0x1400UL, 0x3UL,
    ),
    thread_info_record(
      200U, 0x22U, 5U, 7U, 0UL, 0x20UL, 3UL, 4UL, 0x9000UL, 0UL,
    ),
  ])
  let dump = one_stream_dump(
    thread_info_list_stream,
    body.length().reinterpret_as_uint(),
    zeros(0),
    body,
  )
  assert_eq(
    thread_infos_line(dump),
    "100 0 err=0 exit=0 ct=4096 st=5120 ; 200 WRITING_THREAD|INVALID_TEB err=5 exit=7 ct=0 st=36864",
  )
  // A wide stride: the extra trailing bytes are ignored and the entries are read as usual.
  let wide = cat([
    sized_header(12U, 72U, 1U),
    thread_info_record(1U, 0x10U, 0U, 0U, 0UL, 0UL, 0UL, 0UL, 0x1000UL, 0UL),
    zeros(8),
  ])
  let wide_dump = one_stream_dump(
    thread_info_list_stream,
    wide.length().reinterpret_as_uint(),
    zeros(0),
    wide,
  )
  assert_eq(
    thread_infos_line(wide_dump),
    "1 INVALID_CONTEXT err=0 exit=0 ct=0 st=4096",
  )
  // A stride smaller than 64 cannot fit a MINIDUMP_THREAD_INFO.
  let thin = one_stream_dump(
    thread_info_list_stream,
    (12 + 64).reinterpret_as_uint(),
    zeros(0),
    cat([sized_header(12U, 56U, 1U), zeros(64)]),
  )
  assert_eq(thread_infos_line(thin), "StreamTooSmall")
  assert_eq(
    thread_infos_line(single_module_dump("a.pdb", "a.dll")),
    "no-stream",
  )
  // Flag naming: 0 gives "0", unknown bits give Unknown(0x..), no guessing at meanings.
  assert_eq(thread_dump_flags_name(0U), "0")
  assert_eq(thread_dump_flags_name(0x22U), "WRITING_THREAD|INVALID_TEB")
  assert_eq(thread_dump_flags_name(0x40U), "Unknown(0x40)")
  // Start-address attribution: the ones not found in the module table.
  let mods = cat([word(1U), module_record(0x1000UL, 0x2000U)])
  let both = two_stream_dump(
    (module_list_stream, mods),
    (thread_info_list_stream, body),
  )
  let infos = match both.thread_infos(both.stream_directory()) {
    None => []
    Some(list) => list
  }
  let modules = match both.modules(both.stream_directory()) {
    None => []
    Some(ml) => ml.modules
  }
  assert_eq(infos.length(), 2)
  assert_eq(modules.length(), 1)
  // 0x1400 lies inside the module [0x1000, 0x3000), 0x9000 does not.
  let outside = thread_infos_started_outside_modules(infos, modules)
  assert_eq(outside.map(t => t.thread_id), [200U])
  // Without a module table, no attribution is made.
  assert_eq(thread_infos_started_outside_modules(infos, []).length(), 0)
}
