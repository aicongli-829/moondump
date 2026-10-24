// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! In-package tests: fixed-length record parsing and private helpers.
///! These cases need direct byte control, so they bypass the public-API construction paths.

///|
/// Writes ASCII one character at a time (1 byte each), for assembling fixed-size byte regions such as the CPUID vendor string.
fn ascii(text : String) -> Bytes {
  let buf = Buffer()
  for c in text.to_array() {
    buf.write_char_utf8(c)
  }
  buf.to_bytes()
}

///|
fn zeros(n : Int32) -> Bytes {
  let buf = Buffer()
  for _ in 0..<(n / 4) {
    buf.write_uint_le(0U)
  }
  buf.to_bytes()
}

///|
fn cat(parts : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for p in parts {
    buf.write_bytes(p)
  }
  buf.to_bytes()
}

///|
/// Assembles a dump of the form "header + one fixed-length stream": directory at 32, stream data at 44, no length prefix.
/// Fixed-length structs (SystemInfo/Module/Thread) all use this shape, unlike MINIDUMP_STRING.
fn fixed_stream_dump(
  stream_type : UInt32,
  payload : Bytes,
) -> Dump raise ParseError {
  let buf = Buffer()
  buf.write_uint_le(expected_signature)
  buf.write_uint_le(0x0007_a793U)
  buf.write_uint_le(1U) // number_of_streams
  buf.write_uint_le(32U) // stream_directory_rva
  buf.write_uint_le(0U) // checksum
  buf.write_uint_le(1_730_000_000U) // time_date_stamp
  buf.write_uint64_le(0UL) // flags
  buf.write_uint_le(stream_type)
  buf.write_uint_le(payload.length().reinterpret_as_uint()) // data_size
  buf.write_uint_le(44U) // rva
  buf.write_bytes(payload)
  open_dump(buf.to_bytes())
}

///|
/// A single little-endian 32-bit word, for assembling CPU regions that are "not ASCII".
fn word(w : UInt32) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(w)
  buf.to_bytes()
}

///|
/// A 56-byte MINIDUMP_SYSTEM_INFO with only the fields the cases care about; the cpu region's 24 bytes come from the caller.
fn fake_system_info(arch : UInt16, cpu : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_uint16_le(arch)
  buf.write_uint16_le(6) // ProcessorLevel: family in x86 terms
  buf.write_uint16_le(0xa701) // ProcessorRevision: high byte model 0xa7, low byte stepping 1
  buf.write_uint16_le(16 + 1 * 256) // NumberOfProcessors=16, ProductType=1
  buf.write_uint_le(10U) // MajorVersion
  buf.write_uint_le(0U) // MinorVersion
  buf.write_uint_le(19042U) // BuildNumber
  buf.write_uint_le(2U) // PlatformId = VER_PLATFORM_WIN32_NT
  buf.write_uint_le(0U) // CSDVersionRva = 0, meaning "no such string"
  buf.write_uint16_le(0x0300) // SuiteMask
  buf.write_uint16_le(0) // Reserved2
  buf.write_bytes(cpu)
  buf.to_bytes()
}

///|
/// Parses a synthetic stream and converts failures into error kind names for easy assertions.
fn system_info_outcome(arch : UInt16, cpu : Bytes) -> String raise ParseError {
  let dump = fixed_stream_dump(system_info_stream, fake_system_info(arch, cpu))
  let entries = dump.stream_directory()
  try dump.system_info(entries) catch {
    err => error_kind(err)
  } noraise {
    info =>
      match info {
        Some(si) =>
          si.csd_version +
          "|" +
          (match si.cpu_vendor {
            Some(v) => v
            None => "<none>"
          })
        None => "NoStream"
      }
  }
}

///|
test "SystemInfo: fixed fields read at measured offsets" {
  let dump = fixed_stream_dump(
    system_info_stream,
    fake_system_info(9, cat([ascii("GenuineIntel"), zeros(12)])),
  )
  let info = dump.system_info(dump.stream_directory())
  match info {
    None => assert_eq("should not be None", "None")
    Some(si) => {
      assert_eq(architecture_name(si.processor_architecture), "amd64")
      assert_eq(x86_family_model_stepping(si), (6, 167, 1))
      assert_eq(si.number_of_processors.to_int(), 16)
      assert_eq(product_type_name(si.product_type), "Workstation")
      assert_eq(version_string(si), "10.0.19042")
      assert_eq(platform_id_name(si.platform_id), "Win32NT")
      assert_eq(
        describe_suite_mask(si.suite_mask).join("|"),
        "SingleUserTS|Personal",
      )
      // CSDVersionRva = 0 means "no string", not a read failure
      assert_eq(si.csd_version, "")
      assert_eq(si.cpu.length(), 6)
      assert_eq(si.cpu_vendor, Some("GenuineIntel"))
    }
  }
}

///|
test "SystemInfo: under 56 bytes reports StreamTooSmall" {
  let short = zeros(40)
  let dump = fixed_stream_dump(system_info_stream, short)
  let entries = dump.stream_directory()
  try dump.system_info(entries) catch {
    err => assert_eq(error_kind(err), "StreamTooSmall")
  } noraise {
    _ => assert_eq("short stream should error", "")
  }
  // the description must show which stream, how much is needed, and how much is there
  let msg = describe_error(ParseError::StreamTooSmall(7U, 56UL, 40UL))
  assert_eq(msg.contains("SystemInfoStream"), true)
  assert_eq(msg.contains("56"), true)
  assert_eq(msg.contains("40"), true)
}

///|
test "CPUID vendor string: only printable ASCII counts; all-zero segment and ARM architecture give none" {
  assert_eq(
    system_info_outcome(9, cat([ascii("AuthenticAMD"), zeros(12)])),
    "|AuthenticAMD",
  )
  // Windows x64 dumps often stuff this region with a feature mask (full-dump.dmp is exactly that)
  assert_eq(system_info_outcome(9, zeros(24)), "|<none>")
  // bytes like 0x10f2774c are not printable ASCII, so judged as "no vendor string"
  let mask_like = cat([word(0x10f2774cU), word(0x3f3U), zeros(16)])
  assert_eq(system_info_outcome(9, mask_like), "|<none>")
  // on non-x86 architectures this region is something else and is not interpreted as a vendor string
  assert_eq(
    system_info_outcome(5, cat([ascii("GenuineIntel"), zeros(12)])),
    "|<none>",
  )
}

///|
test "architecture_is_x86 recognizes only INTEL/AMD64/x86-on-64" {
  assert_eq(architecture_is_x86(0), true)
  assert_eq(architecture_is_x86(9), true)
  assert_eq(architecture_is_x86(10), true)
  assert_eq(architecture_is_x86(5), false)
  assert_eq(architecture_is_x86(11), false)
  assert_eq(architecture_is_x86(12), false)
  assert_eq(architecture_is_x86(0xffff), false)
}

///|
test "read_byte: in-bounds value; out-of-range reports Truncated" {
  let dump = fixed_stream_dump(system_info_stream, zeros(56))
  assert_eq(dump.read_byte(44UL).to_int(), 0)
  let size = dump.data.length().to_uint64()
  try dump.read_byte(size) catch {
    err => assert_eq(error_kind(err), "Truncated")
  } noraise {
    _ => assert_eq("out-of-range read should error", "")
  }
}

///|
/// UTF-16LE body (no length prefix), for assembling MINIDUMP_STRINGs.
fn utf16_body(text : String) -> Bytes {
  let buf = Buffer()
  for c in text.to_array() {
    buf.write_char_utf16le(c)
  }
  buf.to_bytes()
}

///|
/// MINIDUMP_STRING: the length is counted in bytes.
fn minidump_string(text : String) -> Bytes {
  let body = utf16_body(text)
  let buf = Buffer()
  buf.write_uint_le(body.length().reinterpret_as_uint())
  buf.write_bytes(body)
  buf.to_bytes()
}

///|
/// A 108-byte MINIDUMP_MODULE with only the fields the cases care about.
/// The offsets are the table verified in moondump.mbt: base@0 size@8 cs@12 tds@16 name@20
/// VersionInfo@24 CvRecord@76 MiscRecord@84.
fn module_record(
  base : UInt64,
  size : UInt32,
  name_rva~ : UInt32 = 0U,
  cv_rva~ : UInt32 = 0U,
  cv_size~ : UInt32 = 0U,
  file_hi~ : UInt32 = 0U,
  file_lo~ : UInt32 = 0U,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint64_le(base)
  buf.write_uint_le(size)
  buf.write_uint_le(0U) // checksum
  buf.write_uint_le(0x45d3_5f6cU) // time_date_stamp
  buf.write_uint_le(name_rva)
  // the 13 words of VS_FIXEDFILEINFO: only the file version is set, the rest stay 0
  buf.write_uint_le(0U) // signature: measured from the main program as 0
  buf.write_uint_le(0U) // struct_version
  buf.write_uint_le(file_hi)
  buf.write_uint_le(file_lo)
  for _ in 0..<9 {
    buf.write_uint_le(0U)
  }
  buf.write_uint_le(cv_size) // LOC: length first
  buf.write_uint_le(cv_rva) // then RVA
  buf.write_uint_le(0U) // MiscRecord.size
  buf.write_uint_le(0U) // MiscRecord.rva
  buf.write_uint64_le(0UL)
  buf.write_uint64_le(0UL)
  buf.to_bytes()
}

///|
/// A dump whose directory has only one stream. The stream data follows `pre`, which sits at 44,
/// simulating the shape of real files where "the name string and CV record are referenced by RVA from outside the stream";
/// the stream's own DataSize covers only the table body, not pre.
fn one_stream_dump(
  stream_type : UInt32,
  declared_size : UInt32,
  pre : Bytes,
  stream_data : Bytes,
) -> Dump raise ParseError {
  let data_rva = 44 + pre.length()
  let buf = Buffer()
  buf.write_uint_le(expected_signature)
  buf.write_uint_le(0x0007_a793U)
  buf.write_uint_le(1U) // number_of_streams
  buf.write_uint_le(32U) // stream_directory_rva
  buf.write_uint_le(0U) // checksum
  buf.write_uint_le(1_730_000_000U) // time_date_stamp
  buf.write_uint64_le(0UL) // flags
  buf.write_uint_le(stream_type)
  buf.write_uint_le(declared_size)
  buf.write_uint_le(data_rva.reinterpret_as_uint())
  buf.write_bytes(pre)
  buf.write_bytes(stream_data)
  open_dump(buf.to_bytes())
}

///|
/// An RSDS record: magic + 16-byte GUID + age + NUL-terminated path.
/// The GUID's 16 bytes are the actual ntdll values from test.dmp, which also pins down the mixed endianness.
fn rsds_record(path : String, age : UInt32) -> Bytes {
  let guid = cat([
    word(0x5a98_32e5U), // little-endian: stored as E5 32 98 5A
    word(0x41c1_2872U),
    word(0x89d9_8e83U), // first 4 bytes of Data4 in original order
    word(0xffb7_e914U),
  ])
  let body = Buffer()
  body.write_uint_le(code_view_rsds_signature)
  body.write_bytes(guid)
  body.write_uint_le(age)
  body.write_bytes(ascii(path))
  body.write_uint_le(0U) // NUL terminator (padding included)
  body.to_bytes()
}

///|
/// Builds a synthetic dump of "one complete module + its name string + its RSDS".
/// Layout: [44]=CV record, [44+cv]=name string, after that=module table (count + records).
fn single_module_dump(pdb : String, name : String) -> Dump raise ParseError {
  let cv = rsds_record(pdb, 2U)
  let str = minidump_string(name)
  let cv_rva = 44U
  let name_rva = 44U + cv.length().reinterpret_as_uint()
  let record = module_record(
    0x400000UL,
    0x2d000U,
    name_rva~,
    cv_rva~,
    cv_size=cv.length().reinterpret_as_uint(),
    file_hi=0x0005_0001U,
    file_lo=0x0a38_088aU,
  )
  one_stream_dump(
    module_list_stream,
    (4 + record.length()).reinterpret_as_uint(),
    cat([cv, str]),
    cat([word(1U), record]),
  )
}

///|
/// Assembles a module table from the given records; passing `declared_size` as
/// Some is used to make malformed dumps where the declared length does not match.
fn module_table_dump(
  records : Array[Bytes],
  declared_size : UInt32?,
) -> Dump raise ParseError {
  let table = cat([word(records.length().reinterpret_as_uint())] + records)
  let size = match declared_size {
    None => table.length().reinterpret_as_uint()
    Some(s) => s
  }
  one_stream_dump(module_list_stream, size, zeros(0), table)
}

///|
/// Parses the module table and converts failures into error kind names; on success gives a "count/skipped" summary.
fn module_outcome(
  records : Array[Bytes],
  declared_size : UInt32?,
) -> String raise ParseError {
  let dump = module_table_dump(records, declared_size)
  let entries = dump.stream_directory()
  try dump.modules(entries) catch {
    err => error_kind(err)
  } noraise {
    list =>
      match list {
        None => "NoStream"
        Some(ml) =>
          ml.modules.length().to_string() + "/" + ml.skipped.to_string()
      }
  }
}

///|
test "ModuleList: fixed fields, mixed-endian GUID, PDB path" {
  let dump = single_module_dump("a.pdb", "a.dll")
  let entries = dump.stream_directory()
  let ml = dump.modules(entries)
  match ml {
    None => assert_eq("should not be None", "None")
    Some(list) => {
      assert_eq(list.modules.length(), 1)
      assert_eq(list.skipped, 0)
      let m = list.modules[0]
      assert_eq(m.name, "a.dll")
      assert_eq(m.base_of_image, 0x400000UL)
      assert_eq(m.size_of_image, 0x2d000U)
      assert_eq(m.end_address(), 0x42d000UL)
      assert_eq(m.contains(0x400000UL), true)
      assert_eq(m.contains(0x42d000UL), false) // end is exclusive
      assert_eq(m.contains(0x3fffffUL), false)
      assert_eq(m.file_version(), "5.1.2616.2186")
      assert_eq(m.product_version(), "0.0.0.0")
      assert_eq(m.time_date_stamp, 0x45d3_5f6cU)
      // VS_FIXEDFILEINFO.signature was measured as 0 in the main program; not validated here, just read out as-is
      assert_eq(m.version_info.signature, 0U)
      match m.code_view {
        Rsds(r) => {
          assert_eq(r.debug_id, "5A9832E5-2872-41C1-838E-D98914E9B7FF")
          assert_eq(r.age, 2U)
          assert_eq(r.pdb_name, "a.pdb")
        }
        _ => assert_eq("RSDS should be decoded", "other")
      }
    }
  }
}

///|
test "ModuleList: DataSize inconsistent with entry count reports ListSizeMismatch" {
  let rec = module_record(0x1000UL, 0x1000U)
  // exact length
  assert_eq(module_outcome([rec], None), "1/0")
  // only 4 bytes over: known generators are lenient, so it is allowed
  assert_eq(module_outcome([rec], Some(116U)), "1/0")
  // 8 bytes over: no longer allowed
  assert_eq(module_outcome([rec], Some(120U)), "ListSizeMismatch")
  // 4 bytes short is also reported
  assert_eq(module_outcome([rec], Some(108U)), "ListSizeMismatch")
  // count claims entries but the table body has none: length mismatch is reported first, no out-of-bounds read
  assert_eq(module_outcome([], Some(112U)), "ListSizeMismatch")
  let msg = describe_error(ListSizeMismatch(4U, 112UL, 120UL))
  assert_eq(msg.contains("ModuleListStream"), true)
  assert_eq(error_kind(ListSizeMismatch(4U, 112UL, 120UL)), "ListSizeMismatch")
}

///|
test "ModuleList: entries with size 0 or address overflow are skipped and counted" {
  let good = module_record(0x400000UL, 0x1000U)
  // size_of_image == 0
  let zero = module_record(0x500000UL, 0U)
  // base + size overflows u64; such a record's address range is untrustworthy
  let wrap = module_record(0xffff_ffff_ffff_f000UL, 0x2000U)
  assert_eq(module_outcome([good, zero, wrap], None), "1/2")
  assert_eq(module_outcome([good], None), "1/0")
}

///|
test "CodeView: the three degradations Missing / Unrecognized / Corrupt" {
  let table = cat([word(1U), module_record(0x1000UL, 0x1000U)])
  let dump = one_stream_dump(module_list_stream, 112U, zeros(0), table)
  let list = dump.modules(dump.stream_directory())
  match list {
    Some(ml) => assert_true(ml.modules[0].code_view is Missing)
    None => assert_eq("should not be None", "None")
  }
  // the magic is breakpad's "LEpB" (Linux build-id); this implementation only reports the raw 4 bytes
  let elf = word(0x4270_454cU)
  let dump2 = one_stream_dump(
    module_list_stream,
    112U,
    elf,
    cat([word(1U), module_record(0x1000UL, 0x1000U, cv_rva=44U, cv_size=24U)]),
  )
  match dump2.modules(dump2.stream_directory()) {
    Some(ml) =>
      assert_true(ml.modules[0].code_view is Unrecognized(0x4270_454cU))
    None => assert_eq("should not be None", "None")
  }
  // CvRecord points outside the file: report Corrupt rather than making the whole module table unreadable
  let dump3 = one_stream_dump(
    module_list_stream,
    112U,
    zeros(0),
    cat([
      word(1U),
      module_record(0x1000UL, 0x1000U, cv_rva=100_000U, cv_size=40U),
    ]),
  )
  match dump3.modules(dump3.stream_directory()) {
    Some(ml) => assert_true(ml.modules[0].code_view is Corrupt)
    None => assert_eq("should not be None", "None")
  }
}

///|
/// In the file a LocationDescriptor is "length first, RVA second"; this is easy to write reversed from memory.
/// The empirical evidence from the corpus is in the moondump.mbt comments.
test "read_location: DataSize first, Rva second" {
  // (40, 4908) at 44, exactly the actual CvRecord values of the first module in test.dmp
  let dump = one_stream_dump(
    module_list_stream,
    8U,
    zeros(0),
    cat([word(40U), word(4908U)]),
  )
  let loc = dump.read_location(44UL)
  assert_eq(loc.size, 40U)
  assert_eq(loc.rva, 4908UL)
  assert_eq(quad_version(0x0005_0001U, 0x0a38_088aU), "5.1.2616.2186")
}

///|
/// Fixed-length WCHAR array: write the body then pad with zeros to the given byte count.
fn wchar_pad(text : String, byte_len : Int32) -> Bytes {
  let body = utf16_body(text)
  let buf = Buffer()
  buf.write_bytes(body)
  let mut left = byte_len - body.length()
  while left >= 2 {
    buf.write_uint16_le(0)
    left = left - 2
  }
  buf.to_bytes()
}

///|
/// SYSTEMTIME: 8 WORDs, in exactly the field order of minwinbase.h:90.
fn system_time_bytes(
  year : UInt16,
  month : UInt16,
  day_of_week : UInt16,
  day : UInt16,
  hour : UInt16,
  minute : UInt16,
  second : UInt16,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint16_le(year)
  buf.write_uint16_le(month)
  buf.write_uint16_le(day_of_week)
  buf.write_uint16_le(day)
  buf.write_uint16_le(hour)
  buf.write_uint16_le(minute)
  buf.write_uint16_le(second)
  buf.write_uint16_le(0)
  buf.to_bytes()
}

///|
/// TIME_ZONE_INFORMATION, which must be exactly 172 bytes or every later field shifts.
fn time_zone_bytes(
  bias : UInt32,
  std_name : String,
  std_date : Bytes,
  std_bias : UInt32,
  dst_name : String,
  dst_date : Bytes,
  dst_bias : UInt32,
) -> Bytes raise {
  let tz = cat([
    word(bias),
    wchar_pad(std_name, 64),
    std_date,
    word(std_bias),
    wchar_pad(dst_name, 64),
    dst_date,
    word(dst_bias),
  ])
  assert_eq(tz.length(), 172)
  tz
}

///|
/// XSTATE_CONFIG_FEATURE_MSC_INFO: 4+4+8+64*8 = 528 bytes.
/// Only the first few features entries are given; the rest are zero-filled.
fn xstate_bytes(
  context_size : UInt32,
  enabled : UInt64,
  features : Array[(UInt32, UInt32)],
) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(528U)
  buf.write_uint_le(context_size)
  buf.write_uint64_le(enabled)
  let mut i : Int32 = 0
  while i < 64 {
    let (offset, size) = if i < features.length() {
      features[i]
    } else {
      (0U, 0U)
    }
    buf.write_uint_le(offset)
    buf.write_uint_le(size)
    i = i + 1
  }
  buf.to_bytes()
}

///|
/// A complete 1364-byte MiscInfo stream; any field not given is zero-filled.
/// The first 15 words (60 bytes) + time zone 172 + BuildString 520 + DbgBldStr 80
/// + XState 528 + ProcessCookie 4.
fn misc_v5_payload(
  flags~ : UInt32 = 0U,
  pid~ : UInt32 = 0U,
  times~ : (UInt32, UInt32, UInt32) = (0U, 0U, 0U),
  power~ : (UInt32, UInt32, UInt32, UInt32, UInt32) = (0U, 0U, 0U, 0U, 0U),
  integrity~ : UInt32 = 0U,
  exec_flags~ : UInt32 = 0U,
  protected_process~ : UInt32 = 0U,
  tz_id~ : UInt32 = 0U,
  tz~ : Bytes = zeros(172),
  build~ : String = "",
  dbg~ : String = "",
  xstate~ : Bytes = zeros(528),
  cookie~ : UInt32 = 0U,
) -> Bytes raise {
  let head = cat([
    word(misc_info_v5_size),
    word(flags),
    word(pid),
    word(times.0),
    word(times.1),
    word(times.2),
    word(power.0),
    word(power.1),
    word(power.2),
    word(power.3),
    word(power.4),
    word(integrity),
    word(exec_flags),
    word(protected_process),
    word(tz_id),
  ])
  assert_eq(head.length(), 60)
  cat([
    head,
    tz,
    wchar_pad(build, 520),
    wchar_pad(dbg, 80),
    xstate,
    word(cookie),
  ])
}

///|
/// Wraps a MiscInfo blob in any declared length: the version is decided by the declared length, which is
/// the only basis this implementation uses (the SizeOfInfo field was measured to be untrustworthy).
fn misc_dump(declared_size : UInt32, payload : Bytes) -> Dump raise ParseError {
  one_stream_dump(misc_info_stream, declared_size, zeros(0), payload)
}

///|
/// Returns the summary line on success; on failure returns the error kind name, so one assertion covers both outcomes.
fn misc_outcome(declared_size : UInt32, payload : Bytes) -> String raise {
  let dump = misc_dump(declared_size, payload)
  let entries = dump.stream_directory()
  try dump.misc_info(entries) catch {
    err => error_kind(err)
  } noraise {
    info =>
      match info {
        None => "NoStream"
        Some(mi) => misc_summary(mi)
      }
  }
}

///|
/// A compact MiscInfo summary: version + "presence + key value" for every optional field.
/// Asserting the gating with it saves twenty lines of per-field matches, and shows at a glance which field got gated off.
fn misc_summary(mi : MiscInfo) -> String {
  let g = match mi.process_id {
    None => "pid=-"
    Some(p) => "pid=" + p.to_string()
  }
  let t = match mi.process_times {
    None => "times=-"
    Some(x) => "times=" + x.create_time.to_string()
  }
  let p = match mi.processor_power_info {
    None => "power=-"
    Some(x) => "power=" + x.max_mhz.to_string()
  }
  let i = match mi.process_integrity_level {
    None => "intg=-"
    Some(x) => "intg=" + x.to_string()
  }
  let e = match mi.process_execute_flags {
    None => "exec=-"
    Some(x) => "exec=0x" + x.to_string(radix=16)
  }
  let pr = match mi.protected_process {
    None => "prot=-"
    Some(x) => "prot=" + x.to_string()
  }
  let z = match mi.time_zone {
    None => "tz=-"
    Some(x) => {
      let id = match mi.time_zone_id {
        None => "?"
        Some(v) => v.to_string()
      }
      "tz=" + id + "/" + x.standard_name + "/" + time_zone_offset_text(x.bias)
    }
  }
  let b = match mi.build_string {
    None => "build=-"
    Some(x) => "build=" + x
  }
  let d = match mi.dbg_build_string {
    None => "dbg=-"
    Some(x) => "dbg=" + x
  }
  let x = match mi.xstate_config {
    None => "xs=-"
    Some(c) => {
      let mut on : Int32 = 0
      let mut k : Int32 = 0
      while k < 64 {
        if c.enabled(k) {
          on = on + 1
        }
        k = k + 1
      }
      "xs=" + c.context_size.to_string() + "/" + on.to_string()
    }
  }
  let c = match mi.process_cookie {
    None => "cookie=-"
    Some(v) => "cookie=0x" + v.to_string(radix=16)
  }
  let v = "v" +
    mi.info_version.to_string() +
    " size=" +
    mi.size_of_info.to_string()
  v + " " + [g, t, p, i, e, pr, z, b, d, x, c].join(" ")
}

///|
test "MiscInfo: version is decided only by the declared size" {
  assert_eq(misc_info_version(0U), 1U)
  assert_eq(misc_info_version(23U), 1U)
  assert_eq(misc_info_version(24U), 1U)
  assert_eq(misc_info_version(43U), 1U)
  assert_eq(misc_info_version(44U), 2U)
  assert_eq(misc_info_version(231U), 2U)
  assert_eq(misc_info_version(232U), 3U)
  assert_eq(misc_info_version(831U), 3U)
  assert_eq(misc_info_version(832U), 4U)
  assert_eq(misc_info_version(1363U), 4U)
  assert_eq(misc_info_version(1364U), 5U)
  // odd lengths beyond v5 are treated as v5, with fields still protected by the gating
  assert_eq(misc_info_version(2000U), 5U)
  assert_eq(misc_info_v5_size, 1364U)
}

///|
/// This is MiscInfo's core semantics: Microsoft's exact wording is "a member is valid = it lies within the available length **and**
/// the corresponding bit is on". The test deliberately provides a stream "that actually contains v3/v4/v5 data in the file"
/// but declares only 44 bytes, and requires that not a single one may be read out.
test "MiscInfo: an insufficient version forbids reading the later fields" {
  let full = misc_v5_payload(
    flags=0x3f7U,
    pid=4242U,
    times=(7U, 8U, 9U),
    power=(10U, 11U, 12U, 13U, 14U),
    integrity=0x2000U,
    exec_flags=0xdU,
    protected_process=1U,
    tz_id=2U,
    tz=time_zone_bytes(
      0xffff_ffc4U,
      "CET",
      system_time_bytes(0, 3, 0, 5, 3, 0, 0),
      0U,
      "CEST",
      system_time_bytes(0, 10, 0, 5, 4, 0, 0),
      0xffff_ffffU,
    ),
    build="17134.1.amd64fre",
    dbg="dbgeng.amd64",
    xstate=xstate_bytes(4096U, 5UL, [
      (0x420U, 0x1a0U),
      (0U, 0U),
      (0x5c0U, 0x100U),
    ]),
    cookie=0xc0ffeeU,
  )
  assert_eq(full.length(), 1364)
  // full v5: everything on
  let all = describe_misc_flags(0x3f7U).join("|")
  assert_eq(
    all, "ProcessId|ProcessTimes|ProcessorPowerInfo|ProcessIntegrity|ProcessExecuteFlags|TimeZone|ProtectedProcess|BuildString|ProcessCookie",
  )
  assert_eq(
    misc_outcome(1364U, full),
    "v5 size=1364 pid=4242 times=7 power=10 intg=8192 exec=0xd prot=1 tz=2/CET/+01:00 build=17134.1.amd64fre dbg=dbgeng.amd64 xs=4096/2 cookie=0xc0ffee",
  )
  // the same bytes with only 44 declared (v2): fields from v3 onward must not be read out
  assert_eq(
    misc_outcome(44U, full),
    "v2 size=1364 pid=4242 times=7 power=10 intg=- exec=- prot=- tz=- build=- dbg=- xs=- cookie=-",
  )
  // 832 declared (v4): time zone and build string are present, the v5 ones are not
  assert_eq(
    misc_outcome(832U, full),
    "v4 size=1364 pid=4242 times=7 power=10 intg=8192 exec=0xd prot=1 tz=2/CET/+01:00 build=17134.1.amd64fre dbg=dbgeng.amd64 xs=- cookie=-",
  )
  // length is enough but no bit is on: only version, SizeOfInfo, and the XState table remain.
  // XState has no corresponding Flags1 bit (Microsoft provides it by struct version only), so it is read as soon as v5 is reached;
  // full-dump/invalid-parameter in the corpus is exactly such an all-zero table with enabled=0x0.
  assert_eq(
    misc_outcome(1364U, misc_v5_payload()),
    "v5 size=1364 pid=- times=- power=- intg=- exec=- prot=- tz=- build=- dbg=- xs=0/0 cookie=-",
  )
}

///|
test "MiscInfo: too short reports StreamTooSmall, file truncation reports Truncated" {
  assert_eq(misc_outcome(23U, zeros(24)), "StreamTooSmall")
  assert_eq(
    misc_outcome(24U, zeros(24)),
    "v1 size=0 pid=- times=- power=- intg=- exec=- prot=- tz=- build=- dbg=- xs=- cookie=-",
  )
  // 1364 declared, only 832 in the file: everything within v4 reads, the v5 XState is out of bounds and reported rather than reading garbage
  let short = zeros(832)
  let dump = misc_dump(1364U, short)
  let entries = dump.stream_directory()
  let e = entries[0]
  try dump.read_misc_info(e) catch {
    err => {
      assert_eq(error_kind(err), "Truncated")
      assert_eq(describe_error(err).contains("bytes"), true)
    }
  } noraise {
    _ => assert_eq("should be out of range", "not out of range")
  }
}

///|
/// The strings and rules inside the 172-byte time zone block are the easiest to misread by one slot:
/// BuildString sits immediately after the time zone, so both reading correctly at once proves 172 is right.
test "MiscInfo: time-zone block fields and BuildString sit adjacent without shifting" {
  let tz = time_zone_bytes(
    300U,
    "Eastern Standard Time",
    system_time_bytes(0, 11, 0, 1, 2, 0, 0),
    0U,
    "Eastern Daylight Time",
    system_time_bytes(0, 3, 0, 2, 2, 0, 0),
    0xffff_ffc4U,
  )
  let payload = misc_v5_payload(
    flags=0x3f7U,
    tz_id=1U,
    tz~,
    build="19041.1.amd64fre.vb_release.191206-1406",
    dbg="dbgeng.amd64,10.0.18362.1",
  )
  let dump = misc_dump(1364U, payload)
  let mi = dump.misc_info(dump.stream_directory())
  match mi {
    None => assert_eq("should not be None", "None")
    Some(info) =>
      match info.time_zone {
        None => assert_eq("time zone should be present", "None")
        Some(t) => {
          assert_eq(t.bias, 300)
          assert_eq(time_zone_offset_text(t.bias), "-05:00")
          assert_eq(t.standard_name, "Eastern Standard Time")
          assert_eq(t.daylight_name, "Eastern Daylight Time")
          assert_eq(t.daylight_bias, -60)
          assert_eq(t.standard_date.rule_text(), "y=0 m=11 dow=0 d=1 02:00:00")
          assert_eq(t.daylight_date.rule_text(), "y=0 m=3 dow=0 d=2 02:00:00")
          assert_eq(t.standard_date.is_empty(), false)
          // the two string pairs right after the time zone: the offsets only line up if read correctly
          assert_eq(
            info.build_string,
            Some("19041.1.amd64fre.vb_release.191206-1406"),
          )
          assert_eq(info.dbg_build_string, Some("dbgeng.amd64,10.0.18362.1"))
        }
      }
  }
  // Bias is the minute count in "local time + Bias = UTC", so its sign is opposite the UTC offset:
  // Eastern in the corpus is Bias=300 → -05:00; Beijing is Bias=-480 → +08:00.
  assert_eq(time_zone_offset_text(-480), "+08:00")
  assert_eq(time_zone_offset_text(480), "-08:00")
  assert_eq(time_zone_offset_text(0), "+00:00")
  assert_eq(time_zone_offset_text(-30), "+00:30")
  let zero_time : SystemTime = {
    year: 0,
    month: 0,
    day_of_week: 0,
    day: 0,
    hour: 0,
    minute: 0,
    second: 0,
    milliseconds: 0,
  }
  assert_eq(zero_time.rule_text(), "-")
}

///|
test "MiscInfo: XState feature table queried bit by bit" {
  let x = xstate_bytes(4096U, 5UL, [
    (0x420U, 0x1a0U),
    (0U, 0U),
    (0x5c0U, 0x100U),
  ])
  let payload = misc_v5_payload(flags=0x3f7U, xstate=x)
  let dump = misc_dump(1364U, payload)
  match dump.misc_info(dump.stream_directory()) {
    None => assert_eq("should not be None", "None")
    Some(info) =>
      match info.xstate_config {
        None => assert_eq("XState should be present", "None")
        Some(c) => {
          assert_eq(c.size_of_info, 528U)
          assert_eq(c.context_size, 4096U)
          assert_eq(c.enabled_features, 5UL)
          assert_eq(c.features.length(), 64)
          assert_eq(c.enabled(0), true)
          assert_eq(c.enabled(1), false)
          assert_eq(c.enabled(2), true)
          assert_eq(c.enabled(63), false)
          assert_eq(c.enabled(-1), false)
          assert_eq(c.enabled(64), false)
          assert_eq(c.feature(0), Some({ offset: 0x420U, size: 0x1a0U, }))
          assert_eq(c.feature(1), None)
          assert_eq(c.feature(2), Some({ offset: 0x5c0U, size: 0x100U, }))
          assert_eq(c.feature(64), None)
        }
      }
  }
}

///|
test "MiscInfo: Flags1 split into names; unknown bits are not silently dropped" {
  assert_eq(describe_misc_flags(0U).join("|"), "")
  assert_eq(
    describe_misc_flags(0x143U).join("|"),
    "ProcessId|ProcessTimes|TimeZone|BuildString",
  )
  assert_eq(describe_misc_flags(0x8U).join("|"), "Unknown(0x8)")
  // known bits + undefined bits: the rest are merged into one Unknown, no information dropped
  assert_eq(describe_misc_flags(0x401U).join("|"), "ProcessId|Unknown(0x400)")
  assert_eq(
    describe_misc_flags(0x3f7U).join("|"),
    "ProcessId|ProcessTimes|ProcessorPowerInfo|ProcessIntegrity|ProcessExecuteFlags|TimeZone|ProtectedProcess|BuildString|ProcessCookie",
  )
}

///|
///! -------- thread table / CONTEXT / exception stream --------
///! The corpus can pin down "what a real writer produces" but not "what a malformed writer produces",
///! so all the cases below assemble their own bytes.

///|
/// Builds a fixed-length zero-filled byte block from "word index → value", for making sparse large
/// structs like CONTEXT: only the words the cases care about are written, the rest stay 0,
/// which also proves "unset" reads back as 0.
fn sparse_words(byte_len : Int32, patches : Array[(Int32, UInt32)]) -> Bytes {
  let ws : Array[UInt32] = []
  for _ in 0..<(byte_len / 4) {
    ws.push(0U)
  }
  for (i, v) in patches {
    ws[i] = v
  }
  let buf = Buffer()
  for w in ws {
    buf.write_uint_le(w)
  }
  buf.to_bytes()
}

///|
/// One thread record. Offsets follow MINIDUMP_THREAD at minidumpcommon.h:245:
/// Id@0 SuspendCount@4 PriorityClass@8 Priority@12 Teb@16
/// Stack(MEMORY_DESCRIPTOR)@24 = StartOfMemoryRange8 + DataSize4 + Rva4
/// ThreadContext(LOC)@40 = Size4 + Rva4; adding 16 bytes of backing makes it a ThreadEx.
fn thread_record(
  id : UInt32,
  teb : UInt64,
  stack_start : UInt64,
  stack_size : UInt32,
  stack_rva : UInt32,
  ctx_size : UInt32,
  ctx_rva : UInt32,
  backing~ : Bytes? = None,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(id)
  buf.write_uint_le(1U) // SuspendCount
  buf.write_uint_le(32U) // PriorityClass
  buf.write_uint_le(0U) // Priority
  buf.write_uint64_le(teb)
  buf.write_uint64_le(stack_start)
  buf.write_uint_le(stack_size)
  buf.write_uint_le(stack_rva)
  buf.write_uint_le(ctx_size)
  buf.write_uint_le(ctx_rva)
  match backing {
    None => ()
    Some(b) => buf.write_bytes(b)
  }
  buf.to_bytes()
}

///|
/// A 16-byte MINIDUMP_MEMORY_DESCRIPTOR (the ThreadEx BackingStore).
fn memory_descriptor(start : UInt64, size : UInt32, rva : UInt32) -> Bytes {
  let buf = Buffer()
  buf.write_uint64_le(start)
  buf.write_uint_le(size)
  buf.write_uint_le(rva)
  buf.to_bytes()
}

///|
/// A dump with only a thread stream + a parse summary; on failure gives the error kind name, one assertion covers both outcomes.

///|
/// A one-line summary of one thread. RVAs use decimal (matching `ctx=716@2760` in the corpus assertions),
/// addresses use hex, and the width `w=` makes explicit whether it was parsed as Thread or ThreadEx.
fn thread_line(t : Thread) -> String {
  let bs = match t.backing_store {
    None => "-"
    Some(b) =>
      hex_uint(b.start_address) +
      "+" +
      b.location.size.to_string() +
      "@" +
      b.location.rva.to_string()
  }
  "id=" +
  t.id.to_string() +
  ",teb=" +
  hex_uint(t.teb) +
  ",stk=" +
  hex_uint(t.stack.start_address) +
  "+" +
  t.stack.location.size.to_string() +
  "@" +
  t.stack.location.rva.to_string() +
  ",ctx=" +
  t.context.size.to_string() +
  "@" +
  t.context.rva.to_string() +
  ",bs=" +
  bs +
  ",w=" +
  t.entry_size.to_string()
}

///|
/// A thread-table outcome with direct control over count: used to make the class of malformed dumps
/// where "count claims entries but the file cannot hold them", i.e. the declared length contradicts itself.
fn thread_table_outcome(
  stream_type : UInt32,
  count : UInt32,
  records : Array[Bytes],
  declared : UInt32,
) -> String raise {
  let dump = one_stream_dump(
    stream_type,
    declared,
    zeros(0),
    cat([word(count)] + records),
  )
  let entries = dump.stream_directory()
  try dump.read_thread_list(entries[0]) catch {
    err => error_kind(err)
  } noraise {
    ts => {
      let lines : Array[String] = []
      for t in ts {
        lines.push(thread_line(t))
      }
      lines.join(" ; ")
    }
  }
}

///|
fn thread_list_outcome(
  stream_type : UInt32,
  records : Array[Bytes],
  declared : UInt32?,
) -> String raise {
  let table = cat([word(records.length().reinterpret_as_uint())] + records)
  let size = match declared {
    None => table.length().reinterpret_as_uint()
    Some(s) => s
  }
  thread_table_outcome(
    stream_type,
    records.length().reinterpret_as_uint(),
    records,
    size,
  )
}

///|
test "Thread: 48-byte record read field by field, CONTEXT not read along with it" {
  let rec = thread_record(
    4242U, 0x7ffd_f000UL, 0x7fff_0000UL, 4096U, 512U, 716U, 44U,
  )
  assert_eq(
    thread_list_outcome(thread_list_stream, [rec], None),
    "id=4242,teb=0x7ffdf000,stk=0x7fff0000+4096@512,ctx=716@44,bs=-,w=48",
  )
  // fields like suspend/priority, not asserted in the helper, get their value source pinned once separately
  let dump = one_stream_dump(
    thread_list_stream,
    52U,
    zeros(0),
    cat([word(1U), rec]),
  )
  let ts = dump.read_thread_list(dump.stream_directory()[0])
  assert_eq(ts[0].suspend_count, 1U)
  assert_eq(ts[0].priority_class, 32U)
  assert_eq(ts[0].priority, 0U)
  // the declared length belongs to the CONTEXT, not the thread: width and rva are carried out as-is
  assert_eq(ts[0].context.size, 716U)
  assert_eq(ts.length(), 1)
}

///|
/// A two-stream synthetic dump: 2 directory entries at 32 (24 bytes), stream data starts at 56.
fn two_stream_dump(
  a : (UInt32, Bytes),
  b : (UInt32, Bytes),
) -> Dump raise ParseError {
  let a_rva = 56
  let b_rva = a_rva + a.1.length()
  let buf = Buffer()
  buf.write_uint_le(expected_signature)
  buf.write_uint_le(0x0007_a793U)
  buf.write_uint_le(2U) // number_of_streams
  buf.write_uint_le(32U) // stream_directory_rva
  buf.write_uint_le(0U)
  buf.write_uint_le(1_730_000_000U)
  buf.write_uint64_le(0UL)
  buf.write_uint_le(a.0)
  buf.write_uint_le(a.1.length().reinterpret_as_uint())
  buf.write_uint_le(a_rva.reinterpret_as_uint())
  buf.write_uint_le(b.0)
  buf.write_uint_le(b.1.length().reinterpret_as_uint())
  buf.write_uint_le(b_rva.reinterpret_as_uint())
  buf.write_bytes(a.1)
  buf.write_bytes(b.1)
  open_dump(buf.to_bytes())
}

///|
/// The entry width is inferred solely from DataSize: real writers stuff ThreadEx records into
/// ThreadListStream(3), so stream type alone cannot decide.
test "Thread: entry width inferred from DataSize; a 64-byte record carries BackingStore" {
  let ex = thread_record(
    7U,
    0x1000UL,
    0x2000UL,
    8U,
    9U,
    1232U,
    300U,
    backing=Some(memory_descriptor(0x2000UL, 65536U, 400U)),
  )
  // a ThreadEx record appears in stream 3: still parsed at 64-byte width
  assert_eq(
    thread_list_outcome(thread_list_stream, [ex], None),
    "id=7,teb=0x1000,stk=0x2000+8@9,ctx=1232@300,bs=0x2000+65536@400,w=64",
  )
  // stream 8 only accepts 64 width: giving it a 48-byte record is a declared-size vs entry-count mismatch
  assert_eq(
    thread_list_outcome(
      thread_ex_list_stream,
      [thread_record(1U, 0UL, 0UL, 0U, 0U, 0U, 0U)],
      None,
    ),
    "ListSizeMismatch",
  )
  // 48 width + 4 bytes over is leniently allowed, 8 bytes over is rejected
  let t = thread_record(1U, 0UL, 0UL, 0U, 0U, 0U, 0U)
  assert_eq(
    thread_list_outcome(thread_list_stream, [t], Some(56U)),
    "id=1,teb=0x0,stk=0x0+0@0,ctx=0@0,bs=-,w=48",
  )
  assert_eq(
    thread_list_outcome(thread_list_stream, [t], Some(60U)),
    "ListSizeMismatch",
  )
  // count=0 is a legal empty table and must not report a length mismatch
  assert_eq(thread_list_outcome(thread_list_stream, [], Some(4U)), "")
  // declared long enough but the file is not: the range check happens first, no out-of-bounds read
  assert_eq(
    thread_table_outcome(thread_list_stream, 2U, [t], 100U),
    "Truncated",
  )
  // count=0 but DataSize claims more entries: the empty table returns directly without a width complaint
  assert_eq(thread_table_outcome(thread_list_stream, 0U, [], 100U), "")
}

///|
/// When ThreadList and ThreadExList both exist, the former wins (matching rust-minidump);
/// when only the latter exists it is still readable.
test "threads: stream 3 takes priority over stream 8" {
  let ex = cat([
    word(1U),
    thread_record(
      99U,
      0UL,
      0UL,
      0U,
      0U,
      0U,
      0U,
      backing=Some(memory_descriptor(0UL, 0U, 0U)),
    ),
  ])
  let plain = cat([word(1U), thread_record(7U, 0UL, 0UL, 0U, 0U, 0U, 0U)])
  let both = two_stream_dump(
    (thread_ex_list_stream, ex),
    (thread_list_stream, plain),
  )
  let ts = both.threads(both.stream_directory())
  match ts {
    None => assert_eq("should not be None", "none")
    Some(list) => {
      assert_eq(list.length(), 1)
      assert_eq(list[0].id, 7U)
      assert_eq(list[0].entry_size, 48U)
    }
  }
  let only_ex = two_stream_dump(
    (module_list_stream, zeros(4)),
    (thread_ex_list_stream, ex),
  )
  let ts2 = only_ex.threads(only_ex.stream_directory())
  match ts2 {
    None => assert_eq("stream 8 should be readable too", "none")
    Some(list) => {
      assert_eq(list[0].id, 99U)
      assert_eq(list[0].entry_size, 64U)
    }
  }
  let none = two_stream_dump(
    (module_list_stream, zeros(4)),
    (system_info_stream, fake_system_info(9, zeros(24))),
  )
  assert_eq(none.threads(none.stream_directory()), None)
}

///|
test "find_thread_by_id: the exception stream gives a thread ID, not an index" {
  let ts = [
    thread_record(10U, 0UL, 0UL, 0U, 0U, 0U, 0U),
    thread_record(20U, 0UL, 0UL, 0U, 0U, 0U, 0U),
  ]
  let dump = one_stream_dump(
    thread_list_stream,
    100U,
    zeros(0),
    cat([word(2U)] + ts),
  )
  let list = dump.read_thread_list(dump.stream_directory()[0])
  match find_thread_by_id(list, 20U) {
    None => assert_eq("should be found", "none")
    Some((i, t)) => {
      assert_eq(i, 1)
      assert_eq(t.id, 20U)
    }
  }
  assert_eq(find_thread_by_id(list, 999U), None)
  assert_eq(find_thread_by_id([], 10U), None)
}

///|
/// Places the payload at RVA 44; all that is needed is a Dump that can read bytes by absolute RVA to call
/// `read_context`. Neither the stream type nor DataSize participates, so any stream that will not be read automatically is fine.
fn context_probe(payload : Bytes) -> Dump raise ParseError {
  one_stream_dump(system_info_stream, 4U, payload, word(0U))
}

///|
/// read_context outcomes: `none` / error kind name / full summary line.
fn context_outcome(
  arch : UInt16,
  payload : Bytes,
  declared : UInt32,
) -> String raise {
  let dump = context_probe(payload)
  let loc : LocationDescriptor = { size: declared, rva: 44UL, }
  try dump.read_context(arch, loc) catch {
    err => error_kind(err)
  } noraise {
    ctx =>
      match ctx {
        None => "none"
        Some(c) => c.layout_name() + "/" + context_summary(c)
      }
  }
}

///|
/// x86: the offset table comes from winnt.h:8506 and has been cross-checked against test.dmp's bytes.
/// Here only a few sparse words are deliberately filled, proving "unset" reads back as 0 rather than sliding into neighboring fields.
test "CONTEXT x86: sparse fields read at offsets; segment registers stay DWORD" {
  let blob = sparse_words(716, [
    (0, 0x1003fU), // ContextFlags
    (1, 0x11U), // Dr0
    (35, 0x2bU), // SegGs@140
    (39, 0xaabb_ccddU), // Edi@156
    (44, 0x1U), // Eax@176
    (46, 0x4042_9eU), // Eip@184
    (47, 0x1bU), // SegCs@188
    (48, 0x246U), // EFlags@192
    (49, 0x12fe_84U), // Esp@196
    (50, 0x23U), // SegSs@200
  ])
  let dump = context_probe(blob)
  let loc : LocationDescriptor = { size: 716U, rva: 44UL, }
  // the three pointer methods are defined on Context and fetch exactly the three values you look at at a crash site
  match dump.read_context(0, loc) {
    Some(c) => {
      assert_eq(c.instruction_pointer(), Some(0x4042_9eUL))
      assert_eq(c.stack_pointer(), Some(0x12fe_84UL))
      assert_eq(c.frame_pointer(), Some(0UL))
    }
    None => assert_eq("should not be None", "none")
  }
  match dump.read_context(0, loc) {
    None => assert_eq("should not be None", "none")
    Some(X86(c)) => {
      assert_eq(c.context_flags, 0x1003fU)
      assert_eq(c.dr0, 0x11U)
      assert_eq(c.dr1, 0U)
      assert_eq(c.seg_gs, 0x2bU)
      assert_eq(c.edi, 0xaabb_ccddU)
      assert_eq(c.eax, 1U)
      assert_eq(c.eip, 0x4042_9eU)
      assert_eq(c.seg_cs, 0x1bU)
      assert_eq(c.eflags, 0x246U)
      assert_eq(c.esp, 0x12fe_84U)
      assert_eq(c.seg_ss, 0x23U)
      assert_eq(c.esi, 0U)
    }
    Some(other) =>
      assert_eq("the x86 table should have been used", other.layout_name())
  }
}

///|
/// amd64: segment registers are WORDs (from winnt.h:4304 on) and the easiest mistake is reading a whole DWORD,
/// so adjacent segments are filled with different values to check each half is read separately.
test "CONTEXT amd64: segment registers split as WORDs; RIP/RSP do not shift" {
  // word14 = SegCs@56 | SegDs@58<<16, word15 = SegEs@60 | SegFs@62<<16,
  // word16 = SegGs@64 | SegSs@66<<16
  let blob = sparse_words(1232, [
    (12, 0x10001fU), // ContextFlags@48
    (13, 0x1f80U), // MxCsr@52
    (14, 0x002b_0033U), // cs=0x33 ds=0x2b
    (15, 0x0000_002bU), // es=0x2b fs=0x00
    (16, 0x002b_0053U), // gs=0x53 ss=0x2b
    (17, 0x246U), // EFlags@68
    (18, 0xdeadU), // low 32 bits of Dr0@72
    (30, 0x11U), // Rax@120
    (38, 0x12fe_84U), // Rsp@152
    (46, 0x1U), // R8@184
    (60, 0x16U), // R15@240
    (62, 0x401d_72U), // Rip@248
  ])
  let dump = context_probe(blob)
  let loc : LocationDescriptor = { size: 1232U, rva: 44UL, }
  match dump.read_context(9, loc) {
    None => assert_eq("should not be None", "none")
    Some(Amd64(c)) => {
      assert_eq(c.context_flags, 0x10001fU)
      assert_eq(c.mx_csr, 0x1f80U)
      assert_eq(c.seg_cs, 0x33)
      assert_eq(c.seg_ds, 0x2b)
      assert_eq(c.seg_es, 0x2b)
      assert_eq(c.seg_fs, 0)
      assert_eq(c.seg_gs, 0x53)
      assert_eq(c.seg_ss, 0x2b)
      assert_eq(c.eflags, 0x246U)
      assert_eq(c.dr0, 0xdeadUL)
      assert_eq(c.dr1, 0UL)
      assert_eq(c.rax, 0x11UL)
      assert_eq(c.rsp, 0x12fe_84UL)
      assert_eq(c.r8, 1UL)
      assert_eq(c.r15, 0x16UL)
      assert_eq(c.rip, 0x401d_72UL)
      assert_eq(c.rbp, 0UL)
    }
    Some(other) =>
      assert_eq("the amd64 table should have been used", other.layout_name())
  }
  // the register listing order is part of the external contract (the CLI and --json use it directly)
  let names : Array[String] = []
  match dump.read_context(9, loc) {
    Some(c) => {
      for (n, _) in c.registers() {
        names.push(n)
      }
      assert_eq(c.instruction_pointer(), Some(0x401d_72UL))
      assert_eq(c.stack_pointer(), Some(0x12fe_84UL))
    }
    None => ()
  }
  assert_eq(
    names.join(","),
    "flags,rip,rsp,rbp,rax,rbx,rcx,rdx,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,eflags,cs,ss,ds,es,fs,gs,mxcsr,dr0,dr1,dr2,dr3,dr6,dr7",
  )
}

///|
/// arm64: the inline comment at winnt.h:6796 is the only source (the corpus has no arm64 dump),
/// so the offsets themselves are tested exhaustively: X register stride, Fp/Lr/Sp/Pc positions, debug register arrays.
test "CONTEXT arm64: X registers, Sp/Pc, and debug arrays read at header-comment offsets" {
  let blob = sparse_words(912, [
    (0, 0x400000U), // ContextFlags
    (1, 0x6000_0000U), // Cpsr@4
    (12, 0x55U), // X5@0x30, low half
    (58, 0x77U), // X28@0xe8, low half
    (60, 0x88U), // Fp@0xf0
    (62, 0x99U), // Lr@0xf8
    (64, 0xaaU), // Sp@0x100
    (66, 0xbbU), // Pc@0x108
    (196, 0x1U), // Fpcr@0x310
    (197, 0x2U), // Fpsr@0x314
    (198, 0x3U), // Bcr[0]@0x318
    (206, 0x4U), // Bvr[0]@0x338
    (222, 0x5U), // Wcr[0]@0x378
    (224, 0x6U), // Wvr[0]@0x380
  ])
  let dump = context_probe(blob)
  let loc : LocationDescriptor = { size: 912U, rva: 44UL, }
  match dump.read_context(12, loc) {
    None => assert_eq("should not be None", "none")
    Some(Arm64(c)) => {
      assert_eq(c.context_flags, 0x400000U)
      assert_eq(c.cpsr, 0x6000_0000U)
      assert_eq(c.x.length(), 31)
      assert_eq(c.x[5], 0x55UL)
      assert_eq(c.x[28], 0x77UL)
      assert_eq(c.x[29], 0x88UL) // Fp is X29
      assert_eq(c.x[30], 0x99UL) // Lr is X30
      assert_eq(c.sp, 0xaaUL)
      assert_eq(c.pc, 0xbbUL)
      assert_eq(c.fpcr, 1U)
      assert_eq(c.fpsr, 2U)
      assert_eq(c.bcr.length(), 8)
      assert_eq(c.bcr[0], 3U)
      assert_eq(c.bvr.length(), 8)
      assert_eq(c.bvr[0], 4UL)
      assert_eq(c.wcr.length(), 2)
      assert_eq(c.wcr[0], 5U)
      assert_eq(c.wvr.length(), 2)
      assert_eq(c.wvr[0], 6UL)
    }
    Some(other) =>
      assert_eq("the arm64 table should have been used", other.layout_name())
  }
  match dump.read_context(12, loc) {
    Some(c) => {
      assert_eq(c.instruction_pointer(), Some(0xbbUL))
      assert_eq(c.stack_pointer(), Some(0xaaUL))
      // the arm64 frame pointer is X29, so the pointer trio holds for it too
      assert_eq(c.frame_pointer(), Some(0x88UL))
    }
    None => assert_eq("should not be None", "none")
  }
  // arm64EC(0x8003) shares the same table as arm64
  assert_eq(context_outcome(0x8003, blob, 912U).contains("pc=0xbb"), true)
}

///|
/// The three outcomes when architecture and declared length contradict each other, none of them guessed:
/// the length is exactly the canonical length of another tier's table → switch tables; the architecture has no table → honestly report undecoded;
/// neither side matches → report an error.
test "CONTEXT: WOW64 table switch / Undecoded for tableless arch / mismatched length errors" {
  // a 716-byte x86 layout, but SystemInfo says amd64 (a 32-bit process on a 64-bit system)
  let x86_blob = sparse_words(716, [(0, 0x1003fU), (46, 0x4042_9eU)])
  assert_eq(
    context_outcome(9, x86_blob, 716U),
    "x86/x86 flags=0x1003f eip=0x40429e esp=0x0 ebp=0x0 eax=0x0 ebx=0x0 ecx=0x0 edx=0x0 esi=0x0 edi=0x0 eflags=0x0 cs=0x0 ss=0x0 ds=0x0 es=0x0 fs=0x0 gs=0x0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
  )
  // declared longer than the table: still read with this architecture's table, the extra part is not guessed at
  let amd_blob = sparse_words(1232, [(12, 0x10001fU), (62, 0x401d_72U)])
  assert_eq(context_outcome(9, amd_blob, 1300U).contains("amd64/"), true)
  // the reverse: SystemInfo says x86 but the context has 1232 bytes, read with the amd64 table implied by the length
  assert_eq(context_outcome(0, amd_blob, 1232U).contains("amd64/"), true)
  // 32-bit ARM: the local SDK computes 416 bytes, which does not match the older layout minidump uses, so only the length is reported
  assert_eq(
    context_outcome(5, sparse_words(368, [(0, 0x1001fU)]), 368U),
    "undecoded/undecoded arch=0x5 size=368",
  )
  assert_eq(
    context_outcome(0xd, sparse_words(1232, []), 1232U),
    "undecoded/undecoded arch=0xd size=1232",
  )
  // neither this architecture's table nor any tier's canonical length: report an error explicitly, never force-read with the nearest table
  assert_eq(
    context_outcome(9, sparse_words(800, []), 800U),
    "ContextSizeMismatch",
  )
  assert_eq(
    describe_error(ContextSizeMismatch(9, 800U, context_amd64_size)).contains(
      "1232",
    ),
    true,
  )
  // the generator never wrote a context: size=0 or rva=0 both count as "absent"
  assert_eq(context_outcome(9, sparse_words(1232, []), 0U), "none")
  let dump = context_probe(sparse_words(1232, []))
  let zero_rva : LocationDescriptor = { size: 1232U, rva: 0UL, }
  assert_eq(dump.read_context(9, zero_rva), None)
  // the table itself: ARM(5) is deliberately absent, and the canonical lengths of amd64/x86/arm64 do not overlap
  assert_eq(context_expected_size(5), None)
  assert_eq(context_expected_size(9), Some(context_amd64_size))
  assert_eq(context_expected_size(10), Some(context_x86_size))
  assert_eq(context_arch_by_size(796U), None)
  assert_eq(context_arch_by_size(context_x86_size), Some(0))
}

///|
test "describe_context_flags: a missing base bit is still reported; unknown bits are not silently dropped" {
  assert_eq(
    describe_context_flags(0, 0x1003fU).join("|"),
    "ARCH_BASE(0x10000)|CONTROL|INTEGER|SEGMENTS|FLOATING_POINT|DEBUG_REGISTERS|EXTENDED_REGISTERS",
  )
  // amd64's 0x10001f: the integer, segment, floating-point, and debug groups are all set, no XSTATE/CET
  assert_eq(
    describe_context_flags(9, 0x10001fU).join("|"),
    "ARCH_BASE(0x100000)|CONTROL|INTEGER|SEGMENTS|FLOATING_POINT|DEBUG_REGISTERS",
  )
  assert_eq(
    describe_context_flags(9, 0x1fU).join("|"),
    "MissingArchBase(0x100000)|CONTROL|INTEGER|SEGMENTS|FLOATING_POINT|DEBUG_REGISTERS",
  )
  // only the CONTROL bit: at crash triage "only ip/sp are trustworthy" is exactly this
  assert_eq(
    describe_context_flags(9, 0x100001U).join("|"),
    "ARCH_BASE(0x100000)|CONTROL",
  )
  assert_eq(
    describe_context_flags(9, 0x100080U).join("|"),
    "ARCH_BASE(0x100000)|KERNEL_CET",
  )
  // base bit off + one unclaimed high bit: both must be stated explicitly
  assert_eq(
    describe_context_flags(9, 0x1000_0001U).join("|"),
    "MissingArchBase(0x100000)|CONTROL|Unknown(0x10000000)",
  )
  assert_eq(
    describe_context_flags(9, 0x110_0001U).join("|"),
    "ARCH_BASE(0x100000)|CONTROL|Unknown(0x1000000)",
  )
  // arm64's per-bit semantics were not verified independently; only the numeric value is given
  assert_eq(
    describe_context_flags(12, 0x400000U).join("|"),
    "ARCH_BASE(0x400000)",
  )
  assert_eq(
    describe_context_flags(12, 0x1U).join("|"),
    "MissingArchBase(0x400000)|Unknown(0x1)",
  )
}

///|
/// A 168-byte MINIDUMP_EXCEPTION_STREAM: ThreadId4 + alignment4 + exception record 152 +
/// ThreadContext8. The parameters are always written as a full 15 (120 bytes) so the later offsets do not all shift.
fn exception_bytes(
  thread_id : UInt32,
  code : UInt32,
  flags : UInt32,
  nested : UInt64,
  address : UInt64,
  declared_params : UInt32,
  params : Array[UInt64],
  ctx_size : UInt32,
  ctx_rva : UInt32,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(thread_id)
  buf.write_uint_le(0U) // __alignment
  buf.write_uint_le(code)
  buf.write_uint_le(flags)
  buf.write_uint64_le(nested)
  buf.write_uint64_le(address)
  buf.write_uint_le(declared_params)
  buf.write_uint_le(0U) // __unusedAlignment
  for i in 0..<15 {
    let v = if i < params.length() { params[i] } else { 0UL }
    buf.write_uint64_le(v)
  }
  buf.write_uint_le(ctx_size)
  buf.write_uint_le(ctx_rva)
  buf.to_bytes()
}

///|
/// A parse summary of the exception stream. `got` is the number of parameters actually taken, reported
/// separately from the declared `np`, which is what makes the truncation visible.
fn exception_outcome(payload : Bytes, declared : UInt32?) -> String raise {
  let size = match declared {
    None => payload.length().reinterpret_as_uint()
    Some(s) => s
  }
  let dump = one_stream_dump(exception_stream, size, zeros(0), payload)
  try dump.read_exception(dump.stream_directory()[0]) catch {
    err => error_kind(err)
  } noraise {
    e =>
      "tid=" +
      e.thread_id.to_string() +
      " code=" +
      hex_uint(e.code.to_uint64()) +
      " flags=" +
      e.flags.to_string() +
      " nest=" +
      hex_uint(e.nested_record_address) +
      " addr=" +
      hex_uint(e.address) +
      " np=" +
      e.number_parameters.to_string() +
      " got=" +
      e.parameters.length().to_string() +
      " p0=" +
      (if e.parameters.length() == 0 { "-" } else { hex_uint(e.parameters[0]) }) +
      " p" +
      (e.parameters.length() - 1).to_string() +
      "=" +
      (if e.parameters.length() == 0 {
        "-"
      } else {
        hex_uint(e.parameters[e.parameters.length() - 1])
      }) +
      " ctx=" +
      e.thread_context.size.to_string() +
      "@" +
      e.thread_context.rva.to_string()
  }
}

///|
/// Reading parameters out of bounds is the classic pitfall of these fixed-length structs: even with 99 declared only 15 can be taken,
/// because the slot of the 16th "parameter" is exactly where ThreadContext lives.
test "ExceptionStream: fields read one by one; parameter count truncated at 15" {
  let params : Array[UInt64] = []
  for i in 1..<16 {
    params.push(i.to_uint64())
  }
  let full = exception_bytes(
    4242U, 0xc000_0005U, 0U, 0xdead_beefUL, 0x4042_9eUL, 15U, params, 716U, 2760U,
  )
  assert_eq(full.length(), 168)
  assert_eq(
    exception_outcome(full, None),
    "tid=4242 code=0xc0000005 flags=0 nest=0xdeadbeef addr=0x40429e np=15 got=15 p0=0x1 p14=0xf ctx=716@2760",
  )
  assert_eq(
    exception_outcome(
      exception_bytes(1U, 0xc000_0005U, 0U, 0UL, 0UL, 99U, params, 716U, 2760U),
      None,
    ),
    "tid=1 code=0xc0000005 flags=0 nest=0x0 addr=0x0 np=99 got=15 p0=0x1 p14=0xf ctx=716@2760",
  )
  // 0 declared: parameters is an empty array, not "read a single 0"
  assert_eq(
    exception_outcome(
      exception_bytes(1U, 0x8000_0003U, 0U, 0UL, 0UL, 0U, [], 1232U, 4530U),
      None,
    ),
    "tid=1 code=0x80000003 flags=0 nest=0x0 addr=0x0 np=0 got=0 p0=- p-1=- ctx=1232@4530",
  )
  // under 168: the exception stream has no "shorter legal version", so reject outright
  let tiny = exception_bytes(1U, 0U, 0U, 0UL, 0UL, 0U, [], 0U, 0U)
  assert_eq(exception_outcome(tiny, Some(167U)), "StreamTooSmall")
  assert_eq(exception_outcome(tiny, Some(168U)).contains("np=0 got=0"), true)
  // no exception stream in the directory means "no crash site", not an error
  let none = one_stream_dump(module_list_stream, 4U, zeros(0), word(0U))
  assert_eq(none.exception(none.stream_directory()), None)
}

///|
test "exception code labels: Windows consults the code table, the Linux family signals, macOS stays Unknown" {
  assert_eq(
    exception_code_label(0x2U, 0xc000_0005U),
    "EXCEPTION_ACCESS_VIOLATION",
  )
  assert_eq(exception_code_label(0U, 0x8000_0003U), "EXCEPTION_BREAKPOINT")
  // Linux(0x8000) / the Android family (0x8201...): the ExceptionCode is the signal number
  assert_eq(exception_code_label(0x8201U, 0xbU), "SIGSEGV")
  assert_eq(exception_code_label(0x8000U, 4U), "SIGILL")
  assert_eq(exception_code_label(0x8203U, 31U), "SIGSYS")
  // if not in the signal table, say plainly it is a signal rather than passing it off as a Windows code
  assert_eq(exception_code_label(0x8201U, 64U), "Signal(0x40)")
  // macOS/iOS writes Mach exceptions; do not force the signal table onto them
  assert_eq(exception_code_label(0x8101U, 0xbU), "Unknown(0xb)")
  assert_eq(exception_code_label(0x8102U, 0U), "Unknown(0x0)")
  assert_eq(signal_name(9U), Some("SIGKILL"))
  assert_eq(signal_name(0U), None)
  assert_eq(platform_uses_signals(0x8101U), false)
  assert_eq(describe_exception_flags(0U).join("|"), "")
  assert_eq(describe_exception_flags(1U).join("|"), "NONCONTINUABLE")
  // 6 = 0b110: the lowest bit is off, so the whole set is reserved bits
  assert_eq(describe_exception_flags(6U).join("|"), "Reserved(0x6)")
  assert_eq(
    describe_exception_flags(7U).join("|"),
    "NONCONTINUABLE|Reserved(0x6)",
  )
}

///|
test "memory access exceptions: read/write/DEP and target address apply only to these two code classes" {
  let av = exception_bytes(
    1U,
    0xc000_0005U,
    0U,
    0UL,
    0x4042_9eUL,
    2U,
    [1UL, 0x45UL],
    716U,
    2760U,
  )
  let dump = one_stream_dump(exception_stream, 168U, zeros(0), av)
  let e = dump.read_exception(dump.stream_directory()[0])
  assert_eq(e.is_memory_access(), true)
  assert_eq(memory_access_kind(e.code, e.parameters), Some("write"))
  assert_eq(e.fault_address(), Some(0x45UL))
  assert_eq(e.underlying_status(), None)
  // 0=read, 8=user-mode DEP; anything else is given as a numeric value
  assert_eq(memory_access_kind(0xc000_0005U, [0UL, 1UL]), Some("read"))
  assert_eq(memory_access_kind(0xc000_0005U, [8UL, 1UL]), Some("dep-execute"))
  assert_eq(memory_access_kind(0xc000_0005U, [3UL]), Some("Unknown(0x3)"))
  // the 3rd parameter of IN_PAGE_ERROR carries the real cause
  let ipe = exception_bytes(
    1U,
    0xc000_0006U,
    0U,
    0UL,
    0UL,
    3U,
    [0UL, 0x1000UL, 0xc000_0011UL],
    0U,
    0U,
  )
  let ipe_dump = one_stream_dump(exception_stream, 168U, zeros(0), ipe)
  let e2 = ipe_dump.read_exception(ipe_dump.stream_directory()[0])
  assert_eq(e2.underlying_status(), Some(0xc000_0011UL))
  assert_eq(e2.fault_address(), Some(0x1000UL))
  // BREAKPOINT has no such convention: it must give None, not casually report a read
  assert_eq(memory_access_kind(0x8000_0003U, [0UL, 0UL]), None)
  assert_eq(memory_access_kind(0xc000_0005U, []), None)
  // no target address when there is only one parameter
  let one = exception_bytes(1U, 0xc000_0005U, 0U, 0UL, 0UL, 1U, [1UL], 0U, 0U)
  let one_dump = one_stream_dump(exception_stream, 168U, zeros(0), one)
  assert_eq(
    one_dump.read_exception(one_dump.stream_directory()[0]).fault_address(),
    None,
  )
}

///|
test "address_module_line: a hit gives module name+offset; an unnamed module gets an index; 0 and out-of-range are reported separately" {
  let named = single_module_dump("a.pdb", "a.dll")
  let modules = match named.modules(named.stream_directory()) {
    None => []
    Some(list) => list.modules
  }
  assert_eq(address_module_line(modules, 0x400000UL), "a.dll+0x0")
  assert_eq(address_module_line(modules, 0x4010_10UL), "a.dll+0x1010")
  assert_eq(address_module_line(modules, 0x42d000UL), "not inside any module")
  assert_eq(address_module_line(modules, 0x0UL), "address is 0")
  assert_eq(address_module_line([], 0x1000UL), "not inside any module")
  // when the name string was not written (name_rva=0), give the index instead of passing off an empty name as the module name
  let anon = module_table_dump([module_record(0x1000UL, 0x1000U)], None)
  let anon_modules = match anon.modules(anon.stream_directory()) {
    None => []
    Some(list) => list.modules
  }
  assert_eq(anon_modules[0].name, "")
  assert_eq(address_module_line(anon_modules, 0x1010UL), "module#0+0x10")
  // when ranges overlap the first hit wins, matching rust-minidump's module list behavior
  let overlap = module_table_dump(
    [module_record(0x1000UL, 0x2000U), module_record(0x1000UL, 0x1000U)],
    None,
  )
  let om = match overlap.modules(overlap.stream_directory()) {
    None => []
    Some(list) => list.modules
  }
  match find_module(om, 0x1500UL) {
    None => assert_eq("should hit", "none")
    Some((i, _)) => assert_eq(i, 0)
  }
  assert_eq(om[0].offset_of(0x3000UL), None)
}
