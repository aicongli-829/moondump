// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! Long-tail streams (format-layer finishers): ThreadNames / UnloadedModuleList
///! / HandleData / FunctionTable / ThreadInfoList.
///!
///! Every offset here comes from the local SDK
///! (`10.0.26100.0\um\minidumpapiset.h`), with the line numbers written into the
///! comments for each one. For streams the SDK defines no struct for —
///! CommentStreamA/W(10/11), HandleOperationList(18)'s AVRF_HANDLE_OPERATION,
///! SystemMemoryInfo(21), ProcessVmCounters(22), and the Breakpad/Crashpad
///! 0x4767…/0x4350…/0x4d7a… series — no guessing parsers are written; they are
///! only listed with their number and length as-is in the stream directory.
///! A wrong offset is worse than not parsing: it produces wrong data that looks
///! perfectly plausible.

///|
/// ThreadNamesStream (24).
/// `MINIDUMP_THREAD_NAME { ULONG ThreadId; RVA64 RvaOfThreadName }`,
/// `MINIDUMP_THREAD_NAME_LIST { ULONG NumberOfThreadNames; ... }`
/// (`um\minidumpapiset.h:719`, `:724`).
/// In C this struct is 8-byte aligned and would be padded to 16 bytes, but the
/// dump writes it compactly: a real 568-byte stream measured (568-4)/12=47
/// entries exactly, while /16 does not divide evenly, so the stride is 12.
pub let thread_names_header_size : UInt32 = 4U

///|
pub let thread_name_entry_size : UInt32 = 12U

///|
#derive(Debug, Eq)
pub(all) struct ThreadName {
  thread_id : UInt32
  name : String
}

///|
pub extend ThreadName with Debug::{to_repr}

///|
pub extend ThreadName with Eq::{equal, not_equal}

///|
pub fn Dump::read_thread_names(
  self : Dump,
  entry : StreamEntry,
) -> Array[ThreadName] raise ParseError {
  let count = self.read_uint32(entry.rva).to_uint64()
  let need = list_need(count, thread_name_entry_size, thread_names_header_size)
  check_list_room(entry.stream_type, entry.data_size, need)
  if !self.range_in_file(entry.rva, need) {
    raise ParseError::Truncated(entry.rva, need, self.data.length().to_uint64())
  }
  let items : Array[ThreadName] = []
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva +
      thread_names_header_size.to_uint64() +
      i * thread_name_entry_size.to_uint64()
    items.push({
      thread_id: self.read_uint32(base),
      name: self.read_optional_string(self.read_uint64(base + 4UL)),
    })
    i = i + 1UL
  }
  items
}

///|
pub fn Dump::thread_names(
  self : Dump,
  entries : Array[StreamEntry],
) -> Array[ThreadName]? raise ParseError {
  match get_stream(entries, thread_names_stream) {
    None => None
    Some(entry) => Some(self.read_thread_names(entry))
  }
}

///|
/// Look up a name by thread id. Returns None when absent — "no such record"
/// and "the name is an empty string" are not the same thing.
pub fn thread_name_for(names : Array[ThreadName], id : UInt32) -> String? {
  let mut out : String? = None
  for n in names {
    if n.thread_id == id && out is None {
      out = Some(n.name)
    }
  }
  out
}

///|
/// UnloadedModuleListStream (14).
/// A 12-byte header `SizeOfHeader/SizeOfEntry/NumberOfEntries`; entries are
/// 24 bytes: `BaseOfImage u64 / SizeOfImage u32 / CheckSum u32 /
/// TimeDateStamp u32 / ModuleNameRva u32` (`um\minidumpapiset.h:538`, `:550`).
/// In the sample analysis this stream is how "modules that were loaded and
/// then unloaded" are identified — after injected code exits, only this is left.
pub let unloaded_module_list_header_size : UInt32 = 12U

///|
pub let unloaded_module_size : UInt32 = 24U

///|
#derive(Debug, Eq)
pub(all) struct UnloadedModule {
  base_of_image : UInt64
  size_of_image : UInt32
  checksum : UInt32
  time_date_stamp : UInt32
  name : String
}

///|
pub extend UnloadedModule with Debug::{to_repr}

///|
pub extend UnloadedModule with Eq::{equal, not_equal}

///|
/// Same as `Module::end_address`: the wraparound itself is exactly what is
/// wanted here. Callers recognize malformed "base+size overflow" records via
/// `end_address() < base_of_image`. Saturating addition would erase this clue
/// (saturating to all ones, never less than the base).
pub fn UnloadedModule::end_address(self : UnloadedModule) -> UInt64 {
  self.base_of_image + self.size_of_image.to_uint64()
}

///|
#derive(Debug, Eq)
pub(all) struct UnloadedModuleList {
  modules : Array[UnloadedModule]
  skipped : UInt32
  declared_count : UInt64
}

///|
pub extend UnloadedModuleList with Debug::{to_repr}

///|
pub extend UnloadedModuleList with Eq::{equal, not_equal}

///|
/// Skipping rules match the module table: `size_of_image == 0`, or the
/// interval addition wraps around.
pub fn Dump::read_unloaded_module_list(
  self : Dump,
  entry : StreamEntry,
) -> UnloadedModuleList raise ParseError {
  let declared_header = self.read_uint32(entry.rva)
  let width = self.read_uint32(entry.rva + 4UL)
  let count = self.read_uint32(entry.rva + 8UL).to_uint64()
  let header = if declared_header < unloaded_module_list_header_size {
    unloaded_module_list_header_size
  } else {
    declared_header
  }
  if width < unloaded_module_size {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      unloaded_module_size.to_uint64(),
      width.to_uint64(),
    )
  }
  if count == 0UL {
    return { modules: [], skipped: 0U, declared_count: 0UL, }
  }
  let need = list_need(count, width, header)
  check_list_room(entry.stream_type, entry.data_size, need)
  if !self.range_in_file(entry.rva, need) {
    raise ParseError::Truncated(entry.rva, need, self.data.length().to_uint64())
  }
  let items : Array[UnloadedModule] = []
  let mut skipped = 0U
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva + header.to_uint64() + i * width.to_uint64()
    let size = self.read_uint32(base + 8UL)
    let m : UnloadedModule = {
      base_of_image: self.read_uint64(base),
      size_of_image: size,
      checksum: self.read_uint32(base + 12UL),
      time_date_stamp: self.read_uint32(base + 16UL),
      name: self.read_optional_string(self.read_uint32(base + 20UL).to_uint64()),
    }
    if size == 0U || m.end_address() < m.base_of_image {
      skipped = skipped + 1U
    } else {
      items.push(m)
    }
    i = i + 1UL
  }
  { modules: items, skipped, declared_count: count, }
}

///|
pub fn Dump::unloaded_modules(
  self : Dump,
  entries : Array[StreamEntry],
) -> UnloadedModuleList? raise ParseError {
  match get_stream(entries, unloaded_module_list_stream) {
    None => None
    Some(entry) => Some(self.read_unloaded_module_list(entry))
  }
}

///|
/// HandleDataStream (12).
/// A 16-byte header `SizeOfHeader/SizeOfDescriptor/NumberOfDescriptors/Reserved`;
/// a v1 descriptor is 32 bytes, a v2 descriptor adds `ObjectInfoRva + Reserved0`
/// for 40 bytes total (`um\minidumpapiset.h:464`, `:474`, `:490`).
/// A handle's type name and object name are the direct clues for investigating
/// named kernel objects, mutexes, and shared memory, so these two RVAs must be
/// decoded into strings, not just reported as numbers.
pub let handle_data_header_size : UInt32 = 16U

///|
pub let handle_descriptor_size : UInt32 = 32U

///|
pub let handle_descriptor_2_size : UInt32 = 40U

///|
#derive(Debug, Eq)
pub(all) struct Handle {
  handle : UInt64
  type_name : String
  object_name : String
  attributes : UInt32
  granted_access : UInt32
  handle_count : UInt32
  pointer_count : UInt32
  /// Not present in a v1 descriptor; taken as 0.
  object_info_rva : UInt64
  descriptor_size : UInt32
}

///|
pub extend Handle with Debug::{to_repr}

///|
pub extend Handle with Eq::{equal, not_equal}

///|
pub fn Dump::read_handle_data(
  self : Dump,
  entry : StreamEntry,
) -> Array[Handle] raise ParseError {
  let declared_header = self.read_uint32(entry.rva)
  let width = self.read_uint32(entry.rva + 4UL)
  let count = self.read_uint32(entry.rva + 8UL).to_uint64()
  let header = if declared_header < handle_data_header_size {
    handle_data_header_size
  } else {
    declared_header
  }
  if width < handle_descriptor_size {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      handle_descriptor_size.to_uint64(),
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
  let items : Array[Handle] = []
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva + header.to_uint64() + i * width.to_uint64()
    // Only the v2 40-byte descriptor carries ObjectInfoRva.
    let info = if width >= handle_descriptor_2_size {
      self.read_uint32(base + 32UL).to_uint64()
    } else {
      0UL
    }
    items.push({
      handle: self.read_uint64(base),
      type_name: self.read_optional_string(
        self.read_uint32(base + 8UL).to_uint64(),
      ),
      object_name: self.read_optional_string(
        self.read_uint32(base + 12UL).to_uint64(),
      ),
      attributes: self.read_uint32(base + 16UL),
      granted_access: self.read_uint32(base + 20UL),
      handle_count: self.read_uint32(base + 24UL),
      pointer_count: self.read_uint32(base + 28UL),
      object_info_rva: info,
      descriptor_size: width,
    })
    i = i + 1UL
  }
  items
}

///|
pub fn Dump::handles(
  self : Dump,
  entries : Array[StreamEntry],
) -> Array[Handle]? raise ParseError {
  match get_stream(entries, handle_data_stream) {
    None => None
    Some(entry) => Some(self.read_handle_data(entry))
  }
}

///|
/// FunctionTableStream (13, written as FunctionListStream in some docs).
/// A 24-byte header `SizeOfHeader/SizeOfDescriptor/SizeOfNativeDescriptor/
/// SizeOfFunctionEntry/NumberOfDescriptors/SizeOfAlignPad`;
/// descriptors are 32 bytes: `MinimumAddress/MaximumAddress/BaseAddress
/// (each u64) + EntryCount u32 + pad u32` (`um\minidumpapiset.h:514`, `:522`).
///
/// **But writers do not all follow that layout.** Measured on a local WER dump:
/// the stream is 21268 bytes and the header declares 24/32/136/12/113/4. Reading
/// with the declared stride of 32, only 6 of the 113 descriptors have addresses
/// that still look like Windows user-mode virtual addresses; after switching to
/// "the array starts at `SizeOfHeader + SizeOfAlignPad`, and each record occupies
/// `SizeOfDescriptor + SizeOfNativeDescriptor + SizeOfFunctionEntry +
/// SizeOfAlignPad` = 184 bytes", all 113/113 are self-consistent, and the 12
/// bytes inlined in each record are exactly an x64 `IMAGE_FUNCTION_ENTRY`
/// (RVAs of the magnitude `BeginAddress=0, EndAddress=0x280,
/// UnwindInfoAddress=0x298`). Exhausting start∈[24,40] and stride∈[32,400]
/// (both 4-aligned), only the (28,184) pair makes all records self-consistent —
/// so this layer computes both layouts, picks the self-consistent one, and
/// records the choice in `layout` so callers can see the confidence. When
/// neither is self-consistent, fall back to the declared stride and set
/// `layout_ok=false`. The entry contents are architecture-dependent; this layer
/// only reports "where, how many, how wide, readable or not" — decoding is left
/// to the caller that needs it.
pub let function_table_header_size : UInt32 = 24U

///|
pub let function_table_descriptor_size : UInt32 = 32U

///|
/// The two layouts of the descriptor array.
#derive(Debug, Eq)
pub enum FunctionTableLayout {
  /// What the SDK declares: descriptors packed contiguously right after the
  /// header, the function entries themselves after the array.
  Declared
  /// Measured WER layout: each record = pad + descriptor + native descriptor +
  /// inline function entry. Under this layout there is no separate "entry
  /// area"; `entries_rva` is only the end of the record region — do not use it
  /// as an offset.
  InlineRecords
}

///|
pub extend FunctionTableLayout with Debug::{to_repr}

///|
pub extend FunctionTableLayout with Eq::{equal, not_equal}

///|
pub fn function_table_layout_name(layout : FunctionTableLayout) -> String {
  match layout {
    Declared => "Declared"
    InlineRecords => "InlineRecords"
  }
}

///|
/// Plausibility check for a user-mode virtual address range — **used only to
/// choose between the two layouts, never to reject data**. Top 48 bits nonzero,
/// minimum below the smallest usable address, maximum below minimum, base below
/// minimum, span over 4GB (`SizeOfImage` itself is 32-bit), EntryCount
/// absurdly large — any one holding means the offset at this step has gone off
/// the rails. User-mode addresses on x64/ARM64 never exceed 48 bits.
fn function_table_descriptor_is_plausible(
  minimum : UInt64,
  maximum : UInt64,
  base : UInt64,
  entry_count : UInt32,
) -> Bool {
  let limit = 0x1000_0000_0000_0000UL
  let span_limit = 0x1_0000_0000UL
  minimum >= 0x1000UL &&
  minimum < limit &&
  maximum < limit &&
  base < limit &&
  maximum >= minimum &&
  maximum - minimum < span_limit &&
  base >= minimum &&
  base - minimum < span_limit &&
  entry_count < 1_000_000U
}

///|
/// Whether `array_offset + count * record_width` lands both within the
/// stream's declared length and inside the file. Saturating arithmetic
/// guarantees a malformed count fails this check outright instead of wrapping
/// into a small number and slipping through.
fn Dump::ft_span_fits(
  self : Dump,
  entry : StreamEntry,
  array_offset : UInt64,
  record_width : UInt64,
  count : UInt64,
) -> Bool {
  let span = add_saturating(array_offset, mul_saturating(count, record_width))
  span <= entry.data_size.to_uint64() && self.range_in_file(entry.rva, span)
}

///|
/// Pull out each descriptor under the given layout and take a look. The count
/// field is already bounded by `ft_span_fits`, so this never spins forever on
/// a huge count.
fn Dump::ft_records_plausible(
  self : Dump,
  rva : UInt64,
  array_offset : UInt64,
  record_width : UInt64,
  count : UInt64,
) -> Bool raise ParseError {
  let mut i : UInt64 = 0UL
  let mut ok = true
  while i < count && ok {
    let base = rva + array_offset + i * record_width
    ok = function_table_descriptor_is_plausible(
      self.read_uint64(base),
      self.read_uint64(base + 8UL),
      self.read_uint64(base + 16UL),
      self.read_uint32(base + 24UL),
    )
    i = i + 1UL
  }
  ok
}

///|
#derive(Debug, Eq)
pub(all) struct FunctionTable {
  minimum_address : UInt64
  maximum_address : UInt64
  base_address : UInt64
  entry_count : UInt32
  /// The function entry inlined in the record under the `InlineRecords`
  /// layout (on x64 it is three RVAs: BeginAddress/EndAddress/UnwindInfoAddress).
  /// Always None under the `Declared` layout, when `EntryCount==0`, or when the
  /// slot runs past the record or the file —
  /// "this one has none" and "this one is 0" are different facts here.
  inline_entry : (UInt32, UInt32, UInt32)?
}

///|
pub extend FunctionTable with Debug::{to_repr}

///|
pub extend FunctionTable with Eq::{equal, not_equal}

///|
#derive(Debug, Eq)
pub(all) struct FunctionTableInfo {
  descriptors : Array[FunctionTable]
  size_of_descriptor : UInt32
  size_of_native_descriptor : UInt32
  size_of_function_entry : UInt32
  declared_header : UInt32
  /// The alignment padding declared by the header; both the offset and the
  /// stride of the `InlineRecords` layout use it.
  size_of_align_pad : UInt32
  /// The layout actually adopted, and whether this choice passed the
  /// self-consistency check.
  layout : FunctionTableLayout
  layout_ok : Bool
  /// Bytes per record under the adopted layout (for `Declared` this is
  /// size_of_descriptor).
  record_width : UInt64
  entries_rva : UInt64
  total_entries : UInt64
  /// Whether the function entry area fully lands inside the file; when it does
  /// not, only the descriptors can be reported. Under `InlineRecords` this
  /// means "every record's inline slot is inside the file".
  entries_in_file : Bool
}

///|
pub extend FunctionTableInfo with Debug::{to_repr}

///|
pub extend FunctionTableInfo with Eq::{equal, not_equal}

///|
pub fn Dump::read_function_table(
  self : Dump,
  entry : StreamEntry,
) -> FunctionTableInfo raise ParseError {
  let declared_header = self.read_uint32(entry.rva)
  let width = self.read_uint32(entry.rva + 4UL)
  let native = self.read_uint32(entry.rva + 8UL)
  let fn_width = self.read_uint32(entry.rva + 12UL)
  let count = self.read_uint32(entry.rva + 16UL).to_uint64()
  let align_pad = self.read_uint32(entry.rva + 20UL)
  let header = if declared_header < function_table_header_size {
    function_table_header_size
  } else {
    declared_header
  }
  if width < function_table_descriptor_size {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      function_table_descriptor_size.to_uint64(),
      width.to_uint64(),
    )
  }
  // Candidate one: the SDK-declared layout.
  let declared_need = list_need(count, width, header)
  let declared_offset = header.to_uint64()
  let declared_fits = self.ft_span_fits(
    entry,
    declared_offset,
    width.to_uint64(),
    count,
  )
  // Candidate two: the inline layout measured on WER. Both the stride and the
  // start are computed from the header itself; 184 is not hardcoded.
  let inline_offset = add_saturating(declared_offset, align_pad.to_uint64())
  let inline_width = add_saturating(
    add_saturating(width.to_uint64(), native.to_uint64()),
    add_saturating(fn_width.to_uint64(), align_pad.to_uint64()),
  )
  let inline_fits = inline_width != width.to_uint64() &&
    self.ft_span_fits(entry, inline_offset, inline_width, count)
  if !declared_fits && !inline_fits {
    // Neither layout fits; report the declared layout's error anyway, staying
    // consistent with the documentation.
    check_list_room(entry.stream_type, entry.data_size, declared_need)
    if !self.range_in_file(entry.rva, declared_need) {
      raise ParseError::Truncated(
        entry.rva,
        declared_need,
        self.data.length().to_uint64(),
      )
    }
  }
  let declared_ok = declared_fits &&
    self.ft_records_plausible(
      entry.rva,
      declared_offset,
      width.to_uint64(),
      count,
    )
  let inline_ok = inline_fits &&
    self.ft_records_plausible(entry.rva, inline_offset, inline_width, count)
  let layout = if declared_ok {
    Declared
  } else if inline_ok {
    InlineRecords
  } else {
    Declared
  }
  let (array_offset, record_width) = match layout {
    Declared => (declared_offset, width.to_uint64())
    InlineRecords => (inline_offset, inline_width)
  }
  let layout_ok = match layout {
    Declared => declared_ok
    InlineRecords => inline_ok
  }
  // Inline function entry slot: does not exist under the declared layout; under
  // the inline layout it is only spread out as a triple when the entry width is
  // exactly 12 bytes (x64 IMAGE_FUNCTION_ENTRY) — no structure is guessed for
  // other architectures.
  let is_inline = match layout {
    Declared => false
    InlineRecords => true
  }
  let slot_at = add_saturating(width.to_uint64(), native.to_uint64())
  let slot_in_record = is_inline &&
    fn_width == 12U &&
    add_saturating(slot_at, 12UL) <= record_width
  let items : Array[FunctionTable] = []
  let mut total = 0UL
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva + array_offset + i * record_width
    let n = self.read_uint32(base + 24UL)
    let slot = base + slot_at
    let inline_entry = if slot_in_record &&
      n != 0U &&
      self.range_in_file(slot, 12UL) {
      Some(
        (
          self.read_uint32(slot),
          self.read_uint32(slot + 4UL),
          self.read_uint32(slot + 8UL),
        ),
      )
    } else {
      None
    }
    items.push({
      minimum_address: self.read_uint64(base),
      maximum_address: self.read_uint64(base + 8UL),
      base_address: self.read_uint64(base + 16UL),
      entry_count: n,
      inline_entry,
    })
    total = add_saturating(total, n.to_uint64())
    i = i + 1UL
  }
  let declared_entries_rva = entry.rva + declared_need
  let entries_rva = if is_inline {
    // The inline layout has no separate entry area; this is only the end of the
    // record region — the field comment states not to use it as an offset.
    entry.rva +
    add_saturating(array_offset, mul_saturating(count, record_width))
  } else {
    declared_entries_rva
  }
  let body = mul_saturating(total, fn_width.to_uint64())
  let entries_in_file = if is_inline {
    // The record region (including each record's inline slot) is already
    // guaranteed in-file by ft_span_fits.
    true
  } else {
    total == 0UL ||
    (fn_width != 0U && self.range_in_file(declared_entries_rva, body))
  }
  {
    descriptors: items,
    size_of_descriptor: width,
    size_of_native_descriptor: native,
    size_of_function_entry: fn_width,
    declared_header,
    size_of_align_pad: align_pad,
    layout,
    layout_ok,
    record_width,
    entries_rva,
    total_entries: total,
    entries_in_file,
  }
}

///|
pub fn Dump::function_table(
  self : Dump,
  entries : Array[StreamEntry],
) -> FunctionTableInfo? raise ParseError {
  match get_stream(entries, function_table_stream) {
    None => None
    Some(entry) => Some(self.read_function_table(entry))
  }
}

///|
/// ThreadInfoListStream (17): each thread's state at the moment the dump was
/// written. A 12-byte header `SizeOfHeader/SizeOfEntry/NumberOfEntries` — the
/// entry count here is 32-bit, unlike MemoryInfoList's 64-bit
/// (`um\minidumpapiset.h:757`); entries are 64 bytes (`:744`).
/// `start_address` is the thread entry point; combined with the module table it
/// directly exposes injection signatures like "a thread's start point is not
/// inside any image".
pub let thread_info_list_header_size : UInt32 = 12U

///|
pub let thread_info_size : UInt32 = 64U

///|
#derive(Debug, Eq)
pub(all) struct ThreadInfo {
  thread_id : UInt32
  dump_flags : UInt32
  dump_error : UInt32
  exit_status : UInt32
  create_time : UInt64
  exit_time : UInt64
  kernel_time : UInt64
  user_time : UInt64
  start_address : UInt64
  affinity : UInt64
}

///|
pub extend ThreadInfo with Debug::{to_repr}

///|
pub extend ThreadInfo with Eq::{equal, not_equal}

///|
/// `MINIDUMP_THREAD_INFO_*` bits (`um\minidumpapiset.h:737`–`:742`).
pub let thread_dump_flag_names : Array[(UInt32, String)] = [
  (0x1U, "ERROR_THREAD"),
  (0x2U, "WRITING_THREAD"),
  (0x4U, "EXITED_THREAD"),
  (0x8U, "INVALID_INFO"),
  (0x10U, "INVALID_CONTEXT"),
  (0x20U, "INVALID_TEB"),
]

///|
pub fn describe_thread_dump_flags(flags : UInt32) -> Array[String] {
  let out : Array[String] = []
  let mut rest = flags
  for (bit, name) in thread_dump_flag_names {
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
/// With no bits set, return `0` rather than `Unknown(0x0)`.
pub fn thread_dump_flags_name(flags : UInt32) -> String {
  let bits = describe_thread_dump_flags(flags)
  if bits.length() == 0 {
    "0"
  } else {
    bits.join("|")
  }
}

///|
pub fn Dump::read_thread_info_list(
  self : Dump,
  entry : StreamEntry,
) -> Array[ThreadInfo] raise ParseError {
  let declared_header = self.read_uint32(entry.rva)
  let width = self.read_uint32(entry.rva + 4UL)
  let count = self.read_uint32(entry.rva + 8UL).to_uint64()
  let header = if declared_header < thread_info_list_header_size {
    thread_info_list_header_size
  } else {
    declared_header
  }
  if width < thread_info_size {
    raise ParseError::StreamTooSmall(
      entry.stream_type,
      thread_info_size.to_uint64(),
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
  let items : Array[ThreadInfo] = []
  let mut i : UInt64 = 0UL
  while i < count {
    let base = entry.rva + header.to_uint64() + i * width.to_uint64()
    items.push({
      thread_id: self.read_uint32(base),
      dump_flags: self.read_uint32(base + 4UL),
      dump_error: self.read_uint32(base + 8UL),
      exit_status: self.read_uint32(base + 12UL),
      create_time: self.read_uint64(base + 16UL),
      exit_time: self.read_uint64(base + 24UL),
      kernel_time: self.read_uint64(base + 32UL),
      user_time: self.read_uint64(base + 40UL),
      start_address: self.read_uint64(base + 48UL),
      affinity: self.read_uint64(base + 56UL),
    })
    i = i + 1UL
  }
  items
}

///|
pub fn Dump::thread_infos(
  self : Dump,
  entries : Array[StreamEntry],
) -> Array[ThreadInfo]? raise ParseError {
  match get_stream(entries, thread_info_list_stream) {
    None => None
    Some(entry) => Some(self.read_thread_info_list(entry))
  }
}

///|
/// Threads whose entry address is not inside any module — the first thing to
/// look at in injection detection. Not evaluated when the module table is empty
/// (an empty array is returned), for the same reason as
/// `memory_info_executable_outside_modules`.
pub fn thread_infos_started_outside_modules(
  infos : Array[ThreadInfo],
  modules : Array[Module],
) -> Array[ThreadInfo] {
  let out : Array[ThreadInfo] = []
  if modules.length() == 0 {
    out
  } else {
    for t in infos {
      if find_module(modules, t.start_address) is None {
        out.push(t)
      }
    }
    out
  }
}
