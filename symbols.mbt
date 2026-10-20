// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! Breakpad textual symbol file (`.sym`, the output of dump_syms) parsing.
///!
///! Only these record kinds are recognized: `MODULE`, `FILE`, `FUNC`, line
///! records, and `PUBLIC`. Both spellings of the line record are accepted:
///! what dump_syms actually writes is **four bare numbers immediately after a
///! FUNC** (`<address> <size> <line> <file>`, with no keyword), while quite a
///! few documents describe it as a line with a `LINE` keyword. There is no
///! offline dump_syms output to check this against, so both are accepted —
///! once a real sample arrives it will settle the question and one form is kept.
///!
///! Unwinding rule lines such as `STACK CFI INIT` / `STACK CFI` / `STACK WIN`
///! are **only counted, never interpreted**: their rule syntax has no
///! authoritative offline source, and by this project's rule of "no parser
///! without an authority" it is better to let the caller see "there are N
///! unused lines here" than to guess at semantics.
///!
///! Parsing never raises: a `.sym` is a file people hand-edit, so bad lines are
///! the norm rather than the exception. Everything falls into counters
///! (`bad_records` / `other_records`), and the caller decides how to report it.

///|
/// A `LINE` record: `size` bytes starting at `address` belong to line `line`
/// of source file number `file`.
#derive(Eq, Debug)
pub(all) struct SymLine {
  address : UInt64
  size : UInt64
  line : Int64
  file : Int64
}

///|
pub extend SymLine with Debug::{to_repr}

///|
pub extend SymLine with Eq::{equal, not_equal}

///|
/// A `FUNC` record. `lines` keeps file order — dump_syms writes them in
/// ascending address order.
#derive(Eq, Debug)
pub(all) struct SymFunction {
  address : UInt64
  size : UInt64
  name : String
  lines : Array[SymLine]
}

///|
pub extend SymFunction with Debug::{to_repr}

///|
pub extend SymFunction with Eq::{equal, not_equal}

///|
/// A `PUBLIC` record: only a name and a size, no line numbers.
#derive(Eq, Debug)
pub(all) struct SymPublic {
  address : UInt64
  size : UInt64
  name : String
}

///|
pub extend SymPublic with Debug::{to_repr}

///|
pub extend SymPublic with Eq::{equal, not_equal}

///|
/// The result of resolving one address. A `line` of None means "hit a function
/// but no line number" or "hit only a PUBLIC"; both must be distinguishable
/// from "no symbol at all".
#derive(Eq, Debug)
pub(all) struct ResolvedFrame {
  name : String
  /// Symbol start address, used to compute the `offset`
  start : UInt64
  /// How the hit was made: "func" / "public"
  kind : String
  file : String
  line : Int64?
}

///|
pub extend ResolvedFrame with Debug::{to_repr}

///|
pub extend ResolvedFrame with Eq::{equal, not_equal}

///|
/// The parsed result of one `.sym` file.
#derive(Eq, Debug)
pub(all) struct SymbolFile {
  /// The four fields of the `MODULE` line; empty strings and `valid == false`
  /// when the line is missing
  os : String
  arch : String
  debug_id : String
  name : String
  /// `FILE N` stored by index; when N is not contiguous the empty slots are
  /// filled with "", and out-of-range indices resolve to the empty string
  files : Array[String]
  functions : Array[SymFunction]
  publics : Array[SymPublic]
  /// Number of `LINE` records
  line_records : Int64
  /// Number of `STACK CFI*` / `STACK WIN` / unrecognized-keyword lines
  other_records : Int64
  /// Number of lines whose keyword is known but whose fields could not be read
  /// (truncation, stray characters in hex values, etc.)
  bad_records : Int64
  /// Sum of all `FUNC` sizes, saturating addition
  total_function_size : UInt64
  /// Whether `FUNC` addresses are ascending; when not, lookup degrades to a
  /// linear scan — same results, just slower
  ascending : Bool
  valid : Bool
}

///|
pub extend SymbolFile with Debug::{to_repr}

///|
pub extend SymbolFile with Eq::{equal, not_equal}

///|
/// A collection of symbol files. Indexed by content (the debug id on the
/// `MODULE` line), not by directory convention: the breakpad
/// `<debug_file>/<debug_id>/<name>.sym` three-level path is not implemented
/// identically by every producer, while the id a file declares for itself is
/// authoritative. So every `.sym` found by recursive loading is parsed and kept.
#derive(Eq, Debug)
pub(all) struct SymbolStore {
  /// `(source path, parsed result)`, in load order
  loaded : Array[(String, SymbolFile)]
  /// Files that were read but had no valid `MODULE` line; not a single one is
  /// silently dropped
  rejected : Array[String]
}

///|
pub extend SymbolStore with Debug::{to_repr}

///|
pub extend SymbolStore with Eq::{equal, not_equal}

///|
pub fn symbol_store_new() -> SymbolStore {
  { loaded: [], rejected: [], }
}

///|
/// Hand in a text. Returns whether it was accepted (has a valid `MODULE` line).
/// A bad file only goes into `rejected` and does not affect symbol files
/// already accepted.
pub fn symbol_store_add(
  store : SymbolStore,
  source : String,
  text : String,
) -> Bool {
  let sf = parse_symbol_file(text)
  if sf.valid {
    store.loaded.push((source, sf))
    true
  } else {
    store.rejected.push(source)
    false
  }
}

///|
/// Find a module's symbol file: first an exact hit on the normalized debug id,
/// then a fallback by module name (case-insensitive). Both are needed because
/// hand-placed symbol files often have only the name changed, not the id.
pub fn symbol_store_find(
  store : SymbolStore,
  debug_id : String,
  name : String,
) -> SymbolFile? {
  let want_id = normalize_debug_id(debug_id)
  let want_name = lower_ascii(name)
  let mut found : SymbolFile? = None
  for (_, sf) in store.loaded {
    if found is None {
      if want_id.length() > 0 && normalize_debug_id(sf.debug_id) == want_id {
        found = Some(sf)
      } else if want_name.length() > 0 &&
        (
          lower_ascii(sf.name) == want_name ||
          lower_ascii(basename_of(sf.name)) == want_name
        ) {
        found = Some(sf)
      }
    }
  }
  found
}

///|
/// How many files matched. When more than one, the caller should say plainly
/// "the symbol file here is ambiguous; the first one was used" rather than
/// pretend the correct one was picked.
pub fn symbol_store_match_count(
  store : SymbolStore,
  debug_id : String,
  name : String,
) -> Int32 {
  let want_id = normalize_debug_id(debug_id)
  let want_name = lower_ascii(name)
  let mut n : Int32 = 0
  for (_, sf) in store.loaded {
    let by_id = want_id.length() > 0 &&
      normalize_debug_id(sf.debug_id) == want_id
    let by_name = want_name.length() > 0 && lower_ascii(sf.name) == want_name
    if by_id || by_name {
      n = n + 1
    }
  }
  n
}

///|
fn basename_of(path : String) -> String {
  let chars = path.to_array()
  let mut out = ""
  for c in chars {
    if c == '/' || c == '\\' {
      out = ""
    } else {
      out = out + c.to_string()
    }
  }
  out
}

///|
/// Mutable accumulator used while parsing. The externally visible `SymbolFile`
/// is immutable data, so the business of "filling fields line by line" stays in
/// this private type, keeping `mut` off the public one.
priv struct SymParse {
  mut os : String
  mut arch : String
  mut debug_id : String
  mut name : String
  mut valid : Bool
  mut line_records : Int64
  mut other_records : Int64
  mut bad_records : Int64
  mut total_function_size : UInt64
  mut ascending : Bool
  files : Array[String]
  functions : Array[SymFunction]
  publics : Array[SymPublic]
}

///|
/// Split into lines. Not using `String::split` for two reasons: its separator
/// is a `StringView` and the returned elements are `StringView`s too, needing
/// another conversion; more importantly a `.sym` may be CRLF, and splitting by
/// hand lets us drop a trailing `\r` in passing, saving a per-line string
/// rebuild.
fn split_lines(text : String) -> Array[String] {
  let lines : Array[String] = []
  let mut cur = ""
  let mut pending_r = false
  for c in text.to_array() {
    if c == '\n' {
      // When the previous character was \r it is already at the end of cur; strip it here
      let body = if pending_r { drop_last(cur) } else { cur }
      lines.push(body)
      cur = ""
      pending_r = false
    } else {
      cur = cur + c.to_string()
      pending_r = c == '\r'
    }
  }
  if cur.length() > 0 {
    lines.push(if pending_r { drop_last(cur) } else { cur })
  }
  lines
}

///|
fn drop_last(s : String) -> String {
  let chars = s.to_array()
  let mut out = ""
  let n = chars.length() - 1
  for i in 0..<n {
    out = out + chars[i].to_string()
  }
  out
}

///|
/// Parse a whole `.sym` file. CRLF, trailing whitespace, and runs of spaces
/// are all tolerated.
pub fn parse_symbol_file(text : String) -> SymbolFile {
  let b : SymParse = {
    os: "",
    arch: "",
    debug_id: "",
    name: "",
    valid: false,
    line_records: 0L,
    other_records: 0L,
    bad_records: 0L,
    total_function_size: 0UL,
    ascending: true,
    files: [],
    functions: [],
    publics: [],
  }
  // Line records belong to the most recent FUNC: that is how the Breakpad format works
  let mut current : Int32 = -1
  for raw in split_lines(text) {
    // `String::trim` returns a `StringView`; what we want here is a `String`
    // that can be stored in a struct
    let line = raw.trim().to_owned()
    if line.length() == 0 {
      continue
    }
    let tokens = split_ws(line)
    let head = tokens[0]
    if head == "MODULE" {
      // MODULE <OS> <ARCH> <DEBUG ID> <NAME>
      // Newer dump_syms versions append file-size / debug-file columns after
      // the name; they cannot be told apart reliably, so "from the 5th token
      // to end of line" is taken as the name as a whole rather than pretending
      // to understand the tail.
      if tokens.length() >= 5 {
        b.os = tokens[1]
        b.arch = tokens[2]
        b.debug_id = tokens[3]
        b.name = rest_of(line, 4)
        b.valid = true
      } else {
        b.bad_records = b.bad_records + 1L
      }
    } else if head == "FILE" {
      // FILE <N> <PATH>
      if tokens.length() >= 3 {
        match parse_dec64(tokens[1]) {
          None => b.bad_records = b.bad_records + 1L
          Some(n) =>
            if n < 0L {
              b.bad_records = b.bad_records + 1L
            } else {
              let want = n.to_int()
              while b.files.length() <= want {
                b.files.push("")
              }
              b.files[want] = rest_of(line, 2)
            }
        }
      } else {
        b.bad_records = b.bad_records + 1L
      }
    } else if head == "FUNC" {
      // FUNC <N> <ADDR> <SIZE> <NAME>
      if tokens.length() >= 5 {
        let addr = parse_hex64(tokens[2])
        let size = parse_hex64(tokens[3])
        match (addr, size) {
          (Some(a), Some(sz)) => {
            if b.functions.length() > 0 {
              let last = b.functions[b.functions.length() - 1]
              if a <= last.address {
                b.ascending = false
              }
            }
            b.functions.push({
              address: a,
              size: sz,
              name: rest_of(line, 4),
              lines: [],
            })
            b.total_function_size = add_u64(b.total_function_size, sz)
            current = b.functions.length() - 1
          }
          _ => b.bad_records = b.bad_records + 1L
        }
      } else {
        b.bad_records = b.bad_records + 1L
      }
    } else if head == "LINE" {
      attach_line(b, current, tokens, 1)
    } else if head == "PUBLIC" {
      // PUBLIC <N> <ADDR> <SIZE> <NAME>
      if tokens.length() >= 5 {
        let addr = parse_hex64(tokens[2])
        let size = parse_hex64(tokens[3])
        match (addr, size) {
          (Some(a), Some(sz)) =>
            b.publics.push({ address: a, size: sz, name: rest_of(line, 4), })
          _ => b.bad_records = b.bad_records + 1L
        }
      } else {
        b.bad_records = b.bad_records + 1L
      }
    } else if tokens.length() == 4 && starts_with_hex(head) {
      // dump_syms' real spelling: four bare numbers right after a FUNC, no keyword
      attach_line(b, current, tokens, 0)
    } else {
      // STACK CFI INIT / STACK CFI / STACK WIN / keywords that may be added in the future
      b.other_records = b.other_records + 1L
    }
  }
  {
    os: b.os,
    arch: b.arch,
    debug_id: b.debug_id,
    name: b.name,
    files: b.files,
    functions: b.functions,
    publics: b.publics,
    line_records: b.line_records,
    other_records: b.other_records,
    bad_records: b.bad_records,
    total_function_size: b.total_function_size,
    ascending: b.ascending,
    valid: b.valid,
  }
}

///|
/// Attach a line record to the current function. `off` is the offset caused by
/// the keyword: 1 with a `LINE` keyword, 0 for dump_syms' bare-four-numbers form.
/// A line record appearing before any FUNC counts as a bad line — it has no
/// owner, and guessing a function is worse than dropping it.
fn attach_line(
  b : SymParse,
  current : Int32,
  tokens : Array[String],
  off : Int32,
) -> Unit {
  if current < 0 {
    b.bad_records = b.bad_records + 1L
  } else {
    let addr = parse_hex64(tokens[off])
    let size = parse_hex64(tokens[off + 1])
    let ln = parse_dec64(tokens[off + 2])
    let fi = parse_dec64(tokens[off + 3])
    match (addr, size, ln, fi) {
      (Some(a), Some(sz), Some(l), Some(f)) => {
        b.functions[current].lines.push({
          address: a,
          size: sz,
          line: l,
          file: f,
        })
        b.line_records = b.line_records + 1L
      }
      _ => b.bad_records = b.bad_records + 1L
    }
  }
}

///|
/// Whether the first character is a hex digit. Used to tell the "bare
/// four-numbers line record" apart from `STACK` / unknown keywords — the
/// latter's keywords always begin with a letter.
fn starts_with_hex(s : String) -> Bool {
  let chars = s.to_array()
  chars.length() > 0 && hex_digit(chars[0]) >= 0
}

///|
/// Split a line on whitespace (spaces and tabs), dropping empty pieces.
fn split_ws(line : String) -> Array[String] {
  let parts : Array[String] = []
  let mut cur = ""
  let mut started = false
  for c in line.to_array() {
    let v = c.to_int()
    let blank = v == 32 || v == 9
    if blank {
      if started {
        parts.push(cur)
        cur = ""
        started = false
      }
    } else {
      cur = cur + c.to_string()
      started = true
    }
  }
  if started {
    parts.push(cur)
  }
  parts
}

///|
/// Take the verbatim text from the first non-whitespace character after the
/// `skip`-th token to end of line. Names of `FUNC` / `MODULE` / `FILE` may
/// contain spaces and cannot be re-joined from split tokens (re-joining would
/// collapse runs of spaces, and the name would no longer match the original).
fn rest_of(line : String, skip : Int32) -> String {
  let chars = line.to_array()
  let mut i : Int32 = 0
  let mut seen : Int32 = 0
  while i < chars.length() && seen < skip {
    while i < chars.length() && (chars[i] == ' ' || chars[i] == '\t') {
      i = i + 1
    }
    while i < chars.length() && chars[i] != ' ' && chars[i] != '\t' {
      i = i + 1
    }
    seen = seen + 1
  }
  while i < chars.length() && (chars[i] == ' ' || chars[i] == '\t') {
    i = i + 1
  }
  let mut out = ""
  while i < chars.length() {
    out = out + chars[i].to_string()
    i = i + 1
  }
  out
}

///|
/// Hex to UInt64: no `0x` prefix, no sign, None on more than 16 digits or
/// overflow. This is exactly how Breakpad writes addresses and sizes.
fn parse_hex64(s : String) -> UInt64? {
  if s.length() == 0 || s.length() > 16 {
    None
  } else {
    let mut v : UInt64 = 0UL
    let mut ok = true
    for c in s.to_array() {
      let d = hex_digit(c)
      if d < 0 {
        ok = false
      } else if v > 0x0fff_ffff_ffff_ffffUL {
        // One more shift left would overflow
        ok = false
      } else {
        v = v * 16UL + d.to_uint64()
      }
    }
    if ok {
      Some(v)
    } else {
      None
    }
  }
}

///|
fn hex_digit(c : Char) -> Int32 {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    -1
  }
}

///|
/// Decimal to Int64: only plain digits with an optional sign; None on overflow.
fn parse_dec64(s : String) -> Int64? {
  let chars = s.to_array()
  if chars.length() == 0 {
    None
  } else {
    let mut i : Int32 = 0
    let mut neg = false
    if chars[0] == '-' {
      neg = true
      i = i + 1
    } else if chars[0] == '+' {
      i = i + 1
    }
    let mut v : Int64 = 0L
    let mut ok = i < chars.length()
    while i < chars.length() {
      let d = chars[i].to_int() - 48
      if d < 0 || d > 9 {
        ok = false
      } else if v > 922337203685477580L {
        // Int64::MAX / 10; one more multiply by 10 would overflow
        ok = false
      } else {
        v = v * 10L + d.to_int64()
      }
      i = i + 1
    }
    if !ok {
      None
    } else if neg {
      Some(0L - v)
    } else {
      Some(v)
    }
  }
}

///|
/// Saturating addition: overflow while summing symbol sizes is not an error,
/// but it must never wrap back into a small number.
fn add_u64(a : UInt64, b : UInt64) -> UInt64 {
  let sum = a + b
  if sum < a {
    0xffff_ffff_ffff_ffffUL
  } else {
    sum
  }
}

///|
/// "Address is inside `[start, start+size)`". `size == 0` matches only the
/// start address itself: dump_syms writes 0 for purely declared functions, and
/// treating that as infinite would shadow every later function. When the upper
/// bound wraps around (past 2^64), treat it as an unbounded upper end.
fn covers(start : UInt64, size : UInt64, address : UInt64) -> Bool {
  if size == 0UL {
    address == start
  } else {
    let end = start + size
    if end <= start {
      address >= start
    } else {
      address >= start && address < end
    }
  }
}

///|
/// Which function an address falls in. Binary search when `ascending`,
/// otherwise a linear scan — same result, just slower.
pub fn symbol_file_function_at(
  sf : SymbolFile,
  address : UInt64,
) -> SymFunction? {
  if !sf.ascending {
    let mut found : SymFunction? = None
    for f in sf.functions {
      if found is None && covers(f.address, f.size, address) {
        found = Some(f)
      }
    }
    found
  } else {
    // Find the last function whose start address does not exceed the target,
    // then check whether it really covers it
    let mut lo : Int32 = 0
    let mut hi = sf.functions.length() - 1
    let mut best : Int32 = -1
    while lo <= hi {
      let mid = lo + (hi - lo) / 2
      if sf.functions[mid].address <= address {
        best = mid
        lo = mid + 1
      } else {
        hi = mid - 1
      }
    }
    if best < 0 {
      None
    } else {
      let f = sf.functions[best]
      if covers(f.address, f.size, address) {
        Some(f)
      } else {
        None
      }
    }
  }
}

///|
/// Find a line number within a function: prefer the last LINE record that
/// really covers the target; when none covers it, fall back to the last record
/// whose start address does not exceed the target — dump_syms' line ranges
/// often have small gaps between them (alignment, trailing instructions), and
/// reporting the previous line beats losing the line number over a gap.
fn sym_line_of(f : SymFunction, address : UInt64) -> SymLine? {
  let mut hit : SymLine? = None
  let mut near : SymLine? = None
  for l in f.lines {
    if covers(l.address, l.size, address) {
      hit = Some(l)
    } else if address >= l.address {
      near = Some(l)
    }
  }
  match hit {
    Some(l) => Some(l)
    None => near
  }
}

///|
/// Full resolution of one address: function + line → PUBLIC only → nothing.
/// Return addresses passed in during stack unwinding have usually already had
/// 1 subtracted by the caller; no correction is done here.
pub fn symbol_file_resolve(sf : SymbolFile, address : UInt64) -> ResolvedFrame? {
  match symbol_file_function_at(sf, address) {
    Some(f) => {
      let loc = sym_line_of(f, address)
      let file = match loc {
        Some(l) => symbol_file_file(sf, l.file)
        None => ""
      }
      let line = match loc {
        Some(l) => Some(l.line)
        None => None
      }
      Some({ name: f.name, start: f.address, kind: "func", file, line, })
    }
    None => {
      let p = symbol_file_public_at(sf, address)
      match p {
        Some(pub_) =>
          Some({
            name: pub_.name,
            start: pub_.address,
            kind: "public",
            file: "",
            line: None,
          })
        None => None
      }
    }
  }
}

///|
/// The PUBLIC with the largest start address not exceeding the target; on a
/// tie, take the one later in the file.
pub fn symbol_file_public_at(sf : SymbolFile, address : UInt64) -> SymPublic? {
  let mut best : SymPublic? = None
  for p in sf.publics {
    if p.address <= address {
      let take = match best {
        None => true
        Some(b) => p.address >= b.address
      }
      if take {
        best = Some(p)
      }
    }
  }
  best
}

///|
/// An out-of-range file index in a `LINE` yields the empty string, no error —
/// the norm for bad symbol files.
pub fn symbol_file_file(sf : SymbolFile, index : Int64) -> String {
  if index < 0L {
    ""
  } else {
    let i = index.to_int()
    if i >= sf.files.length() {
      ""
    } else {
      sf.files[i]
    }
  }
}

///|
/// Debug id normalization: strip hyphens, lowercase to uppercase. Breakpad
/// directories use the form `36515FB5D04345E491F672FA2E2878C02` — "GUID
/// without dashes + age" — while CodeView and hand-placed `.sym` files do not
/// agree on how the dashes are laid out, so both sides are normalized before
/// comparing. Only ASCII case is folded: when a PDB name contains non-ASCII,
/// keeping it verbatim is safer than unicode folding.
pub fn normalize_debug_id(id : String) -> String {
  let uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_array()
  let mut out = ""
  for c in id.to_array() {
    let v = c.to_int()
    if v == 45 {
      continue
    } else if v >= 97 && v <= 122 {
      out = out + uppers[v - 97].to_string()
    } else {
      out = out + c.to_string()
    }
  }
  out
}

///|
/// The source-carrying version of `symbol_store_find`. Symbol files are often
/// placed in the wrong directory, so the report must be able to state "this
/// address was resolved by which file".
pub fn symbol_store_find_with_source(
  store : SymbolStore,
  debug_id : String,
  name : String,
) -> (String, SymbolFile)? {
  let want_id = normalize_debug_id(debug_id)
  let want_name = lower_ascii(name)
  let mut found : (String, SymbolFile)? = None
  for (source, sf) in store.loaded {
    if found is None {
      if want_id.length() > 0 && normalize_debug_id(sf.debug_id) == want_id {
        found = Some((source, sf))
      } else if want_name.length() > 0 &&
        (
          lower_ascii(sf.name) == want_name ||
          lower_ascii(basename_of(sf.name)) == want_name
        ) {
        found = Some((source, sf))
      }
    }
  }
  found
}

///|
/// The module's breakpad-form debug id: the CodeView RSDS GUID with dashes
/// removed and uppercased, followed directly by the age in hex (no leading
/// zeros, no separator), e.g. `66599F779E4E4E0CAF53C37D2F147FB71` (the trailing
/// `1` is age=1).
///
/// This is the spelling dump_syms writes on the `MODULE` line and symbol
/// servers use to lay out directories. With no RSDS record
/// (Missing/Unrecognized/Corrupt) an empty string is returned; an empty string
/// counts as "no id" in `normalize_debug_id`/lookups and never matches by accident.
pub fn module_debug_id(m : Module) -> String {
  match m.code_view {
    Rsds(r) =>
      normalize_debug_id(r.debug_id) + upper_hex(r.age.to_string(radix=16))
    _ => ""
  }
}

///|
/// Uppercase only ASCII a-f: the age's hex string contains nothing but digits
/// and those letters.
fn upper_hex(s : String) -> String {
  let uppers = "ABCDEF".to_array()
  let mut out = ""
  for c in s.to_array() {
    let v = c.to_int()
    if v >= 97 && v <= 102 {
      out = out + uppers[v - 97].to_string()
    } else {
      out = out + c.to_string()
    }
  }
  out
}

///|
/// ASCII lowercase for name comparison; non-ASCII kept verbatim.
fn lower_ascii(s : String) -> String {
  let lowers = "abcdefghijklmnopqrstuvwxyz".to_array()
  let mut out = ""
  for c in s.to_array() {
    let v = c.to_int()
    if v >= 65 && v <= 90 {
      out = out + lowers[v - 65].to_string()
    } else {
      out = out + c.to_string()
    }
  }
  out
}
