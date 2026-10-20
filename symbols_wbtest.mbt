// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! Whitebox tests: Breakpad `.sym` textual symbol file parsing and address
///! lookup. The samples are synthetic (no real dump_syms output is available
///! offline), but every case is written against "what does this line make the
///! lookup do", not by copying the implementation's output.
///! MoonBit has no multi-line string literals, so below they are assembled with
///! `+ "\n" +` — verbose to read but explicit.

///|
/// Record formats: `FUNC <index> <address> <size> <name>`, the line record is
/// the bare four numbers right after it, `<address> <size> <line> <file>`, and
/// `PUBLIC <index> <address> <size> <name>`.
fn sym_sample() -> String {
  "MODULE Windows amd64 36515fb5-d043-45e4-91f6-72fa2e2878c02 ntdll.pdb\n" +
  "FILE 0 ntdll.pdb\n" +
  "FILE 1 C:\\nt\\main.cpp\n" +
  "FUNC 0 1000 40 `ntdll!Foo`\n" +
  "1000 10 1 1\n" +
  "101a 26 2 1\n" +
  "FUNC 1 1040 0 `ntdll!Nop`\n" +
  "PUBLIC 2 2000 8 `ntdll!Bar`\n" +
  "STACK CFI INIT 1000 40 .cfa: $rsp 8 +\n" +
  "STACK CFI 1004 .cfa: $rsp 8 +\n" +
  "garbage\n"
}

///|
test ".sym: how many of the five record kinds are collected, CFI lines only counted" {
  let sf = parse_symbol_file(sym_sample())
  assert_true(sf.valid)
  assert_eq(sf.os, "Windows")
  assert_eq(sf.arch, "amd64")
  assert_eq(sf.debug_id, "36515fb5-d043-45e4-91f6-72fa2e2878c02")
  assert_eq(sf.name, "ntdll.pdb")
  assert_eq(sf.functions.length(), 2)
  assert_eq(sf.publics.length(), 1)
  assert_eq(sf.files.length(), 2)
  assert_eq(sf.files[1], "C:\\nt\\main.cpp")
  assert_eq(sf.line_records, 2L)
  // Two STACK CFI* lines plus one unrecognized line: counted only, not interpreted
  assert_eq(sf.other_records, 3L)
  assert_eq(sf.bad_records, 0L)
  assert_eq(sf.total_function_size, 0x40UL)
  assert_true(sf.ascending)
  // The name is "from the 5th token to end of line"; backticks are part of the name
  assert_eq(sf.functions[0].name, "`ntdll!Foo`")
  assert_eq(sf.functions[1].size, 0UL)
}

///|
/// Runs of spaces in a name must not be eaten by tokenization: calling
/// conventions and parameters inside symbol names really do carry multiple
/// spaces. If the name is mangled, line lookup still matches but the displayed
/// symbol is wrong.
test ".sym: names and paths taken verbatim to end of line" {
  let sf = parse_symbol_file(
    "MODULE Windows x86 ID  test_app.exe\n" +
    "FUNC 10 20 30 int   __cdecl  f(void)\n" +
    "FILE 2 a  b.c\n",
  )
  assert_eq(sf.name, "test_app.exe")
  assert_eq(sf.functions[0].address, 0x20UL)
  assert_eq(sf.functions[0].name, "int   __cdecl  f(void)")
  assert_eq(sf.files[2], "a  b.c")
  assert_eq(sf.files.length(), 3)
}

///|
test ".sym: address lookup - inside function, line-number gap, size 0, PUBLIC, not found" {
  let sf = parse_symbol_file(sym_sample())
  match symbol_file_function_at(sf, 0x1004UL) {
    None => fail("0x1004 should be inside 0x1000+0x40")
    Some(f) => assert_eq(f.name, "`ntdll!Foo`")
  }
  match symbol_file_resolve(sf, 0x1004UL) {
    None => fail("should have a result")
    Some(x) => {
      assert_eq(x.kind, "func")
      assert_eq(x.start, 0x1000UL)
      // 0x1004 falls inside the first line record [0x1000,0x1010)
      assert_eq(x.file, "C:\\nt\\main.cpp")
      assert_eq(x.line, Some(1L))
    }
  }
  // 0x1011 sits in the gap between [0x1000,0x1010) and [0x101a,0x1040):
  // report the previous line rather than dropping the line number over a gap
  match symbol_file_resolve(sf, 0x1011UL) {
    None => fail("line number should be returned even in a gap")
    Some(x) => assert_eq(x.line, Some(1L))
  }
  match symbol_file_resolve(sf, 0x1020UL) {
    None => fail("0x1020 should have a line number")
    Some(x) => assert_eq(x.line, Some(2L))
  }
  // A function with size 0 matches only its start address
  assert_true(symbol_file_function_at(sf, 0x1040UL) is Some(_))
  assert_true(symbol_file_function_at(sf, 0x1041UL) is None)
  assert_true(symbol_file_function_at(sf, 0x103fUL) is Some(_))
  // Outside every function range but after a PUBLIC: per breakpad LookupSymbol
  // semantics, take the largest start address not exceeding the target; the
  // offset is computed by the caller from `start`
  match symbol_file_resolve(sf, 0x2004UL) {
    None => fail("PUBLIC should hit")
    Some(x) => {
      assert_eq(x.kind, "public")
      assert_eq(x.name, "`ntdll!Bar`")
      assert_eq(x.start, 0x2000UL)
      assert_eq(x.line, None)
    }
  }
  // A far address still gets the nearest name — this is a behavioral
  // convention, not a missed detection: the offset becomes absurdly large and
  // the display makes "actually no symbol" obvious at a glance
  match symbol_file_resolve(sf, 0x9000UL) {
    None => fail("far address should still give the nearest PUBLIC name")
    Some(x) => assert_eq(x.kind, "public")
  }
  // Below all symbols: truly nothing
  assert_true(symbol_file_resolve(sf, 0x10UL) is None)
}

///|
/// A symbol file whose addresses are not ascending (someone hand-appended
/// records) must still resolve correctly; it only degrades to a linear scan,
/// and the `ascending` flag must faithfully be false.
test ".sym: out-of-order FUNC addresses mark not ascending, lookup still correct" {
  let sf = parse_symbol_file(
    "MODULE Windows amd64 ID name.pdb\n" +
    "FUNC 0 2000 10 second\n" +
    "FUNC 1 1000 10 first\n",
  )
  assert_false(sf.ascending)
  match symbol_file_function_at(sf, 0x2004UL) {
    None => fail("0x2004 should be found even out of order")
    Some(f) => assert_eq(f.name, "second")
  }
  match symbol_file_function_at(sf, 0x1004UL) {
    None => fail("0x1004 should be found even out of order")
    Some(f) => assert_eq(f.name, "first")
  }
}

///|
/// What counts as a bad line: the keyword is known but the fields are wrong.
/// All of them land in bad_records, and none may take down the whole file.
test ".sym: bad lines counted, good lines still collected" {
  let sf = parse_symbol_file(
    "MODULE Windows amd64 ID\n" +
    "LINE 1000 10 1 0\n" +
    "FUNC 1 zz 10 bad_addr_hex\n" +
    "FUNC 1 1000 10\n" +
    "FUNC 1 11111111111111111 10 addr_too_long\n" +
    "FILE -1 negative\n" +
    "FILE x bad\n" +
    "PUBLIC 1 zz 10 bad\n" +
    "1000 4 7 0\n" +
    "FUNC 1 3000 10 good_after_bad\n",
  )
  // A MODULE with only 4 tokens is not valid
  assert_false(sf.valid)
  assert_eq(sf.functions.length(), 1)
  assert_eq(sf.publics.length(), 0)
  assert_eq(sf.line_records, 0L)
  // In order: MODULE missing fields; a line record (with keyword) before any
  // FUNC; address not hex; FUNC missing its name; a 17-digit overflowing
  // address; negative FILE index; non-numeric FILE index; PUBLIC address not
  // hex; a bare-four-numbers line record before any FUNC
  assert_eq(sf.bad_records, 9L)
  // Overflow yields None instead of wrapping into a small address that slips into the table
  assert_true(symbol_file_function_at(sf, 0x1111111111111111UL) is None)
  assert_true(symbol_file_function_at(sf, 0x3004UL) is Some(_))
}

///|
test ".sym: CRLF and tab separators both readable" {
  let sf = parse_symbol_file(
    "MODULE Windows amd64 ID name.pdb\r\n" +
    "FUNC\t0\t1000\t40\tfoo()\r\n" +
    "1000\t40\t9\t1\r\n" +
    "FILE 1 src.c\r\n",
  )
  assert_true(sf.valid)
  assert_eq(sf.name, "name.pdb")
  assert_eq(sf.functions.length(), 1)
  assert_eq(sf.functions[0].name, "foo()")
  assert_eq(sf.line_records, 1L)
  assert_eq(sf.bad_records, 0L)
  match symbol_file_resolve(sf, 0x1004UL) {
    None => fail("CRLF file should still yield line numbers")
    Some(x) => {
      assert_eq(x.line, Some(9L))
      assert_eq(x.file, "src.c")
    }
  }
}

///|
test "debug id normalization: strip dashes, uppercase" {
  assert_eq(
    normalize_debug_id("36515fb5-d043-45e4-91f6-72fa2e2878c02"),
    "36515FB5D04345E491F672FA2E2878C02",
  )
  assert_eq(normalize_debug_id(""), "")
  assert_eq(normalize_debug_id("ntdll.pdb"), "NTDLL.PDB")
}

///|
test "symbol store: match by id, fall back to name, bad files go to rejected" {
  let store = symbol_store_new()
  let ok = symbol_store_add(
    store,
    "a/ntdll.pdb/36515FB5D04345E491F672FA2E2878C02/ntdll.pdb.sym",
    sym_sample(),
  )
  assert_true(ok)
  assert_eq(store.loaded.length(), 1)
  // Files without a MODULE line are not accepted, but they do not silently vanish either
  assert_false(
    symbol_store_add(store, "b/broken.sym", "FUNC 1 1000 10 orphan\n"),
  )
  assert_eq(store.rejected.length(), 1)
  assert_eq(store.loaded.length(), 1)

  // Hits regardless of dashes in the id or letter case
  let by_id = symbol_store_find(
    store, "36515fb5-d043-45e4-91f6-72fa2e2878c02", "anything",
  )
  assert_true(by_id is Some(_))
  // When the id does not match, fall back to the module name (hand-placed
  // symbol files often have only the name changed, not the id)
  let by_name = symbol_store_find(store, "ffffffffffffffff", "NTDLL.PDB")
  assert_true(by_name is Some(_))
  // When neither matches, the result is None — no arbitrarily picking one to stand in
  assert_true(symbol_store_find(store, "0", "kernel32.pdb") is None)
  assert_eq(symbol_store_match_count(store, "0", "kernel32.pdb"), 0)
  // A single file hit by both id and name counts once
  assert_eq(
    symbol_store_match_count(
      store, "36515FB5D04345E491F672FA2E2878C02", "ntdll.pdb",
    ),
    1,
  )
}
