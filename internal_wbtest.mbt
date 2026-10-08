// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

//! Whitebox tests: internal helpers, plus the Buffer pitfall this project stepped into.

///|
/// Pitfall record: Buffer is a byte buffer and `write_char_utf8` writes UTF-8 bytes,
/// but `Buffer::to_string` **decodes the bytes in the buffer as UTF-16LE**.
/// So use StringBuilder to decode strings; with Buffer you can only write UTF-16LE and then to_string.
test "Buffer::to_string decodes as UTF-16LE, not UTF-8" {
  let utf16 = Buffer()
  utf16.write_char_utf16le('A')
  utf16.write_char_utf16le('崩')
  let bytes = utf16.to_bytes()
  assert_eq(bytes.length(), 4)
  assert_eq(bytes[0], 0x41)
  assert_eq(bytes[1], 0x00)
  assert_eq(bytes[2], 0x29) // U+5D29, little-endian
  assert_eq(bytes[3], 0x5d)
  assert_eq(utf16.to_string(), "A崩")

  // writing the same content into a Buffer as UTF-8 makes to_string come out garbled
  let utf8 = Buffer()
  utf8.write_char_utf8('A')
  utf8.write_char_utf8('B')
  assert_eq(utf8.to_bytes().length(), 2)
  assert_true(utf8.to_string() != "AB")
}

///|
/// 💥 = U+1F4A5; its surrogate pair is D83D DCA5.
test "surrogate pair for an astral character" {
  let buf = Buffer()
  buf.write_char_utf16le('💥')
  let bytes = buf.to_bytes()
  assert_eq(bytes.length(), 4)
  assert_eq(bytes.unsafe_read_uint16_le(0), 0xd83d)
  assert_eq(bytes.unsafe_read_uint16_le(2), 0xdca5)
}

///|
test "range_in_file does a coarse check, never errors" {
  let dump = make_dump_for_range_check()
  let size = dump.data.length().to_uint64()
  assert_true(dump.range_in_file(0UL, 32UL))
  assert_true(dump.range_in_file(0UL, size))
  assert_false(dump.range_in_file(1UL, size))
  assert_false(dump.range_in_file(size + 1UL, 1UL))
}

///|
/// A minimal valid dump with only a header, used for range checks.
fn make_dump_for_range_check() -> Dump raise ParseError {
  let buf = Buffer()
  buf.write_uint_le(expected_signature)
  buf.write_uint_le(0x0007_a793U)
  buf.write_uint_le(0U)
  buf.write_uint_le(32U)
  buf.write_uint_le(0U)
  buf.write_uint_le(0U)
  buf.write_uint64_le(0UL)
  open_dump(buf.to_bytes())
}
