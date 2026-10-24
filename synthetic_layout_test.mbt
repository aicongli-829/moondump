// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

//! Byte-layout comparison tests for synthetic dumps.

///|
/// Reads little-endian u32 words zero-padded, for field-by-field comparison against MINIDUMP_HEADER.
fn hex_words(b : Bytes) -> String {
  let parts : Array[String] = []
  let mut i : Int32 = 0
  while i < b.length() {
    let s = b.unsafe_read_uint32_le(i).to_string(radix=16)
    let mut pad = ""
    for _ in 0..<(8 - s.length()) {
      pad = pad + "0"
    }
    parts.push(pad + s)
    i = i + 4
  }
  parts.join(" ")
}

///|
test "synthetic dump byte layout (golden words)" {
  let bytes = build_dump([(@moondump.comment_stream_w, u16("AB"))])
  assert_eq(bytes.length() % 4, 0)
  // header (8 words) + directory entry (3 words) + MINIDUMP_STRING (length + body)
  assert_eq(
    hex_words(bytes),
    "504d444d 0007a793 00000001 00000020 00000000 671db480 00000000 00000011 0000000b 00000008 0000002c 00000004 00420041",
  )
}
