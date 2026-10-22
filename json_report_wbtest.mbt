// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
///! In-package tests: the rules of the JSON output layer that are "independent of the real
///! corpus and can only be exercised with synthetic data".
///!
///! The public corpora are all too small; caps like `json_list_cap` (2000 entries) can never
///! be hit with this corpus, yet "truncation must be stated explicitly in the document"
///! absolutely must be tested, so here lists are fed straight to `j_list`.
///! Addresses and 64-bit lengths going through the string channel is the same story: double
///! precision is exact only up to 2^53, and a memory region size above 2^53 written as a
///! JSON number has already changed by the time it is read back.

///|
/// `stringify` defaults to compact output (indent=0), so writing the whole text inline in
/// the assertions is simplest.
fn compact(j : Json) -> String {
  j.stringify()
}

///|
/// Fetches one field from an object. Uses iteration instead of `m[key]`: only one level is
/// looked up here, which is enough.
fn at_key(node : Json, key : String) -> Json {
  let mut out = Json::null()
  match node {
    Json::Object(m) =>
      for k, v in m {
        if k == key {
          out = v
        }
      }
    _ => ()
  }
  out
}

///|
test "long list truncation must be documented, not silently dropped" {
  let items : Array[Json] = []
  for i in 0..<5 {
    items.push(Json::number(i.to_double()))
  }
  assert_eq(
    compact(j_list(items, 3)),
    "{\"count\":5,\"truncated\":true,\"items\":[0,1,2]}",
  )
  // Below the cap, truncated=false and count is still the original count (not the number
  // of items placed into the document).
  assert_eq(
    compact(j_list(items, 8)),
    "{\"count\":5,\"truncated\":false,\"items\":[0,1,2,3,4]}",
  )
  assert_eq(
    compact(j_list([], 3)),
    "{\"count\":0,\"truncated\":false,\"items\":[]}",
  )
}

///|
/// The cap itself is part of the schema: the CLI and the test cases both take it from
/// `json_list_cap_value`; this test pins its current value — if it changes, the docs
/// change with it.
test "current value of the list cap" {
  assert_eq(json_list_cap_value(), json_list_cap)
  assert_eq(json_list_cap, 2000)
}

///|
/// Hex and decimal must both be **strings**: `0x…` for addresses, decimal for 64-bit lengths.
/// 9007199254740993 is 2^53+1; written as a number it would be mangled by double precision.
test "addresses and 64-bit lengths go through the string channel" {
  assert_eq(compact(jhex(0x7ff6_0000_0000UL)), "\"0x7ff600000000\"")
  assert_eq(compact(jhex(0UL)), "\"0x0\"")
  assert_eq(compact(jdec(9007199254740993UL)), "\"9007199254740993\"")
  assert_eq(compact(jhex_opt(None)), "null")
  assert_eq(compact(jdec(1024UL)), "\"1024\"")
}

///|
/// One failure section: a kind name plus the full text. The `json_failure` used when the
/// whole document cannot be produced has the same shape, so readers only need to recognize
/// one form.
test "shape of the failure section" {
  assert_eq(
    compact(jerror("stream_directory", "stream directory out of range")),
    "{\"kind\":\"stream_directory\",\"message\":\"stream directory out of range\"}",
  )
  let one = json_failure("read_file", "failed to read file: x.dmp")
  // The top level has only schema / generator / error: the success document has no error,
  // the failure document has none of the 17 sections — readers branch on this one field.
  assert_eq(compact(at_key(one, "schema")), "\"moondump/v1\"")
  assert_eq(
    compact(at_key(one, "error")),
    "{\"kind\":\"read_file\",\"message\":\"failed to read file: x.dmp\"}",
  )
  assert_eq(compact(at_key(one, "stacks")), "null")
  assert_eq(compact(at_key(at_key(one, "generator"), "name")), "\"moondump\"")
}

///|
/// The 4-byte CodeView magic rendered as ASCII: ordered from each byte's low to high (which
/// is little-endian in the dump), with non-printable bytes replaced by `.` so the terminal
/// does not show a run of control characters.
test "printable form of the magic" {
  // The bytes of "RSDS" on the wire are 52 53 44 53; read as a little-endian u32 that is this value
  assert_eq(code_view_magic_text(0x5344_5352U), "RSDS")
  assert_eq(code_view_magic_text(0x31303044U), "D001")
  // The magic of the old-style CV_HEADER for 0x102: the first byte 0x01 is not printable
  assert_eq(code_view_magic_text(0x3230_0100U), "..02")
  assert_eq(code_view_magic_text(0U), "....")
}
