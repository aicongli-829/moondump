// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///|
/// Compile-checked copies of the two "library usage" snippets in README.mbt.md
/// (`@moondump` spelled as this package's alias `@lib`).
/// Keeping them here is deliberate: if a README example drifts from the API — a renamed
/// field, a changed parameter order — `moon check` fails right away instead of leaving a
/// reader stuck with a snippet that doesn't run. When you edit the README snippet, edit
/// this copy in the same change.
pub fn readme_inspect(bytes : Bytes) -> Unit raise {
  let dump = @lib.open_dump(bytes) // validates signature and format version
  let entries = dump.stream_directory() // stream directory, 12 bytes per entry
  match dump.modules(entries) { // ModuleList + VS_FIXEDFILEINFO + CodeView
    None => println("no ModuleList in this dump")
    Some(mods) =>
      println(
        mods.modules.length().to_string() +
        " modules, skipped malformed records: " +
        mods.skipped.to_string(),
      )
  }
  match dump.exception(entries) { // exception code, access-violation address, crash CONTEXT
    None => println("no ExceptionStream in this dump")
    Some(exc) =>
      println(
        "thread " +
        exc.thread_id.to_string() +
        " crashed at 0x" +
        exc.address.to_string(radix=16),
      )
  }
  match dump.memory_map(entries) { // unified index over MemoryList / Memory64List
    None => println("this dump carries no memory stream")
    Some(map) =>
      // An unmapped address, or one straddling two ranges, reads back as None —
      // not as "read 0 bytes".
      match dump.read_memory_at(map, 0x12f31cUL, 16) {
        None => println("virtual address not captured")
        Some(data) => println("read " + data.length().to_string() + " bytes")
      }
  }
}

///|
/// Copy of the README's "stack walk + symbolization" snippet.
pub fn readme_inspect_stack(bytes : Bytes, sym_text : String) -> Unit raise {
  let dump = @lib.open_dump(bytes)
  let entries = dump.stream_directory()
  // Frame-to-module attribution and module-relative offsets both come from the module list
  let mods = match dump.modules(entries) {
    None => []
    Some(m) => m.modules
  }
  // The function-table stream is corroboration only ("was this address ever registered"),
  // it never drives the walk
  let ft = dump.function_table(entries)
  // Architecture comes from SystemInfo; which register table actually applies is decided by
  // the CONTEXT itself (see the README section). With no SystemInfo, pass 0xffff:
  // read_context will not recognize the table and returns None instead of guessing.
  let arch : UInt16 = match dump.system_info(entries) {
    None => 0xffff
    Some(si) => si.processor_architecture
  }
  let store = @lib.symbol_store_new()
  // Only files with a valid MODULE line are accepted; bad ones land in `rejected`,
  // never silently dropped
  let accepted = @lib.symbol_store_add(store, "test_app.sym", sym_text)
  println(
    if accepted {
      "symbol file accepted"
    } else {
      "no valid MODULE line, recorded in rejected"
    },
  )
  match
    (dump.exception(entries), dump.threads(entries), dump.memory_map(entries)) {
    (Some(exc), Some(threads), Some(map)) =>
      match @lib.find_thread_by_id(threads, exc.thread_id) {
        None =>
          println(
            "the thread named by the exception stream is not in the thread list",
          )
        Some((_, t)) =>
          match dump.read_context(arch, exc.thread_context) {
            None =>
              println(
                "context unreadable: register table unsupported or CONTEXT size unreasonable",
              )
            Some(ctx) => {
              let opts = @lib.stack_walk_options_default()
              let w = dump.walk_thread_stack(map, mods, ft, t, ctx, opts)
              println(
                "layout " +
                w.layout +
                " frames " +
                w.frames.length().to_string(),
              )
              for f in w.frames {
                let sym = @lib.symbolize_frame(f, mods, store)
                println(
                  f.kind + " " + @lib.hex_uint(f.address) + " " + sym.status,
                )
              }
            }
          }
      }
    _ => println("missing exception / thread-list / memory stream; cannot walk")
  }
}
