// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! A minimal runnable version of the interface shown in the README:
///!   moon run examples -- testdata/test.dmp
///! It only does "print what can be read, and say clearly why when it cannot"; for the full
///! field display use `moon run cmd/main -- <file>`.

///|
/// Pads to a fixed column width, purely for output alignment (the CLI version measures by display width; that is not reimplemented here).
fn pad(s : String, width : Int32) -> String {
  let mut out = s
  while out.length() < width {
    out = out + " "
  }
  out
}

///|
/// Two hex digits, enough for a byte, with no need to assemble zero padding.
fn hex_byte(b : Byte) -> String {
  let digits = "0123456789abcdef".to_array()
  let v = b.to_int()
  digits[v / 16].to_string() + digits[v % 16].to_string()
}

///|
/// usage: moon run examples -- <crash-dump.dmp>
fn main {
  let args = @env.args()
  if args.length() < 2 {
    println("usage: moon run examples -- <crash-dump.dmp>")
    return ()
  }
  try @fs.read_file_to_bytes(args[1]) catch {
    _ => println("failed to read file: " + args[1])
  } noraise {
    bytes =>
      try @lib.open_dump(bytes) catch {
        err => println("parse failed: " + @lib.describe_error(err))
      } noraise {
        dump =>
          try dump.stream_directory() catch {
            err =>
              println("malformed stream directory: " + @lib.describe_error(err))
          } noraise {
            entries => inspect(dump, entries)
          }
      }
  }
}

///|
/// The directory is listed as-is first: this project's principle is that unrecognized streams must remain visible, never silently dropped.
fn inspect(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  println(
    "read " +
    dump.data.length().to_string() +
    " bytes, " +
    entries.length().to_string() +
    " streams",
  )
  for e in entries {
    println(
      "  " +
      pad(@lib.stream_type_name(e.stream_type), 28) +
      e.data_size.to_string() +
      " bytes",
    )
  }
  println("")
  show_system_info(dump, entries)
  show_modules(dump, entries)
  show_exception(dump, entries)
  show_memory(dump, entries)
  show_stack(dump, entries)
}

///|
fn show_system_info(
  dump : @lib.Dump,
  entries : Array[@lib.StreamEntry],
) -> Unit {
  try dump.system_info(entries) catch {
    err => println("SystemInfo: parse failed " + @lib.describe_error(err))
  } noraise {
    info =>
      match info {
        None => println("SystemInfo: this stream is absent from the dump")
        Some(si) => {
          let os = si.major_version.to_string() +
            "." +
            si.minor_version.to_string() +
            "." +
            si.build_number.to_string()
          let n = si.number_of_processors.to_int().to_string()
          let vendor = match si.cpu_vendor {
            None => "-"
            Some(v) => v
          }
          println(
            "SystemInfo:" +
            @lib.architecture_name(si.processor_architecture) +
            " / " +
            os +
            " / " +
            n +
            " logical processors / " +
            vendor,
          )
        }
      }
  }
}

///|
/// The skipped count must be reported together: a nonzero `skipped` means this dump's module table was written corruptly,
/// and looking only at the modules array would make you think the process really loaded only that many modules.
fn show_modules(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  try dump.modules(entries) catch {
    err => println("ModuleList: parse failed " + @lib.describe_error(err))
  } noraise {
    modules =>
      match modules {
        None => println("ModuleList: this stream is absent from the dump")
        Some(list) => {
          let n = list.modules.length().to_string()
          let skipped = if list.skipped > 0 {
            ", skipped " + list.skipped.to_string() + " malformed records"
          } else {
            ""
          }
          println("ModuleList:" + n + " module(s)" + skipped)
          let total = list.modules.length()
          let shown = if total < 3 { total } else { 3 }
          for i in 0..<shown {
            let m = list.modules[i]
            println(
              "  " +
              m.name +
              "  " +
              @lib.hex_uint(m.base_of_image) +
              " +0x" +
              m.size_of_image.to_string(radix=16),
            )
          }
        }
      }
  }
}

///|
fn show_exception(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  try dump.exception(entries) catch {
    err => println("Exception: parse failed " + @lib.describe_error(err))
  } noraise {
    exception =>
      match exception {
        None =>
          println(
            "Exception: this stream is absent from the dump (which does not mean no crash happened)",
          )
        Some(e) =>
          println(
            "Exception: thread " +
            e.thread_id.to_string() +
            "  0x" +
            e.code.to_string(radix=16) +
            " " +
            @lib.exception_code_name(e.code) +
            "  faulting address " +
            @lib.hex_uint(e.address),
          )
      }
  }
}

///|
/// Reads memory by virtual address. Here it reads the crash thread's stack top: with a memory stream the original bytes are available,
/// while in dumps that only carry stack-walk information the whole range may be uncaptured — both cases are printed as they are.
fn show_memory(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  let map = try dump.memory_map(entries) catch {
    err => {
      println("Memory: parse failed " + @lib.describe_error(err))
      None
    }
  } noraise {
    m => m
  }
  match map {
    None => println("Memory: dump has no memory stream")
    Some(memory_map) => {
      let threads = try dump.threads(entries) catch {
        _ => None
      } noraise {
        ts => ts
      }
      match threads {
        None => println("Memory: no thread table, no address to read from")
        Some(ts) =>
          if ts.length() == 0 {
            println("Memory: thread table is empty")
          } else {
            let t = ts[0]
            let addr = t.stack.start_address
            let sample = try dump.read_memory_at(memory_map, addr, 16) catch {
              _ => None
            } noraise {
              b => b
            }
            let text = match sample {
              None =>
                "not captured (range not in the map, or straddling two regions)"
              Some(bs) => {
                let parts : Array[String] = []
                for b in bs {
                  parts.push(hex_byte(b))
                }
                parts.join(" ")
              }
            }
            println("Memory: stack top " + @lib.hex_uint(addr) + " -> " + text)
          }
      }
    }
  }
}

///|
/// Inlines a `.sym` for test.dmp: the debug id is exactly the one that ships with that corpus,
/// `5A9832E5-2872-41C1-838E-D98914E9B7FF/1`. Only with it can the example produce `ok` instead of
/// `(empty_store)` on every frame; in real use run `moon run cmd/main -- <file> --symbols <dir>`
/// to collect a symbol directory recursively — do not bake `.sym` text into the code.
let demo_sym : String = "MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 c:\\test_app.pdb\nFUNC 0 4280 40 test_app!crash_here\n"

///|
/// Offset within a module: None when not inside any module; in that case "no offset" and "offset 0" are two different things.
fn offset_text(f : @lib.StackFrame) -> String {
  match f.offset {
    None => "?"
    Some(o) => "0x" + o.to_string(radix=16)
  }
}

///|
/// Frame-by-frame output for one stack. The example prints only the first 8 frames and states how many remain — full layout is the CLI's job.
fn print_frames(
  store : @lib.SymbolStore,
  modules : Array[@lib.Module],
  w : @lib.StackWalk,
) -> Unit {
  let total = w.frames.length()
  let head : Array[String] = [
    "thread",
    w.thread_id.to_string(),
    "layout",
    w.layout,
    "pointer",
    w.pointer_size.to_string() + " bytes",
    "frames",
    total.to_string(),
    "fp frames",
    w.fp_frames.to_string(),
  ]
  println("stack walk: " + head.join(" "))
  let shown = if total < 8 { total } else { 8 }
  for i in 0..<shown {
    let f = w.frames[i]
    let sym = @lib.symbolize_frame(f, modules, store)
    let parts : Array[String] = [
      "#" + i.to_string(),
      f.kind,
      @lib.hex_uint(f.address),
      f.module_name + "+" + offset_text(f),
      "(" + sym.status + ")",
      sym.name,
    ]
    println("  " + parts.join("  "))
  }
  if total > shown {
    println(
      "  " +
      (total - shown).to_string() +
      " more frames not shown (the CLI prints them all)",
    )
  }
  for n in w.notes {
    println("  note  " + n)
  }
}

///|
/// Stack walk + symbolization, a runnable version of the README's second example.
/// Every "cannot obtain" step is stated separately: which stream is missing, an unreadable context,
/// the thread to walk not being in the thread table, and the walk itself failing — these are four
/// different things and must not be merged into a single "cannot walk".
fn show_stack(dump : @lib.Dump, entries : Array[@lib.StreamEntry]) -> Unit {
  let mods = try dump.modules(entries) catch {
    _ => None
  } noraise {
    m => m
  }
  let map = try dump.memory_map(entries) catch {
    _ => None
  } noraise {
    m => m
  }
  let threads = try dump.threads(entries) catch {
    _ => None
  } noraise {
    t => t
  }
  let exc = try dump.exception(entries) catch {
    _ => None
  } noraise {
    e => e
  }
  match (mods, map, threads, exc) {
    (Some(list), Some(memory_map), Some(ts), Some(e)) => {
      let ft = try dump.function_table(entries) catch {
        _ => None
      } noraise {
        f => f
      }
      let si = try dump.system_info(entries) catch {
        _ => None
      } noraise {
        s => s
      }
      // without SystemInfo, 0xffff is passed: read_context cannot recognize such a register table,
      // returns None honestly, and never unwinds with a guessed architecture.
      let arch : UInt16 = match si {
        None => 0xffff
        Some(info) => info.processor_architecture
      }
      let store = @lib.symbol_store_new()
      let accepted = @lib.symbol_store_add(
        store, "inline:test_app.sym", demo_sym,
      )
      let sym_note = if accepted {
        "accepted the inline test_app.sym"
      } else {
        "inline text has no valid MODULE line, went into rejected"
      }
      println("symbol table: " + sym_note)
      match @lib.find_thread_by_id(ts, e.thread_id) {
        None =>
          println(
            "stack walk: the thread named by the exception stream is not in the thread table",
          )
        Some((_, t)) => {
          let ctx = try dump.read_context(arch, e.thread_context) catch {
            _ => None
          } noraise {
            c => c
          }
          match ctx {
            None =>
              println(
                "stack walk: context unreadable, architecture " +
                @lib.architecture_name(arch),
              )
            Some(c) => {
              let opts = @lib.stack_walk_options_default()
              let walked = try
                dump.walk_thread_stack(memory_map, list.modules, ft, t, c, opts)
              catch {
                err => {
                  println("stack walk: cannot walk " + @lib.describe_error(err))
                  None
                }
              } noraise {
                w => Some(w)
              }
              match walked {
                None => ()
                Some(w) => print_frames(store, list.modules, w)
              }
            }
          }
        }
      }
    }
    _ =>
      println(
        "stack walk: missing module table / memory stream / thread table / exception stream, not forcing a walk",
      )
  }
}
