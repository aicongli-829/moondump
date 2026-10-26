// Copyright 2026 aicongli-829
// Licensed under the Apache-2.0

///! Real-corpus regression: each of the seven public `.dmp` files is opened in turn, its stream
///! directory listed, then asserted field-by-field down to concrete values (stream count, module
///! names and counts, exception code and thread ID, the whole MiscInfo stream, stack walk frame
///! counts, ...). Malformed corpus must likewise produce a full document, see `corpus/json_corpus_test.mbt`.
///! The loaders live in corpus.mbt of the same package.

///|
test "test.dmp: Windows dump from an older toolchain" {
  let dump = @corpus.open_fixture("test.dmp")
  let entries = dump.stream_directory()
  @corpus.assert_count("test.dmp", entries.length(), 9)
  @corpus.assert_stream_present("test.dmp", entries, @lib.thread_list_stream)
  @corpus.assert_stream_present("test.dmp", entries, @lib.module_list_stream)
  @corpus.assert_stream_present("test.dmp", entries, @lib.memory_list_stream)
  @corpus.assert_stream_present("test.dmp", entries, @lib.exception_stream)
  @corpus.assert_stream_present("test.dmp", entries, @lib.system_info_stream)
  @corpus.assert_stream_present("test.dmp", entries, @lib.misc_info_stream)
}

///|
test "simple-crashpad.dmp: Crashpad orders streams differently" {
  let dump = @corpus.open_fixture("simple-crashpad.dmp")
  let entries = dump.stream_directory()
  @corpus.assert_count("simple-crashpad.dmp", entries.length(), 7)
  @corpus.assert_stream_present(
    "simple-crashpad.dmp", entries, @lib.system_info_stream,
  )
  @corpus.assert_stream_present(
    "simple-crashpad.dmp", entries, @lib.exception_stream,
  )
  @corpus.assert_stream_present(
    "simple-crashpad.dmp", entries, @lib.module_list_stream,
  )
}

///|
test "linux-mini.dmp: extension streams must be listed, not rejected" {
  let dump = @corpus.open_fixture("linux-mini.dmp")
  let entries = dump.stream_directory()
  @corpus.assert_count("linux-mini.dmp", entries.length(), 14)
  @corpus.assert_stream_present(
    "linux-mini.dmp", entries, @lib.module_list_stream,
  )
  // The 0x4767-series Crashpad custom streams appear here as a group; they must be displayed even though unrecognized
  assert_eq(@lib.stream_type_name(0x4767_0003U), "Stream(0x47670003)")
}

///|
test "invalid-parameter.dmp: contains a newer stream type" {
  let dump = @corpus.open_fixture("invalid-parameter.dmp")
  let entries = dump.stream_directory()
  @corpus.assert_count("invalid-parameter.dmp", entries.length(), 14)
  @corpus.assert_stream_present(
    "invalid-parameter.dmp", entries, @lib.system_memory_info_stream,
  )
}

///|
/// Full-memory dump: Memory64List uses 64-bit RVAs, and the expanded flag names must match the directory.
test "full-dump.dmp: Memory64List and Token" {
  let dump = @corpus.open_fixture("full-dump.dmp")
  let entries = dump.stream_directory()
  @corpus.assert_stream_present(
    "full-dump.dmp", entries, @lib.memory_64_list_stream,
  )
  @corpus.assert_stream_present("full-dump.dmp", entries, @lib.token_stream)
  assert_eq(
    @lib.describe_minidump_type(dump.header.flags).join("|"),
    "WithFullMemory|WithTokenInformation",
  )
}

///|
/// SystemInfo is the first stream every generator writes; here we pin field-level goldens from the actual
/// bytes of the 5 real dumps in testdata: XP SP2, Win10 (including full memory), the Win10 invalid-parameter
/// sample, Crashpad macOS, and breakpad Linux. The CSD string and CPUID vendor string are pinned too.
test "SystemInfo field-level assertions" {
  let cases : Array[(String, String)] = [
    (
      "test.dmp", "x86|5.1.2600|Win32NT|1|Workstation|0x100|GenuineIntel|6/13/8|Service Pack 2",
    ),
    (
      "full-dump.dmp", "amd64|10.0.19042|Win32NT|16|Workstation|0x300|-|6/167/1|",
    ),
    (
      "invalid-parameter.dmp", "amd64|10.0.17134|Win32NT|16|Workstation|0x100|-|6/79/1|",
    ),
    (
      "simple-crashpad.dmp", "amd64|10.15.7|MacOS|12|Workstation|0x0|-|6/158/10|19H114",
    ),
    // breakpad's Linux dump leaves the OS version empty and ProductType is 0 too: it must be read out as-is
    (
      "linux-mini.dmp", "amd64|0.0.0|Linux|4|ProductType(0)|0x0|GenuineIntel|6/70/1|Linux 4.9.60-linuxkit-aufs #1 SMP Mon Nov 6 16:00:12 UTC 2017 x86_64",
    ),
  ]
  for (name, want) in cases {
    let dump = @corpus.open_fixture(name)
    @corpus.assert_system_info(name, dump, dump.stream_directory(), want)
  }
}

///|
/// Malformed corpus: the header itself is fine, so the dump opens; but the malformed stream is either judged
/// out of range or reports a named error when read — panicking is never allowed.
test "malformed corpus never panics" {
  for name in ["invalid-range.dmp", "invalid-record-count.dmp"] {
    let dump = @lib.open_dump(@corpus.read_fixture(name))
    try dump.stream_directory() catch {
      err =>
        assert_true(
          @lib.error_kind(err) == "BadStreamCount" ||
          @lib.error_kind(err) == "Truncated",
        )
    } noraise {
      entries => {
        let mut bad : Int32 = 0
        for e in entries {
          if !dump.range_in_file(e.rva, e.data_size.to_uint64()) {
            bad = bad + 1
          }
        }
        assert_true(bad > 0)
      }
    }
  }
}

///|
/// ModuleList field-level golden. Each line is "name|address range|image|file version|product version|
/// timestamp|checksum|debug info". The golden was computed independently, byte by byte, from the same
/// testdata by a separate script — not generated from this implementation's output — so a mis-copied
/// offset, a flipped GUID endianness, or a wrong version split all get caught.
test "ModuleList field-level assertions" {
  let cases : Array[(String, Int32, Int32, String)] = [
    (
      "test.dmp", 13, 0, "c:\\test_app.exe|0x400000-0x42d000|0x2d000|0.0.0.0|0.0.0.0|0x45d35f6c|0x0|RSDS:5A9832E5-2872-41C1-838E-D98914E9B7FF/1:c:\\test_app.pdb",
    ),
    (
      "test.dmp", 13, 1, "C:\\WINDOWS\\system32\\ntdll.dll|0x7c900000-0x7c9b0000|0xb0000|5.1.2600.2180|5.1.2600.2180|0x411096b4|0xaf2f7|RSDS:36515FB5-D043-45E4-91F6-72FA2E2878C0/2:ntdll.pdb",
    ),
    (
      "full-dump.dmp", 6, 0, "E:\\hello-world\\target\\release\\hello-world.exe|0x7ff6e7c40000-0x7ff6e7c68000|0x28000|0.0.0.0|0.0.0.0|0x6205aa29|0x0|RSDS:87D4B192-59BC-495B-A50C-C01B85A57464/1:E:\\hello-world\\target\\release\\deps\\hello_world.pdb",
    ),
    // 1803's ntdll is the classic "file version 6.2, product version 10.0" case, which blocks a flipped hi/lo split
    (
      "invalid-parameter.dmp", 31, 1, "C:\\Windows\\System32\\ntdll.dll|0x7ff806ab0000-0x7ff806c91000|0x1e1000|6.2.17134.254|10.0.17134.254|0xa5a334d4|0x1e8b42|RSDS:5BADA676-3A2D-F568-BAEA-C8F70DA0DF3C/1:ntdll.pdb",
    ),
    // Crashpad/macOS: age is 0 and the pdb name has no extension
    (
      "simple-crashpad.dmp", 40, 0, "/Users/ted/src/crashy|0x10dfe8000-0x10dfec000|0x4000|0.0.0.0|0.0.0.0|0x0|0x0|RSDS:EF1091E3-81DA-369B-9039-EA1591D07E0B/0:crashy",
    ),
    (
      "simple-crashpad.dmp", 40, 1, "/usr/lib/libSystem.B.dylib|0x7fff6c2b2000-0x7fff6c2b4000|0x2000|1281.100.1.0|5.281.16.0|0x5fd06154|0x0|RSDS:8E6AD412-91E7-36FC-A6FD-C13B06A4952A/0:libSystem.B.dylib",
    ),
    // breakpad/Linux's CvRecord is a "LEpB" (build-id) record; this implementation only reports the magic
    (
      "linux-mini.dmp", 8, 0, "/work/linux/build/crash|0x400000-0x41a000|0x1a000|0.0.0.0|0.0.0.0|0x0|0x0|cv:0x4270454c",
    ),
  ]
  for (name, count, index, want) in cases {
    let dump = @corpus.open_fixture(name)
    let entries = dump.stream_directory()
    match dump.modules(entries) {
      None => fail(name + " should have a ModuleListStream")
      Some(list) => {
        @corpus.assert_count(name, list.modules.length(), count)
        // No malformed record in the corpus was skipped
        assert_eq((name, list.skipped), (name, 0))
        @corpus.assert_module(name, list, index, want)
      }
    }
  }
}

///|
/// MiscInfo: the corpus happens to cover three lengths — v1 (old Windows toolchain), v4 (Crashpad/macOS),
/// and v5 (Win10 full memory + full directory) — pinning the version check and the Flags1 gating in one go.
/// The golden was likewise recomputed by an independent byte-level script.
test "MiscInfo field-level assertions: v1 / v4 / v5" {
  let cases : Array[(String, String)] = [
    // v1 has only pid + times; every other group is `-` (not provided, not 0)
    (
      "test.dmp", "v=1|size_of_info=24|flags=0x3|pid=3932|create_time=1171480435|user_time=0|kernel_time=0|max_mhz=-|current_mhz=-|mhz_limit=-|max_idle_state=-|current_idle_state=-|integrity=-|exec_flags=-|protected=-|tz_id=-|tz_bias=-|tz_offset=-|tz_std_name=-|tz_std_rule=-|tz_std_bias=-|tz_dst_name=-|tz_dst_rule=-|tz_dst_bias=-|build=-|dbg=-|xstate_size=-|ctx_size=-|enabled=-|cookie=-",
    ),
    // Win10 v5: Bias=300 → -05:00 (sign is the opposite of the UTC offset); the DST rule is "1st Sunday of November at 02:00"
    (
      "full-dump.dmp", "v=5|size_of_info=1364|flags=0x3f7|pid=544|create_time=1644538475|user_time=0|kernel_time=0|max_mhz=2496|current_mhz=2496|mhz_limit=2496|max_idle_state=2|current_idle_state=2|integrity=8192|exec_flags=0xd|protected=0|tz_id=1|tz_bias=300|tz_offset=-05:00|tz_std_name=Eastern Standard Time|tz_std_rule=y=0 m=11 dow=0 d=1 02:00:00|tz_std_bias=0|tz_dst_name=Eastern Daylight Time|tz_dst_rule=y=0 m=3 dow=0 d=2 02:00:00|tz_dst_bias=-60|build=19041.1.amd64fre.vb_release.191206-1406|dbg=dbgeng.amd64,10.0.18362.1|xstate_size=0|ctx_size=0|enabled=0x0|cookie=0xc0547ff6",
    ),
    (
      "invalid-parameter.dmp", "v=5|size_of_info=1364|flags=0x3f7|pid=6256|create_time=1537549244|user_time=0|kernel_time=0|max_mhz=3501|current_mhz=3501|mhz_limit=3501|max_idle_state=2|current_idle_state=2|integrity=8192|exec_flags=0xd|protected=0|tz_id=2|tz_bias=300|tz_offset=-05:00|tz_std_name=Eastern Standard Time|tz_std_rule=y=0 m=11 dow=0 d=1 02:00:00|tz_std_bias=0|tz_dst_name=Eastern Daylight Time|tz_dst_rule=y=0 m=3 dow=0 d=2 02:00:00|tz_dst_bias=-60|build=17134.1.amd64fre.rs4_release.180410-1804|dbg=dbgcore.amd64,10.0.17134.1|xstate_size=0|ctx_size=0|enabled=0x0|cookie=0x97445b9d",
    ),
    // Crashpad v4: lacks v3's integrity/exec/protected bits but has the time zone;
    // the DST rule block is all zeroes → `-`, which is "does not observe DST", not malformed
    (
      "simple-crashpad.dmp", "v=4|size_of_info=832|flags=0x147|pid=56685|create_time=1608319181|user_time=0|kernel_time=0|max_mhz=2600|current_mhz=2600|mhz_limit=0|max_idle_state=0|current_idle_state=0|integrity=-|exec_flags=-|protected=-|tz_id=1|tz_bias=300|tz_offset=-05:00|tz_std_name=EST|tz_std_rule=-|tz_std_bias=0|tz_dst_name=EDT|tz_dst_rule=-|tz_dst_bias=-60|build=Mac OS X 10.15.7 (19H114); Darwin 19.6.0 Darwin Kernel Version 19.6.0: Tue Nov 10 00:10:30 PST 2020; root:xnu-6153.141.10~1/RELEASE_X86_64 x86_64; MacBookPro15,1 (Mac-937A206F2EE63C01)|dbg=crashpad.amd64,0.8.0,mac,100900,101500|xstate_size=-|ctx_size=-|enabled=-|cookie=-",
    ),
    // breakpad's minimal Linux dump does not write MiscInfo at all
    ("linux-mini.dmp", "no-misc-info"),
  ]
  for (name, want) in cases {
    let dump = @corpus.open_fixture(name)
    let entries = dump.stream_directory()
    @corpus.assert_misc_info(name, dump, entries, want)
  }
}

///|
/// Thread table + CONTEXT + exception stream. The golden was computed by an independent Node
/// extraction script, and one corpus pins all of these at once: the 48-byte Thread, the two
/// CONTEXT tables for x86/amd64, the three label paths for Windows exception codes / Linux
/// signals / macOS Mach codes, and the (read/write/DEP, target address) parameter convention
/// of ACCESS_VIOLATION.
test "ThreadList / CONTEXT / Exception field-level assertions" {
  let cases : Array[(String, String, String, String)] = [
    // With a single thread, crash (the CONTEXT carried by the exception) has exactly the same
    // values as thread 0; when a corpus has more than one thread the two RVAs differ, see test.dmp.
    (
      "test.dmp", "count=2 id=3060,sus=0,pcls=0,prio=0,teb=0x7ffdf000,stk=0x12f31c+3300@5689,ctx=716@3476,w=48 ; id=4544,sus=0,pcls=0,prio=0,teb=0x7ffde000,stk=0x97f6e8+2328@8989,ctx=716@4192,w=48",
      "0:x86 flags=0x1003f eip=0x7c90eb94 esp=0x12f320 ebp=0x12f384 eax=0x400000 ebx=0x7c883780 ecx=0x7c80b46e edx=0x7c97c0d8 esi=0x7b8 edi=0x0 eflags=0x246 cs=0x1b ss=0x23 ds=0x23 es=0x23 fs=0x3b gs=0x0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0 ; 1:x86 flags=0x1003f eip=0x7c90eb94 esp=0x97f6ec ebp=0x97f6fc eax=0xa80000 ebx=0x145ad0 ecx=0x7 edx=0x7c90eb94 esi=0x145aa8 edi=0x145b00 eflags=0x246 cs=0x1b ss=0x23 ds=0x23 es=0x23 fs=0x3b gs=0x0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
      // The thread table's eip is the syscall return point at the time the dump was written; the exception CONTEXT's eip is the real crash point.
       "tid=3060 code=0xc0000005/EXCEPTION_ACCESS_VIOLATION flags=0x0/- addr=0x40429e@c:\\test_app.exe+0x429e nest=0x0 np=2 p=0x1,0x45 kind=write target=0x45 status=- ctx=716@2760 thread=0 crash=x86 flags=0x1003f eip=0x40429e esp=0x12fe84 ebp=0x12fe88 eax=0x45 ebx=0x7c80abc1 ecx=0x12fe94 edx=0x42bc58 esi=0x2 edi=0xa28 eflags=0x10246 cs=0x1b ss=0x23 ds=0x23 es=0x23 fs=0x3b gs=0x0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
    ),
    // Win10 full-memory dump: all 4 threads have suspend=1, and the crashed thread is thread 0.
    (
      "full-dump.dmp", "count=4 id=8124,sus=1,pcls=32,prio=0,teb=0x9897e94000,stk=0x9897d0f230+3536@0,ctx=1232@5762,w=48 ; id=18128,sus=1,pcls=32,prio=0,teb=0x9897e96000,stk=0x98980ffc28+984@0,ctx=1232@6994,w=48 ; id=13256,sus=1,pcls=32,prio=0,teb=0x9897e98000,stk=0x98981ff718+2280@0,ctx=1232@8226,w=48 ; id=11364,sus=1,pcls=32,prio=0,teb=0x9897e9a000,stk=0x98982ff7f8+2056@0,ctx=1232@9458,w=48",
      "0:amd64 flags=0x10001f rip=0x7ffb604806b0 rsp=0x9897d0f230 rbp=0x0 rax=0x0 rbx=0x10 rcx=0x7ffb6044d214 rdx=0x0 rsi=0x7ffb604e1a90 rdi=0x9897e93000 r8=0x9897d0f228 r9=0x0 r10=0x0 r11=0x246 r12=0x40 r13=0x0 r14=0x7ffb604d48f0 r15=0x20993040000 eflags=0x244 cs=0x33 ss=0x2b ds=0x2b es=0x2b fs=0x53 gs=0x2b mxcsr=0x1f80 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0 ; 1:amd64 flags=0x10001f rip=0x7ffb604507c4 rsp=0x98980ffc28 rbp=0x0 rax=0x1d3 rbx=0x20993225f10 rcx=0x74 rdx=0x20993225b90 rsi=0x20993223e30 rdi=0x20993225f10 r8=0x98980ff390 r9=0x20993225f90 r10=0x6c r11=0x98980ff190 r12=0x0 r13=0x0 r14=0x0 r15=0x0 eflags=0x246 cs=0x33 ss=0x2b ds=0x2b es=0x2b fs=0x53 gs=0x2b mxcsr=0x1f80 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
      // int 3: the parameter convention does not apply, so kind/target must be `-`, not 0.
       "tid=8124 code=0x80000003/EXCEPTION_BREAKPOINT flags=0x0/- addr=0x7ffb604806b0@C:\\Windows\\System32\\ntdll.dll+0xd06b0 nest=0x0 np=1 p=0x0 kind=- target=- status=- ctx=1232@4530 thread=0 crash=amd64 flags=0x10005f rip=0x7ffb604806b0 rsp=0x9897d0f230 rbp=0x0 rax=0x0 rbx=0x10 rcx=0x7ffb6044d214 rdx=0x0 rsi=0x7ffb604e1a90 rdi=0x9897e93000 r8=0x9897d0f228 r9=0x0 r10=0x0 r11=0x246 r12=0x40 r13=0x0 r14=0x7ffb604d48f0 r15=0x20993040000 eflags=0x244 cs=0x33 ss=0x2b ds=0x2b es=0x2b fs=0x53 gs=0x2b mxcsr=0x1f80 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
    ),
    // EXCEPTION_INVALID_PARAMETER is not in the local SDK's naming table → Unknown(0x..);
    // but the attribution of address 0 must print as "address is 0", and the crash-site flags=0x10000f lack the SEGMENTS bit.
    (
      "invalid-parameter.dmp", "count=6 id=5896,sus=0,pcls=32,prio=0,teb=0xfc216fd000,stk=0xfc218fe978+5768@34189,ctx=1232@9532,w=48 ; id=4944,sus=0,pcls=32,prio=0,teb=0xfc216ff000,stk=0xfc219fd448+11192@19317,ctx=1232@10764,w=48 ; id=14112,sus=0,pcls=32,prio=0,teb=0xfc21701000,stk=0xfc21aff4e8+2840@39957,ctx=1232@11996,w=48 ; id=11744,sus=0,pcls=32,prio=0,teb=0xfc21703000,stk=0xfc21bff858+1960@30509,ctx=1232@13228,w=48 ; id=12044,sus=0,pcls=32,prio=0,teb=0xfc21705000,stk=0xfc21cffbd8+1064@42797,ctx=1232@14460,w=48 ; id=13188,sus=0,pcls=32,prio=0,teb=0xfc21707000,stk=0xfc21dff948+1720@32469,ctx=1232@15692,w=48",
      "0:amd64 flags=0x10001f rip=0x7ff806b49f74 rsp=0xfc218fe978 rbp=0xfc218ff530 rax=0x4 rbx=0x0 rcx=0x7c rdx=0x0 rsi=0x0 rdi=0x7c r8=0xa r9=0x1 r10=0x0 r11=0x246 r12=0x0 r13=0x0 r14=0x7c r15=0x0 eflags=0x246 cs=0x33 ss=0x2b ds=0x2b es=0x2b fs=0x53 gs=0x2b mxcsr=0x1fa0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0 ; 1:amd64 flags=0x10001f rip=0x7ff806b4bc44 rsp=0xfc219fd448 rbp=0xffffffffffffffff rax=0xeb rbx=0x4d0 rcx=0x270 rdx=0xfc219fd4c0 rsi=0x2b8611c24b8 rdi=0x2b8611c2520 r8=0x9fe r9=0x26c r10=0x0 r11=0x246 r12=0x2b8611c2520 r13=0x2b8611c24b8 r14=0x2b8611c24c8 r15=0x270 eflags=0x246 cs=0x33 ss=0x2b ds=0x2b es=0x2b fs=0x53 gs=0x2b mxcsr=0x1f80 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
      "tid=5896 code=0xc000000d/Unknown(0xc000000d) flags=0x0/- addr=0x0@address is 0 nest=0x0 np=3 p=0xfc218feac0,0xfc218fecc0,0x20 kind=- target=- status=- ctx=1232@8300 thread=0 crash=amd64 flags=0x10000f rip=0x7ff61bcfa9a3 rsp=0xfc218fea60 rbp=0xfc218ff530 rax=0xfc218feeb0 rbx=0x0 rcx=0xfc218feeb0 rdx=0x7ff61bdc5050 rsi=0x0 rdi=0xfc218ff380 r8=0xa0 r9=0xfefefefefefefefe r10=0x7ff61bdcbb70 r11=0xfc218fed20 r12=0x0 r13=0x0 r14=0x0 r15=0x0 eflags=0x246 cs=0x33 ss=0x2b ds=0x2b es=0x2b fs=0x53 gs=0x2b mxcsr=0x1fa0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
    ),
    // breakpad Linux minimal dump: plat=0x8201 → exception codes are interpreted as signals, 0xb = SIGSEGV;
    // the crash address 0x45 falls outside every module range, and teb=0 (Linux has no TEB).
    (
      "linux-mini.dmp", "count=1 id=1304,sus=0,pcls=0,prio=0,teb=0x0,stk=0x7fff5ae4a000+12288@248,ctx=1232@12792,w=48",
      "0:amd64 flags=0x10000b rip=0x401d72 rsp=0x7fff5ae4aa20 rbp=0x7fff5ae4abb0 rax=0xffffffffffffffff rbx=0x7fff5ae4aa20 rcx=0x7f5140521b20 rdx=0x7f5140efc000 rsi=0x0 rdi=0x7fff5ae4aab0 r8=0x0 r9=0x0 r10=0x131 r11=0x7f5140aca4c0 r12=0x401dc0 r13=0x7fff5ae4ac90 r14=0x7fff5ae4aab0 r15=0x0 eflags=0x10206 cs=0x33 ss=0x0 ds=0x0 es=0x0 fs=0x0 gs=0x0 mxcsr=0x0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
      "tid=1304 code=0xb/SIGSEGV flags=0x0/- addr=0x45@not inside any module nest=0x0 np=0 p=- kind=- target=- status=- ctx=1232@12792 thread=0 crash=amd64 flags=0x10000b rip=0x401d72 rsp=0x7fff5ae4aa20 rbp=0x7fff5ae4abb0 rax=0xffffffffffffffff rbx=0x7fff5ae4aa20 rcx=0x7f5140521b20 rdx=0x7f5140efc000 rsi=0x0 rdi=0x7fff5ae4aab0 r8=0x0 r9=0x0 r10=0x131 r11=0x7f5140aca4c0 r12=0x401dc0 r13=0x7fff5ae4ac90 r14=0x7fff5ae4aab0 r15=0x0 eflags=0x10206 cs=0x33 ss=0x0 ds=0x0 es=0x0 fs=0x0 gs=0x0 mxcsr=0x0 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
    ),
    // Crashpad macOS: plat=0x8101 does not use the signal table, so the Mach exception code stays Unknown(0x0);
    // cs=0x7 is macOS's user-mode segment selector, proving the amd64 table can be reused across platforms.
    (
      "simple-crashpad.dmp", "count=1 id=927532,sus=0,pcls=0,prio=0,teb=0x111324ea0,stk=0x7ffee1c16af0+5392@13120,ctx=1232@1088,w=48",
      "0:amd64 flags=0x10001f rip=0x7fff6f41333a rsp=0x7ffee1c16bf8 rbp=0x7ffee1c16c20 rax=0x0 rbx=0x111324dc0 rcx=0x7ffee1c16bf8 rdx=0x0 rsi=0x6 rdi=0x307 r8=0x0 r9=0x0 r10=0x111324dc0 r11=0x246 r12=0x307 r13=0x0 r14=0x6 r15=0x16 eflags=0x246 cs=0x7 ss=0x0 ds=0x0 es=0x0 fs=0x0 gs=0x0 mxcsr=0x1f80 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
      "tid=927532 code=0x0/Unknown(0x0) flags=0x0/- addr=0x7fff6f41333a@/usr/lib/system/libsystem_kernel.dylib+0x733a nest=0x0 np=3 p=0xa,0x6000000,0x0 kind=- target=- status=- ctx=1232@2496 thread=0 crash=amd64 flags=0x10001f rip=0x7fff6f41333a rsp=0x7ffee1c16bf8 rbp=0x7ffee1c16c20 rax=0x0 rbx=0x111324dc0 rcx=0x7ffee1c16bf8 rdx=0x0 rsi=0x6 rdi=0x307 r8=0x0 r9=0x0 r10=0x111324dc0 r11=0x246 r12=0x307 r13=0x0 r14=0x6 r15=0x16 eflags=0x246 cs=0x7 ss=0x0 ds=0x0 es=0x0 fs=0x0 gs=0x0 mxcsr=0x1f80 dr0=0x0 dr1=0x0 dr2=0x0 dr3=0x0 dr6=0x0 dr7=0x0",
    ),
    // The malformed corpus has no thread stream at all: absence is `no-threads`, not `count=0`.
    ("invalid-range.dmp", "no-threads", "", "no-exception"),
    ("invalid-record-count.dmp", "no-threads", "", "no-exception"),
  ]
  for (name, want_threads, want_contexts, want_exception) in cases {
    let dump = @corpus.open_fixture(name)
    let entries = dump.stream_directory()
    @corpus.assert_threads_and_exception(
      name, dump, entries, want_threads, want_contexts, want_exception,
    )
  }
}

///|
/// Memory index + read by virtual address. The golden was computed independently by a Node extraction
/// script; one corpus pins all of these at once: stream 5 (each descriptor carries its own RVA), stream 9
/// (RVAs accumulated from the declared sizes of the preceding sections), sorting and truncation,
/// and "the raw bytes read out after mapping an address to a file location".
///
/// The read-back contents can be independently falsified, and the corpus has three places for it:
/// - full-dump.dmp: the first byte at ip is `cc` = int 3, matching that dump's EXCEPTION_BREAKPOINT;
///   at the other threads the first 8 bytes at sp are return addresses falling inside ntdll's range.
/// - test.dmp: the three dwords at sp, 0x7c90e9c0/0x7c8025cb/0x7b8, all lie near ntdll,
///   and the file location stk maps to matches the 5689 the thread record itself declares.
/// - linux-mini.dmp: at ip is `c7042545000000` = `movl $0x45,0x45`, exactly matching that dump's
///   "out-of-bounds write of 0x45", so the pointer-to-instruction mapping is verified once by the instruction itself.
test "MemoryList / Memory64List / read by virtual address field-level assertions" {
  let cases : Array[(String, String, String)] = [
    (
      "full-dump.dmp", "n=54 dropped=0 total=8396800 head=[0x7ffe0000+4096@11902 0x7ffe9000+4096@15998 0x9897d0d000+12288@20094] tail=[0x7ffb60520000+544768@7863934]",
      "TID 8124 sp=0x9897d0f230->28846 b16=0000000000000000c0f2d09798000000 ip=0x7ffb604806b0->7210286 stk=0x9897d0f230->28846 ; TID 18128 sp=0x98980ffc28->76454 b16=c72d4060fb7f00000000000000000000 ip=0x7ffb604507c4->7013954 stk=0x98980ffc28->76454 ; TID 13256 sp=0x98981ff718->83350 b16=c72d4060fb7f00000f00010000000000 ip=0x7ffb604507c4->7013954 stk=0x98981ff718->83350 ; TID 11364 sp=0x98982ff7f8->87670 b16=c72d4060fb7f00000000000000000000 ip=0x7ffb604507c4->7013954 stk=0x98982ff7f8->87670",
    ),
    (
      "invalid-parameter.dmp", "n=10 dropped=0 total=25568 head=[0xfc218fe978+5768@34189 0xfc219fd448+11192@19317 0xfc21aff4e8+2840@39957] tail=[0x7ff806b4d7c4+256@44373]",
      "TID 5896 sp=0xfc218fe978->34189 b16=5292ae03f87f000030f58f21fc000000 ip=0x7ff806b49f74->43989 stk=0xfc218fe978->34189 ; TID 4944 sp=0xfc219fd448->19317 b16=01000000000000000000000000000000 ip=0x7ff806b4bc44->44245 stk=0xfc219fd448->19317 ; TID 14112 sp=0xfc21aff4e8->39957 b16=56f8ac06f87f00000e00010000000000 ip=0x7ff806b4d844->44501 stk=0xfc21aff4e8->39957 ; TID 11744 sp=0xfc21bff858->30509 b16=56f8ac06f87f00000000000000000000 ip=0x7ff806b4d844->44501 stk=0xfc21bff858->30509 ; TID 12044 sp=0xfc21cffbd8->42797 b16=56f8ac06f87f00000000000000000000 ip=0x7ff806b4d844->44501 stk=0xfc21cffbd8->42797 ; TID 13188 sp=0xfc21dff948->32469 b16=56f8ac06f87f000008d3f75bb8020000 ip=0x7ff806b4d844->44501 stk=0xfc21dff948->32469",
    ),
    (
      "linux-mini.dmp", "n=2 dropped=0 total=12544 head=[0x401cf2+256@12536 0x7fff5ae4a000+12288@248] tail=[0x7fff5ae4a000+12288@248]",
      "TID 1304 sp=0x7fff5ae4aa20->2840 b16=01000000ffffffff38aae45aff7f0000 ip=0x401d72->12664 stk=0x7fff5ae4a000->248",
    ),
    // ip falls outside every captured region (Crashpad carries only the stack), so the mapping must be `-`;
    // the same thread's sp/stk still lie in the single captured segment, so this line pins both "readable" and "unreadable" at once.
    (
      "simple-crashpad.dmp", "n=1 dropped=0 total=5392 head=[0x7ffee1c16af0+5392@13120] tail=[0x7ffee1c16af0+5392@13120]",
      "TID 927532 sp=0x7ffee1c16bf8->13384 b16=60fe4c6fff7f00000300000000000000 ip=0x7fff6f41333a->- stk=0x7ffee1c16af0->13120",
    ),
    (
      "test.dmp", "n=3 dropped=0 total=5884 head=[0x12f31c+3300@5689 0x97f6e8+2328@8989 0x7c90eb14+256@5433] tail=[0x7c90eb14+256@5433]",
      "TID 3060 sp=0x12f320->5693 b16=c0e9907ccb25807cb807000000000000 ip=0x7c90eb94->5561 stk=0x12f31c->5689 ; TID 4544 sp=0x97f6ec->8993 b16=20fa97009fd7907c0000000048f79700 ip=0x7c90eb94->5561 stk=0x97f6e8->8989",
    ),
    // The malformed corpus has no memory stream: absence is `no-memory`, not an empty index.
    ("invalid-range.dmp", "no-memory", "no-memory"),
    ("invalid-record-count.dmp", "no-memory", "no-memory"),
  ]
  for (name, want_map, want_reads) in cases {
    let dump = @corpus.open_fixture(name)
    let entries = dump.stream_directory()
    @corpus.assert_memory(name, dump, entries, want_map, want_reads)
  }
}

///|
/// The long-tail streams (UnloadedModuleList / HandleData / FunctionTable / ThreadInfoList /
/// ThreadNames) come mainly from full Windows Error Reporting (WER) dumps; none of the three
/// public generators (Windows toolchain, Crashpad, breakpad) write them.
/// So this batch of samples can only pin the "absent" half: if the directory lacks the stream, the
/// reader must return None — no throwing, no panicking, no inventing records. The "present" half is
/// cross-checked locally against real WER dumps; those dumps contain process memory and never enter the repository.
test "long-tail streams: absent from all public fixtures and reads must not error" {
  for
    name in [
      "test.dmp", "full-dump.dmp", "invalid-parameter.dmp", "invalid-range.dmp",
      "invalid-record-count.dmp", "linux-mini.dmp", "simple-crashpad.dmp",
    ] {
    let dump = @corpus.open_fixture(name)
    @corpus.assert_long_tail_absent(name, dump, dump.stream_directory())
  }
}

///|
/// Per-frame golden for the crash-site stack.
///
/// The golden is computed independently by `testdata/oracle/stack_oracle.js`: that script reads only,
/// per the SDK layout, the CONTEXT's ip/sp/bp and the stack window the thread record itself declares,
/// then spreads out "the slots on the chain" and "every aligned slot in the window" verbatim, applying
/// no heuristics. `testdata/oracle/stack_crosscheck.js` takes every frame the CLI reports and finds the
/// same (stack slot, value) pair in that raw slot table — all 266 frames across the 5 public corpora,
/// including the non-crashing threads, hit verbatim, and the module attribution agrees too (two `node`
/// commands from the repository root reproduce it; steps are in `testdata/README.md`).
/// In other words: **frame values come from independent extraction; which frames are kept is what this golden pins**.
///
/// A few places that can be explained independently of the implementation:
/// - test.dmp uses the exception's own CONTEXT; the first frame 0x40429e is the exception stream's
///   ExceptionAddress, not the same thing as the thread-table CONTEXT's 0x7c90eb94 (parked in ntdll at
///   dump-writing time). The three chain slots 0x12fe8c/0x12ff74/0x12ffc4 hold 0x404200, 0x4053ec, and
///   0x7c816fd7 respectively; the next slot 0x12fff0 holds 0, the chain breaks there, and the note says "outside the range".
/// - full-dump.dmp has bp=0, so the chain cannot step at all and only scanning remains; the 5th byte
///   before the first scanned value 0x7ffb60483ba2 is `e8` (the oracle's pre column), so the return site is a call.
/// - invalid-parameter.dmp's stretches of `cccccccccccccccc` on the stack are MSVC Debug uninitialized
///   filler; they fall outside every module range, pinning "the scan never mistakes filler bytes for return addresses".
/// - linux-mini.dmp's chain reads [RBP+8]=0x7f514017d830, an address inside libc, but the next slot's
///   RBP=0x414c30 is already outside the window, so no fp frame is produced at all — "the value looks like
///   code" and "the chain connects" are two different things, pinned separately here.
/// - full-dump.dmp and invalid-parameter.dmp have notes about "merged N consecutive slots holding the
///   previous frame's address": the same return address written into several consecutive slots is not that
///   many nested calls; the oracle's slot table lists those slots verbatim, so this pruning decision can be
///   checked externally.
test "crash-site stack walk: per-frame golden" {
  let cases : Array[(String, String)] = [
    (
      "test.dmp", "exception tid=3060 layout=x86 ps=4 supported=y reason=- window=0x12f31c+3300 frames=5 fp=3 slots=95 limited=n [context@0x40429e slot=- mod=c:\\test_app.exe+0x429e ft=- rs=unknown ; fp@0x404200 slot=0x12fe8c mod=c:\\test_app.exe+0x4200 ft=- rs=unknown ; fp@0x4053ec slot=0x12ff74 mod=c:\\test_app.exe+0x53ec ft=- rs=unknown ; fp@0x7c816fd7 slot=0x12ffc4 mod=C:\\WINDOWS\\system32\\kernel32.dll+0x16fd7 ft=- rs=unknown ; scan@0x405443 slot=0x12fff8 mod=c:\\test_app.exe+0x5443 ft=- rs=unknown] notes=[frame-pointer chain broke: next frame pointer 0x0 is outside (0x12fff0, 0x130000)]",
    ),
    (
      "full-dump.dmp", "exception tid=8124 layout=amd64 ps=8 supported=y reason=- window=0x9897d0f230+3536 frames=24 fp=0 slots=442 limited=n [context@0x7ffb604806b0 slot=- mod=C:\\Windows\\System32\\ntdll.dll+0xd06b0 ft=- rs=unknown ; scan@0x7ffb60483ba2 slot=0x9897d0f268 mod=C:\\Windows\\System32\\ntdll.dll+0xd3ba2 ft=- rs=call ; scan@0x7ffb604e1a90 slot=0x9897d0f278 mod=C:\\Windows\\System32\\ntdll.dll+0x131a90 ft=- rs=no_call ; scan@0x7ff6e7c400f0 slot=0x9897d0f330 mod=E:\\hello-world\\target\\release\\hello-world.exe+0xf0 ft=- rs=no_call ; scan@0x7ffb5ee90000 slot=0x9897d0f338 mod=C:\\Windows\\System32\\kernel32.dll+0x0 ft=- rs=unknown ; scan@0x7ffb603b00e8 slot=0x9897d0f360 mod=C:\\Windows\\System32\\ntdll.dll+0xe8 ft=- rs=no_call ; scan@0x7ffb5eeac720 slot=0x9897d0f3a0 mod=C:\\Windows\\System32\\kernel32.dll+0x1c720 ft=- rs=no_call ; scan@0x7ffb603b0000 slot=0x9897d0f3b8 mod=C:\\Windows\\System32\\ntdll.dll+0x0 ft=- rs=unknown …] notes=[frame pointer 0x0 is outside the stack window [0x9897d0f230, 0x9897d10000) ;; scan merged 3 consecutive slots holding the previous frame's address (one frame emitted)]",
    ),
    (
      "invalid-parameter.dmp", "exception tid=5896 layout=amd64 ps=8 supported=y reason=- window=0xfc218fe978+5768 frames=28 fp=0 slots=512 limited=y [context@0x7ff61bcfa9a3 slot=- mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x7a9a3 ft=- rs=unknown ; scan@0x7ff61bdc4dd8 slot=0xfc218fea78 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x144dd8 ft=- rs=unknown ; scan@0x7ff61bdcbb70 slot=0xfc218fea80 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x14bb70 ft=- rs=unknown ; scan@0x7ff61bdc5050 slot=0xfc218fef38 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x145050 ft=- rs=unknown ; scan@0x7ff61bdcbb70 slot=0xfc218fef78 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x14bb70 ft=- rs=unknown ; scan@0x7ff61bcfa9a3 slot=0xfc218fefa8 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x7a9a3 ft=- rs=no_call ; scan@0x7ff61bd2358f slot=0xfc218ff3d8 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0xa358f ft=- rs=unknown ; scan@0x7ff61bdcbc10 slot=0xfc218ff3e0 mod=c:\\build\\CrashTest\\x64\\Debug\\CrashTest.exe+0x14bc10 ft=- rs=unknown …] notes=[frame-pointer chain broke: next frame pointer 0xcccccccccccccccc is outside (0xfc218ff530, 0xfc21900000) ;; scan merged 2 consecutive slots holding the previous frame's address (one frame emitted) ;; scan covered only 4096 bytes; the stack window was not fully scanned]",
    ),
    (
      "linux-mini.dmp", "exception tid=1304 layout=amd64 ps=8 supported=y reason=- window=0x7fff5ae4a000+12288 frames=16 fp=0 slots=512 limited=y [context@0x401d72 slot=- mod=/work/linux/build/crash+0x1d72 ft=- rs=unknown ; scan@0x7f514025002e slot=0x7fff5ae4aa38 mod=/lib/x86_64-linux-gnu/libc-2.23.so+0xf302e ft=- rs=unknown ; scan@0x7f51401e4800 slot=0x7fff5ae4aa58 mod=/lib/x86_64-linux-gnu/libc-2.23.so+0x87800 ft=- rs=unknown ; scan@0x400000 slot=0x7fff5ae4aa80 mod=/work/linux/build/crash+0x0 ft=- rs=unknown ; scan@0x7f5140cebac6 slot=0x7fff5ae4aaa8 mod=/lib/x86_64-linux-gnu/ld-2.23.so+0xfac6 ft=- rs=unknown ; scan@0x401ec0 slot=0x7fff5ae4aab8 mod=/work/linux/build/crash+0x1ec0 ft=- rs=unknown ; scan@0x401c70 slot=0x7fff5ae4abd8 mod=/work/linux/build/crash+0x1c70 ft=- rs=unknown ; scan@0x401dc0 slot=0x7fff5ae4abf0 mod=/work/linux/build/crash+0x1dc0 ft=- rs=no_call …] notes=[frame-pointer chain broke: next frame pointer 0x414c30 is outside (0x7fff5ae4abb0, 0x7fff5ae4d000) ;; scan covered only 4096 bytes; the stack window was not fully scanned]",
    ),
    (
      "simple-crashpad.dmp", "exception tid=927532 layout=amd64 ps=8 supported=y reason=- window=0x7ffee1c16af0+5392 frames=5 fp=3 slots=512 limited=y [context@0x7fff6f41333a slot=- mod=/usr/lib/system/libsystem_kernel.dylib+0x733a ft=- rs=unknown ; scan@0x7fff6f4cfe60 slot=0x7ffee1c16bf8 mod=/usr/lib/system/libsystem_pthread.dylib+0x5e60 ft=- rs=unknown ; fp@0x7fff6f39a808 slot=0x7ffee1c16c28 mod=/usr/lib/system/libsystem_c.dylib+0x7f808 ft=- rs=unknown ; fp@0x10dfebf8b slot=0x7ffee1c16c68 mod=/Users/ted/src/crashy+0x3f8b ft=- rs=unknown ; fp@0x7fff6f2cbcc9 slot=0x7ffee1c16c88 mod=/usr/lib/system/libdyld.dylib+0x1acc9 ft=- rs=unknown] notes=[frame-pointer chain broke: next frame pointer 0x0 is outside (0x7ffee1c16c98, 0x7ffee1c18000) ;; scan covered only 4096 bytes; the stack window was not fully scanned]",
    ),
    // The malformed corpus has no thread stream, hence no "which stack to start walking from" at all.
    ("invalid-range.dmp", "no-crash-target"),
    ("invalid-record-count.dmp", "no-crash-target"),
  ]
  for (name, want) in cases {
    let dump = @corpus.open_fixture(name)
    let entries = dump.stream_directory()
    @corpus.assert_crash_stack_walk(
      name,
      dump,
      entries,
      @lib.stack_walk_options_default(),
      8,
      want,
    )
  }
}

///|
/// Structural invariants: however the heuristics are tuned, these must always hold — the first frame is the
/// context and its address equals the CONTEXT's instruction pointer verbatim, stack slots strictly increase,
/// the merged total frame count never exceeds `max_frames`, module attribution is self-consistent with the
/// module table (offset = address − base), the labels are a closed set, no scan frames appear when scanning is
/// disabled, and unwalkable cases leave exactly the first frame plus a reason. The malformed corpus goes
/// through the same loop, required to "produce nothing at all" rather than error out.
test "stack walk: cross-corpus invariants" {
  for
    name in [
      "test.dmp", "full-dump.dmp", "invalid-parameter.dmp", "invalid-range.dmp",
      "invalid-record-count.dmp", "linux-mini.dmp", "simple-crashpad.dmp",
    ] {
    let dump = @corpus.open_fixture(name)
    @corpus.assert_walk_invariants(name, dump, dump.stream_directory())
  }
}

///|
/// Symbolization: a `.sym` file is written on the spot for test.dmp, its debug id taken verbatim from the
/// module table golden's RSDS (`5A9832E5-2872-41C1-838E-D98914E9B7FF` + age 1), so the hit path should be
/// `debug_id`. The coverage of functions, line tables, and PUBLIC symbols is declared right here, so which
/// symbol and which line each frame lands on can be hand-checked against the raw `.sym` text.
test "crash-site stack walk: handwritten .sym hit by the real corpus debug id" {
  let dump = @corpus.open_fixture("test.dmp")
  let entries = dump.stream_directory()
  let store = @lib.symbol_store_new()
  let sym = "MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 c:\\test_app.pdb\n" +
    "FILE 0 src/main.c\n" +
    "FILE 1 src/util.c\n" +
    "FUNC 0 4280 40 test_app!crash_here\n" +
    "4280 18 3 0\n" +
    "4298 4 13 1\n" +
    "429c 4 14 1\n" +
    "FUNC 1 41f0 20 test_app!worker_body\n" +
    "41f0 20 7 0\n" +
    "FUNC 2 4100 40 test_app!start_worker\n" +
    "4100 40 2 0\n" +
    "PUBLIC 3 53e0 10 test_app!run_loop\n"
  let ok = @lib.symbol_store_add(store, "inline:test_app.sym", sym)
  assert_true(ok)
  assert_eq(
    @corpus.crash_symbol_lines(dump, entries, store),
    "exception 0x40429e ok/debug_id/func name=test_app!crash_here at=src/util.c:14 +sym=0x1e src=inline:test_app.sym n=1 | test_app!crash_here func+0x1e  at src/util.c:14 ; 0x404200 ok/debug_id/func name=test_app!worker_body at=src/main.c:7 +sym=0x10 src=inline:test_app.sym n=1 | test_app!worker_body func+0x10  at src/main.c:7 ; 0x4053ec ok/debug_id/public name=test_app!run_loop at=-:- +sym=0xc src=inline:test_app.sym n=1 | test_app!run_loop public+0xc ; 0x7c816fd7 no_symbol_file/-/- name=- at=-:- +sym=- src=- n=0 | (no_symbol_file) ; 0x405443 ok/debug_id/public name=test_app!run_loop at=-:- +sym=0x63 src=inline:test_app.sym n=1 | test_app!run_loop public+0x63",
  )
  let far = @lib.symbol_store_new()
  let ok2 = @lib.symbol_store_add(
    far,
    "inline:far.sym",
    "MODULE windows x86 5A9832E5287241C1838ED98914E9B7FF1 c:\\test_app.pdb\n" +
    "PUBLIC 0 9000 0 test_app!much_later\n",
  )
  assert_true(ok2)
  let byfile = @lib.symbol_store_new()
  let ok3 = @lib.symbol_store_add(
    byfile,
    "inline:byname.sym",
    "MODULE windows x86 111111111111111111111111111111111 test_app.exe\n" +
    "FUNC 0 4280 40 test_app!crash_here\n",
  )
  assert_true(ok3)
  assert_eq(
    @corpus.crash_symbol_lines(dump, entries, far),
    "exception 0x40429e unresolved/debug_id/- name=- at=-:- +sym=- src=inline:far.sym n=1 | (unresolved) ; 0x404200 unresolved/debug_id/- name=- at=-:- +sym=- src=inline:far.sym n=1 | (unresolved) ; 0x4053ec unresolved/debug_id/- name=- at=-:- +sym=- src=inline:far.sym n=1 | (unresolved) ; 0x7c816fd7 no_symbol_file/-/- name=- at=-:- +sym=- src=- n=0 | (no_symbol_file) ; 0x405443 unresolved/debug_id/- name=- at=-:- +sym=- src=inline:far.sym n=1 | (unresolved)",
  )
  assert_eq(
    @corpus.crash_symbol_lines(dump, entries, byfile),
    "exception 0x40429e ok/module_name/func name=test_app!crash_here at=-:- +sym=0x1e src=inline:byname.sym n=1 | test_app!crash_here func+0x1e ; 0x404200 unresolved/module_name/- name=- at=-:- +sym=- src=inline:byname.sym n=1 | (unresolved) ; 0x4053ec unresolved/module_name/- name=- at=-:- +sym=- src=inline:byname.sym n=1 | (unresolved) ; 0x7c816fd7 no_symbol_file/-/- name=- at=-:- +sym=- src=- n=0 | (no_symbol_file) ; 0x405443 unresolved/module_name/- name=- at=-:- +sym=- src=inline:byname.sym n=1 | (unresolved)",
  )
  assert_eq(
    @corpus.crash_symbol_lines(dump, entries, @lib.symbol_store_new()),
    "exception 0x40429e empty_store/-/- name=- at=-:- +sym=- src=- n=0 | (empty_store) ; 0x404200 empty_store/-/- name=- at=-:- +sym=- src=- n=0 | (empty_store) ; 0x4053ec empty_store/-/- name=- at=-:- +sym=- src=- n=0 | (empty_store) ; 0x7c816fd7 empty_store/-/- name=- at=-:- +sym=- src=- n=0 | (empty_store) ; 0x405443 empty_store/-/- name=- at=-:- +sym=- src=- n=0 | (empty_store)",
  )
}
