// Stack-walk oracle: reads only the "chain" and the raw "slot table" straight out of the
// bytes per the SDK layout, with no heuristics at all. Every frame the MoonBit side reports
// must have the same (stack slot, value) pair in the raw slot table below; otherwise some
// read offset is wrong. Module attribution and the call-site evidence are computed
// independently here too (the module list is parsed from scratch).
//
// Usage (repo root, requires node):
//   node testdata/oracle/stack_oracle.js testdata/test.dmp [more.dmp...] > stack_golden.txt
// This script is the upstream of the goldens pasted in `corpus/corpus_test.mbt`: the script
// answers "what was actually on the stack", the pinned tests answer "which frames we chose to report".
const fs = require("fs");

const u32 = (b, o) => b.readUInt32LE(o);
const u64 = (b, o) => b.readBigUInt64LE(o);

function dirs(buf) {
  const n = u32(buf, 8);
  const drva = u32(buf, 12);
  const out = [];
  for (let i = 0; i < n; i++) {
    const o = drva + i * 12;
    out.push({ type: u32(buf, o), size: u32(buf, o + 4), rva: u32(buf, o + 8) });
  }
  return out;
}
function last(list, type) {
  let f = null;
  for (const e of list) if (e.type === type) f = e;
  return f;
}

// Memory index: MemoryList(5) carries each segment's RVA inline; for Memory64List(9)
// RVA = BaseRva + the sum of the preceding segments' lengths
function regions(buf, d) {
  const out = [];
  const m5 = last(d, 5);
  if (m5) {
    const c = u32(buf, m5.rva);
    for (let i = 0; i < c; i++) {
      const o = m5.rva + 4 + i * 16;
      out.push({ start: u64(buf, o), size: BigInt(u32(buf, o + 8)), rva: BigInt(u32(buf, o + 12)) });
    }
  }
  const m9 = last(d, 9);
  if (m9) {
    const c = Number(u64(buf, m9.rva));
    let cur = u64(buf, m9.rva + 8);
    for (let i = 0; i < c; i++) {
      const o = m9.rva + 16 + i * 16;
      const size = u64(buf, o + 8);
      out.push({ start: u64(buf, o), size, rva: cur });
      cur += size;
    }
  }
  out.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  const fileLen = BigInt(buf.length);
  const kept = [];
  for (const r of out) {
    if (r.size === 0n || r.rva >= fileLen) continue;
    const room = fileLen - r.rva;
    kept.push({ start: r.start, size: r.size <= room ? r.size : room, rva: r.rva });
  }
  return kept;
}
// segment covering [addr, addr+n) (fully covered only, otherwise unreadable)
function cover(kept, addr, n) {
  let best = null;
  for (const r of kept) if (addr >= r.start && addr + BigInt(n) <= r.start + r.size) best = r;
  return best;
}
function readAt(kept, buf, addr, n) {
  const r = cover(kept, addr, n);
  if (!r) return null;
  const off = Number(r.rva + (addr - r.start));
  return buf.subarray(off, off + Number(n));
}

// Module list(4): MINIDUMP_MODULE record is 108 bytes, BaseOfImage@0 SizeOfImage@8 ModuleNameRva@20
function modules(buf, d) {
  const e = last(d, 4);
  if (!e) return [];
  const c = u32(buf, e.rva);
  const out = [];
  for (let i = 0; i < c; i++) {
    const o = e.rva + 4 + i * 108;
    const base = u64(buf, o);
    const size = BigInt(u32(buf, o + 8));
    let name = "?";
    const nrva = u32(buf, o + 20);
    if (nrva > 0 && nrva + 4 <= buf.length) {
      const len = u32(buf, nrva);
      if (len > 0 && nrva + 4 + len <= buf.length) name = buf.toString("utf16le", nrva + 4, nrva + 4 + len);
    }
    out.push({ base, size, name });
  }
  return out;
}
function owner(mods, addr) {
  let best = null;
  for (const m of mods) if (addr >= m.base && addr < m.base + m.size) best = m;
  return best;
}

// Thread list(3)/ThreadList(8): record 48 bytes, stack descriptor @24 (len@32, rva@36), context @40/@44
function threads(buf, d) {
  const e = last(d, 3) || last(d, 8);
  if (!e) return [];
  const c = u32(buf, e.rva);
  const out = [];
  for (let i = 0; i < c; i++) {
    const o = e.rva + 4 + i * 48;
    out.push({
      id: u32(buf, o),
      stkStart: u64(buf, o + 24),
      stkSize: BigInt(u32(buf, o + 32)),
      ctxSize: u32(buf, o + 40),
      ctxRva: BigInt(u32(buf, o + 44)),
    });
  }
  return out;
}
// Exception stream(6): ThreadId@0, ExceptionRecord@8 (ExceptionAddress@32), ExceptionContext@160/164
function exception(buf, d) {
  const e = last(d, 6);
  if (!e) return null;
  return {
    tid: u32(buf, e.rva),
    code: u32(buf, e.rva + 8),
    addr: u64(buf, e.rva + 32),
    ctxSize: u32(buf, e.rva + 160),
    ctxRva: BigInt(u32(buf, e.rva + 164)),
  };
}
// Field table is picked by the context record's declared size (716=x86, 1232=amd64), not by SystemInfo
function tableFor(size) {
  if (size === 716) return { name: "x86", ps: 4, ip: 184, sp: 196, bp: 180 };
  if (size === 1232) return { name: "amd64", ps: 8, ip: 248, sp: 152, bp: 160 };
  return null;
}
function readCtx(buf, off, t) {
  const g = t.ps === 8 ? (o) => u64(buf, off + o) : (o) => BigInt(u32(buf, off + o));
  return { ip: g(t.ip), sp: g(t.sp), bp: g(t.bp) };
}
const hx = (v) => "0x" + v.toString(16);

function report(buf, name, d, kept, mods, ts, label, ctxloc, tid) {
  const t = tableFor(ctxloc.size);
  if (!t) {
    console.log(`#### ${name} ${label} tid=${tid} ctx=${ctxloc.size}@${ctxloc.rva} field table unrecognized`);
    return;
  }
  const p = readCtx(buf, Number(ctxloc.rva), t);
  const thr = ts.find((x) => x.id === tid) || (label.startsWith("thread") ? ts[Number(label.slice(6))] : ts[0]);
  console.log(`#### ${name} ${label} tid=${tid} layout=${t.name} ps=${t.ps}`);
  console.log(`CTX ip=${hx(p.ip)} sp=${hx(p.sp)} bp=${hx(p.bp)}`);
  if (thr) {
    console.log(
      `WINDOW low=${hx(thr.stkStart)} len=${thr.stkSize} high=${hx(thr.stkStart + thr.stkSize)} ` +
        `captured=${cover(kept, thr.stkStart, 1n) ? "yes" : "no"}`,
    );
  }
  const low = thr ? thr.stkStart : 0n;
  const high = thr ? thr.stkStart + thr.stkSize : 0n;
  const chain = [];
  let bp = p.bp;
  for (let i = 0; i < 8; i++) {
    const okAlign = bp % BigInt(t.ps) === 0n;
    const okWin = bp >= low && bp + BigInt(t.ps * 2) <= high;
    if (!okAlign || !okWin) {
      chain.push(`step${i} bp=${hx(bp)} out of window or misaligned`);
      break;
    }
    const next = readAt(kept, buf, bp, t.ps);
    const ret = readAt(kept, buf, bp + BigInt(t.ps), t.ps);
    if (!next || !ret) {
      chain.push(`step${i} bp=${hx(bp)} memory not captured`);
      break;
    }
    const nv = t.ps === 8 ? u64(next, 0) : BigInt(u32(next, 0));
    const rv = t.ps === 8 ? u64(ret, 0) : BigInt(u32(ret, 0));
    const mo = owner(mods, rv);
    chain.push(
      `step${i} bp=${hx(bp)} [bp]=${hx(nv)} [bp+${t.ps}]=${hx(rv)}${mo ? "@" + mo.name + "+" + hx(rv - mo.base) : ""}`,
    );
    if (nv <= bp || nv >= high) {
      chain.push(`step${i + 1} next bp=${hx(nv)} outside window/no backtrack, chain stops`);
      break;
    }
    bp = nv;
  }
  console.log("CHAIN " + chain.join(" ; "));
  const slots = [];
  const start = p.sp - (p.sp % BigInt(t.ps));
  for (let i = 0; i < 4000; i++) {
    const a = start + BigInt(i * t.ps);
    if (a >= high) break;
    const bs = readAt(kept, buf, a, t.ps);
    if (!bs) {
      slots.push(`${hx(a)}=-`);
      continue;
    }
    const v = t.ps === 8 ? u64(bs, 0) : BigInt(u32(bs, 0));
    const mo = owner(mods, v);
    let pre = "-";
    if (mo) {
      const pb = readAt(kept, buf, v - 6n, 6n);
      if (pb) pre = Buffer.from(pb).toString("hex");
    }
    slots.push(`${hx(a)}=${hx(v)}${mo ? "<" + mo.name + "+" + hx(v - mo.base) + " pre=" + pre + ">" : ""}`);
  }
  console.log("SLOTS " + slots.join(" "));
}

for (const p of process.argv.slice(2)) {
  const buf = fs.readFileSync(p);
  const name = p.split(/[\\/]/).pop();
  const d = dirs(buf);
  const kept = regions(buf, d);
  const mods = modules(buf, d);
  const ts = threads(buf, d);
  const exc = exception(buf, d);
  let done = false;
  if (exc && exc.ctxSize > 0) {
    report(buf, name, d, kept, mods, ts, "exception", { size: exc.ctxSize, rva: Number(exc.ctxRva) }, exc.tid);
    done = true;
  }
  ts.forEach((t0, i) => {
    report(buf, name, d, kept, mods, ts, "thread" + i, { size: t0.ctxSize, rva: Number(t0.ctxRva) }, t0.id);
    done = true;
  });
  if (!done) console.log(`#### ${name} has neither a thread list nor an exception stream`);
}
