// Crosscheck: the CLI's stack-walk output vs the raw slot table from stack_oracle.js.
// Rule: for every frame except context frames, the (stack slot, instruction address) pair
// must appear verbatim in the oracle's SLOTS, and the module attribution must match
// (the oracle takes the last hit, the CLI the first — overlapping ranges will show up here).
//
// Usage (repo root, requires node):
//   node testdata/oracle/stack_oracle.js testdata/test.dmp > /tmp/golden.txt
//   moon run cmd/main --target native -- testdata/test.dmp > /tmp/cli.txt
//   node testdata/oracle/stack_crosscheck.js /tmp/golden.txt test.dmp /tmp/cli.txt
// The last line prints `checked=<frames matched> bad=<frames mismatched>`; bad must be 0.
const fs = require("fs");

if (process.argv.length < 5) {
  console.log(
    "usage: node testdata/oracle/stack_crosscheck.js <oracle output> <corpus name> <CLI output>",
  );
  process.exit(2);
}
const gold = fs
  .readFileSync(process.argv[2], "utf8")
  .split("\n");
const slots = {}; // "name|tid|kind" -> { slot: {v, mod, off} }
let cur = null;
for (const line of gold) {
  let m = line.match(/^#### (\S+) (\S+) tid=(\d+)/);
  if (m) {
    cur = m[1] + "|" + m[3] + "|" + (m[2] === "exception" ? "exception" : "thread");
    if (!slots[cur]) slots[cur] = {};
    continue;
  }
  if (!line.startsWith("SLOTS ") || !cur) continue;
  for (const part of line.slice(6).split(" ")) {
    const t = part.match(/^(0x[0-9a-f]+)=(0x[0-9a-f]+)(?:<([^+]+)\+(0x[0-9a-f]+))?/);
    if (t) slots[cur][t[1]] = { v: t[2], mod: t[3] || "-", off: t[4] || "-" };
  }
}

const name = process.argv[3];
const out = fs.readFileSync(process.argv[4], "utf8").split("\n");
let tid = null;
let kind = "thread";
let bad = 0;
let checked = 0;
for (const line of out) {
  let m = line.match(/#\d+\s+thread\s+(\d+)/);
  if (m) {
    tid = m[1];
    continue;
  }
  if (/exception-site context/.test(line)) {
    kind = "exception";
    continue;
  }
  if (/thread-table context/.test(line)) {
    kind = "thread";
    continue;
  }
  m = line.match(/^\s+#(\d+)\s+(0x[0-9a-f]+)\s+(fp|scan)\s+slot\s+(0x[0-9a-f]+)\s+(\S.*?)\+(0x[0-9a-f]+)\s*$/);
  if (!m || !tid) continue;
  const [, idx, addr, k, slot, mod, off] = m;
  const table = slots[name + "|" + tid + "|" + kind];
  if (!table) {
    console.log(`MISSING-ORACLE ${name} tid=${tid} kind=${kind}`);
    bad++;
    continue;
  }
  const g = table[slot];
  checked++;
  if (!g) {
    console.log(`NO-SLOT ${name} tid=${tid} ${kind} #${idx} ${k} ${slot} -> ${addr}`);
    bad++;
  } else if (g.v !== addr) {
    console.log(`VALUE ${name} tid=${tid} ${kind} ${slot}: cli=${addr} oracle=${g.v}`);
    bad++;
  } else if (g.mod.toLowerCase() !== mod.toLowerCase() || g.off !== off) {
    console.log(`MODULE ${name} tid=${tid} ${kind} ${slot} ${addr}: cli=${mod}+${off} oracle=${g.mod}+${g.off}`);
    bad++;
  }
}
console.log(`checked=${checked} bad=${bad}`);
