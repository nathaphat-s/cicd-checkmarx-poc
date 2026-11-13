#!/usr/bin/env node
// Gate for scanners that report findings but do not fail the build themselves (CodeQL).
// Prints the count per severity and exits 1 when anything is High or Critical.
// Usage: node scripts/gate-count.mjs codeql reports/ghas-codeql.sarif
import path from "node:path";
import { GATE, createReader, parseSarif } from "./parsers.mjs";

const [kind, file] = process.argv.slice(2);
if (kind !== "codeql" || !file) {
  console.error("Usage: node scripts/gate-count.mjs codeql <file.sarif>");
  process.exit(2);
}
const read = createReader(path.dirname(file));
const res = parseSarif(read, path.basename(file), { useSecuritySeverity: true, tool: "CodeQL" });
if (!res.ran) {
  console.error(`::warning::${file} not found, CodeQL results unavailable`);
  process.exit(0);
}
const counts = { critical: 0, high: 0, medium: 0, low: 0 };
for (const i of res.items) counts[i.severity]++;
console.log(`CodeQL: ${res.items.length} alerts (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low})`);
const blocking = res.items.filter((i) => GATE.has(i.severity));
for (const b of blocking) console.log(`::error file=${b.location.split(":")[0]},line=${b.location.split(":")[1] || 1}::[${b.severity}] ${b.title}`);
process.exit(blocking.length ? 1 : 0);
