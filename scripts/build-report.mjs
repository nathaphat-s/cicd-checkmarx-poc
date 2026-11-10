#!/usr/bin/env node
// Builds one self-contained report.html from the pipeline results and prints a Markdown
// summary to stdout (CI appends it to $GITHUB_STEP_SUMMARY).
//
// Usage: node scripts/build-report.mjs <results-dir> <output.html>
// Inputs (all optional, a missing file shows as "not run"):
//   test-results.json  Vitest JSON reporter
//   snyk-code.sarif    snyk code test --sarif-file-output
//   snyk-oss.json      snyk test --json-file-output
//   snyk-iac.json      snyk iac test --json-file-output
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const [dir = "reports", out = "report/report.html"] = process.argv.slice(2);
const env = process.env;
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const GATE = new Set(["critical", "high"]);

const readJson = (file) => {
  const p = path.join(dir, file);
  if (!existsSync(p)) return undefined;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return undefined;
  }
};
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const bySeverity = (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);

// ---------- Unit tests (Vitest JSON) ----------
function parseTests() {
  const data = readJson("test-results.json");
  if (!data) return { ran: false, items: [] };
  const items = [];
  for (const file of data.testResults ?? []) {
    const fileName = path.relative(process.cwd(), file.name ?? "") || file.name;
    for (const t of file.assertionResults ?? []) {
      items.push({
        name: t.fullName || t.title,
        file: fileName,
        status: t.status,
        message: (t.failureMessages ?? []).join("\n").split("\n")[0],
      });
    }
  }
  return { ran: true, items, failed: items.filter((t) => t.status === "failed") };
}

// ---------- Snyk Code (SARIF) ----------
function parseCode() {
  const data = readJson("snyk-code.sarif");
  if (!data) return { ran: false, items: [] };
  const items = [];
  for (const run of data.runs ?? []) {
    const rules = Object.fromEntries((run.tool?.driver?.rules ?? []).map((r) => [r.id, r]));
    for (const r of run.results ?? []) {
      const rule = rules[r.ruleId] ?? {};
      const loc = r.locations?.[0]?.physicalLocation;
      const level = r.level ?? rule.defaultConfiguration?.level;
      items.push({
        severity: level === "error" ? "high" : level === "warning" ? "medium" : "low",
        title: rule.shortDescription?.text || rule.name || r.ruleId,
        location: loc ? `${loc.artifactLocation?.uri}:${loc.region?.startLine ?? ""}` : "",
        detail: r.message?.text ?? "",
        cwe: (rule.properties?.cwe ?? []).join(", "),
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

// ---------- Snyk Open Source (JSON) ----------
function parseOss() {
  const data = readJson("snyk-oss.json");
  if (!data) return { ran: false, items: [] };
  const projects = Array.isArray(data) ? data : [data];
  const seen = new Set();
  const items = [];
  for (const p of projects) {
    for (const v of p.vulnerabilities ?? []) {
      const key = `${v.id}@${v.packageName}@${v.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push({
        severity: v.severity,
        title: v.title,
        location: `${v.packageName}@${v.version}`,
        detail: (v.from ?? []).slice(1).join(" › "),
        fix: v.fixedIn?.length ? `upgrade to ${v.packageName}@${v.fixedIn[0]}` : "no fix available",
        id: v.id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

// ---------- Snyk IaC (JSON) ----------
function parseIac() {
  const data = readJson("snyk-iac.json");
  if (!data) return { ran: false, items: [] };
  const files = Array.isArray(data) ? data : [data];
  const items = [];
  for (const f of files) {
    for (const i of f.infrastructureAsCodeIssues ?? []) {
      items.push({
        severity: i.severity,
        title: i.title,
        location: `${f.targetFile ?? f.displayTargetFile ?? ""}${i.lineNumber ? ":" + i.lineNumber : ""}`,
        detail: i.iacDescription?.issue ?? i.msg ?? "",
        fix: i.iacDescription?.resolve ?? i.remediation?.kubernetes ?? "",
        id: i.id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

const tests = parseTests();
const sections = [
  { key: "code", name: "SAST · Snyk Code", what: "Vulnerabilities in our own source code", ...parseCode() },
  { key: "oss", name: "SCA · Snyk Open Source", what: "Known CVEs in npm dependencies", ...parseOss() },
  { key: "iac", name: "IaC · Snyk IaC", what: "Misconfigurations in Kubernetes manifests", ...parseIac() },
];
for (const s of sections) {
  s.counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const i of s.items) if (i.severity in s.counts) s.counts[i.severity]++;
  s.blocking = s.items.filter((i) => GATE.has(i.severity)).length;
  s.status = !s.ran ? "skipped" : s.blocking ? "fail" : "pass";
}
const testStatus = !tests.ran ? "skipped" : tests.failed.length ? "fail" : "pass";
const overallPass = env.BUILD ? env.BUILD === "success" && env.SNYK === "success" : testStatus !== "fail" && sections.every((s) => s.status !== "fail");

// ---------- Markdown summary (stdout) ----------
const icon = { pass: "✅", fail: "❌", skipped: "⏭️" };
const md = [];
md.push(`## ${overallPass ? "✅ Security gate passed" : "❌ Security gate blocked"}`);
md.push("");
md.push("| Check | Result | Critical | High | Medium | Low |");
md.push("|---|---|---|---|---|---|");
md.push(`| Unit tests | ${icon[testStatus]} ${tests.ran ? `${tests.items.length - tests.failed.length}/${tests.items.length} passed` : "not run"} | | | | |`);
for (const s of sections) {
  const c = s.counts;
  md.push(`| ${s.name} | ${icon[s.status]} ${s.ran ? `${s.items.length} issues` : "not run"} | ${c.critical} | ${c.high} | ${c.medium} | ${c.low} |`);
}
const blockers = [
  ...tests.failed?.map((t) => `- ❌ **Test failed:** ${t.name}`) ?? [],
  ...sections.flatMap((s) => s.items.filter((i) => GATE.has(i.severity)).map((i) => `- ❌ **${s.name.split(" · ")[0]} ${i.severity.toUpperCase()}:** ${i.title} — \`${i.location}\``)),
];
if (blockers.length) md.push("", "### What blocked the gate", "", ...blockers);
md.push("", "📄 Full report: download the **security-report** artifact below and open `report.html`.");
console.log(md.join("\n"));

// ---------- HTML ----------
const badge = (sev) => `<span class="sev ${esc(sev)}">${esc(sev)}</span>`;
const pill = (st) => `<span class="pill ${st}">${{ pass: "PASS", fail: "FAIL", skipped: "NOT RUN" }[st]}</span>`;
const findingTable = (s) => {
  if (!s.ran) return `<p class="muted">This scan did not run (missing token or job skipped).</p>`;
  if (!s.items.length) return `<p class="ok">No issues found.</p>`;
  return `<table><thead><tr><th>Severity</th><th>Issue</th><th>Where</th><th>Details / how to fix</th></tr></thead><tbody>${s.items
    .map(
      (i) => `<tr class="${GATE.has(i.severity) ? "block" : ""}"><td>${badge(i.severity)}</td><td><strong>${esc(i.title)}</strong>${
        i.cwe ? `<div class="muted">${esc(i.cwe)}</div>` : ""
      }</td><td><code>${esc(i.location)}</code></td><td>${esc(i.detail)}${i.fix ? `<div class="fix">Fix: ${esc(i.fix)}</div>` : ""}</td></tr>`,
    )
    .join("")}</tbody></table>`;
};
const testTable = () => {
  if (!tests.ran) return `<p class="muted">Tests did not run.</p>`;
  return `<table><thead><tr><th>Result</th><th>Test</th><th>File</th><th>Error</th></tr></thead><tbody>${[...tests.items]
    .sort((a, b) => (a.status === "failed" ? -1 : 1) - (b.status === "failed" ? -1 : 1))
    .map(
      (t) => `<tr class="${t.status === "failed" ? "block" : ""}"><td>${t.status === "failed" ? pill("fail") : t.status === "passed" ? pill("pass") : pill("skipped")}</td><td>${esc(
        t.name,
      )}</td><td><code>${esc(t.file)}</code></td><td class="muted">${esc(t.message)}</td></tr>`,
    )
    .join("")}</tbody></table>`;
};

const cards = [
  `<a class="card ${testStatus}" href="#tests"><div class="label">Unit tests</div><div class="big">${
    tests.ran ? `${tests.items.length - tests.failed.length}/${tests.items.length}` : "—"
  }</div><div class="sub">${tests.ran ? `${tests.failed.length} failed` : "not run"}</div>${pill(testStatus)}</a>`,
  ...sections.map(
    (s) => `<a class="card ${s.status}" href="#${s.key}"><div class="label">${esc(s.name)}</div><div class="big">${s.ran ? s.blocking : "—"}</div><div class="sub">${
      s.ran ? `blocking (C ${s.counts.critical} · H ${s.counts.high} · M ${s.counts.medium} · L ${s.counts.low})` : "not run"
    }</div>${pill(s.status)}</a>`,
  ),
].join("");

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Gate Report</title>
<style>
:root{--bg:#f7f7f8;--panel:#fff;--text:#18181b;--muted:#6b7280;--border:#e5e7eb;--pass:#15803d;--fail:#b91c1c;--skip:#6b7280;--failbg:#fef2f2;
--crit:#7f1d1d;--high:#dc2626;--med:#d97706;--low:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#0f0f11;--panel:#18181b;--text:#f4f4f5;--muted:#a1a1aa;--border:#2e2e33;--failbg:#2a1215;--pass:#4ade80;--fail:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 4px}.muted{color:var(--muted)}
.banner{padding:16px 20px;border-radius:10px;margin:16px 0 20px;font-weight:600;font-size:16px;border:1px solid var(--border);background:var(--panel)}
.banner.pass{border-left:6px solid var(--pass)}.banner.fail{border-left:6px solid var(--fail)}
.meta{color:var(--muted);font-size:13px}.meta a{color:inherit}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.card{display:block;text-decoration:none;color:inherit;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;border-top:4px solid var(--skip)}
.card.pass{border-top-color:var(--pass)}.card.fail{border-top-color:var(--fail)}
.card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.card .big{font-size:28px;font-weight:700}.card .sub{font-size:12px;color:var(--muted);margin-bottom:8px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;color:#fff;background:var(--skip)}.pill.pass{background:var(--pass)}.pill.fail{background:var(--fail)}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-top:8px}
table{width:100%;border-collapse:collapse;min-width:640px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}tr.block{background:var(--failbg)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.sev{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px;color:#fff;background:var(--low)}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}
.fix{margin-top:4px;color:var(--pass);font-size:13px}.ok{color:var(--pass);font-weight:600;padding:12px}
p.muted{padding:12px;margin:0}
</style></head><body><main>
<h1>Security Gate Report</h1>
<div class="meta">Branch <strong>${esc(env.BRANCH ?? "local")}</strong>${env.SHA ? ` · commit <code>${esc(env.SHA.slice(0, 7))}</code>` : ""} · generated ${esc(
  new Date().toISOString().replace("T", " ").slice(0, 16),
)} UTC${env.RUN_URL ? ` · <a href="${esc(env.RUN_URL)}">open the GitHub Actions run</a>` : ""}</div>
<div class="banner ${overallPass ? "pass" : "fail"}">${
  overallPass ? "✅ Gate passed: no failing tests and no Critical/High findings." : `❌ Gate blocked: ${blockers.length} blocking item(s). Rows highlighted in red are what blocked it.`
}</div>
<div class="cards">${cards}</div>
<h2 id="tests">Unit tests</h2><div class="muted">Functional and security regression tests (Vitest)</div><div class="wrap">${testTable()}</div>
${sections.map((s) => `<h2 id="${s.key}">${esc(s.name)}</h2><div class="muted">${esc(s.what)} · gate blocks on Critical/High</div><div class="wrap">${findingTable(s)}</div>`).join("\n")}
</main></body></html>`;

mkdirSync(path.dirname(out), { recursive: true });
writeFileSync(out, html);
