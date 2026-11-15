#!/usr/bin/env node
// Builds one self-contained report.html from the pipeline results of all three tools (Snyk, Aikido,
// GitHub Advanced Security) and prints a Markdown summary to stdout (CI appends it to $GITHUB_STEP_SUMMARY).
//
// Usage: node scripts/build-report.mjs <results-dir> <output.html>
// Inputs (all optional, a missing file shows as "not run"):
//   test-results.json            Vitest JSON reporter
//   snyk-code.sarif              snyk code test --sarif-file-output
//   snyk-oss.json                snyk test --json-file-output
//   snyk-iac.json                snyk iac test --json-file-output
//   snyk-container.json          snyk container test --json-file-output
//   aikido-code.json             aikido-local-scanner scan --gating-result-output
//   aikido-container.json        aikido-local-scanner image-scan --gating-result-output
//   ghas-codeql.sarif            github/codeql-action/analyze output
//   ghas-dependency-review.json  vulnerable-changes output of actions/dependency-review-action
// Env (set by CI): BUILD, SNYK, AIKIDO, GHAS = job results; GATE_TOOLS = tools that block (default "snyk")
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  GATE,
  createReader,
  parseAikido,
  parseDependencyReview,
  parseSarif,
  parseSnykContainer,
  parseSnykIac,
  parseSnykOss,
  parseTests,
} from "./parsers.mjs";

const [dir = "reports", out = "report/report.html"] = process.argv.slice(2);
const env = process.env;
const read = createReader(dir);
const GATE_TOOLS = new Set((env.GATE_TOOLS ?? "snyk").split(/[\s,]+/).filter(Boolean));

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// Comparison columns ("leak" = secrets detection). A section covers one or more adjacent columns (Aikido's code scan covers four).
const CATS = [
  { id: "sast", name: "SAST" },
  { id: "sca", name: "SCA" },
  { id: "iac", name: "IaC" },
  { id: "leak", name: "Secrets" },
  { id: "container", name: "Container" },
];

const tests = parseTests(read);
const snykContainer = parseSnykContainer(read);
const TOOLS = [
  {
    id: "snyk",
    name: "Snyk",
    job: env.SNYK,
    sections: [
      { key: "snyk-code", cats: ["sast"], short: "SAST", name: "Snyk Code", what: "ช่องโหว่ในโค้ดที่เราเขียนเอง (รวม hardcoded secret)", ...parseSarif(read, "snyk-code.sarif", { tool: "Snyk" }) },
      { key: "snyk-oss", cats: ["sca"], short: "SCA", name: "Snyk Open Source", what: "CVE ใน npm dependency ที่ใช้", ...parseSnykOss(read) },
      { key: "snyk-iac", cats: ["iac"], short: "IaC", name: "Snyk IaC", what: "การตั้งค่าที่ไม่ปลอดภัยใน Kubernetes manifest", ...parseSnykIac(read) },
      {
        key: "snyk-container",
        cats: ["container"],
        short: "Container",
        name: "Snyk Container",
        what: `ช่องโหว่ใน Docker image ที่ build จาก Dockerfile (base image และ OS package)${snykContainer.baseImage ? ` · base image: ${snykContainer.baseImage}` : ""}${
          snykContainer.advice ? ` · Snyk: ${snykContainer.advice}` : ""
        }`,
        ...snykContainer,
      },
    ],
    notes: { leak: "รวมใน Snyk Code" },
  },
  {
    id: "aikido",
    name: "Aikido",
    job: env.AIKIDO,
    sections: [
      { key: "aikido-code", cats: ["sast", "sca", "iac", "leak"], short: "Code", name: "Aikido local scanner (code)", what: "สแกนครั้งเดียวได้ SAST + dependency + IaC + secrets (ผลรวมเป็นรายการเดียว)", ...parseAikido(read, "aikido-code.json") },
      { key: "aikido-container", cats: ["container"], short: "Container", name: "Aikido image scan", what: "ช่องโหว่ใน Docker image (OS package และ base image)", ...parseAikido(read, "aikido-container.json") },
    ],
    notes: {},
  },
  {
    id: "ghas",
    name: "GitHub Advanced Security",
    job: env.GHAS,
    sections: [
      { key: "ghas-codeql", cats: ["sast"], short: "SAST", name: "CodeQL", what: "ช่องโหว่ในโค้ด (query ชุด security-extended) ผลขึ้น Security tab ด้วย", ...parseSarif(read, "ghas-codeql.sarif", { useSecuritySeverity: true, tool: "CodeQL" }) },
      { key: "ghas-deps", cats: ["sca"], short: "SCA", name: "Dependency Review", what: "dependency ที่ PR นี้เพิ่มเข้ามาและมีช่องโหว่ (ใช้ฐานข้อมูล GitHub Advisory เดียวกับ Dependabot)", ...parseDependencyReview(read) },
    ],
    notes: {
      iac: "ไม่รองรับ",
      leak: "Secret scanning + push protection (บล็อกตอน push, ดูใน Security tab)",
      container: "ไม่รองรับ",
    },
  },
];

for (const tool of TOOLS) {
  for (const s of tool.sections) {
    s.counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const i of s.items) if (i.severity in s.counts) s.counts[i.severity]++;
    s.blocking = s.items.filter((i) => GATE.has(i.severity)).length;
    s.status = !s.ran ? "skipped" : s.blocking ? "fail" : "pass";
  }
  const ran = tool.sections.filter((s) => s.ran);
  tool.status = tool.job
    ? tool.job === "success" ? (ran.length ? "pass" : "skipped") : tool.job === "skipped" ? "skipped" : "fail"
    : !ran.length ? "skipped" : ran.some((s) => s.status === "fail") ? "fail" : "pass";
  tool.blocking = tool.sections.reduce((n, s) => n + s.blocking, 0);
  tool.gates = GATE_TOOLS.has(tool.id);
}

const testStatus = !tests.ran ? "skipped" : tests.failed.length ? "fail" : "pass";
const gateTools = TOOLS.filter((t) => t.gates);
const overallPass = env.BUILD
  ? env.BUILD === "success" && gateTools.every((t) => t.status !== "fail")
  : testStatus !== "fail" && gateTools.every((t) => t.status !== "fail");

// Every item that blocked a tool's gate, with its reason
const blockers = [
  ...tests.failed.map((t) => ({
    tool: "tests",
    kind: "Unit test",
    title: t.name,
    where: t.file,
    why: t.message || "test ไม่ผ่าน",
    fix: "แก้โค้ดให้ test ผ่าน (test นี้ตรวจว่าช่องโหว่ถูกกันไว้)",
  })),
  ...TOOLS.flatMap((tool) =>
    tool.sections.flatMap((s) =>
      s.items
        .filter((i) => GATE.has(i.severity))
        .map((i) => ({ tool: tool.id, kind: `${tool.name} · ${s.short} ${i.severity.toUpperCase()}`, title: i.title, where: i.location, why: i.why || i.evidence, fix: i.fix })),
    ),
  ),
];

// ---------- Comparison matrix (tool x category) ----------
const matrixRows = TOOLS.map((tool) => {
  const cells = [];
  for (let c = 0; c < CATS.length; c++) {
    const cat = CATS[c].id;
    const s = tool.sections.find((x) => x.cats[0] === cat);
    if (s) {
      cells.push({ span: s.cats.length, section: s });
      c += s.cats.length - 1;
    } else cells.push({ span: 1, note: tool.notes[cat] ?? "—" });
  }
  return { tool, cells };
});
const cellText = (s) => (!s.ran ? "not run" : s.blocking ? `${s.blocking} blocking` : "0 blocking");

// ---------- Markdown summary (stdout) ----------
const icon = { pass: "✅", fail: "❌", skipped: "⏭️" };
const md = [];
md.push(`## ${overallPass ? "✅ Security gate passed" : "❌ Security gate blocked"}`);
md.push("", `Gate ใช้ผลของ: unit tests + ${gateTools.map((t) => t.name).join(", ") || "(ไม่มี scanner)"} · เครื่องมืออื่นแสดงผลเพื่อเปรียบเทียบ`);
md.push("", "### เปรียบเทียบ 3 เครื่องมือ (จำนวนรายการระดับ Critical/High)", "");
md.push(`| Tool | Result | ${CATS.map((c) => c.name).join(" | ")} |`);
md.push(`|---|---|${CATS.map(() => "---").join("|")}|`);
for (const { tool, cells } of matrixRows) {
  const cols = cells.flatMap((c) => {
    const txt = c.section ? `${icon[c.section.status]} ${cellText(c.section)}` : c.note;
    return [txt, ...Array(c.span - 1).fill("↳ รวมในช่อง SAST")];
  });
  md.push(`| ${tool.name}${tool.gates ? " 🔒" : ""} | ${icon[tool.status]} | ${cols.join(" | ")} |`);
}
md.push("", `Unit tests: ${icon[testStatus]} ${tests.ran ? `${tests.items.length - tests.failed.length}/${tests.items.length} passed` : "not run"} · 🔒 = ใช้บล็อก merge`);
if (blockers.length) {
  md.push("", "### รายการระดับ Critical/High", "", "| ประเภท | ปัญหา | ที่ไหน | สาเหตุ |", "|---|---|---|---|");
  const cell = (s) => String(s ?? "").replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\n/g, " ");
  // Keep the run page readable: at most 8 rows per tool, the full list is in report.html
  const shown = {};
  for (const b of blockers) {
    shown[b.tool] = (shown[b.tool] ?? 0) + 1;
    if (shown[b.tool] <= 8) md.push(`| ❌ ${b.kind} | ${cell(b.title)} | \`${cell(b.where)}\` | ${cell(b.why)} |`);
  }
  for (const [tool, n] of Object.entries(shown)) if (n > 8) md.push(`| … | ${tool}: อีก ${n - 8} รายการ ดูใน report.html | | |`);
}
md.push("", "📄 Full report: download the **security-report** artifact below, or run `npm run report` on your machine.");
console.log(md.join("\n"));

// ---------- HTML ----------
const badge = (sev) => `<span class="sev ${esc(sev)}">${esc(sev)}</span>`;
const pill = (st) => `<span class="pill ${st}">${{ pass: "PASS", fail: "FAIL", skipped: "NOT RUN" }[st]}</span>`;
const findingTable = (s) => {
  if (!s.ran) return `<p class="muted">สแกนนี้ไม่ได้รัน (ไม่มี token, job ถูกข้าม หรือไม่ใช่ PR)</p>`;
  if (!s.items.length) return `<p class="ok">ไม่พบปัญหา</p>`;
  return `<table><thead><tr><th>Severity</th><th>ปัญหา</th><th>ที่ไหน</th><th>สาเหตุ</th><th>วิธีแก้</th></tr></thead><tbody>${s.items
    .map(
      (i) => `<tr class="${GATE.has(i.severity) ? "block" : ""}"><td>${badge(i.severity)}</td><td><strong>${esc(i.title)}</strong>${
        i.ref ? `<div class="muted small">${esc(i.ref)}</div>` : ""
      }</td><td><code>${esc(i.location)}</code></td><td>${esc(i.why)}${
        i.evidence ? `<div class="evidence">${esc(i.evidence)}</div>` : ""
      }</td><td class="fix">${esc(i.fix)}</td></tr>`,
    )
    .join("")}</tbody></table>`;
};
const testTable = () => {
  if (!tests.ran) return `<p class="muted">test ไม่ได้รัน</p>`;
  return `<table><thead><tr><th>ผล</th><th>Test</th><th>ที่ไหน</th><th>สาเหตุที่ fail</th></tr></thead><tbody>${[...tests.items]
    .sort((a, b) => (a.status === "failed" ? 0 : 1) - (b.status === "failed" ? 0 : 1))
    .map(
      (t) => `<tr class="${t.status === "failed" ? "block" : ""}"><td>${
        t.status === "failed" ? pill("fail") : t.status === "passed" ? pill("pass") : pill("skipped")
      }</td><td>${esc(t.name)}</td><td><code>${esc(t.file)}</code></td><td>${t.status === "failed" ? esc(t.message) : '<span class="muted">—</span>'}</td></tr>`,
    )
    .join("")}</tbody></table>`;
};
const matrix = () =>
  `<div class="wrap"><table class="matrix"><thead><tr><th>Tool</th>${CATS.map((c) => `<th>${c.name}</th>`).join("")}</tr></thead><tbody>${matrixRows
    .map(
      ({ tool, cells }) =>
        `<tr><td><strong>${esc(tool.name)}</strong> ${pill(tool.status)}${tool.gates ? ' <span class="lock" title="ใช้บล็อก merge">GATE</span>' : ""}</td>${cells
          .map((c) =>
            c.section
              ? `<td colspan="${c.span}" class="m ${c.section.status}"><a href="#${c.section.key}"><b>${c.section.ran ? c.section.blocking : "—"}</b> <span class="small">${
                  c.section.ran ? `blocking · ทั้งหมด ${c.section.items.length}` : "not run"
                }</span><div class="small muted">${esc(c.section.name)}</div></a></td>`
              : `<td class="m na small muted">${esc(c.note)}</td>`,
          )
          .join("")}</tr>`,
    )
    .join("")}</tbody></table></div>`;
const blockerList = () =>
  blockers.length
    ? `<h2 id="why">รายการระดับ Critical/High (${blockers.length})</h2><div class="muted">กติกา gate: test ต้องผ่านทั้งหมด และ ${esc(
        gateTools.map((t) => t.name).join(", ") || "-",
      )} ต้องไม่เจอ Critical/High · รายการของเครื่องมือที่ไม่ได้ใช้บล็อกแสดงเป็นสีเทา</div>
<ol class="why">${blockers
        .map(
          (b) => `<li class="${b.tool === "tests" || GATE_TOOLS.has(b.tool) ? "" : "info"}"><div><span class="tag">${esc(b.kind)}</span> <strong>${esc(b.title)}</strong> <code>${esc(
            b.where,
          )}</code></div><div><b>สาเหตุ:</b> ${esc(b.why)}</div>${b.fix ? `<div class="fix"><b>วิธีแก้:</b> ${esc(b.fix)}</div>` : ""}</li>`,
        )
        .join("")}</ol>`
    : "";

const html = `<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Gate Report</title>
<style>
:root{--bg:#f7f7f8;--panel:#fff;--text:#18181b;--muted:#6b7280;--border:#e5e7eb;--pass:#15803d;--fail:#b91c1c;--skip:#6b7280;--failbg:#fef2f2;--passbg:#f0fdf4;
--crit:#7f1d1d;--high:#dc2626;--med:#d97706;--low:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#0f0f11;--panel:#18181b;--text:#f4f4f5;--muted:#a1a1aa;--border:#2e2e33;--failbg:#2a1215;--passbg:#10221a;--pass:#4ade80;--fail:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI","Noto Sans Thai",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 4px}h3{font-size:15px;margin:20px 0 4px}.muted{color:var(--muted)}.small{font-size:12px}
.banner{padding:16px 20px;border-radius:10px;margin:16px 0 20px;font-weight:600;font-size:16px;border:1px solid var(--border);background:var(--panel)}
.banner.pass{border-left:6px solid var(--pass)}.banner.fail{border-left:6px solid var(--fail)}
.meta{color:var(--muted);font-size:13px}.meta a{color:inherit}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;color:#fff;background:var(--skip)}.pill.pass{background:var(--pass)}.pill.fail{background:var(--fail)}
.lock{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;border:1px solid var(--text)}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-top:8px}
table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}tr.block{background:var(--failbg)}
table.matrix td.m{border-left:1px solid var(--border)}table.matrix td.m a{color:inherit;text-decoration:none;display:block}table.matrix td.m b{font-size:20px}
table.matrix td.fail{background:var(--failbg)}table.matrix td.pass{background:var(--passbg)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.sev{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px;color:#fff;background:var(--low)}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}
.fix{color:var(--pass)}.ok{color:var(--pass);font-weight:600;padding:12px;margin:0}p.muted{padding:12px;margin:0}
.evidence{margin-top:6px;font-size:12px;color:var(--muted)}
ol.why{background:var(--panel);border:1px solid var(--border);border-left:6px solid var(--fail);border-radius:10px;margin:8px 0 0;padding:12px 16px 12px 40px}
ol.why li{padding:8px 0;border-bottom:1px solid var(--border)}ol.why li:last-child{border-bottom:0}ol.why li>div{margin:2px 0}
.tag{display:inline-block;font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;background:var(--fail);color:#fff}
ol.why li.info{opacity:.7}ol.why li.info .tag{background:var(--skip)}
</style></head><body><main>
<h1>Security Gate Report</h1>
<div class="meta">Branch <strong>${esc(env.BRANCH ?? "local")}</strong>${env.SHA ? ` · commit <code>${esc(env.SHA.slice(0, 7))}</code>` : ""} · generated ${esc(
  new Date().toISOString().replace("T", " ").slice(0, 16),
)} UTC${env.RUN_URL ? ` · <a href="${esc(env.RUN_URL)}">เปิด GitHub Actions run</a>` : ""}</div>
<div class="banner ${overallPass ? "pass" : "fail"}">${
  overallPass
    ? `✅ Gate ผ่าน: test ผ่านทั้งหมด และ ${esc(gateTools.map((t) => t.name).join(", "))} ไม่เจอ Critical/High`
    : `❌ Gate ไม่ผ่าน: ดูสาเหตุและวิธีแก้ด้านล่าง (แถวสีแดงในตาราง)`
}</div>
<h2>เปรียบเทียบ Snyk · Aikido · GitHub Advanced Security</h2>
<div class="muted">ตัวเลขใหญ่ = จำนวนรายการระดับ Critical/High ที่เจอ ต่อประเภทการสแกน · Unit tests ${pill(testStatus)} ${
  tests.ran ? `${tests.items.length - tests.failed.length}/${tests.items.length} passed` : ""
}</div>
${matrix()}
${blockerList()}
<h2 id="tests">Unit tests</h2><div class="muted">test การทำงานและ security regression test (Vitest)</div><div class="wrap">${testTable()}</div>
${TOOLS.map(
  (tool) =>
    `<h2 id="${tool.id}">${esc(tool.name)} ${pill(tool.status)}</h2>${tool.sections
      .map((s) => `<h3 id="${s.key}">${esc(s.short)} · ${esc(s.name)}</h3><div class="muted">${esc(s.what)}</div><div class="wrap">${findingTable(s)}</div>`)
      .join("\n")}`,
).join("\n")}
</main></body></html>`;

mkdirSync(path.dirname(out), { recursive: true });
writeFileSync(out, html);
