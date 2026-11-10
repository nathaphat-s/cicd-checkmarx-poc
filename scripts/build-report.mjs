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

// ---------- Plain-language reasons (Thai) by issue type ----------
// Matched against the issue title (lower case). First match wins.
const KNOWLEDGE = [
  { match: ["sql injection"], why: "เอา input ของผู้ใช้ไปต่อเป็นคำสั่ง SQL ตรง ๆ ผู้โจมตีแก้เงื่อนไขของ query เพื่ออ่านหรือแก้ข้อมูลทั้งตารางได้", fix: "ใช้ parameterized query เช่น prepare(\"... WHERE name = ?\").all(name)" },
  { match: ["command injection"], why: "เอา input ของผู้ใช้ไปต่อเป็นคำสั่ง shell ผู้โจมตีใส่ ; หรือ && แล้วรันคำสั่งอะไรก็ได้บนเซิร์ฟเวอร์", fix: "validate input ให้เข้มงวด และใช้ execFile ส่ง argument เป็น list แทน exec (ไม่ผ่าน shell)" },
  { match: ["path traversal"], why: "ใช้ชื่อไฟล์จากผู้ใช้ไปสร้าง path ตรง ๆ ผู้โจมตีใส่ ../ เพื่ออ่านไฟล์นอกโฟลเดอร์ที่อนุญาต เช่น config หรือ source code", fix: "ใช้ allow-list ของชื่อไฟล์ที่อนุญาต ให้ input เป็นแค่ key ห้ามใช้เป็น path" },
  { match: ["server-side request forgery", "server-side request forgery (ssrf)", "ssrf"], why: "เซิร์ฟเวอร์ยิง request ไปยัง URL ที่ผู้ใช้กำหนดได้ ผู้โจมตีใช้เจาะระบบภายใน หรืออ่าน cloud metadata (เช่น 169.254.169.254) เพื่อขโมย credential", fix: "อย่ารับ URL จากผู้ใช้ ให้เลือกปลายทางจากรายการที่กำหนดไว้ฝั่ง server" },
  { match: ["cross-site scripting", "xss"], why: "แสดง input ของผู้ใช้เป็น HTML สคริปต์ของผู้โจมตีจะรันในเบราว์เซอร์ของผู้ใช้คนอื่น (ขโมย session ได้)", fix: "แสดงผลเป็น text เช่น {value} ใน React, ไม่ใช้ dangerouslySetInnerHTML, ส่ง content-type เป็น text/plain" },
  { match: ["prototype pollution"], why: "library เวอร์ชันนี้ยอมให้ input แก้ Object.prototype ได้ ทำให้ logic ทั้งแอปเพี้ยน หรือนำไปสู่การรันโค้ด", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว หรือเลิกใช้" },
  { match: ["regular expression denial of service", "redos"], why: "regex ใน library ทำงานช้ามากกับ input บางรูปแบบ ผู้โจมตีส่ง input เดียวทำให้เซิร์ฟเวอร์ค้างได้ (DoS)", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["arbitrary code injection", "code injection"], why: "library เวอร์ชันนี้มีช่องให้รันโค้ดที่ผู้โจมตีส่งเข้ามาได้", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว หรือเลิกใช้" },
  { match: ["http response splitting"], why: "ผู้โจมตีแทรก header หรือ response ปลอมเข้าไปใน HTTP ได้", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["cross-site request forgery", "csrf"], why: "เปิดช่องให้เว็บอื่นส่ง request แทนผู้ใช้ที่ login อยู่ได้", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["uncontrolled recursion"], why: "input บางแบบทำให้ฟังก์ชันเรียกตัวเองไม่สิ้นสุดจนเซิร์ฟเวอร์ล่ม", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["sensitive information"], why: "อาจส่งข้อมูลลับ เช่น header หรือ credential ไปยังปลายทางที่ไม่ควรได้รับ", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["certificate", "ssl", "tls"], why: "ปิดการตรวจ TLS certificate ทำให้ถูกดักฟังหรือปลอมเป็นเซิร์ฟเวอร์ปลายทางได้", fix: "อย่าปิด certificate verification (rejectUnauthorized / verify=False)" },
  { match: ["hardcoded", "hard-coded", "credential", "secret", "password"], why: "มีรหัสผ่านหรือ secret เขียนไว้ในโค้ด ใครเห็นโค้ดหรือ git history ก็เอาไปใช้ได้", fix: "ย้ายไปเก็บใน environment variable หรือ secret manager" },
  { match: ["privileged", "host network", "hostnetwork", "host pid", "hostpid"], why: "container ได้สิทธิ์ระดับ node ถ้าถูกเจาะจะลามไปทั้งเครื่องได้", fix: "ปิด privileged / hostNetwork / hostPID ใน securityContext" },
];
const explain = (title) => {
  const t = String(title ?? "").toLowerCase();
  return KNOWLEDGE.find((k) => k.match.some((m) => t.includes(m))) ?? {};
};

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
const stripAnsi = (s) => String(s ?? "").replace(/\u001b\[[0-9;]*m/g, "");
const bySeverity = (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);

// ---------- Unit tests (Vitest JSON) ----------
function parseTests() {
  const data = readJson("test-results.json");
  if (!data) return { ran: false, items: [], failed: [] };
  const items = [];
  for (const file of data.testResults ?? []) {
    const fileName = String(file.name ?? "").match(/tests\/[\w./-]+$/)?.[0] ?? path.basename(String(file.name ?? ""));
    for (const t of file.assertionResults ?? []) {
      // First line of the assertion error, e.g. "AssertionError: <reason>: expected 200 to be 400"
      const raw = stripAnsi((t.failureMessages ?? [])[0] ?? "").split("\n")[0];
      const loc = stripAnsi((t.failureMessages ?? [])[0] ?? "").match(/tests\/[\w./-]+:\d+/)?.[0];
      const message = raw.replace(/^AssertionError:\s*/, "").replace(/\s*\/\/ Object\.is equality$/, "");
      items.push({ name: t.fullName || t.title, file: loc ?? fileName, status: t.status, message });
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
      const title = rule.shortDescription?.text || rule.name || r.ruleId;
      const k = explain(title);
      items.push({
        severity: level === "error" ? "high" : level === "warning" ? "medium" : "low",
        title,
        location: loc ? `${loc.artifactLocation?.uri}:${loc.region?.startLine ?? ""}` : "",
        why: k.why,
        evidence: r.message?.text ?? "",
        fix: k.fix,
        ref: (rule.properties?.cwe ?? []).join(", "),
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
      const k = explain(v.title);
      const ids = [...(v.identifiers?.CVE ?? []), ...(v.identifiers?.CWE ?? [])].join(", ");
      const via = (v.from ?? []).slice(1, -1);
      items.push({
        severity: v.severity,
        title: v.title,
        location: `${v.packageName}@${v.version}`,
        why: `${v.packageName}@${v.version} มีช่องโหว่ที่รู้จักแล้ว${ids ? ` (${ids})` : ""}${
          via.length ? ` ติดมาผ่าน ${via.join(" › ")}` : " ถูกติดตั้งตรงจาก package.json"
        }. ${k.why ?? ""}`,
        evidence: "",
        fix: v.fixedIn?.length ? `อัปเกรดเป็น ${v.packageName}@${v.fixedIn.join(" หรือ ")} ขึ้นไป หรือเลิกใช้ package นี้` : "ยังไม่มีเวอร์ชันที่แก้ ให้พิจารณาเลิกใช้",
        ref: v.id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

// ---------- Snyk Container (JSON) ----------
function parseContainer() {
  const data = readJson("snyk-container.json");
  if (!data) return { ran: false, items: [] };
  const projects = Array.isArray(data) ? data : [data];
  const seen = new Set();
  const items = [];
  let baseImage = "";
  let advice = "";
  for (const p of projects) {
    baseImage ||= p.docker?.baseImage ?? "";
    // Turn Snyk's text table into one readable line: current image and suggested alternatives with counts
    const text = (p.docker?.baseImageRemediation?.advice ?? []).map((a) => a.message).join("\n");
    const rows = [...text.matchAll(/^(\S+:\S+)\s+(\d+)\s+(\d+ critical, \d+ high)/gm)].map((m) => `${m[1]} (${m[2]} ช่องโหว่: ${m[3]})`);
    const notes = (p.docker?.baseImageRemediation?.advice ?? []).filter((a) => a.color === "yellow").map((a) => a.message);
    if (!advice && rows.length) advice = `ตอนนี้ ${rows[0]}${rows.length > 1 ? ` · แนะนำเปลี่ยนเป็น ${rows.slice(1).join(" หรือ ")}` : ""}${notes.length ? ` · ${notes.join(" ")}` : ""}`;
    else if (!advice && /most secure version/i.test(text)) advice = "ใช้ base image เวอร์ชันที่ปลอดภัยที่สุดอยู่แล้ว";
    for (const v of p.vulnerabilities ?? []) {
      const key = `${v.id}@${v.packageName}@${v.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const ids = (v.identifiers?.CVE ?? []).join(", ");
      const k = explain(v.title);
      items.push({
        severity: v.severity,
        title: v.title,
        location: `${v.packageName}@${v.version}`,
        why: `OS package ${v.packageName}@${v.version} ใน image${baseImage ? ` (base image ${baseImage})` : ""} มีช่องโหว่ที่รู้จักแล้ว${ids ? ` (${ids})` : ""}. ${k.why ?? ""}`,
        evidence: "",
        fix: v.nearestFixedInVersion || v.fixedIn?.length
          ? `อัปเกรด base image เป็นเวอร์ชันใหม่ที่มี ${v.packageName} ${v.nearestFixedInVersion ?? v.fixedIn[0]} ขึ้นไป หรือเปลี่ยนเป็น image ที่เล็กกว่า (เช่น alpine / slim)`
          : "ยังไม่มีเวอร์ชันที่แก้ พิจารณาเปลี่ยน base image",
        ref: v.id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity), baseImage, advice };
}

// ---------- Snyk IaC (JSON) ----------
function parseIac() {
  const data = readJson("snyk-iac.json");
  if (!data) return { ran: false, items: [] };
  const files = Array.isArray(data) ? data : [data];
  const items = [];
  for (const f of files) {
    for (const i of f.infrastructureAsCodeIssues ?? []) {
      const k = explain(i.title);
      items.push({
        severity: i.severity,
        title: i.title,
        location: `${f.targetFile ?? f.displayTargetFile ?? ""}${i.lineNumber ? ":" + i.lineNumber : ""}`,
        why: k.why ?? i.iacDescription?.issue ?? i.msg ?? "",
        evidence: i.iacDescription?.impact ?? "",
        fix: k.fix ?? i.iacDescription?.resolve ?? "",
        ref: i.id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

const tests = parseTests();
const sections = [
  { key: "code", short: "SAST", name: "SAST · Snyk Code", what: "ช่องโหว่ในโค้ดที่เราเขียนเอง", ...parseCode() },
  { key: "oss", short: "SCA", name: "SCA · Snyk Open Source", what: "CVE ใน npm dependency ที่ใช้", ...parseOss() },
  { key: "iac", short: "IaC", name: "IaC · Snyk IaC", what: "การตั้งค่าที่ไม่ปลอดภัยใน Kubernetes manifest", ...parseIac() },
  { key: "container", short: "Container", name: "Container · Snyk Container", what: "ช่องโหว่ใน Docker image ที่ build จาก Dockerfile (base image และ OS package)", ...parseContainer() },
];
const ctr = sections.find((s) => s.key === "container");
if (ctr.baseImage) ctr.what += ` · base image: ${ctr.baseImage}`;
if (ctr.advice) ctr.what += ` · Snyk: ${ctr.advice}`;
for (const s of sections) {
  s.counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const i of s.items) if (i.severity in s.counts) s.counts[i.severity]++;
  s.blocking = s.items.filter((i) => GATE.has(i.severity)).length;
  s.status = !s.ran ? "skipped" : s.blocking ? "fail" : "pass";
}
const testStatus = !tests.ran ? "skipped" : tests.failed.length ? "fail" : "pass";
const overallPass = env.BUILD
  ? env.BUILD === "success" && env.SNYK === "success"
  : testStatus !== "fail" && sections.every((s) => s.status !== "fail");

// Every item that blocked the gate, with its reason
const blockers = [
  ...tests.failed.map((t) => ({
    kind: "Unit test",
    title: t.name,
    where: t.file,
    why: t.message || "test ไม่ผ่าน",
    fix: "แก้โค้ดให้ test ผ่าน (test นี้ตรวจว่าช่องโหว่ถูกกันไว้)",
  })),
  ...sections.flatMap((s) =>
    s.items
      .filter((i) => GATE.has(i.severity))
      .map((i) => ({ kind: `${s.short} ${i.severity.toUpperCase()}`, title: i.title, where: i.location, why: i.why || i.evidence, fix: i.fix })),
  ),
];

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
if (blockers.length) {
  md.push("", "### สาเหตุที่ gate ไม่ผ่าน", "", "| ประเภท | ปัญหา | ที่ไหน | สาเหตุ |", "|---|---|---|---|");
  const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
  for (const b of blockers) md.push(`| ❌ ${b.kind} | ${cell(b.title)} | \`${cell(b.where)}\` | ${cell(b.why)} |`);
}
md.push("", "📄 Full report: download the **security-report** artifact below, or run `npm run report` on your machine.");
console.log(md.join("\n"));

// ---------- HTML ----------
const badge = (sev) => `<span class="sev ${esc(sev)}">${esc(sev)}</span>`;
const pill = (st) => `<span class="pill ${st}">${{ pass: "PASS", fail: "FAIL", skipped: "NOT RUN" }[st]}</span>`;
const findingTable = (s) => {
  if (!s.ran) return `<p class="muted">สแกนนี้ไม่ได้รัน (ไม่มี token หรือ job ถูกข้าม)</p>`;
  if (!s.items.length) return `<p class="ok">ไม่พบปัญหาระดับ High ขึ้นไป</p>`;
  return `<table><thead><tr><th>Severity</th><th>ปัญหา</th><th>ที่ไหน</th><th>สาเหตุ</th><th>วิธีแก้</th></tr></thead><tbody>${s.items
    .map(
      (i) => `<tr class="${GATE.has(i.severity) ? "block" : ""}"><td>${badge(i.severity)}</td><td><strong>${esc(i.title)}</strong>${
        i.ref ? `<div class="muted small">${esc(i.ref)}</div>` : ""
      }</td><td><code>${esc(i.location)}</code></td><td>${esc(i.why)}${
        i.evidence ? `<div class="evidence">Snyk: ${esc(i.evidence)}</div>` : ""
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
const blockerList = () =>
  blockers.length
    ? `<h2 id="why">สาเหตุที่ gate ไม่ผ่าน (${blockers.length})</h2><div class="muted">กติกา: test ต้องผ่านทั้งหมด และต้องไม่มีปัญหาระดับ Critical/High จาก Snyk</div>
<ol class="why">${blockers
        .map(
          (b) => `<li><div><span class="tag">${esc(b.kind)}</span> <strong>${esc(b.title)}</strong> <code>${esc(b.where)}</code></div><div><b>สาเหตุ:</b> ${esc(
            b.why,
          )}</div>${b.fix ? `<div class="fix"><b>วิธีแก้:</b> ${esc(b.fix)}</div>` : ""}</li>`,
        )
        .join("")}</ol>`
    : "";

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
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Gate Report</title>
<style>
:root{--bg:#f7f7f8;--panel:#fff;--text:#18181b;--muted:#6b7280;--border:#e5e7eb;--pass:#15803d;--fail:#b91c1c;--skip:#6b7280;--failbg:#fef2f2;
--crit:#7f1d1d;--high:#dc2626;--med:#d97706;--low:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#0f0f11;--panel:#18181b;--text:#f4f4f5;--muted:#a1a1aa;--border:#2e2e33;--failbg:#2a1215;--pass:#4ade80;--fail:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI","Noto Sans Thai",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 4px}.muted{color:var(--muted)}.small{font-size:12px}
.banner{padding:16px 20px;border-radius:10px;margin:16px 0 20px;font-weight:600;font-size:16px;border:1px solid var(--border);background:var(--panel)}
.banner.pass{border-left:6px solid var(--pass)}.banner.fail{border-left:6px solid var(--fail)}
.meta{color:var(--muted);font-size:13px}.meta a{color:inherit}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.card{display:block;text-decoration:none;color:inherit;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;border-top:4px solid var(--skip)}
.card.pass{border-top-color:var(--pass)}.card.fail{border-top-color:var(--fail)}
.card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.card .big{font-size:28px;font-weight:700}.card .sub{font-size:12px;color:var(--muted);margin-bottom:8px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;color:#fff;background:var(--skip)}.pill.pass{background:var(--pass)}.pill.fail{background:var(--fail)}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-top:8px}
table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}tr.block{background:var(--failbg)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.sev{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px;color:#fff;background:var(--low)}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}
.fix{color:var(--pass)}.ok{color:var(--pass);font-weight:600;padding:12px;margin:0}p.muted{padding:12px;margin:0}
.evidence{margin-top:6px;font-size:12px;color:var(--muted)}
ol.why{background:var(--panel);border:1px solid var(--border);border-left:6px solid var(--fail);border-radius:10px;margin:8px 0 0;padding:12px 16px 12px 40px}
ol.why li{padding:8px 0;border-bottom:1px solid var(--border)}ol.why li:last-child{border-bottom:0}ol.why li>div{margin:2px 0}
.tag{display:inline-block;font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;background:var(--fail);color:#fff}
</style></head><body><main>
<h1>Security Gate Report</h1>
<div class="meta">Branch <strong>${esc(env.BRANCH ?? "local")}</strong>${env.SHA ? ` · commit <code>${esc(env.SHA.slice(0, 7))}</code>` : ""} · generated ${esc(
  new Date().toISOString().replace("T", " ").slice(0, 16),
)} UTC${env.RUN_URL ? ` · <a href="${esc(env.RUN_URL)}">เปิด GitHub Actions run</a>` : ""}</div>
<div class="banner ${overallPass ? "pass" : "fail"}">${
  overallPass
    ? "✅ Gate ผ่าน: test ผ่านทั้งหมด และไม่มีปัญหาระดับ Critical/High"
    : `❌ Gate ไม่ผ่าน: มี ${blockers.length} รายการที่ทำให้ถูกบล็อก ดูสาเหตุและวิธีแก้ด้านล่าง (แถวสีแดงในตาราง)`
}</div>
<div class="cards">${cards}</div>
${blockerList()}
<h2 id="tests">Unit tests</h2><div class="muted">test การทำงานและ security regression test (Vitest)</div><div class="wrap">${testTable()}</div>
${sections.map((s) => `<h2 id="${s.key}">${esc(s.name)}</h2><div class="muted">${esc(s.what)} · gate บล็อกที่ระดับ Critical/High</div><div class="wrap">${findingTable(s)}</div>`).join("\n")}
</main></body></html>`;

mkdirSync(path.dirname(out), { recursive: true });
writeFileSync(out, html);
