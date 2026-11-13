// Parsers that turn each scanner's output into one common finding shape:
//   { severity: "critical"|"high"|"medium"|"low", title, location, why, evidence, fix, ref }
// Used by build-report.mjs (report.html) and gate-count.mjs (CI gate for tools that do not fail by themselves).
// Every parser returns { ran: false, items: [] } when its input file is missing, so a tool that was
// skipped (no token, job not run) shows as "not run" instead of breaking the report.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
export const GATE = new Set(["critical", "high"]);

// ---------- Plain-language reasons (Thai) by issue type ----------
// Matched against the issue title (lower case). First match wins.
// Titles differ per tool (Snyk "SQL Injection", CodeQL "Database query built from user-controlled sources"),
// so each entry lists the wording of every tool.
const KNOWLEDGE = [
  { match: ["sql injection", "database query built from user-controlled"], why: "เอา input ของผู้ใช้ไปต่อเป็นคำสั่ง SQL ตรง ๆ ผู้โจมตีแก้เงื่อนไขของ query เพื่ออ่านหรือแก้ข้อมูลทั้งตารางได้", fix: "ใช้ parameterized query เช่น prepare(\"... WHERE name = ?\").all(name)" },
  { match: ["command injection", "uncontrolled command line", "shell command built from"], why: "เอา input ของผู้ใช้ไปต่อเป็นคำสั่ง shell ผู้โจมตีใส่ ; หรือ && แล้วรันคำสั่งอะไรก็ได้บนเซิร์ฟเวอร์", fix: "validate input ให้เข้มงวด และใช้ execFile ส่ง argument เป็น list แทน exec (ไม่ผ่าน shell)" },
  { match: ["path traversal", "uncontrolled data used in path expression"], why: "ใช้ชื่อไฟล์จากผู้ใช้ไปสร้าง path ตรง ๆ ผู้โจมตีใส่ ../ เพื่ออ่านไฟล์นอกโฟลเดอร์ที่อนุญาต เช่น config หรือ source code", fix: "ใช้ allow-list ของชื่อไฟล์ที่อนุญาต ให้ input เป็นแค่ key ห้ามใช้เป็น path" },
  { match: ["server-side request forgery", "ssrf"], why: "เซิร์ฟเวอร์ยิง request ไปยัง URL ที่ผู้ใช้กำหนดได้ ผู้โจมตีใช้เจาะระบบภายใน หรืออ่าน cloud metadata (เช่น 169.254.169.254) เพื่อขโมย credential", fix: "อย่ารับ URL จากผู้ใช้ ให้เลือกปลายทางจากรายการที่กำหนดไว้ฝั่ง server" },
  { match: ["open redirect", "url redirect", "url redirection"], why: "redirect ไปยัง URL ที่ผู้ใช้กำหนดได้ ผู้โจมตีใช้ลิงก์ของเว็บเราพาเหยื่อไปเว็บ phishing", fix: "อนุญาตเฉพาะ path ภายใน (ขึ้นต้นด้วย / แต่ไม่ใช่ //) หรือเลือกปลายทางจาก allow-list" },
  { match: ["cross-site scripting", "xss", "dom text reinterpreted as html"], why: "แสดง input ของผู้ใช้เป็น HTML สคริปต์ของผู้โจมตีจะรันในเบราว์เซอร์ของผู้ใช้คนอื่น (ขโมย session ได้)", fix: "แสดงผลเป็น text เช่น {value} ใน React, ไม่ใช้ dangerouslySetInnerHTML / innerHTML, ส่ง content-type เป็น text/plain" },
  { match: ["origin verification", "postmessage"], why: "รับ postMessage จากหน้าเว็บใดก็ได้โดยไม่ตรวจ origin เว็บอื่นจึงส่งคำสั่งเข้ามาในหน้าเราได้", fix: "ตรวจ event.origin กับ allow-list และห้ามส่งข้อมูลจาก message เข้า eval / innerHTML" },
  { match: ["prototype pollution"], why: "library เวอร์ชันนี้ยอมให้ input แก้ Object.prototype ได้ ทำให้ logic ทั้งแอปเพี้ยน หรือนำไปสู่การรันโค้ด", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว หรือเลิกใช้" },
  { match: ["regular expression denial of service", "redos", "inefficient regular expression"], why: "regex ทำงานช้ามากกับ input บางรูปแบบ ผู้โจมตีส่ง input เดียวทำให้เซิร์ฟเวอร์ค้างได้ (DoS)", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว หรือเขียน regex ใหม่" },
  { match: ["arbitrary code injection", "code injection", "eval"], why: "เอา input ไปรันเป็นโค้ด (eval / new Function) ผู้โจมตีรันโค้ดอะไรก็ได้", fix: "ห้ามใช้ eval กับ input ของผู้ใช้ ใช้ parser ที่จำกัดสิ่งที่ทำได้ หรืออัปเกรด library ที่มีช่องโหว่" },
  { match: ["http response splitting"], why: "ผู้โจมตีแทรก header หรือ response ปลอมเข้าไปใน HTTP ได้", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["cross-site request forgery", "csrf"], why: "เปิดช่องให้เว็บอื่นส่ง request แทนผู้ใช้ที่ login อยู่ได้", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["uncontrolled recursion"], why: "input บางแบบทำให้ฟังก์ชันเรียกตัวเองไม่สิ้นสุดจนเซิร์ฟเวอร์ล่ม", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["sensitive information"], why: "อาจส่งข้อมูลลับ เช่น header หรือ credential ไปยังปลายทางที่ไม่ควรได้รับ", fix: "อัปเกรด library เป็นเวอร์ชันที่แก้แล้ว" },
  { match: ["certificate", "ssl", "tls"], why: "ปิดการตรวจ TLS certificate ทำให้ถูกดักฟังหรือปลอมเป็นเซิร์ฟเวอร์ปลายทางได้", fix: "อย่าปิด certificate verification (rejectUnauthorized / verify=False)" },
  { match: ["hardcoded", "hard-coded", "credential", "secret", "password", "api key", "token"], why: "มีรหัสผ่านหรือ secret เขียนไว้ในโค้ด ใครเห็นโค้ดหรือ git history ก็เอาไปใช้ได้", fix: "ย้ายไปเก็บใน environment variable หรือ secret manager และ rotate ค่าที่หลุดไปแล้ว" },
  { match: ["privileged", "host network", "hostnetwork", "host pid", "hostpid"], why: "container ได้สิทธิ์ระดับ node ถ้าถูกเจาะจะลามไปทั้งเครื่องได้", fix: "ปิด privileged / hostNetwork / hostPID ใน securityContext" },
  { match: ["root"], why: "container รันเป็น root ถ้าแอปถูกเจาะ ผู้โจมตีได้สิทธิ์สูงสุดใน container", fix: "เพิ่ม USER ที่ไม่ใช่ root ใน Dockerfile และ runAsNonRoot ใน k8s" },
];
export const explain = (title) => {
  const t = String(title ?? "").toLowerCase();
  return KNOWLEDGE.find((k) => k.match.some((m) => t.includes(m))) ?? {};
};

export const bySeverity = (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
const stripAnsi = (s) => String(s ?? "").replace(/\u001b\[[0-9;]*m/g, "");

// Normalise any severity spelling (HIGH, moderate, 8.1, error) to critical/high/medium/low
export function normSeverity(v) {
  if (typeof v === "number" || /^\d+(\.\d+)?$/.test(String(v ?? ""))) {
    const n = Number(v);
    // CVSS-like 0-10, or Aikido-like 0-100 score
    const x = n > 10 ? n / 10 : n;
    return x >= 9 ? "critical" : x >= 7 ? "high" : x >= 4 ? "medium" : "low";
  }
  const s = String(v ?? "").toLowerCase();
  if (s.startsWith("crit")) return "critical";
  if (s.startsWith("high") || s === "error") return "high";
  if (s.startsWith("med") || s === "moderate" || s === "warning") return "medium";
  return "low";
}

export function createReader(dir) {
  return (file) => {
    const p = path.join(dir, file);
    if (!existsSync(p)) return undefined;
    try {
      return JSON.parse(readFileSync(p, "utf8"));
    } catch {
      return undefined;
    }
  };
}

// ---------- Unit tests (Vitest JSON) ----------
export function parseTests(read) {
  const data = read("test-results.json");
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

// ---------- SARIF (Snyk Code, CodeQL) ----------
// useSecuritySeverity: CodeQL puts a CVSS-like score in rule.properties["security-severity"]; GitHub's
// Security tab maps >= 9 critical, >= 7 high, >= 4 medium. Snyk Code has no such score, so it uses level.
export function parseSarif(read, file, { useSecuritySeverity = false, tool = "" } = {}) {
  const data = read(file);
  if (!data) return { ran: false, items: [] };
  const items = [];
  for (const run of data.runs ?? []) {
    // CodeQL keeps rules in tool.extensions (one per query pack), Snyk in tool.driver
    const allRules = [run.tool?.driver, ...(run.tool?.extensions ?? [])].flatMap((c) => c?.rules ?? []);
    const rules = Object.fromEntries(allRules.map((r) => [r.id, r]));
    for (const r of run.results ?? []) {
      if (r.suppressions?.length) continue;
      const rule = rules[r.ruleId ?? r.rule?.id] ?? {};
      const loc = r.locations?.[0]?.physicalLocation;
      const level = r.level ?? rule.defaultConfiguration?.level;
      const score = rule.properties?.["security-severity"];
      const title = rule.shortDescription?.text || rule.name || r.ruleId;
      const k = explain(title);
      const cwes = [
        ...(rule.properties?.cwe ?? []),
        ...(rule.properties?.tags ?? []).filter((t) => /cwe-\d+/i.test(t)).map((t) => t.replace(/^external\/cwe\//i, "").toUpperCase()),
      ];
      items.push({
        severity: useSecuritySeverity && score != null ? normSeverity(score) : level === "error" ? "high" : level === "warning" ? "medium" : "low",
        title,
        location: loc ? `${loc.artifactLocation?.uri}:${loc.region?.startLine ?? ""}` : "",
        why: k.why,
        evidence: r.message?.text ? `${tool ? tool + ": " : ""}${r.message.text}` : "",
        fix: k.fix,
        ref: [r.ruleId, ...new Set(cwes)].filter(Boolean).join(", "),
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

// ---------- Snyk Open Source (JSON) ----------
export function parseSnykOss(read) {
  const data = read("snyk-oss.json");
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
export function parseSnykContainer(read) {
  const data = read("snyk-container.json");
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
export function parseSnykIac(read) {
  const data = read("snyk-iac.json");
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
        evidence: i.iacDescription?.impact ? `Snyk: ${i.iacDescription.impact}` : "",
        fix: k.fix ?? i.iacDescription?.resolve ?? "",
        ref: i.id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

// ---------- GitHub Dependency Review (vulnerable-changes output of actions/dependency-review-action) ----------
// Shape: [{ change_type, manifest, name, version, vulnerabilities: [{ severity, advisory_ghsa_id, advisory_summary, advisory_url }] }]
export function parseDependencyReview(read) {
  const data = read("ghas-dependency-review.json");
  if (!data) return { ran: false, items: [] };
  const items = [];
  for (const c of Array.isArray(data) ? data : []) {
    if (c.change_type && c.change_type !== "added") continue;
    for (const v of c.vulnerabilities ?? []) {
      const k = explain(v.advisory_summary);
      items.push({
        severity: normSeverity(v.severity),
        title: v.advisory_summary,
        location: `${c.name}@${c.version}`,
        why: `${c.name}@${c.version} (เพิ่มใน ${c.manifest ?? "package-lock.json"}) มีช่องโหว่ที่รู้จักแล้ว (${v.advisory_ghsa_id}). ${k.why ?? ""}`,
        evidence: "",
        fix: k.fix ?? "อัปเกรดเป็นเวอร์ชันที่แก้แล้ว (ดู advisory) หรือเลิกใช้ package นี้",
        ref: v.advisory_ghsa_id,
      });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}

// ---------- Aikido local scanner (--gating-result-output JSON) ----------
// Aikido does not publish the schema of this file, so read it defensively: walk the JSON, take every
// object that looks like an issue (has a severity and a title-like field) and map common field names.
// If the file only has counts (issue_breakdown / gate_passed), show those as one row per severity.
const pick = (o, keys) => keys.map((k) => o?.[k]).find((v) => v !== undefined && v !== null && v !== "");
function findIssues(node, out = [], depth = 0) {
  if (!node || typeof node !== "object" || depth > 6) return out;
  if (Array.isArray(node)) {
    for (const n of node) findIssues(n, out, depth + 1);
    return out;
  }
  const sev = pick(node, ["severity", "severity_level", "severity_score", "severityScore", "level"]);
  const title = pick(node, ["title", "rule", "rule_name", "ruleName", "issue_type", "type", "cve_id", "cve", "name"]);
  if (sev !== undefined && typeof title === "string") {
    out.push(node);
    return out;
  }
  for (const v of Object.values(node)) findIssues(v, out, depth + 1);
  return out;
}
export function parseAikido(read, file) {
  const data = read(file);
  if (!data) return { ran: false, items: [] };
  const items = findIssues(data).map((i) => {
    const title = pick(i, ["title", "rule", "rule_name", "ruleName", "issue_type", "type", "cve_id", "cve", "name"]);
    const k = explain(title);
    const fileName = pick(i, ["affected_file", "file", "filename", "file_path", "path", "location"]);
    const line = pick(i, ["start_line", "line", "line_number", "lineNumber"]);
    const pkg = pick(i, ["affected_package", "package_name", "package", "image"]);
    const ver = pick(i, ["installed_version", "version"]);
    const location = fileName ? `${fileName}${line ? ":" + line : ""}` : pkg ? `${pkg}${ver ? "@" + ver : ""}` : "";
    return {
      severity: normSeverity(pick(i, ["severity", "severity_level", "severity_score", "severityScore", "level"])),
      title,
      location: typeof location === "string" ? location : JSON.stringify(location),
      why: k.why ?? pick(i, ["description", "tldr", "message"]) ?? "",
      evidence: pick(i, ["tldr", "description", "message"]) && k.why ? `Aikido: ${pick(i, ["tldr", "description", "message"])}` : "",
      fix: k.fix ?? pick(i, ["how_to_fix", "fix", "remediation", "patched_versions"]) ?? "",
      ref: [pick(i, ["cve_id", "cve", "rule_id", "id"]), pick(i, ["cwe", "cwe_id"])].filter(Boolean).join(", "),
    };
  });
  // Counts-only output, e.g. { gate_passed: false, issue_breakdown: { high: 2, critical: 0 } }
  if (!items.length) {
    const b = data.issue_breakdown ?? data.issueBreakdown ?? data.counts;
    for (const [sev, n] of Object.entries(b ?? {})) {
      const count = typeof n === "number" ? n : Number(n?.count ?? 0);
      if (count > 0) items.push({ severity: normSeverity(sev), title: `${count} issue(s) ระดับ ${sev}`, location: "", why: "Aikido ส่งมาแค่จำนวน ดูรายละเอียดใน Aikido dashboard", evidence: "", fix: "", ref: "" });
    }
  }
  return { ran: true, items: items.sort(bySeverity) };
}
