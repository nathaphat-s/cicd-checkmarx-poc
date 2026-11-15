# เปรียบเทียบ Snyk · Aikido · GitHub Advanced Security

ทั้ง 3 เครื่องมือรันใน workflow เดียวกัน (`.github/workflows/ci.yml`) กับโค้ดชุดเดียวกัน แล้วรวมผลไว้ใน `report.html` ไฟล์เดียว
หน้าแรกของ report เป็นตาราง **tool × ประเภทการสแกน** ให้เห็นว่าใครเจออะไรบน PR เดียวกัน

```
push / PR / Run workflow
   ├─► Build & unit test
   ├─► Snyk    Code · Open Source · IaC · Container
   ├─► Aikido  local scanner (Code + deps + IaC + secrets) · image-scan
   └─► GHAS    CodeQL · Dependency Review          (+ secret scanning / Dependabot เป็น repo setting)
         └─► Report: report.html + commit status แยกต่อ tool + "CI + Security Gate"
```

## ใครครอบคลุมอะไร

| ประเภท | Snyk | Aikido | GitHub Advanced Security |
|---|---|---|---|
| SAST | Snyk Code | local scanner (`scan`) | CodeQL (`security-extended`) |
| SCA | Snyk Open Source | local scanner (`scan`) | Dependency Review (ใน PR) + Dependabot alerts (บน main) |
| IaC (k8s, Dockerfile) | Snyk IaC | local scanner (`scan`) | ❌ ไม่มี |
| Secrets | รวมใน Snyk Code | local scanner (`scan`) | Secret scanning + push protection (บล็อกตั้งแต่ตอน push) |
| Container image | Snyk Container | `image-scan` | ❌ ไม่มี |
| Auto-fix PR | Fix PR (dependency) | AutoFix (แผนเสียเงิน) | Dependabot security updates |
| ลด noise | priority score + reachability | AutoTriage (แผนเสียเงิน) | Copilot Autofix อธิบาย/เสนอแก้ alert ของ CodeQL |
| ผลขึ้นที่ไหน | Snyk dashboard + PR check | Aikido dashboard + PR check | Security tab ของ GitHub |

## Gate: ใครเป็นคนบล็อก merge

- ค่าเริ่มต้น gate = unit tests + **Snyk** (เหมือนเดิม) อีก 2 ตัวแสดงผลเพื่อเปรียบเทียบอย่างเดียว
- ทุก tool ใช้เกณฑ์เดียวกัน: เจอ **High หรือ Critical = fail**
  - Snyk: `--severity-threshold=high`
  - Aikido: `--fail-on high`
  - CodeQL: ไม่ fail เอง ใช้ `scripts/gate-count.mjs` นับ alert ที่ `security-severity >= 7.0` (เกณฑ์เดียวกับที่ GitHub ใช้แสดง High)
  - Dependency Review: `fail-on-severity: high`
- บน PR จะเห็น commit status 4 อัน: `Scanner / snyk`, `Scanner / aikido`, `Scanner / ghas` และ `CI + Security Gate`
- เปลี่ยน tool ที่ใช้บล็อกได้โดยไม่ต้องแก้ไฟล์:
  ```bash
  gh variable set GATE_TOOLS --body "snyk aikido ghas"
  ```

> **ความต่างที่ต้องรู้ตอนอ่านผล:** Aikido (PR gating mode) และ Dependency Review นับเฉพาะ **ปัญหาใหม่ที่ branch นี้เพิ่มเข้ามาเทียบกับ main** ส่วน Snyk และ CodeQL นับ **ทุกปัญหาในโค้ดปัจจุบัน** ถ้า main มีช่องโหว่เดิมอยู่แล้ว ตัวเลขจึงไม่เท่ากันโดยธรรมชาติ

## ตั้งค่า Aikido

1. สมัคร https://app.aikido.dev ด้วยบัญชี GitHub (แผน Free: 2 users, 10 repos, 2 container images, rescan อัตโนมัติทุก 3 วัน, ไม่มี AutoTriage)
2. เลือก repo `cicd-checkmarx-poc` ให้ Aikido เข้าถึง (ได้ dashboard และสแกนรอบแรกทันที)
3. สร้าง token สำหรับ local scanner: Settings → Integrations → **Local scanner** (ขึ้นต้นด้วย `AIK_CI_`) แล้วรัน:
   ```bash
   gh secret set AIKIDO_API_KEY
   ```
4. สั่งรัน workflow บน PR เดโม แล้วดูผลใน report

ถ้าไม่ได้ใส่ `AIKIDO_API_KEY` job Aikido จะข้ามพร้อม warning และ report แสดงเป็น NOT RUN

**ข้อควรระวังของแผน Free**
- เอกสารของ Aikido ระบุว่า PR gating แบบเขียนใน CI (in-code) ต้องใช้แผน Pro ส่วน local scanner ไม่ได้ระบุแผน ถ้า job ขึ้น error เรื่อง plan/permission ให้ใช้ **PR gating ผ่าน Aikido dashboard** แทน (Settings → PR Checks เปิดสำหรับ repo นี้) ซึ่งจะได้ check `Aikido Security` บน PR โดยไม่ต้องใช้ CI (แต่ผลจะไม่เข้า report.html)
- image-scan ใช้ชื่อ image เดียว (`poc-app`) และแยกด้วย tag เพื่อไม่ให้เกินโควตา 2 images
- ไฟล์ผลของ `--gating-result-output` ไม่มี schema ในเอกสาร parser ใน `scripts/parsers.mjs` อ่านแบบยืดหยุ่น ถ้าได้ไฟล์จริงแล้วชื่อ field ไม่ตรง ให้ปรับที่ฟังก์ชัน `parseAikido`

ลองในเครื่องก่อน push (ต้องมี Docker):

```bash
export AIKIDO_API_KEY=AIK_CI_xxx
npm run security:local
```

## ตั้งค่า GitHub Advanced Security

repo นี้เป็น **public** จึงใช้ GHAS ได้ฟรีทั้งหมด (ถ้าเป็น private ต้องซื้อ GitHub Code Security / Secret Protection ซึ่งคิดตามจำนวน active committer)

| ฟีเจอร์ | สถานะตอนนี้ | เปิดที่ไหน |
|---|---|---|
| Secret scanning | ✅ เปิดแล้ว | Settings → Code security |
| Push protection | ✅ เปิดแล้ว | Settings → Code security |
| Dependabot alerts | ❌ ปิดอยู่ | Settings → Code security → Dependabot alerts → Enable |
| Dependabot security updates | ❌ ปิดอยู่ | หน้าเดียวกัน (เปิดหลัง alerts) |
| Dependabot version updates | มากับ `.github/dependabot.yml` | ทำงานเองหลัง merge เข้า main |
| CodeQL (code scanning) | มากับ job `ghas` ใน ci.yml | ไม่ต้องเปิด default setup (ถ้าเปิดไว้จะชนกับ advanced setup ใน workflow) |
| Dependency Review | มากับ job `ghas` ใน ci.yml | ต้องเปิด Dependency graph (public repo เปิดให้อยู่แล้ว) |

ดู alert ที่ GITHUB_TOKEN ใน workflow อ่านไม่ได้ (Dependabot, Secret scanning) ด้วยบัญชีของเราเอง:

```bash
npm run ghas:alerts
```

```bash
npm run ghas:alerts -- demo/nextjs-vulnerable
```

**ข้อควรระวัง**
- Secret scanning จับเฉพาะ token ที่มีรูปแบบของผู้ให้บริการ (AWS key, GitHub token, Slack ฯลฯ) รหัสผ่านทั่วไปอย่าง `"SuperSecret123!"` ใน PR เดโมจะ **ไม่ถูกจับ** ต้องใช้ non-provider patterns / Copilot secret scanning ซึ่งอาจต้องมี license Secret Protection
- CodeQL ไม่สแกน IaC และ container image ช่องนี้ในตารางจึงเป็น "ไม่รองรับ"
- Dependency Review เทียบ 2 commit จึงไม่รันบน main (ไม่มีอะไรให้เทียบ) บน main ให้ดู Dependabot alerts แทน

## วิธีเปรียบเทียบบน PR เดโม

1. merge branch นี้เข้า `main` แล้ว merge `main` เข้า `demo/nextjs-vulnerable` และ `demo/nextjs-secure` (แบบเดียวกับที่ทำตอนเพิ่ม Snyk Container)
2. รัน workflow ทั้งสอง branch:
   ```bash
   gh workflow run ci.yml --ref demo/nextjs-vulnerable
   ```
   ```bash
   gh workflow run ci.yml --ref demo/nextjs-secure
   ```
3. ดึง report:
   ```bash
   npm run report -- 4
   ```
   ```bash
   npm run report -- 5
   ```
4. กรอกตารางผลด้านล่าง

### ตารางผล (รันจริง 15 พ.ย. 2026)

ช่องโหว่ที่ตั้งใจใส่ไว้ (โค้ดชุดเดียวกันใน #4 Snyk, #7 Aikido, #9 GHAS) และใครจับได้
(✅ = รายงานระดับ High ขึ้นไป, 🟡 = รายงานแต่ต่ำกว่า High, ❌ = ไม่รายงาน, ⏳ = ยังไม่ได้ผล)

| ช่องโหว่ | ไฟล์ | Unit test | Snyk (#4) | Aikido (#7) | GHAS / CodeQL (#9) |
|---|---|---|---|---|---|
| SQL Injection | `lib/users.ts` | ✅ | ❌ | ✅ Critical | ✅ High |
| XSS (`dangerouslySetInnerHTML`) | `app/page.tsx` | | ❌ | ✅ High | ❌ |
| DOM XSS (`innerHTML`) | `app/welcome/WelcomeClient.tsx` | | ✅ | ✅ High | ✅ High |
| postMessage → `eval` | `app/welcome/WelcomeClient.tsx` | | ❌ | ✅ Critical | ✅ Critical |
| Client open redirect (`location.href`) | `app/welcome/WelcomeClient.tsx` | | ❌ | ✅ High (เป็น XSS) | ✅ High (เป็น XSS) + 🟡 redirect |
| Command Injection | `app/api/tools/ping` | ✅ | ✅ | ❌ | ✅ Critical |
| Path Traversal | `app/api/tools/files` | ✅ | ✅ | ✅ High | ❌ |
| SSRF | `app/api/tools/notify` | ✅ | ✅ | 🟡 Medium | ✅ Critical |
| ปิด TLS (`rejectUnauthorized: false`) | `app/api/tools/notify` | | ❌ | ❌ | ✅ High |
| Code Injection (`eval`) | `app/api/calc` | | ✅ | ✅ Critical | ✅ Critical |
| Server open redirect | `app/api/go` | | ❌ | ✅ Critical | ❌ |
| Hardcoded password | `app/api/tools/notify` | | ❌ | ❌ | ❌ |
| axios 0.21.1 / lodash 4.17.15 | `package.json` | | ✅ 16 | ✅ 14 (Critical 1, High 7) | ⏳ ต้องเปิด Dependency graph |
| k8s hostNetwork / hostPID | `k8s/deployment.yaml` | | 🟡 | ❌ | ไม่รองรับ |
| base image bullseye, root | `Dockerfile` | | ✅ 31 CVE | 🟡 root user (Medium) ไม่ได้สแกน image | ไม่รองรับ |
| **รวมที่จับได้ระดับ High ขึ้นไป (โค้ด 12 จุด)** | | 4 | 5 | 8 | 8 |

ฝั่ง secure ทุก tool ผ่าน: Snyk #5 ผ่าน, Aikido #8 ผ่าน (เจอ Low 1), CodeQL #10 ผ่าน (เจอ Medium 1 เป็น client-side URL redirect)

**ข้อสังเกต**
- Aikido ใช้ PR check ของ GitHub App (ไม่ใช่ local scanner ใน CI) ค่าเริ่มต้นจะ fail เมื่อเจอ **Critical** เท่านั้น ถ้าจะให้เทียบกับ Snyk/CodeQL แบบยุติธรรม ควรตั้งให้ fail ที่ High ใน dashboard
- Aikido แสดงผลเป็น comment บนบรรทัดโค้ดใน PR พร้อมปุ่ม "Show fix" ส่วน Deep Review ถูกข้าม เพราะแผนฟรีไม่มีเครดิต AI
- CodeQL จับ command injection, SSRF และ TLS ได้แม่นที่สุด แต่ไม่จับ path traversal กับ `dangerouslySetInnerHTML` ในโค้ดนี้
- Aikido จับ open redirect, path traversal และ SQLi ได้ แต่พลาด command injection (`exec`) และไม่สแกน k8s / container image ใน PR check
- ไม่มี tool ไหนจับ hardcoded password `"SuperSecret123!"` ได้ที่ระดับ High
