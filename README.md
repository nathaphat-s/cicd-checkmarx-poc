# POC: CI/CD + Security Gate (Next.js + Snyk · Aikido · GitHub Advanced Security)

แอปตัวอย่าง **Next.js (TypeScript)** สำหรับสาธิต pipeline บน **GitHub Actions** ที่สแกนโค้ดด้วย **Snyk**, **Aikido** และ **GitHub Advanced Security** คู่กันบนโค้ดชุดเดียว แล้ว **บล็อกอัตโนมัติ** เมื่อพบช่องโหว่ระดับ High ขึ้นไป

```
push / PR ──► Build & unit test ──┐
          ├─► Snyk ───────────────┤
          ├─► Aikido ─────────────┼─► Report (เทียบ 3 tool) ─► Gate (High ขึ้นไป = fail) ─► merge ได้ / ถูกบล็อก
          └─► GHAS (CodeQL + Dependency Review)
```

ตารางเทียบความสามารถ, วิธีตั้งค่า Aikido / GHAS และตารางผลบน PR เดโม อยู่ใน [docs/tool-comparison.md](docs/tool-comparison.md)

## โครงสร้าง

```
app/page.tsx                   หน้า User search (/?q=alice)
app/api/users/route.ts         GET /api/users?name=
app/api/tools/ping/route.ts    GET /api/tools/ping?host=        (เฉพาะใน PR เดโม)
app/api/tools/files/route.ts   GET /api/tools/files?name=       (เฉพาะใน PR เดโม)
app/api/tools/notify/route.ts  POST /api/tools/notify {url}     (เฉพาะใน PR เดโม)
lib/                           SQLite (better-sqlite3, in-memory)
tests/                         Vitest รวม security regression test
k8s/, Dockerfile               ไฟล์ IaC ที่ถูกสแกนด้วย
```

## PR เดโม

| Branch | เนื้อหา | ผลที่คาดหวัง |
|---|---|---|
| `demo/nextjs-vulnerable` | ฟีเจอร์ที่มีช่องโหว่ตั้งใจใส่ไว้ | ❌ gate fail |
| `demo/nextjs-secure` | ฟีเจอร์เดียวกันที่เขียนอย่างปลอดภัย | ✅ gate pass |

| ประเภท | ❌ โค้ดที่มีช่องโหว่ | ✅ วิธีแก้ |
|---|---|---|
| SQL Injection | `` prepare(`... WHERE name = '${name}'`) `` | `prepare("... WHERE name = ?").all(name)` |
| XSS | `dangerouslySetInnerHTML={{ __html: q }}` | `<p>{q}</p>` (React escape ให้) |
| Command Injection | `` exec(`ping -c 1 ${host}`) `` | ตรวจ host + `execFile("ping", ["-c","1",host])` |
| Path Traversal | `readFile(path.join(DIR, name))` + `text/html` | allow-list ชื่อไฟล์ + `text/plain` |
| SSRF / TLS | `axios.post(userUrl, …, { rejectUnauthorized: false })` | ให้เลือก webhook จากชื่อ ส่วน URL กำหนดไว้ฝั่ง server, ใช้ `fetch` ปกติ |
| Hardcoded secret | `const WEBHOOK_PASSWORD = "SuperSecret123!"` | `process.env.WEBHOOK_PASSWORD` + k8s `secretKeyRef` |
| Dependency เก่า (SCA) | `axios@0.21.1`, `lodash@4.17.15` | ไม่ใช้ / ใช้ `fetch` ที่มากับ Node |
| IaC | k8s `hostNetwork`, `hostPID`, secret เป็น plain text | securityContext แบบ hardened |

## 1) รันในเครื่อง

ต้องมี Node.js 22+ และ Docker Desktop (เครื่อง M2 ใช้ได้)

```bash
cd ~/cicd-checkmarx-poc && npm install
```

```bash
npm run dev
```

เปิด http://localhost:3000 แล้วลองค้นหา `alice`

ลองโจมตีบน branch ที่มีช่องโหว่:

```bash
git checkout demo/nextjs-vulnerable && npm install && npm run dev
```

- SQL Injection: http://localhost:3000/api/users?name=%27%20OR%20%271%27=%271 คืน user ทุกคน
- XSS: http://localhost:3000/?q=%3Cimg%20src=x%20onerror=alert(1)%3E ขึ้น alert
- Path Traversal: http://localhost:3000/api/tools/files?name=../../package.json อ่านไฟล์นอกโฟลเดอร์ได้

รัน test (มี security regression test ที่จะ fail บน branch ที่มีช่องโหว่):

```bash
npm test
```

รัน security gate ในเครื่อง ไม่ต้องมีบัญชี (Semgrep = SAST, npm audit = SCA, KICS = IaC ผ่าน Docker):

```bash
./scripts/local-scan.sh
```

> Semgrep rule ฟรีจับได้น้อยกว่า Snyk Code (ไม่ไล่ data flow ข้ามฟังก์ชันใน route handler) ในเครื่องจะเห็นแค่ hardcoded secret, dependency เก่า และ k8s ส่วน injection ทั้งหมดจะเห็นใน Snyk บน Actions

## 2) Snyk

1. สมัคร https://snyk.io ด้วยบัญชี GitHub แล้ว import repo นี้ (ได้ dashboard + PR check `security/snyk`)
2. เปิด Snyk Code ที่ Settings → Snyk Code → Enable
3. copy token จาก Account settings (Auth Token หรือ Personal Access Token) แล้วรัน:
   ```bash
   gh secret set SNYK_TOKEN
   ```

ถ้าไม่ได้ใส่ `SNYK_TOKEN` job Snyk ใน Actions จะข้ามพร้อม warning

## 3) Aikido และ GitHub Advanced Security

- **Aikido**: สมัคร https://app.aikido.dev ด้วย GitHub, เลือก repo นี้, สร้าง token ที่ Settings → Integrations → Local scanner แล้ว `gh secret set AIKIDO_API_KEY` (ไม่ใส่ = job ข้ามพร้อม warning)
- **GHAS**: repo เป็น public จึงใช้ได้ฟรี CodeQL และ Dependency Review รันใน workflow เลย, Secret scanning + push protection เปิดอยู่แล้ว, ควรเปิด Dependabot alerts ที่ Settings → Code security
- ดู alert ของ Dependabot / Secret scanning (workflow อ่านไม่ได้): `npm run ghas:alerts`
- รายละเอียดและข้อจำกัดของแผนฟรี: [docs/tool-comparison.md](docs/tool-comparison.md)

## 4) GitHub Actions

- workflow `.github/workflows/ci.yml` มี job `Build & unit test`, `Snyk (...)`, `Aikido (...)`, `GHAS (CodeQL + Dependency Review)` และ `Report`
- ทุก tool ใช้เกณฑ์ High ขึ้นไป (Snyk `--severity-threshold=high`, Aikido `--fail-on high`, CodeQL `security-severity >= 7.0`, Dependency Review `fail-on-severity: high`)
- gate ที่บล็อก merge (`CI + Security Gate`) = unit tests + Snyk เป็นค่าเริ่มต้น เพิ่ม tool อื่นได้ด้วย `gh variable set GATE_TOOLS --body "snyk aikido ghas"` และบน PR จะเห็น status แยก `Scanner / snyk`, `Scanner / aikido`, `Scanner / ghas`
- สั่งรันเองได้ที่ tab Actions → *Run workflow* หรือ:
  ```bash
  gh workflow run ci.yml --ref demo/nextjs-vulnerable
  ```
- ให้ gate บล็อกการ merge จริง: Settings → Branches → Branch protection ของ `main` → *Require status checks* เลือก `CI + Security Gate`

## 5) Report (report.html)

ทุกครั้งที่ pipeline รันเสร็จ จะได้:
- สรุปผลบนหน้า run ของ Actions (ตาราง + รายการที่ทำให้ gate บล็อก)
- `report.html` ใน artifact ชื่อ `security-report` หน้าแรกเป็นตารางเทียบ Snyk · Aikido · GHAS ต่อประเภทการสแกน (SAST, SCA, IaC, Secrets, Container)

ดึง report ลงเครื่องตัวเอง (ถ้า pipeline ยังรันอยู่ คำสั่งจะรอจนเสร็จแล้วดาวน์โหลดให้เอง):

```bash
npm run report -- 4
```

ไม่ใส่เลข PR = ใช้ branch ปัจจุบัน ไฟล์จะอยู่ที่ `reports/pr-4/report.html` แล้วเปิดในเบราว์เซอร์ให้อัตโนมัติ

รันสแกนแบบเดียวกับ CI ในเครื่องก่อน push (Snyk รันเมื่อ `npx snyk auth` แล้ว, Aikido รันเมื่อ `export AIKIDO_API_KEY=...`, CodeQL รันบน Actions เท่านั้น):

```bash
npm run security:local
```

โฟลเดอร์ `reports/` อยู่ใน `.gitignore` แล้ว report จะไม่ติดไปกับ commit หรือ push

## เพิ่ม Checkmarx One ภายหลัง

เมื่อได้ tenant แล้ว เพิ่ม job นี้ใน `ci.yml` และใส่ secret `CX_BASE_URI`, `CX_TENANT`, `CX_CLIENT_ID`, `CX_CLIENT_SECRET`:

```yaml
  checkmarx:
    name: Checkmarx One (SAST + SCA + KICS)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: checkmarx/ast-github-action@2.3.47
        with:
          base_uri: ${{ secrets.CX_BASE_URI }}
          cx_tenant: ${{ secrets.CX_TENANT }}
          cx_client_id: ${{ secrets.CX_CLIENT_ID }}
          cx_client_secret: ${{ secrets.CX_CLIENT_SECRET }}
          scan_params: --scan-types sast,sca,kics --threshold "sast-high=1;sca-high=1;kics-high=1"
```
