# คู่มือทบทวนโค้ด POC (CI/CD + Security Gate)

แต่ละไฟล์ตอบ 4 คำถาม: **ทำอะไร / ทำไมเขียนแบบนี้ / มีวิธีอื่นไหม / config ตรงไหน**
ให้เปิดไฟล์จริงดูคู่กันไป แล้วลองอธิบายด้วยคำพูดตัวเองก่อนอ่านคำตอบ

---

## 1. `lib/db.ts` และ `lib/users.ts`

**ทำอะไร**
- `db.ts` สร้างฐานข้อมูล SQLite ในหน่วยความจำ (`:memory:`) ใส่ user ตัวอย่าง 3 คน ถูกสร้างครั้งแรกที่มีคนเรียกแล้วใช้ซ้ำ
- `users.ts` มีฟังก์ชัน `findUsersByName(name)` ค้นหา user ตามชื่อ

**ทำไมเขียนแบบนี้**
- ใช้ SQLite in-memory เพราะเป็นเดโม ไม่ต้องติดตั้ง database แยก รันที่ไหนก็ได้ทั้งในเครื่องและใน CI
- บน `main` / PR #5 ใช้ `prepare("... WHERE name = ?").all(name)` คือ **parameterized query**: คำสั่ง SQL ถูกส่งไปก่อน ค่า `name` ส่งตามไปทีหลังแยกกัน database จึงมองว่าเป็น "ข้อมูล" เสมอ
- บน PR #4 ใช้ `` `WHERE name = '${name}'` `` คือเอา input ไปต่อเป็นส่วนหนึ่งของคำสั่ง ใส่ `' OR '1'='1` แล้วเงื่อนไขกลายเป็นจริงทุกแถว = SQL Injection

**มีวิธีอื่นไหม**
- **ORM** เช่น Prisma, Drizzle, TypeORM: เขียนเป็น `prisma.user.findMany({ where: { name } })` ข้างในจะทำ parameterized query ให้เอง ปลอดภัยโดยปริยาย แต่ถ้าใช้ `$queryRawUnsafe` แล้วต่อ string เอง ก็กลับมาเป็นช่องโหว่ได้เหมือนเดิม
- **Query builder** เช่น Knex: `knex("users").where({ name })` ได้ผลเหมือนกัน
- **ไม่ควร**: กรองตัวอักษรเอง (ลบ `'` ทิ้ง) เพราะมักมีวิธีเลี่ยงเสมอ

**Config ตรงไหน**
- ตัว DB อยู่ใน `getDb()` ของ `lib/db.ts` ถ้าจะใช้ไฟล์จริงเปลี่ยน `":memory:"` เป็น path
- `next.config.ts` มี `serverExternalPackages: ["better-sqlite3"]` เพราะเป็น native module ห้าม Next.js bundle รวม

---

## 2. `app/api/tools/*` (ping, files, notify)

**ทำอะไร** API 3 ตัวสำหรับเดโม: ping host, อ่านไฟล์รายงาน, ส่ง webhook

| ไฟล์ | PR #4 (มีช่องโหว่) | PR #5 (แก้แล้ว) | ทำไมแบบ #5 ถึงปลอดภัย |
|---|---|---|---|
| `ping` | `` exec(`ping -c 1 ${host}`) `` | ตรวจ `isIP` / regex แล้ว `execFile("ping", ["-c","1",host])` | `exec` ส่งทั้งบรรทัดให้ shell ตีความ `;` `&&` จึงรันคำสั่งเพิ่มได้ ส่วน `execFile` ไม่ผ่าน shell argument เป็นแค่ข้อความ |
| `files` | `readFile(path.join(DIR, name))` + `text/html` | allow-list `FILES[name]` + `text/plain` | input เป็นแค่ "กุญแจ" ค้นในรายการ ไม่เคยกลายเป็น path จึงใส่ `../` ไม่ได้ และ text/plain ทำให้เบราว์เซอร์ไม่รัน HTML |
| `notify` | `axios.post(userUrl)` + ปิด TLS check + password ในโค้ด | ให้เลือก webhook จาก "ชื่อ" URL อยู่ฝั่ง server, `fetch` ปกติ, password จาก env | ผู้ใช้กำหนดปลายทางไม่ได้ จึงยิงเข้าระบบภายในไม่ได้ (SSRF) และ secret ไม่อยู่ใน git |

**มีวิธีอื่นไหม**
- ping: ใช้ library ping ที่ไม่เรียก shell หรือไม่ต้องมี feature นี้เลย (ปลอดภัยที่สุดคือไม่ทำ)
- files: เก็บไฟล์ใน object storage แล้วอ้างด้วย id, หรือใช้ `path.resolve` + เช็ก prefix (ใช้ได้ แต่ Snyk Code ไม่รู้จักว่าเป็นการป้องกัน ยังโดน flag)
- notify: allow-list ของ host ก็กัน SSRF ได้ แต่ใน POC Snyk ยังรายงานอยู่ จึงเปลี่ยนเป็นเลือกจากชื่อ

**Config ตรงไหน** รายการที่อนุญาตอยู่ในตัวไฟล์ (`FILES`, `WEBHOOKS`, `HOSTNAME_RE`) ส่วน password อ่านจาก env `WEBHOOK_PASSWORD`

---

## 3. `tests/`

**ทำอะไร** Vitest เรียก route handler ตรง ๆ ด้วย `new Request(...)` ไม่ต้องเปิด server มีทั้ง test การทำงานปกติ และ **security regression test** (ส่ง input โจมตีแล้วต้องถูกปฏิเสธ)

**ทำไมเขียนแบบนี้**
- `vi.mock("node:child_process")` แทนการรัน ping จริง: test เร็ว ไม่พึ่ง network และนับได้ว่ามีคำสั่งถูกรันหรือไม่
- ข้อความใน `expect(value, "เหตุผล")` ทำให้ตอน fail บอกสาเหตุเป็นภาษาคน (ไปโผล่ใน report ด้วย)

**ทำไมต้องมี security test ทั้งที่มี Snyk** เพราะ scanner จับไม่ครบ ใน POC Snyk Code **ไม่ได้รายงาน SQL Injection** ใน PR #4 แต่ test จับได้ และ test พิสูจน์ "พฤติกรรมจริง" ไม่ใช่แค่ pattern ในโค้ด ถ้าวันหลังมีคนแก้แล้วช่องโหว่กลับมา test จะ fail ทันที

**มีวิธีอื่นไหม** Jest (คล้ายกัน), Playwright สำหรับ test ผ่านเบราว์เซอร์จริง (จับ XSS ได้)

**Config ตรงไหน** `vitest.config.ts` (ไฟล์ที่รัน, timeout) และ `package.json` script `test`

---

## 4. `.github/workflows/ci.yml`

**ทำอะไร** pipeline 3 job:
1. **Build & unit test**: `npm ci` → test → `next build`
2. **Snyk**: SAST (Snyk Code) → SCA (Open Source) → IaC → build Docker image → Container
3. **Report**: รวมผลเป็น `report.html`, สรุปบนหน้า Actions, ส่ง check `CI + Security Gate` ไปที่ PR

**ทำไมเขียนแบบนี้**
- job 1 กับ 2 รันขนานกัน ประหยัดเวลา
- แต่ละขั้นของ Snyk มี `if: always()` เพื่อให้รันครบทุกขั้นแม้ขั้นก่อนหน้า fail จะได้เห็นปัญหาทั้งหมดในรอบเดียว
- เช็กว่ามี `SNYK_TOKEN` ก่อน ถ้าไม่มีให้ข้ามพร้อม warning แทนที่จะพัง
- `permissions: contents: read` ให้สิทธิ์ token น้อยที่สุด เพิ่ม `statuses: write` เฉพาะ job report
- job report ส่ง commit status เอง เพราะ repo นี้ Actions ไม่ trigger ตอนเปิด PR ต้องกดรันเอง (workflow_dispatch)

**gate ทำไมตั้งที่ `--severity-threshold=high`**
- บล็อกเฉพาะ High / Critical ส่วน Medium / Low แค่รายงาน กันไม่ให้ทีมโดนบล็อกจนทำงานไม่ได้ตั้งแต่วันแรก
- ถ้าเปลี่ยนเป็น `medium`: จะบล็อกมากขึ้น เช่น IaC ใน PR #4 (hostNetwork / hostPID) จะเริ่ม fail ด้วย
- ถ้าเจอ **false positive**: ใช้ไฟล์ `.snyk` ที่ root หรือคำสั่ง `snyk ignore --id=<ISSUE_ID> --reason="..." --expiry=2026-12-31` ต้องใส่เหตุผลและวันหมดอายุเสมอ และให้ AppSec review (ไม่ควรลด threshold ทั้งโปรเจกต์เพราะ issue เดียว)

**มีวิธีอื่นไหม**
- ใช้ `snyk/actions/node@master` แทนการติดตั้ง CLI เอง
- ส่งผลเป็น SARIF ขึ้น GitHub Security tab (ต้องมี GitHub Advanced Security สำหรับ private repo)
- Checkmarx: ใช้ `checkmarx/ast-github-action` กับ `--threshold "sast-high=1;sca-high=1;kics-high=1"` (ตัวอย่างอยู่ใน README)
- บังคับใช้จริงด้วย **branch protection** ให้ `CI + Security Gate` เป็น required check

**Config ตรงไหน** trigger (`on:`), threshold (flag ในแต่ละคำสั่ง snyk), secret `SNYK_TOKEN` (Settings → Secrets → Actions)

---

## 5. `Dockerfile`

**ทำอะไร** สร้าง image สำหรับรันแอป

**ทำไมเขียนแบบนี้ (PR #5 / main)**
- **multi-stage**: stage `build` มีเครื่องมือ compile (python3, make, g++ สำหรับ better-sqlite3) และ devDependencies แต่ stage สุดท้ายคัดลอกแค่ผล build (`.next/standalone`) ไป image ที่ใช้รันจึงเล็กและมีของน้อย = ช่องโหว่น้อย
- **`node:22-alpine`**: base image เล็ก OS package น้อย Snyk Container เจอ 0 รายการ
- **`USER node`**: ไม่รันเป็น root ถ้าแอปถูกเจาะ ผู้โจมตีได้สิทธิ์จำกัด
- **HEALTHCHECK**: ให้ Docker / orchestrator รู้ว่าแอปยังตอบอยู่
- PR #4 ใช้ `node:22-bullseye` (Debian 11 ที่หมดการดูแล) stage เดียว รันเป็น root: Snyk Container เจอ 31 รายการ image ใหญ่ ~2.8 GB

**alpine vs slim vs distroless**

| | ขนาด | ข้อดี | ข้อควรระวัง |
|---|---|---|---|
| `node:22-alpine` | เล็ก | package น้อย ช่องโหว่น้อย | ใช้ musl แทน glibc native module บางตัวต้อง compile เอง |
| `node:22-*-slim` (Debian) | กลาง | glibc เข้ากันได้กับเกือบทุก library | มี package มากกว่า alpine |
| distroless (`gcr.io/distroless/nodejs22`) | เล็กมาก | ไม่มี shell / package manager เลย ผู้โจมตีทำอะไรต่อยาก | debug ยาก เข้า shell ใน container ไม่ได้ |

**Config ตรงไหน** `FROM` (base image), `USER`, `ENV PORT/HOSTNAME`, `.dockerignore` (ไม่ส่ง node_modules / .git เข้า build)

---

## 6. `k8s/deployment.yaml`

**ทำอะไร** บอก Kubernetes ว่าจะรันแอปยังไง

**ทำไมเขียนแบบนี้ (main / PR #5)**
- `runAsNonRoot`, `allowPrivilegeEscalation: false`, `capabilities: drop: [ALL]`, `readOnlyRootFilesystem`: ลดสิ่งที่ผู้โจมตีทำได้ถ้าเจาะ container ได้
- `resources` limits: กันแอปตัวเดียวกิน CPU / RAM ทั้ง node
- `livenessProbe` / `readinessProbe`: restart เมื่อแอปค้าง และไม่ส่ง traffic ก่อนพร้อม
- password มาจาก `secretKeyRef` (Kubernetes Secret) ไม่เขียนลงไฟล์
- PR #4 เพิ่ม `hostNetwork` / `hostPID` และ secret แบบ plain text: Snyk IaC ให้ต่ำกว่า High เลยไม่บล็อก แต่ KICS ในเครื่องจับได้ 1 High

**มีวิธีอื่นไหม** Helm chart / Kustomize สำหรับหลาย environment, ใช้ External Secrets / Vault แทน Kubernetes Secret, บังคับกติกาตอน deploy ด้วย Pod Security Admission หรือ Kyverno / OPA

**Config ตรงไหน** `securityContext` (ระดับ pod และ container), `resources`, `env`

---

## สรุปที่ควรพูดได้ใน 1 นาที

1. ช่องโหว่ในโค้ดเกือบทั้งหมดมาจาก **เชื่อ input ของผู้ใช้แล้วใช้ตรง ๆ** วิธีแก้คือ **แยกข้อมูลออกจากคำสั่ง** (parameter, argument list, allow-list, escape)
2. **ไม่มี tool ไหนจับได้ครบ** จึงใช้หลายชั้น: test + SAST + SCA + IaC + Container (+ DAST ในอนาคต)
3. gate บล็อกที่ High ขึ้นไป ปรับได้ด้วย flag และยกเว้นเป็นรายกรณีด้วย `.snyk` พร้อมเหตุผล
4. image เล็ก + ไม่รันเป็น root + k8s securityContext ลดความเสียหายแม้แอปถูกเจาะ
