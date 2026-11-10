# POC: CI/CD + Checkmarx Security Gate

โปรเจกต์ตัวอย่างสำหรับสาธิต pipeline บน **GitHub Actions** ที่สแกนโค้ดด้วย **Checkmarx One** (SAST + SCA + KICS) และ **บล็อก PR อัตโนมัติ** เมื่อพบช่องโหว่ระดับ High

```
push / PR ──► Build & unit test ──┐
          └─► Checkmarx One ──────┴─► Threshold gate (High ≥ 1 = fail) ──► merge ได้ / ถูกบล็อก
              SAST | SCA | KICS
```

## Git history ที่เตรียมไว้

| Branch | เนื้อหา | ผลที่คาดหวัง |
|---|---|---|
| `main` | แอปที่มีช่องโหว่ตั้งใจใส่ไว้ | ❌ gate fail |
| `fix/security-findings` | แก้ทุกจุดแล้ว | ✅ gate pass |

ช่องโหว่ที่ใส่ไว้ใน `main`:

| ประเภท | ไฟล์ | ปัญหา | วิธีแก้ใน fix branch |
|---|---|---|---|
| SAST | `app/main.py` | SQL Injection (CWE-89) ต่อ string เข้า SQL | parameterized query (`?`) |
| SAST | `app/main.py` | `debug=True` + bind `0.0.0.0` | อ่านจาก env, default `127.0.0.1` |
| SCA | `requirements.txt` | `requests==2.25.0`, `flask==3.1.0` มี CVE | อัปเป็น `requests==2.34.2`, `flask==3.1.3` |
| KICS | `Dockerfile` | `python:latest`, รันเป็น root, ไม่มี HEALTHCHECK | pin `3.12-slim`, non-root, HEALTHCHECK |
| KICS | `k8s/deployment.yaml` | `privileged: true`, privilege escalation | securityContext แบบ hardened |

## 1) รันในเครื่อง (ไม่ต้องมี Checkmarx tenant)

ต้องมี Python 3 และ Docker Desktop (เครื่อง M2 ใช้ได้)

```bash
cd ~/cicd-checkmarx-poc
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
python3 -m venv .venv-tools && .venv-tools/bin/pip install -r requirements-tools.txt
```

ลองโจมตี SQL Injection บน `main`:

```bash
git checkout main
.venv/bin/python -m app.main
```

เปิดอีก terminal:

```bash
curl "http://127.0.0.1:5000/users?name=alice"
curl "http://127.0.0.1:5000/users?name='%20OR%20'1'='1"
```

คำสั่งที่สองจะคืนข้อมูล user **ทุกคน** (ช่องโหว่ทำงาน) ถ้ารันบน `fix/security-findings` จะได้ `[]`

รัน unit test และ security gate แบบ open-source (Bandit = SAST, pip-audit = SCA, KICS = IaC ซึ่งเป็น engine เดียวกับใน Checkmarx One):

```bash
.venv/bin/pytest -v
```

```bash
./scripts/local-scan-oss.sh
```

ผลบน `main`: test `test_sql_injection_is_blocked` fail และ gate ขึ้น `❌ GATE FAILED`
สลับไป `git checkout fix/security-findings` แล้ว `.venv/bin/pip install -r requirements-dev.txt` จากนั้นรันซ้ำ จะได้ `3 passed` และ `✅ GATE PASSED`

## 2) สแกนด้วย Checkmarx One จากเครื่อง (ต้องมี tenant)

สร้าง OAuth Client ใน Checkmarx One (Identity and Access Management → OAuth Clients) ให้มีสิทธิ์ `ast-scanner` แล้ว:

```bash
export CX_BASE_URI="https://ast.checkmarx.net"   # หรือ region ของคุณ เช่น https://eu.ast.checkmarx.net
export CX_TENANT="<tenant-name>"
export CX_CLIENT_ID="<client-id>"
export CX_CLIENT_SECRET="<client-secret>"
./scripts/cx-scan.sh
```

สคริปต์ใช้ Docker image `checkmarx/ast-cli` (ไม่ต้องติดตั้ง cx CLI เอง) และใช้ threshold เดียวกับใน CI รายงาน HTML อยู่ที่ `cx-report/`

## 3) ต่อเข้า GitHub Actions

1. สร้าง repo (private ก็ได้) แล้ว push ทั้งสอง branch:
   ```bash
   gh repo create cicd-checkmarx-poc --private --source . --push
   ```
   ```bash
   git push -u origin fix/security-findings
   ```
2. ใส่ secrets ที่ Settings → Secrets and variables → Actions: `CX_BASE_URI`, `CX_TENANT`, `CX_CLIENT_ID`, `CX_CLIENT_SECRET`
   ```bash
   gh secret set CX_CLIENT_SECRET
   ```
3. เปิด PR จาก `fix/security-findings` → `main` แล้วดูผลใน tab **Actions**
4. ตั้ง Branch protection ให้ `main` (Settings → Branches) ติ๊ก *Require status checks* เลือก `Checkmarx One (SAST + SCA + KICS)` และ `Build & unit test` เพื่อให้ gate บล็อกการ merge จริง

> ถ้ายังไม่ได้ใส่ secrets job Checkmarx จะข้ามพร้อม warning (ไม่ fail) ส่วน unit test ยังรันตามปกติ

**เดโม "ถูกบล็อก":** หลังตั้ง secrets แล้ว ให้กด *Run workflow* บน `main` (workflow_dispatch) หรือสร้าง branch ใหม่จาก commit แรกแล้วเปิด PR จะเห็น job Checkmarx fail เพราะเจอ High

## ไฟล์สำคัญ

- `.github/workflows/ci.yml` — pipeline: test + Checkmarx (`checkmarx/ast-github-action@2.3.47`), threshold `sast-high=1;sca-high=1;kics-high=1`, ส่ง SARIF ไป Security tab และเก็บรายงานเป็น artifact
- `scripts/cx-scan.sh` — สแกน Checkmarx One จากเครื่อง
- `scripts/local-scan-oss.sh` — gate แบบ open-source ไม่ต้องมี tenant
- `tests/test_app.py` — มี security regression test สำหรับ SQL Injection

## หมายเหตุ

- การอัป SARIF ไป Security tab ของ private repo ต้องมี GitHub Advanced Security ถ้าไม่มี step นั้นจะข้ามไป (`continue-on-error`) แต่รายงานยังดูได้ใน artifact และ PR comment จาก Checkmarx
- ปรับความเข้มของ gate ได้ที่ `--threshold` เช่น `sast-high=1;sast-medium=5`

## ทางเลือก: ใช้ Snyk (ระหว่างยังไม่มี Checkmarx tenant)

workflow มี job `Snyk (Code + Open Source + IaC)` ที่ใช้ gate แบบเดียวกัน (High ขึ้นไป = fail)

1. สมัคร https://snyk.io ด้วยบัญชี GitHub แล้ว import repo นี้
2. เปิด Snyk Code ที่ Settings → Snyk Code → Enable
3. copy token จาก Account settings (Auth Token หรือ Personal Access Token) แล้วรัน `gh secret set SNYK_TOKEN`

ถ้าไม่ได้ใส่ `SNYK_TOKEN` job นี้จะข้ามพร้อม warning
