# POC: CI/CD + Security Gate (Snyk)

โปรเจกต์ตัวอย่างสำหรับสาธิต pipeline บน **GitHub Actions** ที่สแกนโค้ดด้วย **Snyk** (SAST + SCA + IaC) และ **บล็อกอัตโนมัติ** เมื่อพบช่องโหว่ระดับ High ขึ้นไป

```
push / PR ──► Build & unit test ──┐
          └─► Snyk ───────────────┴─► Gate (High ขึ้นไป = fail) ──► merge ได้ / ถูกบล็อก
              Code | Open Source | IaC
```

> ตอนนี้ยังไม่ใช้ Checkmarx One (ต้องมี tenant แบบเสียเงิน) ถ้าจะกลับมาใช้ ดูหัวข้อ "เพิ่ม Checkmarx One ภายหลัง" ด้านล่าง

## PR เดโม

| Branch | เนื้อหา | ผลที่คาดหวัง |
|---|---|---|
| `demo/vulnerable-feature` | ฟีเจอร์ admin tools ที่มีช่องโหว่ตั้งใจใส่ไว้ | ❌ gate fail |
| `demo/secure-feature` | ฟีเจอร์เดียวกันที่เขียนอย่างปลอดภัย | ✅ gate pass |

ช่องโหว่ที่ใส่ไว้ใน `demo/vulnerable-feature`:

| ประเภท | ปัญหา | วิธีแก้ใน `demo/secure-feature` |
|---|---|---|
| SAST | Command Injection (`shell=True`) ใน `/tools/ping` | ตรวจ host + ส่ง argument เป็น list ไม่ผ่าน shell |
| SAST | Path Traversal / XSS ใน `/tools/files` | allow-list ชื่อไฟล์ + `send_from_directory` แบบ `text/plain` |
| SAST | SSRF + ปิด SSL verification ใน `/tools/notify` | อนุญาตเฉพาะ HTTPS ไปยัง host ที่กำหนด, เปิด TLS verification |
| SAST | Hardcoded password | อ่านจาก env / Kubernetes Secret |
| SCA | `urllib3==1.26.5` มี CVE | ไม่ downgrade |
| IaC | `hostNetwork` / `hostPID`, secret เป็น plain text ใน k8s | ใช้ `secretKeyRef` |

ประวัติก่อนหน้า: commit แรกของ `main` มีช่องโหว่ SQL Injection, dependency เก่า และ Dockerfile/k8s ที่ไม่ปลอดภัย ซึ่งแก้แล้วใน PR #1

## 1) รันในเครื่อง

ต้องมี Python 3 และ Docker Desktop (เครื่อง M2 ใช้ได้)

```bash
cd ~/cicd-checkmarx-poc
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
python3 -m venv .venv-tools && .venv-tools/bin/pip install -r requirements-tools.txt
```

รัน unit test (มี security regression test สำหรับ injection, traversal และ SSRF):

```bash
.venv/bin/pytest -v
```

รัน security gate แบบ open source ไม่ต้องมีบัญชี (Bandit = SAST, pip-audit = SCA, KICS = IaC ผ่าน Docker):

```bash
./scripts/local-scan-oss.sh
```

ลองสลับ branch เพื่อดูผลต่างกัน:

```bash
git checkout demo/vulnerable-feature && ./scripts/local-scan-oss.sh
```

```bash
git checkout demo/secure-feature && ./scripts/local-scan-oss.sh
```

## 2) Snyk

1. สมัคร https://snyk.io ด้วยบัญชี GitHub แล้ว import repo นี้ (ได้ dashboard + PR check `security/snyk`)
2. เปิด Snyk Code ที่ Settings → Snyk Code → Enable
3. copy token จาก Account settings (Auth Token หรือ Personal Access Token) แล้วรัน:
   ```bash
   gh secret set SNYK_TOKEN
   ```

ถ้าไม่ได้ใส่ `SNYK_TOKEN` job Snyk ใน Actions จะข้ามพร้อม warning

## 3) GitHub Actions

- workflow `.github/workflows/ci.yml` มี 2 job คือ `Build & unit test` และ `Snyk (Code + Open Source + IaC)`
- gate ใช้ `--severity-threshold=high` ในทุกขั้นของ Snyk
- สั่งรันเองได้ที่ tab Actions → *Run workflow* หรือ:
  ```bash
  gh workflow run ci.yml --ref demo/vulnerable-feature
  ```
- ให้ gate บล็อกการ merge จริง: Settings → Branches → Branch protection ของ `main` → *Require status checks* เลือก `Build & unit test` และ `Snyk (Code + Open Source + IaC)`

## เพิ่ม Checkmarx One ภายหลัง

เมื่อได้ tenant แล้ว เพิ่ม job นี้ใน `ci.yml` และใส่ secret `CX_BASE_URI`, `CX_TENANT`, `CX_CLIENT_ID`, `CX_CLIENT_SECRET` (เวอร์ชันเต็มพร้อม SARIF/report และสคริปต์ `scripts/cx-scan.sh` ดูได้ใน git history ก่อน commit "Remove Checkmarx One job for now"):

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
