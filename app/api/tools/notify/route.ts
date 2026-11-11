import https from "node:https";
import axios from "axios";
import _ from "lodash";

// ⚠️ VULNERABLE (CWE-798): hardcoded credential committed to source control
const WEBHOOK_PASSWORD = "SuperSecret123!";

// ⚠️ VULNERABLE (CWE-918 SSRF + CWE-295 TLS verification disabled + prototype pollution via
// an outdated lodash.merge). Try POST {"url": "http://169.254.169.254/latest/meta-data"}
export async function POST(req: Request) {
  const body = await req.json();
  const opts = _.merge({ url: "", timeout: 2000 }, body);
  const res = await axios.post(
    opts.url,
    { password: WEBHOOK_PASSWORD },
    { timeout: opts.timeout, httpsAgent: new https.Agent({ rejectUnauthorized: false }) },
  );
  return Response.json({ status: res.status });
}
