import { execFile } from "node:child_process";
import { isIP } from "node:net";

const HOSTNAME_RE =
  /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

// ✅ Strict validation + execFile with an argument list (no shell involved)
export async function GET(req: Request) {
  const host = new URL(req.url).searchParams.get("host") ?? "";
  if (!isIP(host) && !HOSTNAME_RE.test(host)) {
    return Response.json({ error: "invalid host" }, { status: 400 });
  }
  const output = await new Promise<string>((resolve) =>
    execFile("ping", ["-c", "1", host], { timeout: 5000 }, (_err, stdout) => resolve(stdout)),
  );
  return Response.json({ host, output });
}
