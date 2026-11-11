import { exec } from "node:child_process";

// ⚠️ VULNERABLE (CWE-78 OS Command Injection): user input goes straight into a shell.
// Try: /api/tools/ping?host=127.0.0.1;cat /etc/passwd
export async function GET(req: Request) {
  const host = new URL(req.url).searchParams.get("host") ?? "";
  const output = await new Promise<string>((resolve) =>
    exec(`ping -c 1 ${host}`, (_err, stdout) => resolve(stdout)),
  );
  return Response.json({ host, output });
}
