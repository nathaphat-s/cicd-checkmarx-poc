// ✅ Only HTTPS to an allow-listed host (prevents SSRF); TLS verification stays on (default fetch)
const ALLOWED_WEBHOOK_HOSTS = new Set(["hooks.example.com"]);

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as { url?: unknown };
  let url: URL;
  try {
    url = new URL(String(body.url ?? ""));
  } catch {
    return Response.json({ error: "invalid url" }, { status: 400 });
  }
  if (url.protocol !== "https:" || !ALLOWED_WEBHOOK_HOSTS.has(url.hostname)) {
    return Response.json({ error: "webhook host not allowed" }, { status: 400 });
  }

  // ✅ Secret comes from the environment / secret manager, never from source code
  const password = process.env.WEBHOOK_PASSWORD;
  if (!password) {
    return Response.json({ error: "webhook not configured" }, { status: 503 });
  }

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password }),
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  return Response.json({ status: res.status });
}
