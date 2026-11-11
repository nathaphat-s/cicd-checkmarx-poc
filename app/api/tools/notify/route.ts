// ✅ SSRF prevention: the client picks a webhook by NAME; the URL itself is fixed server-side.
//    User input is only a lookup key and never becomes part of the request URL.
const WEBHOOKS: Record<string, string> = {
  deploy: "https://hooks.example.com/deploy",
  alerts: "https://hooks.example.com/alerts",
};

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as { target?: unknown };
  const target = typeof body.target === "string" ? body.target : "";
  const url = Object.hasOwn(WEBHOOKS, target) ? WEBHOOKS[target] : undefined;
  if (!url) {
    return Response.json({ error: "unknown webhook" }, { status: 400 });
  }

  // ✅ Secret comes from the environment / secret manager, never from source code
  const password = process.env.WEBHOOK_PASSWORD;
  if (!password) {
    return Response.json({ error: "webhook not configured" }, { status: 503 });
  }

  // ✅ Native fetch keeps TLS verification on; no redirects; timeout
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password }),
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  return Response.json({ status: res.status });
}
