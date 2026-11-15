// ⚠️ DEMO (SAST): Open Redirect (CWE-601)
// Redirects to whatever URL the user passes, so attackers can make a trusted link
// on our domain send people to a phishing site.
// Try: /api/go?to=https://evil.example.com
export function GET(req: Request) {
  const to = new URL(req.url).searchParams.get("to") ?? "/";
  return Response.redirect(to, 302);
}
