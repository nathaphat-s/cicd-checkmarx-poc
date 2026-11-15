// ⚠️ DEMO (SAST): Code Injection (CWE-94)
// A "calculator" endpoint that evaluates the user's expression with eval().
// Try: /api/calc?expr=1+2   (works)
//      /api/calc?expr=process.env   (leaks every environment variable / secret)
export function GET(req: Request) {
  const expr = new URL(req.url).searchParams.get("expr") ?? "0";
  // eslint-disable-next-line no-eval
  const result = eval(expr);
  return Response.json({ expr, result });
}
