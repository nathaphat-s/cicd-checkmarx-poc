import { readFile } from "node:fs/promises";
import path from "node:path";

const FILES_DIR = path.join(process.cwd(), "data", "files");

// ⚠️ VULNERABLE (CWE-22 Path Traversal + CWE-79 XSS): "../" escapes FILES_DIR,
// and the file content is served as HTML.
// Try: /api/tools/files?name=../../package.json
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  try {
    const content = await readFile(path.join(FILES_DIR, name), "utf8");
    return new Response(content, { headers: { "content-type": "text/html" } });
  } catch {
    return new Response("not found", { status: 404 });
  }
}
