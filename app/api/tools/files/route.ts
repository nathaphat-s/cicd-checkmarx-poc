import { readFile } from "node:fs/promises";
import path from "node:path";

// ✅ Allow-list of known files: user input is only used as a lookup key, never as a path
const FILES: Record<string, string> = {
  "report.txt": path.join(process.cwd(), "data", "files", "report.txt"),
  "readme.txt": path.join(process.cwd(), "data", "files", "readme.txt"),
};

export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  const file = Object.hasOwn(FILES, name) ? FILES[name] : undefined;
  if (!file) {
    return new Response("not found", { status: 404 });
  }
  // ✅ Served as plain text with nosniff, so the browser never renders it as HTML
  return new Response(await readFile(file, "utf8"), {
    headers: { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" },
  });
}
