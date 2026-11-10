import { findUsersByName } from "../lib/users";

export const dynamic = "force-dynamic";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q = "" } = await searchParams;
  const users = q ? findUsersByName(q) : [];

  return (
    <main>
      <h1>User search</h1>
      <form>
        <input name="q" defaultValue={q} placeholder="ชื่อผู้ใช้ เช่น alice" />
        <button type="submit">ค้นหา</button>
      </form>
      {q && (
        // ⚠️ VULNERABLE (CWE-79 XSS): raw query string injected as HTML
        // Try: /?q=<img src=x onerror=alert(document.cookie)>
        <p dangerouslySetInnerHTML={{ __html: "ผลการค้นหา: " + q }} />
      )}
      <ul>
        {users.map((u) => (
          <li key={u.email}>
            {u.name} ({u.email}) – {u.role}
          </li>
        ))}
      </ul>
    </main>
  );
}
