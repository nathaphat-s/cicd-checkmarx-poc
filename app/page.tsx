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
        // ✅ React escapes {q} automatically, so HTML in the query is shown as text
        <p>ผลการค้นหา: {q}</p>
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
