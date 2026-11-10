import { getDb, type User } from "./db";

export function findUsersByName(name: string): User[] {
  // ✅ Parameterized query: input is bound as data, never parsed as SQL
  return getDb()
    .prepare("SELECT name, email, role FROM users WHERE name = ?")
    .all(name) as User[];
}
