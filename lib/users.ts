import { getDb, type User } from "./db";

export function findUsersByName(name: string): User[] {
  // ⚠️ VULNERABLE (CWE-89 SQL Injection): user input is concatenated into SQL.
  // Try: /api/users?name=' OR '1'='1
  return getDb()
    .prepare(`SELECT name, email, role FROM users WHERE name = '${name}'`)
    .all() as User[];
}
