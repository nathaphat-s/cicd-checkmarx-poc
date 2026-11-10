import Database from "better-sqlite3";

export type User = { name: string; email: string; role: string };

const SEED: User[] = [
  { name: "alice", email: "alice@example.com", role: "admin" },
  { name: "bob", email: "bob@example.com", role: "user" },
  { name: "carol", email: "carol@example.com", role: "user" },
];

let db: Database.Database | undefined;

export function getDb(): Database.Database {
  if (!db) {
    db = new Database(":memory:");
    db.exec("CREATE TABLE users (name TEXT, email TEXT, role TEXT)");
    const insert = db.prepare("INSERT INTO users VALUES (@name, @email, @role)");
    for (const u of SEED) insert.run(u);
  }
  return db;
}
