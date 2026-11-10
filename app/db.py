import sqlite3

SEED_USERS = [
    ("alice", "alice@example.com", "admin"),
    ("bob", "bob@example.com", "user"),
    ("carol", "carol@example.com", "user"),
]


def get_conn(path=":memory:"):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, email TEXT, role TEXT)")
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany("INSERT INTO users VALUES (?, ?, ?)", SEED_USERS)
        conn.commit()
    return conn
