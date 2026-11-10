from flask import Flask, jsonify, request

from app.db import get_conn

app = Flask(__name__)
conn = get_conn()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/users")
def search_users():
    name = request.args.get("name", "")
    # ⚠️ VULNERABLE (CWE-89 SQL Injection): user input is concatenated into SQL.
    # Try: /users?name=' OR '1'='1
    query = "SELECT name, email, role FROM users WHERE name = '" + name + "'"
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    # ⚠️ debug=True + bind 0.0.0.0 is also flagged by SAST
    app.run(host="0.0.0.0", port=5000, debug=True)
