from flask import Flask, jsonify, request

from app.db import get_conn
from app.tools import tools_bp

app = Flask(__name__)
conn = get_conn()
app.register_blueprint(tools_bp)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/users")
def search_users():
    name = request.args.get("name", "")
    # ✅ FIXED: parameterized query, input is bound as data, never parsed as SQL.
    rows = conn.execute(
        "SELECT name, email, role FROM users WHERE name = ?", (name,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    import os

    # ✅ FIXED: no debug in code; host/port come from env (container sets APP_HOST=0.0.0.0)
    app.run(host=os.getenv("APP_HOST", "127.0.0.1"), port=int(os.getenv("APP_PORT", "5000")))
