"""Admin tools: ping a host and read a report file.

⚠️ DEMO: this version is intentionally INSECURE so the security scan has something to catch.
"""
import os
import subprocess

import requests
from flask import Blueprint, abort, jsonify, request

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

# ⚠️ CWE-798: hardcoded credential committed to source control
WEBHOOK_PASSWORD = "SuperSecret123!"


@tools_bp.get("/ping")
def ping():
    host = request.args.get("host", "")
    # ⚠️ CWE-78 OS command injection: user input goes straight into a shell
    result = subprocess.run(
        "ping -c 1 " + host, shell=True, capture_output=True, text=True
    )
    return jsonify({"host": host, "output": result.stdout})


@tools_bp.get("/files")
def read_file():
    name = request.args.get("name", "")
    # ⚠️ CWE-22 path traversal: "../" escapes FILES_DIR
    path = os.path.join(FILES_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    with open(path) as f:
        return f.read()


@tools_bp.post("/notify")
def notify():
    url = request.json.get("url")
    # ⚠️ CWE-918 SSRF + CWE-295 TLS verification disabled
    r = requests.post(url, json={"password": WEBHOOK_PASSWORD}, verify=False, timeout=5)
    return jsonify({"status": r.status_code})
