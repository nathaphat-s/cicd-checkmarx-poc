"""Admin tools: ping a host and read a report file.

✅ SECURE version of the same feature as the demo/vulnerable-feature branch.
"""
import ipaddress
import os
import re
import subprocess
from urllib.parse import urlparse

import requests
from flask import Blueprint, abort, jsonify, request

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")

FILES_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
ALLOWED_WEBHOOK_HOSTS = {"hooks.example.com"}


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


@tools_bp.get("/ping")
def ping():
    host = request.args.get("host", "")
    # ✅ strict allow-list validation + argument list, no shell
    if not _valid_host(host):
        abort(400, "invalid host")
    result = subprocess.run(  # nosec B603 B607 - fixed binary, validated argument, no shell
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5
    )
    return jsonify({"host": host, "output": result.stdout})


@tools_bp.get("/files")
def read_file():
    name = request.args.get("name", "")
    # ✅ resolve the real path and make sure it stays inside FILES_DIR
    path = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([path, FILES_DIR]) != FILES_DIR:
        abort(400, "invalid file name")
    if not os.path.isfile(path):
        abort(404)
    with open(path) as f:
        return f.read()


@tools_bp.post("/notify")
def notify():
    url = (request.get_json(silent=True) or {}).get("url", "")
    parsed = urlparse(url)
    # ✅ only HTTPS to an allow-listed host (prevents SSRF); TLS verification stays on
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_WEBHOOK_HOSTS:
        abort(400, "webhook host not allowed")
    # ✅ secret comes from the environment / secret manager, never from source code
    password = os.environ.get("WEBHOOK_PASSWORD")
    if not password:
        abort(503, "webhook not configured")
    r = requests.post(url, json={"password": password}, timeout=5)
    return jsonify({"status": r.status_code})
