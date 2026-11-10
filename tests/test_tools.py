import subprocess

import pytest

from app import tools
from app.main import app


@pytest.fixture
def client(monkeypatch):
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="1 packets received", stderr="")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    app.config["TESTING"] = True
    c = app.test_client()
    c.calls = calls
    return c


def test_ping_valid_host(client):
    res = client.get("/tools/ping", query_string={"host": "127.0.0.1"})
    assert res.status_code == 200
    assert len(client.calls) == 1


def test_ping_command_injection_is_blocked(client):
    """Security regression: shell metacharacters must be rejected, no command run."""
    res = client.get("/tools/ping", query_string={"host": "127.0.0.1; cat /etc/passwd"})
    assert res.status_code == 400
    assert client.calls == []


def test_read_allowed_file(client):
    res = client.get("/tools/files", query_string={"name": "report.txt"})
    assert res.status_code == 200
    assert "Quarterly report" in res.get_data(as_text=True)


def test_path_traversal_is_blocked(client):
    """Security regression: ../ must not escape the files directory."""
    res = client.get("/tools/files", query_string={"name": "../db.py"})
    assert res.status_code in (400, 404)


def test_notify_rejects_untrusted_host(client):
    """Security regression: SSRF to internal addresses must be refused."""
    res = client.post("/tools/notify", json={"url": "http://169.254.169.254/latest/meta-data"})
    assert res.status_code == 400
