import pytest

from app.main import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    assert client.get("/health").json == {"status": "ok"}


def test_search_existing_user(client):
    res = client.get("/users", query_string={"name": "alice"})
    assert res.status_code == 200
    assert [u["name"] for u in res.json] == ["alice"]


def test_sql_injection_is_blocked(client):
    """Security regression test: payload must NOT dump every user."""
    res = client.get("/users", query_string={"name": "' OR '1'='1"})
    assert res.status_code == 200
    assert res.json == []
