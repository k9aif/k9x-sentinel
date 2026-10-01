# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
import pytest
from fastapi.testclient import TestClient

from sentinel import api, runner


SCRIPT = {"X-Sentinel-Client": "test"}


@pytest.fixture
def client(monkeypatch):
    from sentinel import auth
    auth._fails.clear()
    auth._locked.clear()
    monkeypatch.setattr(runner, "start_scheduler", lambda: None)
    with TestClient(api.app) as c:
        yield c


def test_health_is_open(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_everything_else_needs_the_login(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    for path in ("/api/status", "/api/items", "/api/items/1"):
        r = client.get(path)
        assert r.status_code == 401 and "www-authenticate" not in r.headers   # never the browser popup
        assert client.get(path, auth=("admin", "wrong"), headers=SCRIPT).status_code == 401
    assert client.post("/api/run", json={}).status_code == 401
    assert client.get("/api/items", auth=("admin", "s3cret"), headers=SCRIPT).status_code == 200


def test_no_password_disables_the_ui(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "")
    assert client.get("/api/items", auth=("admin", "")).status_code == 503


def test_public_pages_reveal_no_findings(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    page = client.get("/")
    assert page.status_code == 200 and "SIGN IN TO K9X SENTINEL" in page.text and "/api/items" not in page.text
    about = client.get("/about")
    assert about.status_code == 200 and "another AI" in about.text
    for path in ("/logo.svg", "/architecture.svg"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")


def test_sign_in_sets_a_session_that_opens_the_app(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    assert client.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401
    r = client.post("/api/login", json={"username": "admin", "password": "s3cret"})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert 'data-view="architecture"' in client.get("/").text        # the app, not the sign-in page
    assert client.get("/api/items").status_code == 200
    client.post("/api/logout")
    assert client.get("/api/items").status_code == 401


def test_tampered_or_stale_sessions_are_refused(client, monkeypatch):
    from sentinel import auth
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    good = auth.issue("admin")
    assert auth.verify(good) == "admin"
    assert auth.verify(good.replace("admin", "root", 1)) is None
    assert auth.verify(auth.issue("admin", now=1.0)) is None             # expired
    monkeypatch.setenv("SENTINEL_PASSWORD", "changed")
    assert auth.verify(good) is None                                      # password change ends sessions


def test_repeated_failures_lock_the_address(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    for _ in range(5):
        client.post("/api/login", json={"username": "admin", "password": "bad"})
    r = client.post("/api/login", json={"username": "admin", "password": "s3cret"})
    assert r.status_code == 429


def test_sign_out_wins_over_remembered_browser_basic_credentials(client, monkeypatch):
    """A browser that used the old Basic popup resends those credentials by
    itself. Without the script header they must not sign it back in."""
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    client.post("/api/login", json={"username": "admin", "password": "s3cret"})
    client.post("/api/logout")
    page = client.get("/", auth=("admin", "s3cret"))
    assert "SIGN IN TO K9X SENTINEL" in page.text
    assert client.get("/api/items", auth=("admin", "s3cret")).status_code == 401
    assert client.get("/api/items", auth=("admin", "s3cret"), headers=SCRIPT).status_code == 200
