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
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    page = client.get("/login")
    assert page.status_code == 200 and "SIGN IN TO K9X SENTINEL" in page.text and "/api/items" not in page.text
    assert page.headers["cache-control"] == "no-store"
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
    assert "httponly" in cookie and "samesite=lax" in cookie
    app_page = client.get("/")
    assert 'data-view="architecture"' in app_page.text                  # the app, not the sign-in page
    assert app_page.headers["cache-control"] == "no-store"
    assert client.get("/login", follow_redirects=False).headers["location"] == "/"
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


def test_live_activity_feed(client, monkeypatch):
    from sentinel import activity
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    assert client.get("/api/activity").status_code == 401
    start = activity.current()["last_seq"]
    activity.emit("sources", "Connecting to OSV …", source="osv_dependencies")
    activity.emit("compare", "verdict: gap · high · confidence 0.9", "error", item=7)
    client.post("/api/login", json={"username": "admin", "password": "s3cret"})
    d = client.get(f"/api/activity?since={start}").json()
    assert [e["msg"] for e in d["events"]] == ["Connecting to OSV …", "verdict: gap · high · confidence 0.9"]
    assert d["current"]["stage"] == "compare" and d["current"]["item"] == 7
    assert client.get(f"/api/activity?since={d['current']['last_seq']}").json()["events"] == []



@pytest.fixture
def demo_on(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    monkeypatch.setenv("SENTINEL_DEMO_USER", "demo")
    monkeypatch.setenv("SENTINEL_DEMO_PASSWORD", "demo")


def _seed():
    from sentinel import store
    gap = store.add_item({"uid": "d:1", "source": "willison_prompt_injection", "kind": "article",
                          "title": "Secret technique X", "link": "https://example.com/x"})
    store.update_item(gap, verdict="gap", severity="high", status="pending_hil", correlation_id="c-x",
                      assessment={"verdict": "gap", "severity": "high", "threat": "how X works",
                                  "suggested_fix": "add check Y", "rationale": "no control"},
                      content="full article about X")
    store.audit("raised_to_hil", gap, correlation_id="c-x", priority="high")
    cov = store.add_item({"uid": "d:2", "source": "owasp_genai", "kind": "article", "title": "Known injection"})
    store.update_item(cov, verdict="covered", severity="medium", status="assessed",
                      assessment={"verdict": "covered", "rationale": "Shield + Guardian stop it"})
    return gap, cov


def test_demo_login_is_shown_and_read_only(client, demo_on):
    assert client.get("/api/public").json()["demo"] == {"user": "demo", "password": "demo"}
    assert client.post("/api/login", json={"username": "demo", "password": "demo"}).status_code == 200
    assert client.get("/api/me").json() == {"user": "demo", "role": "viewer"}
    assert client.post("/api/run", json={}).status_code == 403
    assert client.get("/api/audit.csv").status_code == 403
    assert client.get("/api/status").json()["database"]["where"] == "hidden"


def test_demo_never_sees_an_open_gap(client, demo_on):
    gap, cov = _seed()
    client.post("/api/login", json={"username": "demo", "password": "demo"})
    rows = {r["id"]: r for r in client.get("/api/items").json()}
    assert rows[gap]["title"] == "Finding under private review" and rows[gap]["verdict"] == "gap"
    assert rows[cov]["title"] == "Known injection"                                     # covered: shown
    body = client.get(f"/api/items/{gap}").text
    for secret in ("Secret technique X", "how X works", "add check Y", "full article", "example.com/x"):
        assert secret not in body
    assert "Shield + Guardian stop it" in client.get(f"/api/items/{cov}").text
    assert client.get(f"/api/items/{gap}/audit").json() == []
    hil = client.get("/api/hil").text
    assert "Secret technique X" not in hil and "under private review" in hil


def test_demo_live_log_hides_titles(client, demo_on):
    from sentinel import activity
    start = activity.current()["last_seq"]
    activity.emit("screen", "#9 Secret technique X", item=9)
    activity.emit("compare", "verdict: gap · high · confidence 0.9 · controls: shield.prompt_injection", "error", item=9)
    client.post("/api/login", json={"username": "demo", "password": "demo"})
    msgs = [e["msg"] for e in client.get(f"/api/activity?since={start}").json()["events"]]
    assert msgs == ["screening an item with Shield + Guardian", "verdict: gap · high · confidence 0.9"]


def test_admin_still_sees_everything(client, demo_on):
    gap, _ = _seed()
    client.post("/api/login", json={"username": "admin", "password": "s3cret"})
    assert client.get("/api/me").json()["role"] == "admin"
    assert "Secret technique X" in client.get(f"/api/items/{gap}").text


def test_demo_off_by_default(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    monkeypatch.setenv("SENTINEL_DEMO_PASSWORD", "")
    assert client.get("/api/public").json()["demo"] is None
    assert client.post("/api/login", json={"username": "demo", "password": ""}).status_code == 401


def test_feed_endpoints_are_public_but_infrastructure_is_not(client):
    srcs = client.get("/api/public").json()["sources"]
    assert any(s["url"].startswith("https://www.zscaler.com/") for s in srcs)
    body = client.get("/api/public").text
    for private in ("11434", "9092", "5432", "POSTGRES", "password\": \"s3cret"):
        assert private not in body
