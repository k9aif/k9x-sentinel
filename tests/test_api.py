# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
import pytest
from fastapi.testclient import TestClient

from sentinel import api, runner


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(runner, "start_scheduler", lambda: None)
    with TestClient(api.app) as c:
        yield c


def test_health_is_open(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_everything_else_needs_the_login(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "s3cret")
    for path in ("/", "/api/status", "/api/items", "/api/items/1"):
        assert client.get(path).status_code == 401
        assert client.get(path, auth=("admin", "wrong")).status_code == 401
    assert client.post("/api/run", json={}).status_code == 401
    assert client.get("/api/items", auth=("admin", "s3cret")).status_code == 200


def test_no_password_disables_the_ui(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "")
    assert client.get("/api/items", auth=("admin", "")).status_code == 503
