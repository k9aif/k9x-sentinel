# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""An approved finding becomes a Jira ticket assigned to its owner (the work item), and each run reads the
ticket's status back. No network: the framework's HttpApiAdapter endpoint call is replaced."""

import asyncio

import pytest
from k9_aif_abb.k9_adapters.integration.http_api_adapter import HttpApiAdapter

from sentinel import jira_tickets, store
from tests.test_flow import FakeBus, article, build, model  # noqa: F401 (model is a fixture)


def _item(**assessment):
    a = {"verdict": "gap", "severity": "critical", "confidence": 0.95, "taxonomy": ["ASI02"],
         "threat": "Agentic pentest framework abused", "rationale": "No control covers it.",
         "suggested_fix": "Add a check.", "matched_capabilities": []}
    a.update(assessment)
    item_id = article()
    store.update_item(item_id, assessment=a, verdict=a["verdict"], severity=a["severity"])
    return store.get_item(item_id)


@pytest.fixture
def live(monkeypatch):
    for k, v in {"SENTINEL_JIRA_MODE": "live", "SENTINEL_JIRA_URL": "https://k9x.atlassian.net",
                 "SENTINEL_JIRA_EMAIL": "owner@example.com", "SENTINEL_JIRA_TOKEN": "t0ken",
                 "SENTINEL_JIRA_PROJECT": "SEC"}.items():
        monkeypatch.setenv(k, v)
    calls = []

    def endpoint(self, url, method, headers, body):
        calls.append({"url": url, "method": method, "headers": headers, "body": body,
                      "allowed": self.config.get("allowed_hosts")})
        if url.endswith("/myself"):
            return {"accountId": "acc-owner"}
        if url.endswith("/rest/api/2/issue"):
            return {"key": "SEC-7", "id": "10007"}
        if "/rest/api/2/issue/SEC-7" in url:
            return {"fields": {"status": {"name": "Done", "statusCategory": {"key": "done"}}}}
        raise AssertionError(url)
    monkeypatch.setattr(HttpApiAdapter, "call_endpoint", endpoint)
    return calls


def test_dry_run_records_the_request_and_sends_nothing(monkeypatch):
    monkeypatch.setattr(HttpApiAdapter, "call_endpoint", lambda *a, **k: pytest.fail("no request in dry_run"))
    out = jira_tickets.create(_item(), "1.27.0")
    assert out["mode"] == "dry_run"
    fields = out["request"]["json"]["fields"]
    assert fields["summary"].startswith("[Sentinel #") and "critical" in fields["summary"]
    assert "Definition of done" in fields["description"] and "capabilities.yaml" in fields["description"]
    assert "k9x-sentinel" in fields["labels"] and "severity-critical" in fields["labels"]


def test_live_creates_a_ticket_assigned_to_the_token_owner(live):
    out = jira_tickets.create(_item(), "1.27.0")
    assert out == {"mode": "live", "ok": True, "key": "SEC-7", "url": "https://k9x.atlassian.net/browse/SEC-7",
                   "assignee": "acc-owner", "status": "To Do"}
    post = [c for c in live if c["method"] == "POST"][0]
    assert post["body"]["json"]["fields"]["assignee"] == {"accountId": "acc-owner"}
    assert post["body"]["json"]["fields"]["project"] == {"key": "SEC"}
    assert post["headers"]["Authorization"].startswith("Basic ")
    assert all(c["allowed"] == ["k9x.atlassian.net"] for c in live)       # only the Jira host is reachable


def test_a_jira_failure_is_recorded_not_raised(live, monkeypatch):
    def down(self, url, method, headers, body):
        raise ConnectionError("jira down")
    monkeypatch.setattr(HttpApiAdapter, "call_endpoint", down)
    monkeypatch.setenv("SENTINEL_JIRA_ASSIGNEE", "acc-owner")
    out = jira_tickets.create(_item(), "1.27.0")
    assert out["ok"] is False and "jira down" in out["error"]


def test_approval_in_hil_creates_the_ticket(shield_only, model, live):
    """Property: approving a finding in K9X HIL produces a work item assigned to the owner, recorded with the
    finding and in the audit trail."""
    bus = FakeBus()
    router = build(bus)
    out = router.route({"event_type": "sentinel.assess", "item_id": article()})
    asyncio.run(router._on_hil_reply({"correlation_id": out["correlation_id"], "action": "complete",
                                      "actor": "ravinata", "status": "completed"}))
    it = store.get_item(out["item_id"])
    assert it["status"] == "decided" and it["data"]["jira"]["key"] == "SEC-7"
    assert "jira_ticket" in [e["event"] for e in store.item_audit(it["id"])]


def test_rejected_finding_creates_no_ticket(shield_only, model, live):
    router = build(FakeBus())
    out = router.route({"event_type": "sentinel.assess", "item_id": article()})
    asyncio.run(router._on_hil_reply({"correlation_id": out["correlation_id"], "action": "reject", "actor": "r"}))
    assert "jira" not in (store.get_item(out["item_id"])["data"] or {})


def test_each_run_reads_the_ticket_status_back(live):
    it = _item()
    store.update_item(it["id"], status="decided", data={"jira": {"mode": "live", "ok": True, "key": "SEC-7",
                                                                  "status": "To Do"}})
    assert jira_tickets.sync() == {"checked": 1, "done": 1, "changed": 1}
    t = store.get_item(it["id"])["data"]["jira"]
    assert t["status"] == "Done" and t["done"] is True
    assert jira_tickets.sync()["checked"] == 0                              # done tickets aren't re-read
