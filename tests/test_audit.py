# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""The audit trail: append-only, hash-chained, and the HIL history built from it."""

import time

import pytest
from sqlalchemy import text

from sentinel import store
from tests.test_flow import model  # noqa: F401  (fixture)


def test_events_chain_and_verify():
    store.audit("run_started", run_id=1)
    item_id = store.add_item({"uid": "a:1", "source": "s", "kind": "article", "title": "T"})
    store.audit("assessed", item_id, verdict="gap", severity="high")
    events = store.item_audit(item_id)
    assert [e["event"] for e in events] == ["item_collected", "assessed"]
    assert events[1]["prev_hash"] == events[0]["hash"]
    assert store.verify_chain() == {"ok": True, "events": 3, "broken_at": None}


def test_database_refuses_updates_and_deletes():
    store.audit("signed_in", actor="admin")
    eng = store._engine()
    for sql in ("UPDATE audit_events SET actor='someone-else'", "DELETE FROM audit_events"):
        with pytest.raises(Exception, match="append-only"):
            with eng.begin() as con:
                con.execute(text(sql))
    assert store.audit_events()[0]["actor"] == "admin"


def test_tampering_behind_the_trigger_is_detected():
    store.audit("signed_in", actor="admin")
    store.audit("run_requested", actor="admin")
    with store._engine().begin() as con:            # an attacker with DB access drops the guard
        con.execute(text("DROP TRIGGER audit_events_no_update"))
        con.execute(text("UPDATE audit_events SET actor='intruder' WHERE id=1"))
    assert store.verify_chain() == {"ok": False, "events": 1, "broken_at": 1}


def test_hil_history_reports_waiting_overdue_and_decisions():
    now = time.time()
    a = store.add_item({"uid": "h:1", "source": "threatlabz", "kind": "article", "title": "Waiting one"})
    b = store.add_item({"uid": "h:2", "source": "osv", "kind": "dependency", "title": "Decided one"})
    store.update_item(a, status="pending_hil", verdict="gap", severity="high", correlation_id="c-a")
    store.update_item(b, status="decided", verdict="gap", severity="medium", correlation_id="c-b")
    store.audit("raised_to_hil", a, correlation_id="c-a", priority="high", topic="hil.requests.x")
    store.audit("raised_to_hil", b, correlation_id="c-b", priority="medium", topic="hil.requests.x")
    store.audit("decision_ignored_unauthorized", b, actor="demo@k9x.ai", action="complete")
    store.audit("decision_received", b, actor="ravinatarajan@k9x.ai", outcome="rejected", comment="already fixed in 1.14")
    cases = {c["id"]: c for c in store.hil_history(overdue_days=7, now=now + 9 * 86400)}
    assert cases[a]["waiting_days"] >= 9 and cases[a]["overdue"] and cases[a]["outcome"] is None
    assert cases[b]["outcome"] == "rejected" and cases[b]["decided_by"] == "ravinatarajan@k9x.ai"
    assert cases[b]["comment"] == "already fixed in 1.14" and cases[b]["waiting_days"] is None
    assert cases[b]["ignored"][0]["actor"] == "demo@k9x.ai"
    fresh = {c["id"]: c for c in store.hil_history(overdue_days=7, now=now + 86400)}
    assert not fresh[a]["overdue"]


def test_full_round_trip_is_in_the_audit_trail(shield_only, model):
    import asyncio
    from tests.test_flow import FakeBus, article, build
    router = build(FakeBus())
    out = router.route({"event_type": "sentinel.assess", "item_id": article()})
    asyncio.run(router._on_hil_reply({"correlation_id": out["correlation_id"], "action": "complete",
                                      "actor": "ravinatarajan@k9x.ai", "comment": "ship a check"}))
    events = [e["event"] for e in store.item_audit(out["item_id"])]
    assert events == ["item_collected", "screened", "assessed", "raised_to_hil", "decision_received", "github_action"]
    assessed = store.item_audit(out["item_id"])[2]["detail"]
    assert assessed["model"] and assessed["framework_version"] and len(assessed["text_sha256"]) == 64
    assert store.verify_chain()["ok"]



def test_cases_raised_before_the_audit_trail_still_show():
    i = store.add_item({"uid": "old:1", "source": "s", "kind": "article", "title": "Old case"})
    # raised by an older Sentinel: a case id and status, but no raised_to_hil event
    store.update_item(i, status="pending_hil", correlation_id="old-case", verdict="partial", severity="medium")
    cases = {c["id"]: c for c in store.hil_history()}
    assert cases[i]["legacy"] and cases[i]["times_raised"] == 1 and cases[i]["status"] == "pending_hil"
