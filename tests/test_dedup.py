# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""No duplicate review cases: running Sentinel again, or the same threat from
another source, must not create a second HIL case."""

import pytest

from sentinel import dedup, store
from tests.test_flow import FakeBus, answer, build, model  # noqa: F401  (fixture)


class FakeEmbedder:
    """Unit vectors: texts sharing a 'topic' word are similar, others are not."""
    TOPICS = {"web page": [1.0, 0.0, 0.0], "website": [0.95, 0.31, 0.0], "compaction": [0.0, 0.0, 1.0],
              "metadata": [0.0, 1.0, 0.0], "borderline": [0.75, 0.66, 0.0]}

    def vector(self, text):
        for word, vec in self.TOPICS.items():
            if word in (text or "").lower():
                return vec
        return [0.0, 0.0, 0.0]


@pytest.fixture
def embed(monkeypatch):
    fake = FakeEmbedder()
    monkeypatch.setattr(dedup.Embedder, "vector", lambda self, text: fake.vector(text))


def _raised(uid, title, threat, taxonomy=("LLM01",), kind="article", data=None):
    i = store.add_item({"uid": uid, "source": "willison_prompt_injection", "kind": kind, "title": title,
                        "data": data or {}})
    store.update_item(i, status="pending_hil", correlation_id=f"c-{uid}", verdict="partial", severity="high",
                      assessment={"threat": threat, "taxonomy": list(taxonomy), "verdict": "partial"})
    return i


def _article(uid, title="New write-up"):
    return store.add_item({"uid": uid, "source": "embracethered", "kind": "article", "title": title,
                           "content": "text"})


def test_running_again_raises_nothing_new(shield_only, model, embed):
    bus = FakeBus()
    router = build(bus)
    from tests.test_flow import article
    item = article()
    router.route({"event_type": "sentinel.assess", "item_id": item})
    assert len(bus.sent) == 1
    assert store.add_item({"uid": "t:1", "source": "willison_prompt_injection", "kind": "article",
                           "title": "Tool poisoning"}) is None          # same uid: never collected twice
    from sentinel.orchestrators.sentinel_orchestrators import assess_queue
    assert item not in assess_queue()                                    # pending_hil is not re-queued
    assert len(bus.sent) == 1


def test_same_threat_from_another_source_is_not_raised(shield_only, model, embed):
    first = _raised("w:1", "Prompt injection via web page content",
                    "Indirect prompt injection planted in web page content hijacks agents.")
    model[1][0] = answer(threat="Attackers hide instructions in website text for agents to follow.",
                         taxonomy=["LLM01", "ASI01"])
    bus = FakeBus()
    second = _article("e:1")
    out = build(bus).route({"event_type": "sentinel.assess", "item_id": second})
    it = store.get_item(second)
    assert out["status"] == "assessed" and not bus.sent
    assert it["status"] == "duplicate" and it["data"]["duplicate_of"] == first
    assert store.item_audit(second)[-1]["event"] == "duplicate_not_raised"


def test_similar_but_borderline_is_raised_and_labelled(shield_only, model, embed):
    first = _raised("w:2", "Web page injection", "Instructions in web page content hijack agents.")
    model[1][0] = answer(threat="A borderline variant of that technique.", taxonomy=["LLM01"])
    bus = FakeBus()
    second = _article("e:2")
    build(bus).route({"event_type": "sentinel.assess", "item_id": second})
    assert len(bus.sent) == 1 and f"Possible duplicate of #{first}" in bus.sent[0][1]["title"]
    assert store.get_item(second)["data"]["possible_duplicate_of"] == first


def test_different_threat_is_raised(shield_only, model, embed):
    _raised("w:3", "Metadata injection", "Instructions in database metadata escalate privileges.")
    model[1][0] = answer(threat="A model self-injects into its own compaction summary.")
    bus = FakeBus()
    build(bus).route({"event_type": "sentinel.assess", "item_id": _article("e:3")})
    assert len(bus.sent) == 1 and "duplicate" not in bus.sent[0][1]["title"].lower()


def test_same_cve_is_a_duplicate_without_any_model(shield_only, model, monkeypatch):
    monkeypatch.setattr(dedup.Embedder, "vector", lambda self, t: pytest.fail("embedding not needed"))
    first = _raised("k:1", "CVE-2026-1111: Ollama path traversal", "Path traversal in model pull.")
    model[1][0] = answer(threat="Ollama model pull path traversal (CVE-2026-1111) lets attackers write files.")
    bus = FakeBus()
    second = _article("e:4", title="Exploiting CVE-2026-1111 in the wild")
    build(bus).route({"event_type": "sentinel.assess", "item_id": second})
    assert not bus.sent and store.get_item(second)["data"]["duplicate_of"] == first


def test_dependency_with_an_open_case_is_not_raised_again(shield_only, monkeypatch):
    monkeypatch.setattr(dedup.Embedder, "vector", lambda self, t: None)
    data = {"package": "pyjwt", "spec": ">=2.8", "floor": "2.8", "recommended": "pyjwt>=2.15.0", "extras": ["oidc"],
            "severity": "high", "advisories": [{"id": "GHSA-aaaa-bbbb-cccc", "fixed": "2.15.0", "severity": "high",
                                                "summary": "x", "aliases": []}]}
    first = _raised("osv:a", "k9-aif allows pyjwt>=2.8 — fixed in 2.15.0", "", kind="dependency", data=data)
    newer = store.add_item({"uid": "osv:b", "source": "osv_dependencies", "kind": "dependency",
                            "title": "k9-aif allows pyjwt>=2.8 — fixed in 2.16.0", "summary": "s",
                            "data": {**data, "recommended": "pyjwt>=2.16.0",
                                     "advisories": [{"id": "GHSA-dddd-eeee-ffff", "fixed": "2.16.0",
                                                     "severity": "high", "summary": "y", "aliases": []}]}})
    bus = FakeBus()
    build(bus).route({"event_type": "sentinel.assess", "item_id": newer})
    assert not bus.sent and store.get_item(newer)["data"]["duplicate_of"] == first


def test_embedding_outage_never_blocks_a_finding(shield_only, model, monkeypatch):
    monkeypatch.setattr(dedup.Embedder, "vector", lambda self, t: None)
    _raised("w:5", "Web page injection", "Instructions in web page content hijack agents.")
    model[1][0] = answer(threat="Instructions in website text hijack agents.")
    bus = FakeBus()
    build(bus).route({"event_type": "sentinel.assess", "item_id": _article("e:5")})
    assert len(bus.sent) == 1


def test_advisory_ids_are_collected_from_text_and_osv_data():
    item = {"title": "CVE-2026-0001 and ghsa-2345-6789-cfgh", "summary": "",
            "data": {"cve": "CVE-2026-0002", "advisories": [{"id": "PYSEC-1", "aliases": ["CVE-2026-0003"]}]}}
    assert dedup.advisory_ids(item, {"threat": "see CVE-2026-0004"}) == {
        "CVE-2026-0001", "GHSA-2345-6789-CFGH", "CVE-2026-0002", "PYSEC-1", "CVE-2026-0003", "CVE-2026-0004"}
