# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
import pytest

from sentinel import catalog
from sentinel.agents.assess_agents import extract_json, should_raise, validate

TRIAGE = {"min_confidence": 0.5, "min_severity": "medium", "known_gap_reraise_severity": "high"}


def good(**kw):
    base = {"relevant": True, "threat": "t", "taxonomy": ["LLM01"], "verdict": "partial",
            "matched_capabilities": ["shield.prompt_injection"], "known_gap": None, "severity": "high",
            "confidence": 0.8, "rationale": "r", "suggested_fix": "f"}
    return {**base, **kw}


def test_extract_json_handles_thinking_fences_and_prose():
    assert extract_json('<think>{"no": 1}</think>Here: ```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! {"a": {"b": 2}} done') == {"a": {"b": 2}}
    assert extract_json("no json here") is None


def test_validate_keeps_only_catalog_ids():
    cat = catalog.load()
    out = validate(good(taxonomy=["LLM01", "LLM99"], matched_capabilities=["shield.prompt_injection", "made.up"],
                        known_gap="gap.invented"), cat)
    assert out["taxonomy"] == ["LLM01"]
    assert out["matched_capabilities"] == ["shield.prompt_injection"]
    assert out["known_gap"] is None
    assert set(out["dropped_ids"]) == {"LLM99", "made.up"}


def test_validate_rejects_unusable_answers():
    cat = catalog.load()
    with pytest.raises(ValueError):
        validate(good(verdict="probably fine"), cat)
    with pytest.raises(ValueError):
        validate(good(severity="extreme"), cat)


def test_irrelevant_is_forced_to_not_relevant():
    out = validate(good(relevant=False, verdict="gap"), catalog.load())
    assert out["verdict"] == "not_relevant" and out["relevant"] is False


@pytest.mark.parametrize("assessment,expected", [
    (good(), True),
    (good(verdict="gap"), True),
    (good(verdict="covered"), False),
    (good(relevant=False), False),
    (good(confidence=0.3), False),
    (good(severity="low"), False),
    (good(known_gap="gap.token_budgets", severity="medium"), False),
    (good(known_gap="gap.token_budgets", severity="critical"), True),
])
def test_triage(assessment, expected):
    assert should_raise(assessment, TRIAGE)[0] is expected
