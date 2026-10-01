# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Sentinel's orchestrators. Each knows its squads, never the router.

    ScanOrchestrator     sentinel.scan    CollectSquad
    AssessOrchestrator   sentinel.assess  AssessSquad for one item; on resume
                                          (hil_decision present) DecisionSquad

A finding a human must review is signalled by TriageAgent raising
RequiresHIL. AssessOrchestrator catches it and hands it to the framework's
HIL path (handle_requires_hil -> BaseHILOrchestrator), which publishes
hil.requests.framework_security_updates and records the pending flow, so
the reviewer's decision resumes this same orchestrator."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from k9_aif_abb.k9_agents.registry.agent_registry import AgentRegistry
from k9_aif_abb.k9_core.orchestration.base_orchestrator import BaseOrchestrator
from k9_aif_abb.k9_core.orchestration.hil_signal import RequiresHIL
from k9_aif_abb.k9_security.vulnerability.shield_governance import ShieldGovernance
from k9_aif_abb.k9_squad.squad_loader import SquadLoader

from sentinel import activity, store
from sentinel.agents.action_agents import DecisionAgent
from sentinel.agents.assess_agents import ContentScreenAgent, GapAnalysisAgent, TriageAgent
from sentinel.agents.collect_agents import DependencyAuditAgent, FeedCollectorAgent
from sentinel.agents.common import agent_config

log = logging.getLogger(__name__)

_SQUADS_YAML = Path(__file__).resolve().parent.parent / "squads" / "sentinel_squads.yaml"
_AGENTS = [FeedCollectorAgent, DependencyAuditAgent, ContentScreenAgent, GapAnalysisAgent,
           TriageAgent, DecisionAgent]
MAX_ATTEMPTS = 3


class _SentinelOrchestrator(BaseOrchestrator):
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        config = config or {}
        kwargs.setdefault("governance", ShieldGovernance(config=config))
        super().__init__(config, **kwargs)

    def _squad(self, squad_id: str):
        registry = AgentRegistry()
        for cls in _AGENTS:
            registry.register(cls.__name__, lambda c=cls: c(config=agent_config(c.__name__, self.config)))
        return SquadLoader(registry).load_one(_SQUADS_YAML, squad_id)

    def run(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return self.execute_flow(event)


class ScanOrchestrator(_SentinelOrchestrator):
    layer = "K9X Sentinel ScanOrchestrator SBB"

    def execute_flow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        result = self._squad("CollectSquad").execute({"sources": payload.get("sources") or []})
        stats: Dict[str, Any] = {}
        for key in ("feeds", "dependencies"):
            stats.update((result.get(key) or {}).get("sources", {}))
        return {"status": "completed", "sources": stats}


class AssessOrchestrator(_SentinelOrchestrator):
    layer = "K9X Sentinel AssessOrchestrator SBB"

    def execute_flow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        item_id = int(payload["item_id"])
        if payload.get("hil_decision"):
            result = self._squad("DecisionSquad").execute({"item_id": item_id,
                                                            "hil_decision": payload["hil_decision"]})
            return {"status": "decided", "item_id": item_id, **(result.get("decision") or {})}
        try:
            result = self._squad("AssessSquad").execute({"item_id": item_id})
        except RequiresHIL as exc:
            return self._raise_to_hil(exc, payload, item_id)
        except Exception as exc:
            return self._failed(item_id, exc)
        return {"status": "assessed", "item_id": item_id, **(result.get("triage") or {})}

    def _raise_to_hil(self, exc: RequiresHIL, payload: Dict[str, Any], item_id: int) -> Dict[str, Any]:
        connected = bool(self.message_bus and getattr(self.message_bus, "_producer", None))
        if not connected:
            # Without Kafka the case would be recorded as pending but never reach
            # k9x-hil; keep it visible and retry it on the next run instead.
            store.update_item(item_id, status="hil_failed", error="Kafka unavailable: HIL case not sent")
            activity.emit("hil", "Kafka not configured / unreachable: kept, will be sent on the next run", "warn", item=item_id)
            return {"status": "hil_failed", "item_id": item_id}
        resume = {"event_type": "sentinel.assess", "item_id": item_id}
        out = self.handle_requires_hil(exc, resume)
        store.update_item(item_id, status="pending_hil", correlation_id=out.get("correlation_id"), error=None)
        activity.emit("hil", f"Published to k9x-hil · {out.get('reply_to', '').replace('replies', 'requests')}", "ok",
                      item=item_id)
        return {**out, "item_id": item_id}

    @staticmethod
    def _failed(item_id: int, exc: Exception) -> Dict[str, Any]:
        item = store.get_item(item_id) or {}
        data = dict(item.get("data") or {})
        data["attempts"] = int(data.get("attempts", 0)) + 1
        status = "failed" if data["attempts"] >= MAX_ATTEMPTS else "error"
        log.warning("[AssessOrchestrator] item %s %s (attempt %d): %s", item_id, status, data["attempts"], exc)
        activity.emit("compare", f"assessment failed ({status}, attempt {data['attempts']}): {str(exc)[:120]}", "error",
                      item=item_id)
        store.update_item(item_id, status=status, data=data, error=f"{exc.__class__.__name__}: {exc}"[:500])
        return {"status": status, "item_id": item_id, "error": str(exc)[:300]}


def assess_queue() -> List[int]:
    """Items waiting for assessment (new, retryable errors, unsent HIL cases)."""
    return store.ids_with_status(["new", "error", "hil_failed"])
