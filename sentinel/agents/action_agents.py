# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""DecisionSquad agent: act on a reviewer's decision from k9x-hil.

k9x-hil publishes only terminal decisions: complete (approved), reject,
expire. Only an approval reaches GitHub; Sentinel never changes code."""

from __future__ import annotations

from typing import Any, Dict

from sentinel import activity, github_actions, store
from sentinel.agents.common import SentinelAgent
from sentinel.settings import hil_approvers

OUTCOME = {"complete": "approved", "reject": "rejected", "expire": "expired"}


class DecisionAgent(SentinelAgent):
    layer = "K9X Sentinel DecisionAgent SBB"

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.enforce_governance()
        item = store.get_item(int(payload["item_id"]))
        decision = payload.get("hil_decision") or {}
        outcome = OUTCOME.get(str(decision.get("action", "")).lower(), "unknown")
        record = {"outcome": outcome, "actor": decision.get("actor"), "comment": decision.get("comment"),
                  "decided_at": decision.get("decided_at")}
        approvers = hil_approvers()
        actor = str(decision.get("actor") or "").strip().lower()
        if approvers and actor not in approvers:
            # Not an approver: ignore the decision and re-raise the case next run
            # (the pending HIL row is already resolved, so a new case is needed).
            record["outcome"] = "ignored_unauthorized"
            store.audit("decision_ignored_unauthorized", item["id"], actor=actor or "unknown",
                        action=decision.get("action"), comment=decision.get("comment"),
                        correlation_id=decision.get("correlation_id"))
            store.update_item(item["id"], status="hil_failed", decision=record,
                              error=f"decision by {actor or 'unknown'} ignored (not in SENTINEL_HIL_APPROVERS); re-raised next run")
            return {"outcome": "ignored_unauthorized", "action": None}
        action = None
        if outcome == "approved":
            version = (item.get("assessment") or {}).get("framework_version") or "unknown"
            action = github_actions.perform(item, version)
        store.update_item(item["id"], status="decided", decision=record, action=action)
        store.audit("decision_received", item["id"], actor=decision.get("actor") or "unknown", outcome=outcome,
                    comment=decision.get("comment"), decided_at=decision.get("decided_at"),
                    correlation_id=decision.get("correlation_id"))
        if action:
            store.audit("github_action", item["id"], mode=action.get("mode"), kind=action.get("kind"),
                        ok=action.get("ok"), url=action.get("url"), error=action.get("error"),
                        request_url=(action.get("request") or {}).get("url"))
        activity.emit("decision", f"#{item['id']} {outcome} by {decision.get('actor') or '?'}"
                      + (f" → GitHub {action['kind']} ({action['mode']})" if action else ""), "ok", item=item["id"])
        return {"outcome": outcome, "action": action}
