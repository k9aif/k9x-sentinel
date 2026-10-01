# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""CollectSquad agents: read every source, store what's new. No model calls.

The first time a source is read, items older than lookback_days are stored
as baseline (never assessed), so day one doesn't flood the review queue
with last year's news."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

from sentinel import activity, osv, sources, store
from sentinel.agents.common import SentinelAgent
from sentinel.settings import sources as configured_sources

log = logging.getLogger(__name__)


class FeedCollectorAgent(SentinelAgent):
    layer = "K9X Sentinel FeedCollectorAgent SBB"

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.enforce_governance()
        cfg = self.config.get("sentinel", {})
        timeout = float(cfg.get("fetch_timeout_s", 20))
        agent = cfg.get("user_agent", "K9X-Sentinel")
        limit = int(cfg.get("max_items_per_source", 25))
        cutoff = time.time() - float(cfg.get("lookback_days", 14)) * 86400
        only = set(payload.get("sources") or [])
        stats: Dict[str, Any] = {}
        for src in configured_sources(self.config):
            if src["kind"] == "osv" or (only and src["id"] not in only):
                continue
            if activity.stop_requested():
                break
            first_time = store.source_first_run(src["id"]) is None
            name = src.get("name", src["id"])
            activity.emit("sources", f"Connecting to {name} …", source=src["id"])
            try:
                items = sources.read_source(src, timeout, agent)[:limit]
            except Exception as exc:
                log.warning("[FeedCollector] %s failed: %s", src["id"], exc)
                stats[src["id"]] = {"error": f"{exc.__class__.__name__}: {exc}"[:300]}
                activity.emit("sources", f"{name}: unreachable ({exc.__class__.__name__})", "error", source=src["id"])
                continue
            new = baseline = 0
            for item in items:
                old = first_time and item.get("published") and item["published"] < cutoff
                if store.add_item(item, status="baseline" if old else "new"):
                    baseline += bool(old)
                    new += not old
            store.mark_source_seen(src["id"], time.time())
            stats[src["id"]] = {"read": len(items), "new": new, "baseline": baseline}
            activity.emit("sources", f"{name}: read {len(items)} · {new} new"
                          + (f" · {baseline} baseline" if baseline else ""), "ok", source=src["id"], new=new)
        return {"sources": stats}


class DependencyAuditAgent(SentinelAgent):
    layer = "K9X Sentinel DependencyAuditAgent SBB"

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.enforce_governance()
        timeout = float(self.config.get("sentinel", {}).get("fetch_timeout_s", 20))
        only = set(payload.get("sources") or [])
        stats: Dict[str, Any] = {}
        for src in configured_sources(self.config):
            if src["kind"] != "osv" or (only and src["id"] not in only):
                continue
            if activity.stop_requested():
                break
            activity.emit("sources", "Connecting to OSV: checking every dependency k9-aif declares …", source=src["id"])
            try:
                findings = osv.audit(src, timeout, on_package=lambda name, hit: activity.emit(
                    "osv", f"OSV · {name}: " + (hit if hit else "no fixable advisory at its floor"),
                    "warn" if hit else "info", source=src["id"]))
            except Exception as exc:
                log.warning("[DependencyAudit] %s failed: %s", src["id"], exc)
                stats[src["id"]] = {"error": f"{exc.__class__.__name__}: {exc}"[:300]}
                activity.emit("sources", f"OSV: unreachable ({exc.__class__.__name__})", "error", source=src["id"])
                continue
            new = sum(1 for f in findings if store.add_item(f))
            store.mark_source_seen(src["id"], time.time())
            stats[src["id"]] = {"read": len(findings), "new": new, "baseline": 0}
            activity.emit("sources", f"OSV: {len(findings)} dependency floors need raising · {new} new",
                          "ok", source=src["id"], new=new)
        return {"sources": stats}
