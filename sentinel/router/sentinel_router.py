# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""SentinelRouter: the single entry point.

Extends the framework's K9EventRouter for its HIL reply handling
(listen_for_hil_replies: one consumer on hil.replies.framework_security_updates,
resolve by correlation_id, re-route the resumed payload), but routes
in-process instead of via domain topics — Sentinel is one process.

    sentinel.scan    -> ScanOrchestrator
    sentinel.assess  -> AssessOrchestrator (also the resume path after a decision)"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, Dict, Optional

from k9_aif_abb.k9_core.messaging.k9_event_bus import K9EventBus
from k9_aif_abb.k9_core.router.k9_event_router import K9EventRouter
from k9_aif_abb.k9_security.vulnerability.shield_governance import ShieldGovernance

from sentinel import store
from sentinel.orchestrators.sentinel_orchestrators import AssessOrchestrator, ScanOrchestrator
from sentinel.settings import db_mode, kafka_broker, load_config, postgres

log = logging.getLogger(__name__)


class SentinelRouter(K9EventRouter):
    layer = "K9X Sentinel SentinelRouter SBB"

    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        config = config or {}
        kwargs.setdefault("governance", ShieldGovernance(config=config))
        super().__init__(config=config, **kwargs)

    def route(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        event_type = str(payload.get("event_type", "")).strip().lower()
        orchestrator = self.registry.get(event_type)
        if orchestrator is None:
            raise KeyError(f"[{self.layer}] no orchestrator for event_type={event_type!r}")
        return orchestrator.run({**payload, "event_type": event_type})


def build_bus() -> Optional[K9EventBus]:
    broker = kafka_broker()
    if not broker:
        log.warning("[SentinelRouter] KAFKA_BROKER not set: findings stay in Sentinel's UI, no HIL")
        return None
    return K9EventBus(broker_url=broker, topic="k9x-sentinel-events", group_id="k9x-sentinel-hil")


def build_hil_state_store():
    """Where open HIL cases are remembered (so a reply resumes the right flow).
    PostgreSQL mode: the framework's RoutingStateStore in Sentinel's own schema;
    SQLite mode: None, i.e. the framework's zero-config SQLite file (hil.db_path)."""
    if db_mode() != "postgres":
        return None
    from k9_aif_abb.k9_storage.postgres_database_storage import PostgresDatabaseStorage
    from k9_aif_abb.k9_storage.routing_state_store import RoutingStateStore
    store.init()   # creates the schema first
    return RoutingStateStore(db=PostgresDatabaseStorage(config={"postgres": postgres()}))


@lru_cache(maxsize=1)
def get_router() -> SentinelRouter:
    config = load_config()
    bus = build_bus()
    router = SentinelRouter(config=config, message_bus=bus, state_store=build_hil_state_store())
    router.register_orchestrator("sentinel.scan", ScanOrchestrator(config=config))
    router.register_orchestrator("sentinel.assess", AssessOrchestrator(
        config=config, message_bus=bus, hil_state_store=router.state_store))
    return router
