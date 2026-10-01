# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""One Sentinel run, and the daily schedule.

A run is the application entry point driving the router: one sentinel.scan,
then one sentinel.assess per item waiting (each its own flow, so each
finding becomes its own HIL case). Only one run at a time."""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sentinel import store
from sentinel.orchestrators.sentinel_orchestrators import assess_queue
from sentinel.router.sentinel_router import get_router
from sentinel.settings import run_at

log = logging.getLogger(__name__)

_RUN_LOCK = threading.Lock()
STATE: Dict[str, Any] = {"running": False, "phase": "", "item": None, "next_run": None}


def run_once(sources: Optional[List[str]] = None) -> Dict[str, Any]:
    if not _RUN_LOCK.acquire(blocking=False):
        return {"status": "busy"}
    run_id = store.start_run()
    STATE.update(running=True, phase="collecting", item=None)
    stats: Dict[str, Any] = {}
    try:
        router = get_router()
        stats["sources"] = router.route({"event_type": "sentinel.scan", "sources": sources or []})["sources"]
        outcomes: Counter = Counter()
        queue = assess_queue()
        STATE["phase"] = f"assessing {len(queue)}"
        for item_id in queue:
            STATE["item"] = item_id
            result = router.route({"event_type": "sentinel.assess", "item_id": item_id})
            outcomes[result.get("status", "unknown")] += 1
        stats["assessed"] = dict(outcomes)
        store.finish_run(run_id, "completed", stats)
        log.info("[Sentinel] run %d completed: %s", run_id, stats)
        return {"status": "completed", "run_id": run_id, **stats}
    except Exception as exc:
        log.exception("[Sentinel] run %d failed", run_id)
        store.finish_run(run_id, "failed", stats, f"{exc.__class__.__name__}: {exc}"[:500])
        return {"status": "failed", "run_id": run_id, "error": str(exc)}
    finally:
        STATE.update(running=False, phase="", item=None)
        _RUN_LOCK.release()


def next_run_after(now: datetime, hhmm: str) -> datetime:
    hour, minute = (int(x) for x in hhmm.split(":"))
    nxt = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return nxt if nxt > now else nxt + timedelta(days=1)


def _loop(stop: threading.Event) -> None:
    while not stop.is_set():
        nxt = next_run_after(datetime.now(), run_at())
        STATE["next_run"] = nxt.isoformat(timespec="minutes")
        while not stop.is_set() and datetime.now() < nxt:
            stop.wait(min(60, max(1, (nxt - datetime.now()).total_seconds())))
        if not stop.is_set():
            run_once()


def start_scheduler() -> threading.Event:
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="sentinel-scheduler", daemon=True).start()
    return stop


def run_in_background(sources: Optional[List[str]] = None) -> bool:
    if STATE["running"]:
        return False
    threading.Thread(target=run_once, args=(sources,), name="sentinel-run", daemon=True).start()
    time.sleep(0.05)
    return True
