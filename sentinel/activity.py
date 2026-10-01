# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Live activity of the current run, for the UI ("Connecting to ...", "Screening ...").

An in-memory ring buffer of events; the UI polls /api/activity?since=<seq>.
Display only — the audit record is the store, not this.

    stage   sources | collect | osv | screen | compare | triage | hil | decision | run
    level   info | ok | warn | error
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

_LOCK = threading.Lock()
_EVENTS: Deque[Dict[str, Any]] = deque(maxlen=600)
_SEQ = 0
_CURRENT: Dict[str, Any] = {"stage": None, "source": None, "item": None}


def emit(stage: str, msg: str, level: str = "info", source: Optional[str] = None,
         item: Optional[int] = None, **extra: Any) -> None:
    global _SEQ
    with _LOCK:
        _SEQ += 1
        _EVENTS.append({"seq": _SEQ, "ts": time.time(), "stage": stage, "level": level,
                        "msg": msg[:300], "source": source, "item": item, **extra})
        if stage != "run":
            _CURRENT.update(stage=stage, source=source, item=item)


_STOP = threading.Event()


def request_stop() -> None:
    _STOP.set()


def clear_stop() -> None:
    _STOP.clear()


def stop_requested() -> bool:
    return _STOP.is_set()


def wait(seconds: float) -> bool:
    """Sleep, waking early when a stop is requested. True = stop requested."""
    return _STOP.wait(seconds)


def reset_current() -> None:
    with _LOCK:
        _CURRENT.update(stage=None, source=None, item=None)


def since(seq: int, limit: int = 300) -> List[Dict[str, Any]]:
    with _LOCK:
        return [e for e in _EVENTS if e["seq"] > seq][:limit]


def current() -> Dict[str, Any]:
    with _LOCK:
        return dict(_CURRENT, last_seq=_SEQ)
