# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Sign-in for the Sentinel UI: one account from .env, a signed session cookie.

    session cookie  "<user>|<expiry>|<HMAC-SHA256>"  HttpOnly, SameSite=Lax, 12 h
                    signed with SENTINEL_SESSION_SECRET, or a random per-process
                    secret (sessions then end when the server restarts)
    HTTP Basic      scripts only, with an X-Sentinel-Client header (build-run.sh run,
                    curl -u ... -H 'X-Sentinel-Client: me'); a browser's remembered
                    Basic credentials are ignored, so Sign out really signs out
    lockout         5 failed sign-ins from one address -> 5 minutes refused

Changing SENTINEL_PASSWORD ends every session (the password is part of the key)."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from typing import Dict, List, Optional

from sentinel.settings import accounts, credentials

COOKIE = "k9x_sentinel_session"
TTL_S = 12 * 3600
MAX_FAILS, WINDOW_S, LOCK_S = 5, 300, 300

_PROCESS_SECRET = secrets.token_bytes(32)
_fails: Dict[str, List[float]] = {}
_locked: Dict[str, float] = {}
_lock = threading.Lock()


def _key() -> bytes:
    base = os.environ.get("SENTINEL_SESSION_SECRET", "").encode() or _PROCESS_SECRET
    pw = "|".join(f"{u}:{a['password']}" for u, a in sorted(accounts().items()))
    return hashlib.sha256(base + b"|" + pw.encode()).digest()


def check_password(user: str, password: str) -> bool:
    acct = accounts().get(user)
    want = acct["password"] if acct else secrets.token_hex(16)   # same work for unknown users
    return bool(acct) & secrets.compare_digest(password.encode(), want.encode())


def role(user: Optional[str]) -> Optional[str]:
    acct = accounts().get(user or "")
    return acct["role"] if acct else None


def issue(user: str, now: Optional[float] = None) -> str:
    exp = int((now or time.time()) + TTL_S)
    body = f"{user}|{exp}"
    sig = hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}|{sig}"


def verify(token: Optional[str], now: Optional[float] = None) -> Optional[str]:
    """The signed-in user, or None (missing, tampered, expired, or password changed)."""
    if not token or not credentials()["password"]:
        return None
    try:
        user, exp, sig = token.rsplit("|", 2)
        exp_i = int(exp)
    except ValueError:
        return None
    good = hmac.new(_key(), f"{user}|{exp}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good) or exp_i < (now or time.time()):
        return None
    return user if user in accounts() else None


def locked(addr: str, now: Optional[float] = None) -> float:
    """Seconds this address must still wait (0 = may try)."""
    now = now or time.time()
    with _lock:
        until = _locked.get(addr, 0)
        return max(0.0, until - now)


def record_failure(addr: str, now: Optional[float] = None) -> None:
    now = now or time.time()
    with _lock:
        recent = [t for t in _fails.get(addr, []) if now - t < WINDOW_S] + [now]
        _fails[addr] = recent
        if len(recent) >= MAX_FAILS:
            _locked[addr] = now + LOCK_S
            _fails[addr] = []


def record_success(addr: str) -> None:
    with _lock:
        _fails.pop(addr, None)
        _locked.pop(addr, None)
