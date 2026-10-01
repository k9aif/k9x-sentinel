# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""K9X Sentinel web API and UI (private: findings describe unpatched gaps).

Everything except /api/health, the sign-in page and its assets needs the
single login from .env (SENTINEL_USER / SENTINEL_PASSWORD): a signed session
cookie from the sign-in page, or HTTP Basic plus an X-Sentinel-Client header
for scripts (see auth.py). No
password set = the UI and API are disabled; the scheduler still runs.

On start: the SQLite store, the daily scheduler, and (when KAFKA_BROKER is
set) the router's HIL reply listener."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from sentinel import activity, auth, catalog, runner, store
from sentinel.router.sentinel_router import get_router
from sentinel.settings import (REPO_URL, analysis_model, credentials, github, hil_detail, hil_overdue_days, kafka_broker,
                               run_at)

log = logging.getLogger(__name__)
WEB = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="K9X Sentinel", docs_url=None, redoc_url=None, openapi_url=None)
_basic = HTTPBasic(auto_error=False)   # no WWW-Authenticate: never the browser's own popup
SCRIPT_HEADER = "X-Sentinel-Client"     # required with HTTP Basic (scripts: build-run.sh run, curl)


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_user(request: Request, basic: Optional[HTTPBasicCredentials] = Depends(_basic)) -> Optional[str]:
    if not credentials()["password"]:
        raise HTTPException(503, "Set SENTINEL_PASSWORD in .env to enable the UI")
    user = auth.verify(request.cookies.get(auth.COOKIE))
    if user:
        return user
    # Basic auth is for scripts only, and they must say so. A browser that once
    # used the old Basic popup keeps resending those credentials on its own;
    # without this header they would sign it straight back in after Sign out.
    if basic is not None and request.headers.get(SCRIPT_HEADER):
        addr = _client(request)
        if auth.locked(addr):
            raise HTTPException(429, "Too many failed sign-ins; try again in a few minutes")
        if auth.check_password(basic.username, basic.password):
            auth.record_success(addr)
            return basic.username
        auth.record_failure(addr)
    return None


def login(user: Optional[str] = Depends(current_user)) -> str:
    if not user:
        raise HTTPException(401, "Sign in required")
    return user


async def _listen_for_replies() -> None:
    router = get_router()
    delay = 5
    while True:
        try:
            await router.listen_for_hil_replies()
            delay = 5
        except Exception as exc:
            log.warning("[Sentinel] HIL reply listener stopped (%s); retrying in %ss", exc, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 300)


@app.on_event("startup")
async def _startup() -> None:
    store.init()
    get_router()
    runner.start_scheduler()
    if kafka_broker():
        asyncio.create_task(_listen_for_replies())


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/status")
def status(_: str = Depends(login)):
    try:
        cat = catalog.load()
        cat_info = {"origin": cat.get("_origin"), "framework_version": cat.get("framework_version"),
                    "capabilities": len(cat["capabilities"]), "known_gaps": len(cat.get("known_gaps", []))}
    except Exception as exc:
        cat_info = {"error": str(exc)[:300]}
    gh = github()
    return {"state": runner.STATE, "counts": store.counts(), "runs": store.last_runs(10), "catalog": cat_info,
            "settings": {"model": analysis_model(), "run_at": run_at(), "hil": bool(kafka_broker()),
                         "hil_detail": hil_detail(), "github_mode": gh["mode"], "github_repo": gh["repo"],
                         "github_token": bool(gh["token"])},
            "database": store.backend(),
            "by_source": store.source_counts(),
            "sources": [{"id": src["id"], "name": src.get("name", src["id"])} for src in get_router().config["sentinel"]["sources"]],
            "repo": REPO_URL}


@app.get("/api/items")
def items(status: Optional[str] = None, verdict: Optional[str] = None, source: Optional[str] = None,
          limit: int = 200, _: str = Depends(login)):
    return store.list_items(status=status, verdict=verdict, source=source, limit=max(1, min(limit, 1000)))


@app.get("/api/items/{item_id}")
def item(item_id: int, _: str = Depends(login)):
    found = store.get_item(item_id)
    if not found:
        raise HTTPException(404, "not found")
    return found


@app.get("/api/activity")
def live(since: int = 0, _: str = Depends(login)):
    return {"running": runner.STATE["running"], "phase": runner.STATE["phase"],
            "current": activity.current(), "events": activity.since(since)}


@app.get("/api/items/{item_id}/audit")
def item_audit(item_id: int, _: str = Depends(login)):
    return store.item_audit(item_id)


@app.get("/api/hil")
def hil_history(_: str = Depends(login)):
    return {"overdue_days": hil_overdue_days(), "cases": store.hil_history(hil_overdue_days())}


@app.get("/api/audit/verify")
def audit_verify(_: str = Depends(login)):
    return store.verify_chain()


@app.get("/api/audit.csv")
def audit_csv(request: Request, user: str = Depends(login)):
    import csv
    import io
    import json as _json
    from datetime import datetime, timezone
    store.audit("audit_exported", actor=user, address=_client(request))

    def rows():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "time_utc", "run_id", "item_id", "event", "actor", "detail", "prev_hash", "hash"])
        for e in store.audit_events():
            w.writerow([e["id"], datetime.fromtimestamp(e["ts"], timezone.utc).isoformat(timespec="seconds"),
                        e["run_id"], e["item_id"], e["event"], e["actor"],
                        _json.dumps(e["detail"], sort_keys=True), e["prev_hash"], e["hash"]])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
    return StreamingResponse(rows(), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="k9x-sentinel-audit.csv"'})


class RunRequest(BaseModel):
    sources: List[str] = []


@app.post("/api/run")
def run(body: RunRequest, request: Request, user: str = Depends(login)):
    store.audit("run_requested", actor=user, address=_client(request), sources=body.sources or "all")
    if not runner.run_in_background(body.sources or None):
        raise HTTPException(409, "a run is already in progress")
    return {"status": "started"}


class SignIn(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def sign_in(body: SignIn, request: Request):
    if not credentials()["password"]:
        raise HTTPException(503, "Set SENTINEL_PASSWORD in .env to enable the UI")
    addr = _client(request)
    wait = auth.locked(addr)
    if wait:
        raise HTTPException(429, f"Too many failed sign-ins. Try again in {int(wait) // 60 + 1} min.")
    if not auth.check_password(body.username.strip(), body.password):
        auth.record_failure(addr)
        store.audit("sign_in_failed", actor=body.username.strip()[:100] or "?", address=addr)
        raise HTTPException(401, "Wrong username or password")
    auth.record_success(addr)
    store.audit("signed_in", actor=body.username.strip(), address=addr)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(auth.COOKIE, auth.issue(body.username.strip()), max_age=auth.TTL_S, httponly=True,
                    samesite="lax", secure=request.url.scheme == "https", path="/")
    return resp


@app.post("/api/logout")
def sign_out(request: Request):
    user = auth.verify(request.cookies.get(auth.COOKIE))
    if user:
        store.audit("signed_out", actor=user, address=_client(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


# The app and the sign-in page live at different URLs and are never cached.
# (One URL serving either page let the browser show a cached copy of the wrong
# one: the sign-in page after signing in, and after Sign out the app, whose 401s
# sent it back to "/" in an endless loop.)
NO_STORE = {"Cache-Control": "no-store", "Vary": "Cookie"}


@app.get("/")
def index(user: Optional[str] = Depends(current_user)):
    if not user:
        return RedirectResponse("/login", status_code=303, headers=NO_STORE)
    return FileResponse(WEB / "index.html", headers=NO_STORE)


@app.get("/login")
def login_page(user: Optional[str] = Depends(current_user)):
    if user:
        return RedirectResponse("/", status_code=303, headers=NO_STORE)
    return FileResponse(WEB / "login.html", headers=NO_STORE)


@app.get("/about")
def about():
    return FileResponse(WEB / "about.html")


@app.get("/logo.svg")
def logo():
    return FileResponse(WEB / "logo.svg", media_type="image/svg+xml")


@app.get("/architecture.svg")
def architecture():
    return FileResponse(WEB / "architecture.svg", media_type="image/svg+xml")
