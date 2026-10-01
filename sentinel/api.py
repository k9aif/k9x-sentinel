# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""K9X Sentinel web API and UI (private: findings describe unpatched gaps).

Everything except /api/health needs the single login from .env
(SENTINEL_USER / SENTINEL_PASSWORD, HTTP Basic). No password set = the UI
and API are disabled; the scheduler still runs.

On start: the SQLite store, the daily scheduler, and (when KAFKA_BROKER is
set) the router's HIL reply listener."""

from __future__ import annotations

import asyncio
import logging
import secrets
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from sentinel import catalog, runner, store
from sentinel.router.sentinel_router import get_router
from sentinel.settings import (REPO_URL, analysis_model, credentials, github, hil_detail, kafka_broker, run_at)

log = logging.getLogger(__name__)
WEB = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="K9X Sentinel", docs_url=None, redoc_url=None, openapi_url=None)
_basic = HTTPBasic(realm="K9X Sentinel")


def login(creds: HTTPBasicCredentials = Depends(_basic)) -> str:
    want = credentials()
    if not want["password"]:
        raise HTTPException(503, "Set SENTINEL_PASSWORD in .env to enable the UI")
    ok = secrets.compare_digest(creds.username.encode(), want["user"].encode()) and \
        secrets.compare_digest(creds.password.encode(), want["password"].encode())
    if not ok:
        raise HTTPException(401, "Invalid login", headers={"WWW-Authenticate": 'Basic realm="K9X Sentinel"'})
    return creds.username


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
            "repo": REPO_URL}


@app.get("/api/items")
def items(status: Optional[str] = None, verdict: Optional[str] = None, limit: int = 200,
          _: str = Depends(login)):
    return store.list_items(status=status, verdict=verdict, limit=max(1, min(limit, 1000)))


@app.get("/api/items/{item_id}")
def item(item_id: int, _: str = Depends(login)):
    found = store.get_item(item_id)
    if not found:
        raise HTTPException(404, "not found")
    return found


class RunRequest(BaseModel):
    sources: List[str] = []


@app.post("/api/run")
def run(body: RunRequest, _: str = Depends(login)):
    if not runner.run_in_background(body.sources or None):
        raise HTTPException(409, "a run is already in progress")
    return {"status": "started"}


@app.get("/")
def index(_: str = Depends(login)):
    return FileResponse(WEB / "index.html")


@app.get("/architecture.svg")
def architecture(_: str = Depends(login)):
    return FileResponse(WEB / "architecture.svg", media_type="image/svg+xml")
