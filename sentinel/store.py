# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Sentinel's database: PostgreSQL (schema ``k9sentinel``), or SQLite as the
zero-config fallback for local runs and tests (settings.database_url()).

Tables
    items          one row per thing a source published; its current state
    sources_seen   first time each source was read (baseline cut-off)
    runs           one row per run
    audit_events   APPEND-ONLY audit trail. A database trigger refuses UPDATE,
                   DELETE (and TRUNCATE on PostgreSQL). Each row carries the
                   SHA-256 of the previous row (hash chain), so verify_chain()
                   detects a row edited or removed behind the trigger's back.

An item's ``uid`` is stable per source, so a re-fetched item is never assessed
or raised twice. ``items`` is the current state (updated in place); the history
of how it got there is in ``audit_events``.

    status  new          fetched, waiting for assessment
            baseline     older than lookback_days when its source was first seen
            assessed     analysed; not raised (covered, irrelevant, below threshold, known gap)
            pending_hil  raised to k9x-hil, waiting for a decision
            hil_failed   raised but Kafka was unavailable; retried next run
            decided      a reviewer approved, rejected or the case expired
            error        assessment failed; retried next run (up to 3 attempts)
            failed       assessment failed 3 times; left for a person to look at
            duplicate    same finding as one already sent for review (data.duplicate_of); not raised
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import (JSON, Column, Float, Index, Integer, MetaData, String, Table, Text, create_engine, func,
                        insert, select, text, update)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from sentinel.settings import database_url, db_schema

_LOCK = threading.Lock()
_ENGINES: Dict[str, Engine] = {}
_TABLES: Dict[str, Dict[str, Table]] = {}
_RUN: Dict[str, Optional[int]] = {"id": None}
GENESIS = "0" * 64


# ── schema ───────────────────────────────────────────────────────────────────
def _tables(schema: Optional[str]) -> Dict[str, Table]:
    key = schema or ""
    if key in _TABLES:
        return _TABLES[key]
    md = MetaData(schema=schema)
    t = {
        "items": Table(
            "items", md,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("uid", String(200), unique=True, nullable=False),
            Column("source", String(100), nullable=False),
            Column("kind", String(40), nullable=False),
            Column("title", String(500), nullable=False),
            Column("link", Text), Column("published", Float), Column("first_seen", Float, nullable=False),
            Column("summary", Text), Column("content", Text), Column("data", JSON),
            Column("status", String(32), nullable=False, server_default="new"),
            Column("screen", JSON), Column("assessment", JSON),
            Column("verdict", String(32)), Column("severity", String(16)), Column("correlation_id", String(100)),
            Column("decision", JSON), Column("action", JSON), Column("error", Text), Column("updated", Float),
            Index("items_status", "status")),
        "sources_seen": Table(
            "sources_seen", md,
            Column("source", String(100), primary_key=True), Column("first_run", Float, nullable=False)),
        "runs": Table(
            "runs", md,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("started", Float, nullable=False), Column("finished", Float),
            Column("status", String(20), nullable=False), Column("stats", JSON), Column("error", Text)),
        "audit_events": Table(
            "audit_events", md,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("ts", Float, nullable=False),
            Column("run_id", Integer), Column("item_id", Integer),
            Column("event", String(60), nullable=False),
            Column("actor", String(200), nullable=False),
            Column("detail", JSON),
            Column("prev_hash", String(64), nullable=False),
            Column("hash", String(64), nullable=False),
            Index("audit_item", "item_id"), Index("audit_run", "run_id")),
    }
    t["_md"] = md  # type: ignore[assignment]
    _TABLES[key] = t
    return t


def _engine() -> Engine:
    url = database_url()
    if url not in _ENGINES:
        kw: Dict[str, Any] = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
        _ENGINES[url] = create_engine(url, **kw)
    return _ENGINES[url]


def _t(name: str) -> Table:
    return _tables(db_schema() if _engine().dialect.name == "postgresql" else None)[name]


def backend() -> Dict[str, Any]:
    eng = _engine()
    return {"dialect": eng.dialect.name, "schema": db_schema() if eng.dialect.name == "postgresql" else None,
            "where": eng.url.render_as_string(hide_password=True)}


def init() -> None:
    eng = _engine()
    pg = eng.dialect.name == "postgresql"
    schema = db_schema() if pg else None
    with eng.begin() as con:
        if pg:
            con.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
        _tables(schema)["_md"].create_all(con)  # type: ignore[union-attr]
        if pg:
            q = f'"{schema}".audit_events'
            con.execute(text(f'''CREATE OR REPLACE FUNCTION "{schema}".audit_events_append_only() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION 'audit_events is append-only'; END; $$ LANGUAGE plpgsql'''))
            con.execute(text(f"DROP TRIGGER IF EXISTS audit_events_no_change ON {q}"))
            con.execute(text(f'''CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON {q}
                FOR EACH ROW EXECUTE FUNCTION "{schema}".audit_events_append_only()'''))
            con.execute(text(f"DROP TRIGGER IF EXISTS audit_events_no_truncate ON {q}"))
            con.execute(text(f'''CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON {q}
                FOR EACH STATEMENT EXECUTE FUNCTION "{schema}".audit_events_append_only()'''))
        else:
            for op in ("UPDATE", "DELETE"):
                con.execute(text(f'''CREATE TRIGGER IF NOT EXISTS audit_events_no_{op.lower()}
                    BEFORE {op} ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END'''))


def _row(r) -> Optional[Dict[str, Any]]:
    return dict(r._mapping) if r is not None else None


# ── audit trail ──────────────────────────────────────────────────────────────
def _canonical(ts: float, run_id, item_id, event: str, actor: str, detail: Any) -> bytes:
    return json.dumps([ts, run_id, item_id, event, actor, detail], sort_keys=True, separators=(",", ":"),
                      default=str).encode()


def set_run(run_id: Optional[int]) -> None:
    _RUN["id"] = run_id


def audit(event: str, item_id: Optional[int] = None, actor: str = "sentinel",
          run_id: Optional[int] = None, **detail: Any) -> None:
    """Append one audit event (never updated or deleted)."""
    t = _t("audit_events")
    ts = round(time.time(), 6)
    run_id = run_id if run_id is not None else _RUN["id"]
    detail = json.loads(json.dumps(detail, default=str))  # exactly what is stored is what is hashed
    with _LOCK, _engine().begin() as con:
        if con.dialect.name == "postgresql":   # one writer at a time across processes too
            con.execute(text("SELECT pg_advisory_xact_lock(hashtext('k9sentinel.audit_events'))"))
        prev = con.execute(select(t.c.hash).order_by(t.c.id.desc()).limit(1)).scalar() or GENESIS
        digest = hashlib.sha256(prev.encode() + _canonical(ts, run_id, item_id, event, actor, detail)).hexdigest()
        con.execute(insert(t).values(ts=ts, run_id=run_id, item_id=item_id, event=event, actor=actor,
                                     detail=detail, prev_hash=prev, hash=digest))


def item_audit(item_id: int) -> List[Dict[str, Any]]:
    t = _t("audit_events")
    with _engine().connect() as con:
        return [_row(r) for r in con.execute(select(t).where(t.c.item_id == item_id).order_by(t.c.id))]


def audit_events(after_id: int = 0, limit: int = 100000) -> List[Dict[str, Any]]:
    t = _t("audit_events")
    with _engine().connect() as con:
        return [_row(r) for r in con.execute(select(t).where(t.c.id > after_id).order_by(t.c.id).limit(limit))]


def verify_chain() -> Dict[str, Any]:
    """Recompute every hash. A row changed or removed outside the trigger shows up here."""
    prev, n = GENESIS, 0
    for r in audit_events():
        n += 1
        expect = hashlib.sha256(prev.encode() + _canonical(r["ts"], r["run_id"], r["item_id"], r["event"],
                                                           r["actor"], r["detail"])).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != expect:
            return {"ok": False, "events": n, "broken_at": r["id"]}
        prev = r["hash"]
    return {"ok": True, "events": n, "broken_at": None}


HIL_EVENTS = ("raised_to_hil", "hil_unsent", "decision_received", "decision_ignored_unauthorized", "github_action")


def hil_history(overdue_days: float = 7.0, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every finding ever sent (or meant to be sent) for human review, with its
    review history from the audit trail: when raised, how long it waited, who
    decided, what happened. Newest first."""
    now = now or time.time()
    ev, it = _t("audit_events"), _t("items")
    with _engine().connect() as con:
        rows = [_row(r) for r in con.execute(
            select(ev).where(ev.c.event.in_(HIL_EVENTS), ev.c.item_id.is_not(None)).order_by(ev.c.id))]
        # Findings that went to review before the audit trail existed (or whose
        # events are missing) still count: a HIL case id or a review status.
        legacy = [r[0] for r in con.execute(select(it.c.id).where(
            (it.c.correlation_id.is_not(None)) | (it.c.status.in_(("pending_hil", "hil_failed", "decided")))))]
        ids = sorted({r["item_id"] for r in rows} | set(legacy))
        items = {r._mapping["id"]: _row(r) for r in con.execute(
            select(it.c.id, it.c.title, it.c.kind, it.c.source, it.c.link, it.c.published, it.c.verdict,
                   it.c.severity, it.c.status, it.c.correlation_id).where(it.c.id.in_(ids)))} if ids else {}
    out: Dict[int, Dict[str, Any]] = {}
    blank = {"raised_at": None, "times_raised": 0, "unsent": 0, "outcome": None, "decided_by": None,
             "decided_at": None, "comment": None, "ignored": [], "github": None}
    for i in ids:
        out[i] = {**items.get(i, {"id": i}), **blank, "ignored": []}
    for r in rows:
        h = out[r["item_id"]]
        d = r["detail"] or {}
        if r["event"] == "raised_to_hil":
            h["times_raised"] += 1
            h["raised_at"] = h["raised_at"] or r["ts"]
            h["last_raised_at"] = r["ts"]
            h["priority"] = d.get("priority")
        elif r["event"] == "hil_unsent":
            h["unsent"] += 1
        elif r["event"] == "decision_received":
            h.update(outcome=d.get("outcome"), decided_by=r["actor"], decided_at=r["ts"], comment=d.get("comment"))
        elif r["event"] == "decision_ignored_unauthorized":
            h["ignored"].append({"actor": r["actor"], "ts": r["ts"]})
        elif r["event"] == "github_action":
            h["github"] = {k: d.get(k) for k in ("mode", "kind", "ok", "url", "error")}
    for h in out.values():
        if not h["times_raised"] and h.get("correlation_id"):
            h["times_raised"] = 1           # raised before the audit trail: time unknown
            h["legacy"] = True
        start = h.get("last_raised_at") or h.get("raised_at")
        waiting = h["outcome"] is None and h.get("status") == "pending_hil" and start
        h["waiting_days"] = round((now - start) / 86400, 1) if waiting else None
        h["overdue"] = bool(waiting and h["waiting_days"] >= overdue_days)
    return sorted(out.values(), key=lambda h: -(h.get("last_raised_at") or h.get("raised_at") or 0))


# ── sources ──────────────────────────────────────────────────────────────────
def source_first_run(source: str) -> Optional[float]:
    t = _t("sources_seen")
    with _engine().connect() as con:
        return con.execute(select(t.c.first_run).where(t.c.source == source)).scalar()


def mark_source_seen(source: str, when: float) -> None:
    t = _t("sources_seen")
    try:
        with _engine().begin() as con:
            con.execute(insert(t).values(source=source, first_run=when))
    except IntegrityError:
        pass


# ── items ────────────────────────────────────────────────────────────────────
def add_item(item: Dict[str, Any], status: str = "new") -> Optional[int]:
    """Insert unless the uid already exists. Returns the new id, or None."""
    t = _t("items")
    now = time.time()
    try:
        with _engine().begin() as con:
            res = con.execute(insert(t).values(
                uid=item["uid"], source=item["source"], kind=item["kind"], title=item["title"][:500],
                link=item.get("link"), published=item.get("published"), first_seen=now, summary=item.get("summary"),
                content=item.get("content"), data=item.get("data") or {}, status=status, updated=now))
            item_id = res.inserted_primary_key[0]
    except IntegrityError:
        return None
    audit("item_collected", item_id, source=item["source"], kind=item["kind"], title=item["title"][:300],
          link=item.get("link"), status=status)
    return item_id


def get_item(item_id: int) -> Optional[Dict[str, Any]]:
    t = _t("items")
    with _engine().connect() as con:
        return _row(con.execute(select(t).where(t.c.id == item_id)).first())


def update_item(item_id: int, **fields: Any) -> None:
    if not fields:
        return
    t = _t("items")
    fields["updated"] = time.time()
    with _engine().begin() as con:
        con.execute(update(t).where(t.c.id == item_id).values(**fields))


def items_for_dedup(statuses: Iterable[str], since: float) -> List[Dict[str, Any]]:
    """Findings already sent for review, newest first (duplicate detection)."""
    t = _t("items")
    q = select(t.c.id, t.c.kind, t.c.title, t.c.summary, t.c.status, t.c.data, t.c.assessment).where(
        t.c.status.in_(list(statuses)), func.coalesce(t.c.updated, t.c.first_seen) >= since).order_by(t.c.id.desc())
    with _engine().connect() as con:
        return [_row(r) for r in con.execute(q)]


def ids_with_status(statuses: Iterable[str]) -> List[int]:
    t = _t("items")
    with _engine().connect() as con:
        return [r[0] for r in con.execute(select(t.c.id).where(t.c.status.in_(list(statuses))).order_by(t.c.id))]


def list_items(status: Optional[str] = None, verdict: Optional[str] = None, source: Optional[str] = None,
               limit: int = 200) -> List[Dict[str, Any]]:
    t = _t("items")
    q = select(t.c.id, t.c.uid, t.c.source, t.c.kind, t.c.title, t.c.link, t.c.published, t.c.first_seen,
               t.c.status, t.c.verdict, t.c.severity, t.c.correlation_id, t.c.error, t.c.updated)
    if status:
        q = q.where(t.c.status == status)
    if verdict:
        q = q.where(t.c.verdict == verdict)
    if source:
        q = q.where(t.c.source == source)
    q = q.order_by(func.coalesce(t.c.published, t.c.first_seen).desc()).limit(limit)
    with _engine().connect() as con:
        return [_row(r) for r in con.execute(q)]


def counts() -> Dict[str, Dict[str, int]]:
    t = _t("items")
    with _engine().connect() as con:
        by_status = {r[0]: r[1] for r in con.execute(select(t.c.status, func.count()).group_by(t.c.status))}
        by_verdict = {r[0]: r[1] for r in con.execute(
            select(t.c.verdict, func.count()).where(t.c.verdict.is_not(None)).group_by(t.c.verdict))}
    return {"status": by_status, "verdict": by_verdict}


def source_counts() -> Dict[str, Dict[str, int]]:
    """Per source: gaps, partial gaps, and cases waiting for review (all time)."""
    t = _t("items")
    out: Dict[str, Dict[str, int]] = {}
    with _engine().connect() as con:
        for src, verdict, status, n in con.execute(
                select(t.c.source, t.c.verdict, t.c.status, func.count()).group_by(t.c.source, t.c.verdict, t.c.status)):
            c = out.setdefault(src, {"gap": 0, "partial": 0, "raised": 0})
            if verdict in ("gap", "partial"):
                c[verdict] += n
            if status == "pending_hil":
                c["raised"] += n
    return out


# ── runs ─────────────────────────────────────────────────────────────────────
def start_run() -> int:
    t = _t("runs")
    with _engine().begin() as con:
        run_id = con.execute(insert(t).values(started=time.time(), status="running")).inserted_primary_key[0]
    set_run(run_id)
    audit("run_started", run_id=run_id)
    return run_id


def finish_run(run_id: int, status: str, stats: Dict[str, Any], error: Optional[str] = None) -> None:
    t = _t("runs")
    with _engine().begin() as con:
        con.execute(update(t).where(t.c.id == run_id).values(finished=time.time(), status=status,
                                                             stats=stats, error=error))
    audit(f"run_{status}", run_id=run_id, stats=stats, error=error)
    set_run(None)


def last_runs(limit: int = 10) -> List[Dict[str, Any]]:
    t = _t("runs")
    with _engine().connect() as con:
        return [_row(r) for r in con.execute(select(t).order_by(t.c.id.desc()).limit(limit))]
