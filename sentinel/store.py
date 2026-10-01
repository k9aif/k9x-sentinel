# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""SQLite store: items seen, their assessments and decisions, and runs.

An item is anything a source published (an article, a KEV entry, a release,
a dependency advisory). Its ``uid`` is stable per source, so a re-fetched
item is never assessed or raised twice.

    status  new          fetched, waiting for assessment
            baseline     older than lookback_days when its source was first seen
            assessed     analysed; not raised (covered, irrelevant, below threshold, known gap)
            pending_hil  raised to k9x-hil, waiting for a decision
            hil_failed   raised but Kafka was unavailable; retried next run
            decided      a reviewer approved, rejected or the case expired
            error        assessment failed; retried next run (up to 3 attempts)
            failed       assessment failed 3 times; left for a person to look at
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from sentinel.settings import db_path

_LOCK = threading.Lock()
_JSON = ("data", "screen", "assessment", "decision", "action", "stats")

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    link TEXT,
    published REAL,
    first_seen REAL NOT NULL,
    summary TEXT,
    content TEXT,
    data TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    screen TEXT,
    assessment TEXT,
    verdict TEXT,
    severity TEXT,
    correlation_id TEXT,
    decision TEXT,
    action TEXT,
    error TEXT,
    updated REAL
);
CREATE INDEX IF NOT EXISTS items_status ON items(status);
CREATE TABLE IF NOT EXISTS sources_seen (source TEXT PRIMARY KEY, first_run REAL NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL,
    finished REAL,
    status TEXT NOT NULL,
    stats TEXT,
    error TEXT
);
"""


@contextmanager
def _conn():
    with _LOCK:
        con = sqlite3.connect(str(db_path()), timeout=30)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()


def init() -> None:
    with _conn() as con:
        con.executescript(SCHEMA)


def _row(r: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if r is None:
        return None
    d = dict(r)
    for k in _JSON:
        if k in d and d[k]:
            d[k] = json.loads(d[k])
    return d


def _dump(v: Any) -> Any:
    return json.dumps(v) if isinstance(v, (dict, list)) else v


# ── sources ──────────────────────────────────────────────────────────────────
def source_first_run(source: str) -> Optional[float]:
    with _conn() as con:
        r = con.execute("SELECT first_run FROM sources_seen WHERE source=?", (source,)).fetchone()
        return r[0] if r else None


def mark_source_seen(source: str, when: float) -> None:
    with _conn() as con:
        con.execute("INSERT OR IGNORE INTO sources_seen(source, first_run) VALUES (?, ?)", (source, when))


# ── items ────────────────────────────────────────────────────────────────────
def add_item(item: Dict[str, Any], status: str = "new") -> Optional[int]:
    """Insert unless the uid already exists. Returns the new id, or None."""
    now = time.time()
    with _conn() as con:
        cur = con.execute(
            "INSERT OR IGNORE INTO items(uid, source, kind, title, link, published, first_seen, summary,"
            " content, data, status, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (item["uid"], item["source"], item["kind"], item["title"][:500], item.get("link"),
             item.get("published"), now, item.get("summary"), item.get("content"),
             _dump(item.get("data") or {}), status, now))
        return cur.lastrowid if cur.rowcount else None


def get_item(item_id: int) -> Optional[Dict[str, Any]]:
    with _conn() as con:
        return _row(con.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone())


def update_item(item_id: int, **fields: Any) -> None:
    if not fields:
        return
    fields["updated"] = time.time()
    cols = ", ".join(f"{k}=?" for k in fields)
    with _conn() as con:
        con.execute(f"UPDATE items SET {cols} WHERE id=?", [*(_dump(v) for v in fields.values()), item_id])


def ids_with_status(statuses: Iterable[str]) -> List[int]:
    statuses = list(statuses)
    marks = ",".join("?" * len(statuses))
    with _conn() as con:
        return [r[0] for r in con.execute(
            f"SELECT id FROM items WHERE status IN ({marks}) ORDER BY id", statuses).fetchall()]


def list_items(status: Optional[str] = None, verdict: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    sql, args = "SELECT id, uid, source, kind, title, link, published, first_seen, status, verdict, severity," \
                " correlation_id, error, updated FROM items WHERE 1=1", []
    if status:
        sql += " AND status=?"
        args.append(status)
    if verdict:
        sql += " AND verdict=?"
        args.append(verdict)
    sql += " ORDER BY COALESCE(published, first_seen) DESC LIMIT ?"
    args.append(limit)
    with _conn() as con:
        return [dict(r) for r in con.execute(sql, args).fetchall()]


def counts() -> Dict[str, Dict[str, int]]:
    with _conn() as con:
        by_status = {r[0]: r[1] for r in con.execute("SELECT status, COUNT(*) FROM items GROUP BY status")}
        by_verdict = {r[0]: r[1] for r in con.execute(
            "SELECT verdict, COUNT(*) FROM items WHERE verdict IS NOT NULL GROUP BY verdict")}
    return {"status": by_status, "verdict": by_verdict}


# ── runs ─────────────────────────────────────────────────────────────────────
def start_run() -> int:
    with _conn() as con:
        return con.execute("INSERT INTO runs(started, status) VALUES (?, 'running')", (time.time(),)).lastrowid


def finish_run(run_id: int, status: str, stats: Dict[str, Any], error: Optional[str] = None) -> None:
    with _conn() as con:
        con.execute("UPDATE runs SET finished=?, status=?, stats=?, error=? WHERE id=?",
                    (time.time(), status, json.dumps(stats), error, run_id))


def last_runs(limit: int = 10) -> List[Dict[str, Any]]:
    with _conn() as con:
        return [_row(r) for r in con.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
