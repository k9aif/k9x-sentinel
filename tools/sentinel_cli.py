#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""K9X Sentinel command line: read findings from a running Sentinel and trigger runs.

Talks to the Sentinel API with the admin login (HTTP Basic + the
X-Sentinel-Client header scripts must send). Settings come from the
environment, else from this repo's .env (read, never sourced):

    SENTINEL_URL       default https://sentinel.k9x.ai
    SENTINEL_USER      admin login
    SENTINEL_PASSWORD

Commands (add --json for machine-readable output):
    status                     run state, schedule, catalog version, counts
    findings [--open|--all]    open = gaps / partial gaps raised or waiting (default)
    item <id>                  one finding with its assessment and audit trail
    hil                        HIL history (every case sent for review)
    run [--wait]               start a run; --wait follows it until it ends
    report <run_id> [--save F] the run's HTML report (to a file, or its path)

Stdlib only. Never prints the password."""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent


def _env(key: str, default: str = "") -> str:
    if os.environ.get(key):
        return os.environ[key]
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith(key + "="):
                v = line.split("=", 1)[1].strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                return v
    return default


URL = _env("SENTINEL_URL", "https://sentinel.k9x.ai").rstrip("/")


def _call(method: str, path: str, body: Optional[dict] = None, raw: bool = False) -> Any:
    user, pw = _env("SENTINEL_USER", "admin"), _env("SENTINEL_PASSWORD")
    if not pw:
        sys.exit("SENTINEL_PASSWORD not set (environment or k9x_sentinel/.env)")
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Basic {token}", "X-Sentinel-Client": "sentinel_cli",
                                          "Content-Type": "application/json", "User-Agent": "k9x-sentinel-cli"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
            return data.decode() if raw else json.loads(data or b"null")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        sys.exit(f"Sentinel {method} {path}: HTTP {e.code} {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach Sentinel at {URL}: {e.reason}")


def _ts(t: Optional[float]) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "—"


def cmd_status(as_json: bool) -> None:
    s = _call("GET", "/api/status")
    if as_json:
        print(json.dumps(s, indent=2, default=str))
        return
    st, sc, cat = s["state"], s.get("schedule") or {}, s.get("catalog") or {}
    last = (s.get("runs") or [{}])[0]
    print(f"Sentinel   {URL}")
    print(f"Running    {st['running']} {st.get('phase') or ''}".rstrip())
    print(f"Last run   #{last.get('id', '—')} {last.get('status', '—')} {_ts(last.get('started'))}")
    print(f"Schedule   {'daily at ' + sc.get('time', '?') + ' ' + sc.get('timezone', '') if sc.get('enabled') else 'paused'}"
          f" · next {sc.get('next_run') or '—'}")
    print(f"Catalog    k9-aif {cat.get('framework_version')} · {cat.get('capabilities')} controls · {cat.get('origin')}")
    print(f"Models     {s['settings'].get('model')} · Guardian {s['settings'].get('guardian_model')}")
    print(f"Counts     {s['counts']}")


def cmd_findings(mode: str, as_json: bool) -> None:
    rows = _call("GET", "/api/items?limit=1000")
    if mode == "open":
        rows = [r for r in rows if r.get("verdict") in ("gap", "partial")
                and r.get("status") in ("pending_hil", "hil_failed", "decided", "assessed")]
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    if not rows:
        print("No findings." if mode == "all" else "No open gaps or partial gaps.")
        return
    for r in rows:
        print(f"#{r['id']:<5} {r.get('verdict') or '—':12} {r.get('severity') or '—':8} {r.get('status'):12} "
              f"{r.get('source'):26} {r.get('title', '')[:80]}")


def cmd_item(item_id: int, as_json: bool) -> None:
    it = _call("GET", f"/api/items/{item_id}")
    it["audit"] = _call("GET", f"/api/items/{item_id}/audit")
    it.pop("content", None) if not as_json else None
    if as_json:
        print(json.dumps(it, indent=2, default=str))
        return
    a = it.get("assessment") or {}
    print(f"#{it['id']} {it['title']}\n{it.get('link') or ''}")
    print(f"source {it['source']} · status {it['status']} · verdict {a.get('verdict')} · severity {a.get('severity')}"
          f" · confidence {a.get('confidence')}")
    for k in ("threat", "rationale", "suggested_fix"):
        print(f"\n{k.replace('_', ' ').title()}:\n  {a.get(k) or '—'}")
    print(f"\nOWASP: {', '.join(a.get('taxonomy') or []) or '—'}")
    print(f"Relevant controls: {', '.join(a.get('matched_capabilities') or []) or 'none'}")
    print(f"Known gap: {a.get('known_gap') or '—'} · assessed against k9-aif {a.get('framework_version')}")
    if it.get("decision"):
        print(f"Decision: {it['decision']}")
    print("\nAudit trail:")
    for e in it["audit"]:
        print(f"  {_ts(e['ts'])}  {e['event']:30} {e['actor']}")


def cmd_hil(as_json: bool) -> None:
    h = _call("GET", "/api/hil")
    if as_json:
        print(json.dumps(h, indent=2, default=str))
        return
    for c in h["cases"]:
        print(f"#{c['id']:<5} {c.get('verdict') or '—':10} {c.get('severity') or '—':8} "
              f"{(c.get('outcome') or 'pending'):10} {c.get('decided_by') or '—':26} {(c.get('title') or '')[:60]}")


def cmd_run(wait: bool) -> None:
    _call("POST", "/api/run", {})
    print("Run started.")
    if not wait:
        return
    seq, last_phase = 0, ""
    while True:
        time.sleep(3)
        d = _call("GET", f"/api/activity?since={seq}")
        for e in d["events"]:
            seq = e["seq"]
            print(f"  {time.strftime('%H:%M:%S', time.localtime(e['ts']))}  {e['msg']}")
        if not d["running"]:
            break
        if d["phase"] != last_phase:
            last_phase = d["phase"]
    s = _call("GET", "/api/status")
    last = (s.get("runs") or [{}])[0]
    print(f"Run #{last.get('id')} {last.get('status')} · {json.dumps((last.get('stats') or {}).get('assessed', {}))}")


def cmd_report(run_id: int, save: Optional[str]) -> None:
    page = _call("GET", f"/api/runs/{run_id}/report.html", raw=True)
    path = Path(save or f"k9x-sentinel-run-{run_id}.html").expanduser()
    path.write_text(page)
    print(path.resolve())


def main(argv) -> None:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    as_json = "--json" in argv
    args = [a for a in argv if a != "--json"]
    cmd = args[0]
    if cmd == "status":
        cmd_status(as_json)
    elif cmd == "findings":
        cmd_findings("all" if "--all" in args else "open", as_json)
    elif cmd == "item" and len(args) > 1:
        cmd_item(int(args[1].lstrip("#")), as_json)
    elif cmd == "hil":
        cmd_hil(as_json)
    elif cmd == "run":
        cmd_run("--wait" in args)
    elif cmd == "report" and len(args) > 1:
        cmd_report(int(args[1].lstrip("#")), args[args.index("--save") + 1] if "--save" in args else None)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
