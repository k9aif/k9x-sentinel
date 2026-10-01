# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""One run as a standalone HTML report (open, save, attach, print).

Built from the audit trail: every audit event carries the run id, so the
report shows exactly what that run collected, screened, assessed, raised,
deduplicated or failed, with the model and catalog versions it used and
whether the audit chain verifies. A viewer (demo) gets open gaps redacted,
the same rule as the UI."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from sentinel import store

HIDDEN = "Finding under private review"


def _t(ts: Optional[float]) -> str:
    return datetime.fromtimestamp(ts).strftime("%a %b %d %Y, %H:%M:%S") if ts else "—"


def _dur(a: Optional[float], b: Optional[float]) -> str:
    if not (a and b):
        return "—"
    s = int(b - a)
    return f"{s // 3600}h {s % 3600 // 60}m {s % 60}s" if s >= 3600 else f"{s // 60}m {s % 60}s"


def _e(v: Any) -> str:
    return html.escape(str(v if v is not None else "—"))


def build(run_id: int, viewer: bool, sensitive: Callable[[dict], bool], settings: Dict[str, Any]) -> Optional[str]:
    run = next((r for r in store.last_runs(100000) if r["id"] == run_id), None)
    if run is None:
        return None
    events = [e for e in store.audit_events() if e["run_id"] == run_id]
    by_item: Dict[int, List[dict]] = {}
    for e in events:
        if e["item_id"] is not None:
            by_item.setdefault(e["item_id"], []).append(e)
    trigger = next((e for e in store.audit_events() if e["event"] == "run_requested"
                    and e["ts"] <= run["started"] and run["started"] - e["ts"] < 10), None)
    stats = run.get("stats") or {}
    chain = store.verify_chain()

    rows = {"raised": [], "covered": [], "not_relevant": [], "duplicate": [], "failed": [], "other": []}
    collected = 0
    for item_id, evs in sorted(by_item.items()):
        names = {e["event"] for e in evs}
        if "item_collected" in names:
            collected += 1
        if names <= {"item_collected"}:
            continue
        item = store.get_item(item_id) or {"id": item_id, "title": "(removed)"}
        a = item.get("assessment") or {}
        hide = viewer and sensitive(item)
        row = {"id": item_id, "title": HIDDEN if hide else item.get("title"), "source": item.get("source"),
               "verdict": item.get("verdict"), "severity": item.get("severity"),
               "taxonomy": "" if hide else ", ".join(a.get("taxonomy") or []),
               "controls": "" if hide else ", ".join(a.get("matched_capabilities") or []),
               "fix": "" if hide else a.get("suggested_fix"), "hidden": hide,
               "why": next((e["detail"].get("why") or e["detail"].get("reason") for e in evs
                            if e["event"] in ("prefiltered", "recorded_not_raised", "duplicate_not_raised")), None),
               "dup": next((e["detail"].get("duplicate_of") for e in evs if e["event"] == "duplicate_not_raised"), None),
               "error": next((e["detail"].get("error") for e in evs
                              if e["event"] in ("assessment_failed", "assessment_deferred")), None)}
        if "raised_to_hil" in names or "hil_unsent" in names:
            rows["raised"].append(row)
        elif "duplicate_not_raised" in names:
            rows["duplicate"].append(row)
        elif names & {"assessment_failed", "assessment_deferred"} and "assessed" not in names:
            rows["failed"].append(row)
        elif item.get("verdict") == "covered":
            rows["covered"].append(row)
        elif item.get("verdict") == "not_relevant" or "prefiltered" in names:
            rows["not_relevant"].append(row)
        else:
            rows["other"].append(row)

    def table(items: List[dict], cols: List[tuple]) -> str:
        if not items:
            return '<p class="none">None in this run.</p>'
        head = "".join(f"<th>{_e(c[0])}</th>" for c in cols)
        body = "".join("<tr>" + "".join(f"<td>{c[1](r)}</td>" for c in cols) + "</tr>" for r in items)
        return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    title_col = ("Finding", lambda r: (f'<span class="hidden">{_e(r["title"])}</span>' if r["hidden"] else _e(r["title"])))
    sources = stats.get("sources") or {}
    src_rows = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v.get('read'))}</td><td>{_e(v.get('new'))}</td><td>{_e(v.get('baseline'))}</td>"
        f"<td>{_e(v.get('error') or '')}</td></tr>" for k, v in sources.items())
    outcome = Counter((stats.get("assessed") or {}))
    status_cls = {"completed": "ok", "stopped": "warn", "failed": "bad"}.get(run["status"], "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>K9X Sentinel — run #{run_id} report</title>
<style>
  :root {{ --ink:#1d2330; --mute:#5d6678; --line:#e1e4ea; --bg:#f6f7f9; --ok:#1e8449; --warn:#b9770e; --bad:#c0392b; --acc:#5b3fd6; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }}
  main {{ max-width:1100px; margin:0 auto; padding:28px 18px 60px; }}
  h1 {{ margin:0; font-size:22px; }} h2 {{ margin:28px 0 8px; font-size:16px; }}
  .sub {{ color:var(--mute); margin:4px 0 18px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:10px; }}
  .card {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:10px 12px; }}
  .card .k {{ color:var(--mute); font-size:11.5px; text-transform:uppercase; letter-spacing:.04em; }}
  .card .v {{ font-size:15px; margin-top:3px; }}
  .ok {{ color:var(--ok); }} .warn {{ color:var(--warn); }} .bad {{ color:var(--bad); }}
  .wrap {{ overflow-x:auto; background:#fff; border:1px solid var(--line); border-radius:8px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; vertical-align:top; padding:7px 10px; border-bottom:1px solid var(--line); font-size:13px; }}
  th {{ color:var(--mute); font-weight:600; background:#fafbfc; }}
  .hidden {{ color:var(--mute); font-style:italic; }} .none {{ color:var(--mute); }}
  .foot {{ margin-top:30px; color:var(--mute); font-size:12px; }}
  @media print {{ body {{ background:#fff; }} main {{ padding:0; }} }}
</style></head><body><main>
<h1>K9X Sentinel — run #{run_id}</h1>
<div class="sub">Threat watch for the K9-AIF framework · generated {_t(datetime.now().timestamp())}{' · demo view: open gaps redacted' if viewer else ''}</div>
<div class="grid">
  <div class="card"><div class="k">Status</div><div class="v {status_cls}">{_e(run['status'])}</div></div>
  <div class="card"><div class="k">Started</div><div class="v">{_t(run['started'])}</div></div>
  <div class="card"><div class="k">Duration</div><div class="v">{_dur(run['started'], run.get('finished'))}</div></div>
  <div class="card"><div class="k">Triggered by</div><div class="v">{_e(trigger['actor']) + ' (Run now)' if trigger else 'schedule'}</div></div>
  <div class="card"><div class="k">Models</div><div class="v">{_e(settings.get('model'))}<br><span class="sub">Guardian {_e(settings.get('guardian_model'))}</span></div></div>
  <div class="card"><div class="k">Catalog</div><div class="v">k9-aif {_e(settings.get('framework_version'))}</div></div>
</div>
<h2>Summary</h2>
<div class="grid">
  <div class="card"><div class="k">New items collected</div><div class="v">{collected}</div></div>
  <div class="card"><div class="k">Raised for review</div><div class="v {'bad' if rows['raised'] else ''}">{len(rows['raised'])}</div></div>
  <div class="card"><div class="k">Covered</div><div class="v ok">{len(rows['covered'])}</div></div>
  <div class="card"><div class="k">Not relevant</div><div class="v">{len(rows['not_relevant'])}</div></div>
  <div class="card"><div class="k">Duplicates</div><div class="v">{len(rows['duplicate'])}</div></div>
  <div class="card"><div class="k">Failed / deferred</div><div class="v {'warn' if rows['failed'] else ''}">{len(rows['failed'])}</div></div>
</div>
{f'<p class="sub">Stop reason: {_e(stats.get("reason"))}</p>' if stats.get('reason') else ''}
<h2>Raised for human review</h2>
{table(rows['raised'], [('#', lambda r: _e(r['id'])), title_col, ('Source', lambda r: _e(r['source'])),
                        ('Verdict', lambda r: _e(r['verdict'])), ('Severity', lambda r: _e(r['severity'])),
                        ('OWASP', lambda r: _e(r['taxonomy'])), ('Suggested fix', lambda r: _e(r['fix']))])}
<h2>Covered by the framework</h2>
{table(rows['covered'], [('#', lambda r: _e(r['id'])), title_col, ('Source', lambda r: _e(r['source'])),
                         ('Controls', lambda r: _e(r['controls'])), ('OWASP', lambda r: _e(r['taxonomy']))])}
<h2>Duplicates (not raised again)</h2>
{table(rows['duplicate'], [('#', lambda r: _e(r['id'])), title_col, ('Duplicate of', lambda r: '#' + _e(r['dup'])),
                           ('Why', lambda r: _e(r['why']))])}
<h2>Not relevant</h2>
{table(rows['not_relevant'] + rows['other'], [('#', lambda r: _e(r['id'])), title_col, ('Source', lambda r: _e(r['source'])),
                                               ('Why', lambda r: _e(r['why'] or r['verdict']))])}
<h2>Failed or deferred</h2>
{table(rows['failed'], [('#', lambda r: _e(r['id'])), title_col, ('Error', lambda r: _e((r['error'] or '')[:200]))])}
<h2>Sources</h2>
<div class="wrap"><table><thead><tr><th>Source</th><th>Read</th><th>New</th><th>Baseline</th><th>Error</th></tr></thead>
<tbody>{src_rows or '<tr><td colspan="5" class="none">No collection in this run.</td></tr>'}</tbody></table></div>
<h2>Audit</h2>
<p>{len(events)} audit events recorded for this run. Audit chain:
<b class="{'ok' if chain['ok'] else 'bad'}">{'intact' if chain['ok'] else 'BROKEN at event ' + _e(chain['broken_at'])}</b>
({chain['events']} events verified{', last hash ' + _e(events[-1]['hash'][:16]) + '…' if events else ''}).</p>
<p class="foot">Assessment outcomes: {_e(', '.join(f'{v} {k.replace("_", " ")}' for k, v in outcome.items()) or 'none')}.
Generated by K9X Sentinel from its append-only audit trail · github.com/k9aif/k9x-sentinel</p>
</main></body></html>"""
