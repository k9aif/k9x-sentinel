# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""An approved finding becomes a Jira ticket assigned to its owner: the work item that gets the gap closed.

The HIL decision answers "is this a real gap?". The ticket is the work: it carries the finding, the suggested
fix and a definition of done, and is assigned to the owner (by default the account that owns the API token).
Jira emails the assignee. Each run reads the ticket's status back, so Sentinel shows when the work is done.

Calls go through K9-AIF's HttpApiAdapter (a deterministic integration, no model), restricted to the Jira host.
dry_run (the default) builds the exact request and records it without sending; live needs
SENTINEL_JIRA_MODE=live with the URL, email, API token and project key (settings.jira()).
The ticket stays in your Jira site: a gap is private until its fix ships.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from k9_aif_abb.k9_adapters.integration.http_api_adapter import HttpApiAdapter

from sentinel.settings import jira, public_url

DONE = ("- [ ] Control added or changed in k9-aif (commit / PR)\n"
        "- [ ] capabilities.yaml updated in the same commit\n"
        "- [ ] K9X Inspector rule added or updated (rule id), or N/A with the reason\n"
        "- [ ] Regression test that fails on the old code\n"
        "- [ ] Released in k9-aif x.y.z; GitHub advisory published with the release")


def _adapter(cfg: Dict[str, str], url: str, method: str = "POST") -> HttpApiAdapter:
    token = base64.b64encode(f"{cfg['email']}:{cfg['token']}".encode()).decode()
    return HttpApiAdapter(config={
        "url": url, "method": method, "timeout": 30,
        "allowed_hosts": [urlsplit(cfg["url"]).hostname],
        "headers": {"Authorization": f"Basic {token}", "Accept": "application/json",
                    "Content-Type": "application/json"}})


def ticket_fields(item: Dict[str, Any], framework_version: str, cfg: Dict[str, str],
                  assignee: Optional[str]) -> Dict[str, Any]:
    a = item.get("assessment") or {}
    label = "dependency floor" if item.get("kind") == "dependency" else a.get("verdict", "finding")
    summary = f"[Sentinel #{item['id']}] {label}, {a.get('severity', '?')}: {a.get('threat') or item.get('title') or ''}"
    lines = [
        f"K9X Sentinel finding #{item['id']}, approved in K9X HIL as a real {label}.",
        f"Severity: {a.get('severity')} · confidence {a.get('confidence')} · taxonomy: {', '.join(a.get('taxonomy') or []) or '-'}",
        f"Judged against the k9-aif {framework_version} capability catalog.",
        f"Source: {item.get('source')} · {item.get('link') or ''}",
        f"Finding in Sentinel: {public_url()}/#item-{item['id']}",
        "",
        "Threat:", str(a.get("threat") or item.get("title") or ""),
        "",
        "Why it is a gap:", str(a.get("rationale") or ""),
        "",
        "Controls that already apply: " + (", ".join(a.get("matched_capabilities") or []) or "none"),
        "",
        "Suggested fix:", str(a.get("suggested_fix") or ""),
        "",
        "Definition of done:", DONE,
    ]
    fields: Dict[str, Any] = {
        "project": {"key": cfg["project"]},
        "issuetype": {"name": cfg["issue_type"]},
        "summary": summary[:250],
        "description": "\n".join(lines),
        "labels": ["k9x-sentinel", f"severity-{a.get('severity', 'unknown')}",
                   str(label).replace(" ", "-"), f"finding-{item['id']}"],
    }
    if assignee:
        fields["assignee"] = {"accountId": assignee}
    return {"fields": fields}


def _assignee(cfg: Dict[str, str]) -> Optional[str]:
    """The configured owner, else the account that owns the API token (GET /myself)."""
    if cfg["assignee"]:
        return cfg["assignee"]
    out = _adapter(cfg, f"{cfg['url']}/rest/api/2/myself", "GET").execute({})
    return ((out.get("result") or {}).get("accountId")) if out.get("status") == "success" else None


def configured(cfg: Dict[str, str]) -> bool:
    return cfg["mode"] == "live" and all(cfg[k] for k in ("url", "email", "token", "project"))


def create(item: Dict[str, Any], framework_version: str) -> Dict[str, Any]:
    """Create the ticket (live) or record the exact request (dry_run). Never raises: the result is recorded
    with the finding, and a failure is visible there and in the audit trail."""
    cfg = jira()
    if not configured(cfg):
        body = ticket_fields(item, framework_version, cfg, cfg["assignee"] or None)
        return {"mode": "dry_run", "request": {"url": f"{cfg['url'] or '<SENTINEL_JIRA_URL>'}/rest/api/2/issue",
                                               "json": body},
                "note": "SENTINEL_JIRA_MODE=live with SENTINEL_JIRA_URL, _EMAIL, _TOKEN and _PROJECT to create it"}
    assignee = _assignee(cfg)
    body = ticket_fields(item, framework_version, cfg, assignee)
    out = _adapter(cfg, f"{cfg['url']}/rest/api/2/issue").execute({"json": body})
    if out.get("status") != "success" or not isinstance(out.get("result"), dict):
        return {"mode": "live", "ok": False, "error": str(out.get("error") or out.get("result"))[:300]}
    key = out["result"].get("key")
    return {"mode": "live", "ok": True, "key": key, "url": f"{cfg['url']}/browse/{key}",
            "assignee": assignee, "status": "To Do"}


def status_of(key: str) -> Optional[Dict[str, Any]]:
    """The ticket's current status (name, and whether Jira counts it as done), or None if it can't be read."""
    cfg = jira()
    if not configured(cfg) or not key:
        return None
    out = _adapter(cfg, f"{cfg['url']}/rest/api/2/issue/{key}", "GET").execute(
        {"params": {"fields": "status,resolution,assignee"}})
    res = out.get("result") if out.get("status") == "success" else None
    if not isinstance(res, dict):
        return None
    st = (res.get("fields") or {}).get("status") or {}
    return {"status": st.get("name"), "done": (st.get("statusCategory") or {}).get("key") == "done"}


def sync() -> Dict[str, int]:
    """Read each open ticket's status back into its finding (every run). A ticket moved to a done status marks
    the finding's work as done in Sentinel; the change is audited once."""
    from sentinel import activity, store
    counts = {"checked": 0, "done": 0, "changed": 0}
    if not configured(jira()):
        return counts
    for item_id in store.ids_with_status(["decided"]):
        item = store.get_item(item_id) or {}
        t = (item.get("data") or {}).get("jira") or {}
        if not t.get("key") or t.get("done"):
            continue
        now = status_of(t["key"])
        counts["checked"] += 1
        if not now or now["status"] == t.get("status"):
            continue
        counts["changed"] += 1
        counts["done"] += int(now["done"])
        store.update_item(item_id, data={**(item.get("data") or {}), "jira": {**t, **now}})
        store.audit("jira_status", item_id, key=t["key"], status=now["status"], done=now["done"])
        activity.emit("decision", f"#{item_id} Jira {t['key']}: {now['status']}", "ok" if now["done"] else "info",
                      item=item_id)
    return counts
