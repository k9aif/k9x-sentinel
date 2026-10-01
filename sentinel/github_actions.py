# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""What an approved finding turns into on GitHub.

    technique gap / partial  -> private DRAFT repository security advisory
                                (visible only to maintainers until published,
                                because it describes an unpatched weakness)
    dependency floor         -> ordinary issue (the advisories are already public)

dry_run (the default) builds the exact request and records it without
sending; live sends it with SENTINEL_GITHUB_TOKEN."""

from __future__ import annotations

from typing import Any, Dict

import requests

from sentinel.settings import github

API = "https://api.github.com"


def _issue_body(item: Dict[str, Any]) -> Dict[str, Any]:
    d = item.get("data") or {}
    advisories = "\n".join(
        f"- [{a['id']}](https://osv.dev/vulnerability/{a['id']}) ({a['severity']}, fixed in {a['fixed']}): {a['summary']}"
        for a in d.get("advisories", []))
    return {
        "title": f"Raise dependency floor: {d.get('recommended', item['title'])}",
        "body": (f"K9X Sentinel finding #{item['id']}, approved in k9x-hil.\n\n"
                 f"`pyproject.toml` declares `{d.get('package')}{d.get('spec', '')}`; its lowest allowed version "
                 f"({d.get('floor')}) is affected by:\n\n{advisories}\n\n"
                 f"Proposed change: `{d.get('recommended')}` "
                 f"({'core' if not d.get('extras') else 'extras: ' + ', '.join(d['extras'])})."),
        "labels": ["security", "dependencies"],
    }


def _advisory_body(item: Dict[str, Any], framework_version: str) -> Dict[str, Any]:
    a = item.get("assessment") or {}
    covers = ", ".join(a.get("taxonomy", [])) or "—"
    return {
        "summary": f"[Sentinel #{item['id']}] {a.get('threat', item['title'])}"[:1000],
        "description": (
            f"Found by K9X Sentinel (finding #{item['id']}), approved in k9x-hil.\n\n"
            f"**Source:** {item.get('link') or item['source']}\n\n"
            f"**Threat:** {a.get('threat', '')}\n\n"
            f"**Verdict:** {a.get('verdict')} — {a.get('rationale', '')}\n\n"
            f"**OWASP:** {covers}\n\n"
            f"**Relevant controls:** {', '.join(a.get('matched_capabilities', [])) or 'none'}\n\n"
            f"**Suggested fix:** {a.get('suggested_fix', '')}\n\n"
            f"Assessed against the capability catalog of k9-aif {framework_version}."),
        "severity": a.get("severity", "medium"),
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "k9-aif"},
                             "vulnerable_version_range": f"<= {framework_version}",
                             "patched_versions": None}],
    }


def build(item: Dict[str, Any], framework_version: str) -> Dict[str, Any]:
    repo = github()["repo"]
    if item["kind"] == "dependency":
        return {"kind": "issue", "method": "POST", "url": f"{API}/repos/{repo}/issues", "json": _issue_body(item)}
    return {"kind": "security_advisory_draft", "method": "POST",
            "url": f"{API}/repos/{repo}/security-advisories", "json": _advisory_body(item, framework_version)}


def perform(item: Dict[str, Any], framework_version: str) -> Dict[str, Any]:
    """Returns the action record stored on the item."""
    gh = github()
    req = build(item, framework_version)
    if gh["mode"] != "live" or not gh["token"]:
        return {"mode": "dry_run", "kind": req["kind"], "request": {"url": req["url"], "json": req["json"]},
                "note": "SENTINEL_GITHUB_MODE=live and SENTINEL_GITHUB_TOKEN to create it on GitHub"}
    resp = requests.post(req["url"], json=req["json"], timeout=30, headers={
        "Authorization": f"Bearer {gh['token']}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    if resp.status_code >= 300:
        return {"mode": "live", "kind": req["kind"], "ok": False, "status": resp.status_code,
                "error": resp.text[:500]}
    body = resp.json()
    return {"mode": "live", "kind": req["kind"], "ok": True,
            "url": body.get("html_url"), "id": body.get("ghsa_id") or body.get("number")}
