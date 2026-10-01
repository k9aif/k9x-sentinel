# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Dependency track: does k9-aif *allow* a vulnerable version of a dependency?

Deterministic, no model. For every requirement k9-aif declares (core and
extras), the lowest version its specifier permits (the "floor", e.g. 2.28
for ``requests>=2.28``) is checked against OSV. If the floor is affected by
an advisory that has a fix, the finding is "raise the floor to the fixed
version". One item per package and recommended floor, so a later advisory
that needs a higher floor is a new finding, and the same one is never
raised twice."""

from __future__ import annotations

from importlib import metadata
from typing import Any, Dict, List, Optional, Tuple

import requests
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from sentinel.sources import uid

SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
_ORDER = ["low", "medium", "high", "critical"]


def requirements(package: str = "k9-aif") -> Dict[str, Dict[str, Any]]:
    """{canonical name: {"spec": str, "floor": Version|None, "extras": [..]}} from installed metadata."""
    out: Dict[str, Dict[str, Any]] = {}
    for line in metadata.requires(package) or []:
        req = Requirement(line)
        name = canonicalize_name(req.name)
        extra = None
        if req.marker and "extra" in str(req.marker):
            extra = str(req.marker).split("==")[-1].strip().strip("'\"")
        entry = out.setdefault(name, {"spec": str(req.specifier), "floor": floor(str(req.specifier)),
                                      "extras": []})
        if extra and extra not in entry["extras"]:
            entry["extras"].append(extra)
    return out


def floor(spec: str) -> Optional[Version]:
    """Lowest version a specifier allows; None when it has no lower bound."""
    best: Optional[Version] = None
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        for op in (">=", "==", "~=", ">"):
            if part.startswith(op):
                try:
                    v = Version(part[len(op):].strip().rstrip(".*"))
                except InvalidVersion:
                    continue
                best = v if best is None or v > best else best
                break
    return best


def _v(s: str) -> Optional[Version]:
    try:
        return Version(s)
    except (InvalidVersion, TypeError):
        return None


def affected(version: Version, ranges: List[Dict[str, Any]], versions: List[str]) -> Tuple[bool, Optional[Version]]:
    """(is `version` affected, smallest fixed version above it) per OSV ECOSYSTEM ranges."""
    if str(version) in versions:
        hit = True
    else:
        hit = False
    fixes: List[Version] = []
    for rng in ranges:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        inside = False
        for ev in rng.get("events", []):
            if "introduced" in ev:
                intro = Version("0") if ev["introduced"] == "0" else _v(ev["introduced"])
                if intro is not None and version >= intro:
                    inside = True
            elif "fixed" in ev:
                fix = _v(ev["fixed"])
                if fix is None:
                    continue
                if fix > version:
                    fixes.append(fix)
                if version >= fix:
                    inside = False
            elif "last_affected" in ev:
                last = _v(ev["last_affected"])
                if last is not None and version > last:
                    inside = False
        hit = hit or inside
    return hit, (min(fixes) if fixes else None)


def query(package: str, url: str, timeout: float) -> List[Dict[str, Any]]:
    vulns: List[Dict[str, Any]] = []
    body: Dict[str, Any] = {"package": {"name": package, "ecosystem": "PyPI"}}
    for _ in range(10):
        resp = requests.post(url, json=body, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        vulns += data.get("vulns", [])
        if not data.get("next_page_token"):
            break
        body["page_token"] = data["next_page_token"]
    return vulns


def _severity(v: Dict[str, Any]) -> str:
    raw = str((v.get("database_specific") or {}).get("severity", "")).upper()
    return SEVERITY.get(raw, "medium")


def findings_for(name: str, info: Dict[str, Any], vulns: List[Dict[str, Any]], source: str) -> Optional[Dict[str, Any]]:
    """One item for this package when its floor is affected by fixable advisories."""
    base = info["floor"] or Version("0")
    hits: List[Dict[str, Any]] = []
    for v in vulns:
        if v.get("withdrawn"):
            continue
        for aff in v.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != "PyPI" or canonicalize_name(pkg.get("name", "")) != name:
                continue
            hit, fix = affected(base, aff.get("ranges", []), aff.get("versions", []))
            if hit and fix is not None:
                hits.append({"id": v.get("id"), "aliases": v.get("aliases", []), "summary": v.get("summary", ""),
                             "fixed": str(fix), "severity": _severity(v)})
                break
    if not hits:
        return None
    hits = _merge_duplicates(hits)
    target = max(Version(h["fixed"]) for h in hits)
    sev = max((h["severity"] for h in hits), key=_ORDER.index)
    spec = info["spec"] or "(any version)"
    where = "core" if not info["extras"] else "extras: " + ", ".join(sorted(info["extras"]))
    return {
        "uid": uid(source, f"{name}>={target}"), "source": source, "kind": "dependency",
        "title": f"k9-aif allows {name}{info['spec']} — {len(hits)} known "
                 f"{'vulnerability' if len(hits) == 1 else 'vulnerabilities'}, fixed in {target}",
        "link": f"https://osv.dev/list?ecosystem=PyPI&q={name}",
        "published": None,
        "summary": f"k9-aif ({where}) declares {name}{spec}, whose lowest allowed version {base} is affected by "
                   + "; ".join(f"{h['id']} ({h['severity']}, fixed {h['fixed']}): {h['summary']}" for h in hits)
                   + f". Raising the floor to {name}>={target} excludes all of them.",
        "data": {"package": name, "spec": info["spec"], "floor": str(base), "recommended": f"{name}>={target}",
                 "extras": info["extras"], "severity": sev, "advisories": hits},
    }


def _merge_duplicates(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """OSV lists one vulnerability under several records (GitHub GHSA, PyPI PYSEC,
    the CVE). Merge records that share any id, so counts are distinct
    vulnerabilities, not records (counting records doubled every figure)."""
    groups: List[Dict[str, Any]] = []
    for h in hits:
        ids = {h["id"], *(h.get("aliases") or [])}
        merged = [g for g in groups if g["_ids"] & ids]
        for g in merged:
            groups.remove(g)
            ids |= g["_ids"]
        keep = min([h, *merged], key=lambda x: (not str(x["id"]).startswith("GHSA-"), str(x["id"])))
        sev = max([h["severity"], *[g["severity"] for g in merged]], key=_ORDER.index)
        fixed = str(max(Version(x["fixed"]) for x in [h, *merged]))
        groups.append({**keep, "severity": sev, "fixed": fixed,
                       "aliases": sorted(ids - {keep["id"]}), "_ids": ids})
    for g in groups:
        g.pop("_ids", None)
    return groups


def audit(src: Dict[str, Any], timeout: float, on_package=None) -> List[Dict[str, Any]]:
    """on_package(name, summary_or_None) is called after each package (live view)."""
    out = []
    for name, info in sorted(requirements(src.get("package", "k9-aif")).items()):
        item = findings_for(name, info, query(name, src["url"], timeout), src["id"])
        if item:
            out.append(item)
        if on_package:
            d = (item or {}).get("data") or {}
            on_package(name, f"{info['spec']} allows {len(d['advisories'])} fixed advisories → {d['recommended']}"
                       if item else None)
    return out
