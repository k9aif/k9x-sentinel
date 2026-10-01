# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""The framework's security capability catalog (k9_security/capabilities.yaml).

Looked up in order: SENTINEL_CATALOG_PATH, the installed k9-aif package
(>= 1.14.1 ships it), the framework's main branch on GitHub. Whichever is
used is reported in the UI, so a gap is always judged against a known
framework version."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Set

import requests
import yaml

from sentinel.settings import catalog_path

GITHUB_RAW = ("https://raw.githubusercontent.com/k9aif/k9-aif-framework/main/"
              "k9_aif_abb/k9_security/capabilities.yaml")

_CACHE: Dict[str, Any] = {}


def load(refresh: bool = False) -> Dict[str, Any]:
    if _CACHE and not refresh:
        return _CACHE
    text, origin = _read()
    cat = yaml.safe_load(text)
    if not isinstance(cat, dict) or "capabilities" not in cat:
        raise ValueError(f"capability catalog from {origin} is not valid")
    cat["_origin"] = origin
    _CACHE.clear()
    _CACHE.update(cat)
    return _CACHE


def _read():
    path = catalog_path()
    if path:
        return Path(path).read_text(), path
    try:
        res = resources.files("k9_aif_abb.k9_security") / "capabilities.yaml"
        if res.is_file():
            return res.read_text(), "installed k9-aif package"
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    resp = requests.get(GITHUB_RAW, timeout=20)
    resp.raise_for_status()
    return resp.text, GITHUB_RAW


def taxonomy_ids(cat: Dict[str, Any]) -> Set[str]:
    tax = cat.get("taxonomies", {})
    return set(tax.get("owasp_llm_2025", {})) | set(tax.get("owasp_agentic_2026", {}))


def capability_ids(cat: Dict[str, Any]) -> Set[str]:
    return {c["id"] for c in cat["capabilities"]}


def known_gap_ids(cat: Dict[str, Any]) -> Set[str]:
    return {g["id"] for g in cat.get("known_gaps", [])}


def prompt_text(cat: Dict[str, Any]) -> str:
    """Compact text form of the catalog for the analysis model."""
    lines: List[str] = [f"K9-AIF framework version {cat.get('framework_version', '?')}", "", "Taxonomy:"]
    for name, ids in cat.get("taxonomies", {}).items():
        lines.append(f"  {name}: " + "; ".join(f"{k} {v}" for k, v in ids.items()))
    lines += ["", "Capabilities (id | stage | covers | what it does | limits | on by default):"]
    for c in cat["capabilities"]:
        covers = ", ".join(f"{k}={v}" for k, v in c.get("covers", {}).items())
        lines.append(f"- {c['id']} | {c.get('stage', '')} | {covers} | {c.get('summary', '')}"
                     f" | {c.get('limits', '-')} | {c.get('enabled_by_default', False)}")
    lines += ["", "Known gaps (already tracked by the maintainers):"]
    for g in cat.get("known_gaps", []):
        lines.append(f"- {g['id']} | {', '.join(g.get('covers', []))} | {g.get('summary', '')}")
    return "\n".join(lines)
