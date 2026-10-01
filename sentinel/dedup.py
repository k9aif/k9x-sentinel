# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Duplicate detection before a finding is raised to human review.

A finding is compared with every finding already sent for review (pending,
decided or waiting to be sent) within ``duplicate_window_days``:

    certain   same CVE / GHSA id                                -> not raised
              same dependency package with a case still open    -> not raised
              threat meaning similarity >= duplicate_similarity
                and at least one shared OWASP id                -> not raised
    possible  similarity >= possible_duplicate_similarity       -> raised, labelled
                                                                   "possible duplicate of #N"

Meaning similarity uses the framework's embedding service (EmbeddingServiceFactory,
Ollama ``nomic-embed-text``) through k9-aif's ServicePromptEmbedder. Measured on
real threat descriptions: same technique 0.81-0.88, different 0.54-0.68. If the
embedding model is unavailable only the id rules apply: a finding is never
blocked because the comparison could not run."""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Set

from sentinel import store

log = logging.getLogger(__name__)

_IDS = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b", re.I)
REVIEW_STATUSES = ("pending_hil", "decided", "hil_failed")


def advisory_ids(item: Dict[str, Any], assessment: Optional[Dict[str, Any]] = None) -> Set[str]:
    a = assessment or item.get("assessment") or {}
    text = " ".join(str(x or "") for x in (item.get("title"), item.get("summary"), a.get("threat")))
    found = {m.upper() for m in _IDS.findall(text)}
    d = item.get("data") or {}
    if d.get("cve"):
        found.add(str(d["cve"]).upper())
    for adv in d.get("advisories") or []:
        found.update(str(x).upper() for x in [adv.get("id"), *(adv.get("aliases") or [])] if x)
    return found


class Embedder:
    """Lazily built k9-aif ServicePromptEmbedder; None when unavailable."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._e = None
        self._failed = False

    def vector(self, text: str):
        if self._failed or not text:
            return None
        try:
            if self._e is None:
                from k9_aif_abb.k9_inference.learning.prompt_embedder import build_embedder
                self._e = build_embedder({"embedder": "service"}, self.config)
            return self._e.embed(text)
        except Exception as exc:   # model not pulled, Ollama down, package missing
            log.warning("[dedup] embedding unavailable (%s): only id rules apply", exc)
            self._failed = True
            return None


def _similarity(a, b) -> float:
    from k9_aif_abb.k9_inference.learning.prompt_embedder import similarity
    return float(similarity(a, b))


def find_duplicate(item: Dict[str, Any], assessment: Dict[str, Any], config: Dict[str, Any],
                   embedder: Optional[Embedder] = None) -> Optional[Dict[str, Any]]:
    """{"of": id, "certain": bool, "reason": str, "score": float|None} or None."""
    triage = config.get("sentinel", {}).get("triage", {})
    certain_at = float(triage.get("duplicate_similarity", 0.80))
    possible_at = float(triage.get("possible_duplicate_similarity", 0.72))
    window = time.time() - float(triage.get("duplicate_window_days", 180)) * 86400
    candidates = [c for c in store.items_for_dedup(REVIEW_STATUSES, since=window) if c["id"] != item["id"]]
    if not candidates:
        return None

    ids = advisory_ids(item, assessment)
    pkg = (item.get("data") or {}).get("package") if item.get("kind") == "dependency" else None
    for c in candidates:
        shared = ids & advisory_ids(c)
        if shared:
            return {"of": c["id"], "certain": True, "reason": f"same advisory {sorted(shared)[0]}", "score": None}
        if pkg and c.get("kind") == "dependency" and (c.get("data") or {}).get("package") == pkg \
                and c.get("status") in ("pending_hil", "hil_failed"):
            return {"of": c["id"], "certain": True, "reason": f"open case for dependency {pkg}", "score": None}

    threat = assessment.get("threat") or ""
    if item.get("kind") == "dependency" or not threat:
        return None
    embedder = embedder or Embedder(config)
    mine = embedder.vector(threat)
    if mine is None:
        return None
    best = None
    for c in candidates:
        if c.get("kind") == "dependency":
            continue
        ca = c.get("assessment") or {}
        other = embedder.vector(ca.get("threat") or "")
        if other is None:
            continue
        score = _similarity(mine, other)
        if best is None or score > best[0]:
            best = (score, c, ca)
    if best is None:
        return None
    score, c, ca = best
    shared_tax = set(assessment.get("taxonomy") or []) & set(ca.get("taxonomy") or [])
    if score >= certain_at and shared_tax:
        return {"of": c["id"], "certain": True, "score": round(score, 3),
                "reason": f"same threat (similarity {score:.2f}, shared {', '.join(sorted(shared_tax))})"}
    if score >= possible_at:
        return {"of": c["id"], "certain": False, "score": round(score, 3),
                "reason": f"similar threat (similarity {score:.2f})"}
    return None
