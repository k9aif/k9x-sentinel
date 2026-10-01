# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Readers for the threat-intelligence sources (RSS, Atom, CISA KEV).

Everything fetched here is untrusted: feeds are parsed with defusedxml,
article links are fetched only when they resolve to a public address (a
poisoned feed must not be able to point Sentinel at the LAN), responses are
size-capped, and HTML is reduced to plain text before anything else sees it.
The dependency source (OSV) lives in osv.py."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from defusedxml import ElementTree as ET

MAX_BYTES = 3 * 1024 * 1024
ATOM = "{http://www.w3.org/2005/Atom}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"


# ── fetching ─────────────────────────────────────────────────────────────────
def public_url(url: str) -> bool:
    """http(s) and every address the host resolves to is public."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except (OSError, ValueError):
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return False
    return bool(infos)


def fetch(url: str, timeout: float, user_agent: str, _hops: int = 0) -> bytes:
    """GET a public URL. Redirects are followed by hand (max 5) so every hop
    is checked against public_url, not just the first."""
    if not public_url(url):
        raise ValueError(f"refused to fetch non-public URL: {url}")
    with requests.get(url, timeout=timeout, headers={"User-Agent": user_agent}, stream=True,
                      allow_redirects=False) as resp:
        if resp.is_redirect:
            if _hops >= 5:
                raise ValueError(f"too many redirects: {url}")
            target = resp.headers.get("Location", "")
            return fetch(requests.compat.urljoin(url, target), timeout, user_agent, _hops + 1)
        resp.raise_for_status()
        body = b""
        for chunk in resp.iter_content(65536):
            body += chunk
            if len(body) > MAX_BYTES:
                break
        return body[:MAX_BYTES]


# ── HTML → text ──────────────────────────────────────────────────────────────
class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form", "iframe"}
    BLOCK = {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "tr", "pre", "section", "article"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _Text()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html or "")
    text = "".join(parser.parts)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


# ── parsing ──────────────────────────────────────────────────────────────────
def uid(source: str, key: str) -> str:
    return f"{source}:{hashlib.sha256(key.encode()).hexdigest()[:24]}"


def _ts(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _t(el, path: str) -> str:
    node = el.find(path)
    return (node.text or "").strip() if node is not None and node.text else ""


def parse_feed(body: bytes, source: str) -> List[Dict[str, Any]]:
    """RSS 2.0 or Atom → items (newest first, as published)."""
    root = ET.fromstring(body)
    items: List[Dict[str, Any]] = []
    if root.tag == f"{ATOM}feed":
        for e in root.findall(f"{ATOM}entry"):
            link = ""
            for ln in e.findall(f"{ATOM}link"):
                if ln.get("rel", "alternate") == "alternate":
                    link = ln.get("href", "")
                    break
            key = _t(e, f"{ATOM}id") or link
            summary = _t(e, f"{ATOM}content") or _t(e, f"{ATOM}summary")
            items.append({"uid": uid(source, key), "source": source, "kind": "article",
                          "title": html_to_text(_t(e, f"{ATOM}title")) or "(untitled)", "link": link,
                          "published": _ts(_t(e, f"{ATOM}published") or _t(e, f"{ATOM}updated")),
                          "summary": html_to_text(summary)})
        return items
    channel = root.find("channel")
    for e in (channel.findall("item") if channel is not None else []):
        link = _t(e, "link")
        key = _t(e, "guid") or link
        summary = _t(e, CONTENT) or _t(e, "description")
        items.append({"uid": uid(source, key), "source": source, "kind": "article",
                      "title": html_to_text(_t(e, "title")) or "(untitled)", "link": link,
                      "published": _ts(_t(e, "pubDate")), "summary": html_to_text(summary)})
    return items


def parse_kev(body: bytes, source: str, keywords: List[str]) -> List[Dict[str, Any]]:
    """CISA KEV entries whose vendor, product, name or description mention a keyword."""
    data = json.loads(body)
    # Whole words only: "ai" must not match "detail", "kafka" must not match "kafkaesque".
    pattern = re.compile(r"\b(" + "|".join(re.escape(k.strip().lower()) for k in keywords if k.strip()) + r")\b") \
        if keywords else None
    out: List[Dict[str, Any]] = []
    for v in data.get("vulnerabilities", []):
        text = " ".join(str(v.get(k, "")) for k in
                        ("vendorProject", "product", "vulnerabilityName", "shortDescription")).lower()
        if pattern and not pattern.search(text):
            continue
        cve = v.get("cveID", "")
        out.append({
            "uid": uid(source, cve), "source": source, "kind": "kev",
            "title": f"{cve}: {v.get('vulnerabilityName', '')}".strip(),
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            "published": _ts(v.get("dateAdded")),
            "summary": (f"{v.get('vendorProject', '')} {v.get('product', '')}. {v.get('shortDescription', '')}"
                        f" Required action: {v.get('requiredAction', '')}").strip(),
            "data": {"cve": cve, "vendor": v.get("vendorProject"), "product": v.get("product"),
                     "ransomware": v.get("knownRansomwareCampaignUse")},
        })
    out.sort(key=lambda i: i["published"] or 0, reverse=True)
    return out


def read_source(src: Dict[str, Any], timeout: float, user_agent: str) -> List[Dict[str, Any]]:
    body = fetch(src["url"], timeout, user_agent)
    if src["kind"] in ("rss", "atom"):
        return parse_feed(body, src["id"])
    if src["kind"] == "cisa_kev":
        return parse_kev(body, src["id"], src.get("keywords", []))
    raise ValueError(f"unknown source kind {src['kind']!r}")


def article_text(link: str, timeout: float, user_agent: str, limit: int) -> str:
    body = fetch(link, timeout, user_agent)
    return html_to_text(body.decode("utf-8", errors="replace"))[:limit]
