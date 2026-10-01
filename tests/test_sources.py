# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
from pathlib import Path

import pytest

from sentinel import sources

FIX = Path(__file__).parent / "fixtures"


def test_rss_items_are_plain_text_with_stable_uids():
    items = sources.parse_feed((FIX / "rss.xml").read_bytes(), "threatlabz")
    assert [i["link"] for i in items] == ["https://example.com/a1", "https://example.com/old"]
    first = items[0]
    assert first["title"] == "Agents phishing agents: a new technique"
    assert "alert(1)" not in first["summary"] and "tool output" in first["summary"]
    assert first["published"] > items[1]["published"]
    again = sources.parse_feed((FIX / "rss.xml").read_bytes(), "threatlabz")
    assert again[0]["uid"] == first["uid"]
    assert sources.parse_feed((FIX / "rss.xml").read_bytes(), "other")[0]["uid"] != first["uid"]


def test_atom_entries():
    items = sources.parse_feed((FIX / "atom.xml").read_bytes(), "mitre_atlas_releases")
    assert len(items) == 1
    assert items[0]["link"].endswith("/v5.0.0")
    assert items[0]["summary"] == "New techniques for agent memory poisoning"


def test_kev_keeps_only_keyword_matches():
    items = sources.parse_kev((FIX / "kev.json").read_bytes(), "cisa_kev", ["ollama", "kafka"])
    assert [i["data"]["cve"] for i in items] == ["CVE-2026-2222"]
    assert items[0]["link"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-2222"


def test_xml_bombs_are_refused():
    bomb = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>'
    with pytest.raises(Exception):
        sources.parse_feed(bomb, "x")


@pytest.mark.parametrize("url", ["http://127.0.0.1/x", "http://localhost:8114/", "http://192.168.1.10/",
                                 "http://10.0.0.5/", "http://169.254.169.254/latest/meta-data",
                                 "file:///etc/passwd", "ftp://example.com/x", "http://[::1]/"])
def test_non_public_urls_are_never_fetched(url):
    assert not sources.public_url(url)
    with pytest.raises(ValueError):
        sources.fetch(url, 5, "test")


def test_html_to_text_drops_scripts_and_styles():
    html = "<html><head><style>p{}</style></head><body><nav>menu</nav><p>Hello</p><script>evil()</script><p>world</p></body></html>"
    text = sources.html_to_text(html)
    assert "Hello" in text and "world" in text
    assert "evil" not in text and "menu" not in text and "p{}" not in text


def test_kev_keywords_match_whole_words_only():
    body = (b'{"vulnerabilities": [{"cveID": "CVE-1", "vendorProject": "Adobe", "product": "Commerce",'
            b' "vulnerabilityName": "Incorrect authorization detail", "dateAdded": "2026-09-01"},'
            b' {"cveID": "CVE-2", "vendorProject": "Ollama", "product": "Ollama", "vulnerabilityName": "x",'
            b' "dateAdded": "2026-09-02"}]}')
    items = sources.parse_kev(body, "cisa_kev", ["ai", "ollama"])
    assert [i["data"]["cve"] for i in items] == ["CVE-2"]
