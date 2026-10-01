# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
from packaging.version import Version

from sentinel import osv


def vuln(vid, fixed, introduced="0", severity="HIGH", withdrawn=None, name="requests"):
    v = {"id": vid, "summary": f"{vid} summary", "database_specific": {"severity": severity},
         "affected": [{"package": {"ecosystem": "PyPI", "name": name},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]}
    if withdrawn:
        v["withdrawn"] = withdrawn
    return v


def test_floor_of_specifiers():
    assert osv.floor(">=2.28") == Version("2.28")
    assert osv.floor(">=1.0,<3") == Version("1.0")
    assert osv.floor("~=2.8") == Version("2.8")
    assert osv.floor("<3") is None
    assert osv.floor("") is None


def test_affected_ranges():
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.31.0"}]}]
    assert osv.affected(Version("2.28"), ranges, []) == (True, Version("2.31.0"))
    assert osv.affected(Version("2.31.0"), ranges, [])[0] is False
    assert osv.affected(Version("1.9"), ranges, [])[0] is False
    last = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.2"}]}]
    assert osv.affected(Version("1.3"), last, [])[0] is False
    assert osv.affected(Version("1.2"), last, [])[0] is True


def test_finding_recommends_the_highest_needed_fix():
    info = {"spec": ">=2.28", "floor": Version("2.28"), "extras": []}
    item = osv.findings_for("requests", info, [vuln("GHSA-a", "2.31.0", severity="MODERATE"),
                                               vuln("GHSA-b", "2.32.4", severity="HIGH"),
                                               vuln("GHSA-c", "2.20.0")], "osv_dependencies")
    assert item["kind"] == "dependency"
    assert item["data"]["recommended"] == "requests>=2.32.4"
    assert [a["id"] for a in item["data"]["advisories"]] == ["GHSA-a", "GHSA-b"]
    assert item["data"]["severity"] == "high"


def test_no_finding_when_floor_is_safe_withdrawn_or_unfixed():
    info = {"spec": ">=2.32.4", "floor": Version("2.32.4"), "extras": []}
    assert osv.findings_for("requests", info, [vuln("GHSA-a", "2.31.0")], "s") is None
    low = {"spec": ">=2.0", "floor": Version("2.0"), "extras": []}
    assert osv.findings_for("requests", low, [vuln("GHSA-w", "2.31.0", withdrawn="2026-01-01")], "s") is None
    unfixed = {"id": "GHSA-u", "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert osv.findings_for("requests", low, [unfixed], "s") is None


def test_uid_changes_only_when_the_needed_floor_changes():
    info = {"spec": ">=2.28", "floor": Version("2.28"), "extras": ["server"]}
    a = osv.findings_for("requests", info, [vuln("GHSA-a", "2.31.0")], "s")
    b = osv.findings_for("requests", info, [vuln("GHSA-a", "2.31.0"), vuln("GHSA-z", "2.30.0")], "s")
    c = osv.findings_for("requests", info, [vuln("GHSA-n", "2.33.0")], "s")
    assert a["uid"] == b["uid"] != c["uid"]


def test_requirements_read_from_installed_k9_aif():
    reqs = osv.requirements("k9-aif")
    assert "pyyaml" in reqs and reqs["pyyaml"]["floor"] is not None
    assert "pyjwt" in reqs and "oidc" in reqs["pyjwt"]["extras"]



def test_duplicate_osv_records_count_once():
    """GHSA-x and PYSEC-y for the same CVE are one vulnerability, not two."""
    def rec(vid, aliases, fixed):
        v = vuln(vid, fixed)
        v["aliases"] = aliases
        return v
    info = {"spec": ">=3.9", "floor": Version("3.9"), "extras": []}
    vulns = [rec("GHSA-aaaa-bbbb-cccc", ["CVE-2024-0001"], "3.9.2"), rec("PYSEC-2024-1", ["CVE-2024-0001"], "3.9.2"),
             rec("GHSA-dddd-eeee-ffff", ["CVE-2024-0002"], "3.10.0"), rec("PYSEC-2024-2", ["CVE-2024-0002", "GHSA-dddd-eeee-ffff"], "3.10.0")]
    item = osv.findings_for("requests", info, [dict(v, affected=[{**v["affected"][0], "package": {"ecosystem": "PyPI", "name": "requests"}}]) for v in vulns], "s")
    assert "2 known vulnerabilities" in item["title"]
    assert sorted(a["id"] for a in item["data"]["advisories"]) == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
