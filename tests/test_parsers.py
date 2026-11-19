from pathlib import Path

import pytest

from rockhard.parsers import parse_oval_results, parse_xccdf_results

FIX = Path(__file__).parent / "fixtures"
RULE = "xccdf_org.ssgproject.content_rule_"


@pytest.fixture(scope="module")
def compliance():
    return parse_xccdf_results(FIX / "ubuntu2004-stig-arf.xml")


def test_xccdf_metadata(compliance):
    assert compliance.profile == "xccdf_org.ssgproject.content_profile_stig"
    assert compliance.benchmark_id == "xccdf_org.ssgproject.content_benchmark_UBUNTU_20-04"
    assert compliance.benchmark_version == "0.1.71"
    assert compliance.counts == {"fail": 2, "notapplicable": 2, "pass": 2}
    assert compliance.score == 50.0


def test_xccdf_failed_rule_details(compliance):
    failed = {f.rule_id: f for f in compliance.failed()}
    assert set(failed) == {RULE + "package_aide_installed", RULE + "file_permissions_etc_shadow"}
    aide = failed[RULE + "package_aide_installed"]
    assert aide.title == "Install AIDE"
    assert aide.severity == "medium"
    assert aide.category == "automatable"
    assert aide.stig_ids == ["UBTU-20-010450"]
    assert aide.srg_ids == ["SRG-OS-000445-GPOS-00199"]
    assert "CCI-002696" in aide.cci
    assert aide.fix["reboot"] == "false"
    assert aide.short_id == "package_aide_installed"
    assert "apt-get install aide" in aide.description


def test_xccdf_to_dict_hides_passing_by_default(compliance):
    d = compliance.to_dict()
    assert {f["result"] for f in d["findings"]} == {"fail"}
    assert d["summary"] == {"automatable": 2, "manual": 0, "review": 0}
    assert len(compliance.to_dict(include_passing=True)["findings"]) == 6


def test_xccdf_unknown_result_id():
    with pytest.raises(ValueError):
        parse_xccdf_results(FIX / "ubuntu2004-stig-arf.xml", result_id="nope")


@pytest.fixture(scope="module")
def cve():
    return parse_oval_results(FIX / "sample-oval-results.xml")


def test_oval_only_true_vulnerability_and_patch_definitions(cve):
    ids = [f.definition_id for f in cve.findings]
    # inventory def 5 is true but not a finding; def 2 evaluated false
    assert ids == ["oval:test.ubuntu:def:1", "oval:test.redhat:def:3", "oval:test.debian:def:4"]
    assert cve.definitions_evaluated == 5
    assert cve.feed_timestamp == "2026-11-19T00:00:00"


def test_oval_ubuntu_style(cve):
    f = cve.findings[0]
    assert f.severity == "high"
    assert [c.id for c in f.cves] == ["CVE-2099-0001"]
    assert f.cves[0].severity == "high"
    assert f.cves[0].cvss3.startswith("CVSS:3.1")
    assert f.evidence and "bash package in focal" in f.evidence[0]


def test_oval_redhat_style(cve):
    f = cve.findings[1]
    assert (f.severity, f.vendor_severity) == ("medium", "Moderate")
    assert f.advisories == ["RHSA-2099:0003"]
    assert [c.id for c in f.cves] == ["CVE-2099-0003", "CVE-2099-0004"]
    assert f.cves[0].url.endswith("CVE-2099-0003")  # filled from reference
    # Only the criterion that evaluated true is evidence.
    assert f.evidence == ["dpkg is earlier than 0:99.0"]


def test_oval_debian_style_without_advisory(cve):
    f = cve.findings[2]
    assert f.severity == "unknown"
    assert [c.id for c in f.cves] == ["CVE-2099-0005"]


def test_oval_summary(cve):
    d = cve.to_dict()
    assert d["unique_cves"] == 4
    assert d["summary"] == {"high": 1, "medium": 1, "unknown": 1}


def test_oval_rejects_non_results(tmp_path):
    with pytest.raises(ValueError):
        parse_oval_results(FIX / "sample-oval-definitions.xml")
