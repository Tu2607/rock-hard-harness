import json
import stat
from pathlib import Path

from rockhard.parsers import parse_xccdf_results
from rockhard.remediate import build_plan, split_fix_script

FIX = Path(__file__).parent / "fixtures"
RULE = "xccdf_org.ssgproject.content_rule_"


def test_split_fix_script():
    fixes = split_fix_script((FIX / "ubuntu2004-generated-fix.sh").read_text())
    assert set(fixes) == {RULE + "package_aide_installed", RULE + "file_permissions_etc_shadow"}
    aide = fixes[RULE + "package_aide_installed"]
    assert 'apt-get install -y "aide"' in aide
    assert "BEGIN fix" not in aide and "END fix" not in aide and "Remediating rule" not in aide
    # oscap marks this one as missing (platform not applicable): no script.
    assert fixes[RULE + "file_permissions_etc_shadow"] == ""


def test_build_plan(tmp_path):
    arf = FIX / "ubuntu2004-stig-arf.xml"
    report = parse_xccdf_results(arf)
    plan = build_plan(report, arf, tmp_path, script=(FIX / "ubuntu2004-generated-fix.sh").read_text())

    assert [s["rule_id"] for s in plan.scripts] == [RULE + "package_aide_installed"]
    assert [m["rule_id"] for m in plan.manual] == [RULE + "file_permissions_etc_shadow"]

    script = Path(plan.scripts[0]["path"])
    text = script.read_text()
    assert text.startswith("#!/usr/bin/env bash\n# rock-hard-harness remediation (generated for review; NOT applied)")
    assert "UBTU-20-010450" in text
    assert 'apt-get install -y "aide"' in text
    assert not script.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    manifest = json.loads((tmp_path / "plan.json").read_text())
    assert manifest["summary"] == {"scripts": 1, "manual": 1, "review": 0}
