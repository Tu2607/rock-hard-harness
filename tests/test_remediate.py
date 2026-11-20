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


def test_split_fix_script_oscap14_subshell():
    # oscap 1.4 wraps each fix in a subshell: `(>&2 echo ...); (` ... `) # END fix`.
    # Each body must be valid bash on its own, without a stray `)`.
    import subprocess

    fixes = split_fix_script((FIX / "ubuntu2204-generated-fix-oscap142.sh").read_text())
    assert set(fixes) == {RULE + "package_aide_installed", RULE + "disable_ctrlaltdel_reboot"}
    for body in fixes.values():
        assert body.startswith("# Remediation is applicable only in certain platforms")
        assert body.endswith("fi")
        assert subprocess.run(["bash", "-n"], input=body, text=True).returncode == 0


def test_build_plan_keeps_oscap_fix_order(tmp_path):
    # Scripts are numbered in oscap's order, not by severity or rule id:
    # SSG installs packages before the rules that configure them.
    arf = FIX / "ubuntu2004-stig-arf.xml"
    report = parse_xccdf_results(arf)

    def block(n, rule, body):
        return (
            f"# BEGIN fix ({n} / 2) for '{RULE}{rule}'\n" + "#" * 79 + "\n"
            f"(>&2 echo \"Remediating rule {n}/2: '{RULE}{rule}'\"); (\n{body}\n) # END fix for '{RULE}{rule}'\n"
        )

    script = block(1, "package_aide_installed", "apt-get install -y aide") + block(
        2, "file_permissions_etc_shadow", "chmod 0640 /etc/shadow"
    )
    plan = build_plan(report, arf, tmp_path, script=script)

    names = [Path(s["path"]).name for s in plan.scripts]
    assert names == ["001_medium_package_aide_installed.sh", "002_medium_file_permissions_etc_shadow.sh"]
    assert sorted(names) == names


def test_boot_parameter_note(tmp_path):
    arf = FIX / "ubuntu2004-stig-arf.xml"
    report = parse_xccdf_results(arf)
    plan = build_plan(report, arf, tmp_path / "a", script=(FIX / "ubuntu2004-generated-fix.sh").read_text())
    assert plan.notes == []
    # Pretend the automatable rule is a grub kernel argument.
    rule = report.failed()[0]
    script = (FIX / "ubuntu2004-generated-fix.sh").read_text().replace(rule.short_id, "grub2_audit_argument")
    rule.rule_id = RULE + "grub2_audit_argument"
    plan = build_plan(report, arf, tmp_path / "b", script=script)
    assert len(plan.notes) == 1 and "reboot" in plan.notes[0]
