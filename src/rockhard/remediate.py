"""Turn a compliance scan into per-rule remediation scripts for review.

Scripts come from SCAP Security Guide's own fixes (``oscap xccdf generate
fix``), split into one file per rule. Rules with no usable fix are listed
for Claude to handle. Nothing here runs a script.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import oscap
from .parsers.xccdf import ComplianceReport, RuleFinding

_BEGIN = re.compile(r"^# BEGIN fix \((\d+) / (\d+)\) for '([^']+)'\s*$", re.M)
_END = "# END fix for '{rule}'"
_MISSING = "IS MISSING!"
_RULE_LINE = "#" * 79

SCRIPT_HEADER = """#!/usr/bin/env bash
# rock-hard-harness remediation (generated for review; NOT applied)
#
# Rule:      {rule_id}
# Title:     {title}
# Severity:  {severity}
# STIG IDs:  {stig}
# SRG / CCI: {srg}
# Fix:       {fix}
# Source:    SCAP Security Guide fix via `oscap xccdf generate fix`
#
# Review before running. Run as root on the scanned host, then rescan.
"""


@dataclass
class RemediationPlan:
    profile: str
    out_dir: str
    scripts: list[dict] = field(default_factory=list)  # rule_id, path, severity
    manual: list[dict] = field(default_factory=list)  # failed, no usable SSG fix: Claude's job
    review: list[dict] = field(default_factory=list)  # error / unknown / notchecked

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = {"scripts": len(self.scripts), "manual": len(self.manual), "review": len(self.review)}
        return d


def split_fix_script(script: str) -> dict[str, str]:
    """Split oscap's combined bash remediation into ``{rule_id: body}``.

    A body is ``""`` when oscap reports the fix as missing.
    """
    fixes: dict[str, str] = {}
    matches = list(_BEGIN.finditer(script))
    for m in matches:
        rule = m.group(3)
        start = m.end()
        end_marker = script.find(_END.format(rule=rule), start)
        body = script[start : end_marker if end_marker != -1 else len(script)]
        lines = body.splitlines()
        # Drop the banner line after BEGIN and oscap's progress echo.
        subshell = False
        while lines and (lines[0].strip() in ("", _RULE_LINE) or lines[0].startswith('(>&2 echo "Remediating rule')):
            # oscap >= 1.4 opens a subshell on the echo line (`...; (`) and
            # closes it on the END line (`) # END fix ...`).
            subshell = subshell or lines[0].rstrip().endswith("; (")
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if subshell and lines and lines[-1].strip() == ")":
            lines.pop()
        body = "\n".join(lines).strip()
        fixes[rule] = "" if _MISSING in body else body
    return fixes


def _summary(f: RuleFinding) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "result": f.result,
        "stig_ids": f.stig_ids,
    }


def _filename(index: int, f: RuleFinding) -> str:
    sev = {"high": "1-high", "medium": "2-medium", "low": "3-low"}.get(f.severity, "4-unknown")
    return f"{sev}_{index:03d}_{f.short_id}.sh"


def build_plan(report: ComplianceReport, arf: str | Path, out_dir: str | Path, script: str | None = None) -> RemediationPlan:
    """Write per-rule scripts and a manifest under ``out_dir``.

    ``script`` lets callers (and tests) supply oscap's combined output
    instead of invoking oscap.
    """
    out = Path(out_dir)
    scripts_dir = out / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    failed = report.failed()
    fixes: dict[str, str] = {}
    if any(f.has_sh_fix for f in failed):
        if script is None:
            script = oscap.generate_bash_fix(arf, report.test_result_id)
        fixes = split_fix_script(script)

    plan = RemediationPlan(profile=report.profile, out_dir=str(out))
    order = {"high": 0, "medium": 1, "low": 2}
    for i, f in enumerate(sorted(failed, key=lambda f: (order.get(f.severity, 3), f.rule_id)), start=1):
        body = fixes.get(f.rule_id, "")
        if not body:
            entry = _summary(f)
            entry["reason"] = "SSG ships no bash fix for this rule" if not f.has_sh_fix else "SSG fix not applicable or not generated"
            entry["description"] = f.description
            plan.manual.append(entry)
            continue
        path = scripts_dir / _filename(i, f)
        header = SCRIPT_HEADER.format(
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            stig=", ".join(f.stig_ids) or "-",
            srg=", ".join(f.srg_ids + f.cci) or "-",
            fix=", ".join(f"{k}={v}" for k, v in f.fix.items()) or "-",
        )
        path.write_text(header + "\n" + body + "\n")
        path.chmod(0o640)  # deliberately not executable until reviewed
        entry = _summary(f)
        entry["path"] = str(path)
        entry["fix"] = f.fix
        plan.scripts.append(entry)

    plan.review = [_summary(f) for f in report.findings if f.category == "review"]
    (out / "plan.json").write_text(json.dumps(plan.to_dict(), indent=2))
    return plan
