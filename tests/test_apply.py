import json
import os
import socket
from pathlib import Path

import pytest

from rockhard import apply
from rockhard.apply import ApplyError, apply_plan, check_host_context, host_command, select_scripts

RULE = "xccdf_org.ssgproject.content_rule_"


@pytest.fixture
def plan(tmp_path):
    scripts = tmp_path / "remediation" / "scripts"
    scripts.mkdir(parents=True)
    marker = tmp_path / "applied"
    entries = []
    for name, body in [("ok_one", f"echo one >> {marker}"), ("fails", "exit 3"), ("ok_two", f"echo two >> {marker}")]:
        path = scripts / f"{name}.sh"
        path.write_text("#!/usr/bin/env bash\n" + body + "\n")
        entries.append({"rule_id": RULE + name, "path": str(path)})
    plan_path = tmp_path / "remediation" / "plan.json"
    plan_path.write_text(json.dumps({"scripts": entries}))
    return plan_path, marker


@pytest.fixture(autouse=True)
def no_real_backup(monkeypatch, tmp_path):
    monkeypatch.setattr(apply, "backup_etc", lambda mode, out: out / "fake-backup.tar.gz")


def hostname():
    return Path("/proc/sys/kernel/hostname").read_text().strip() if Path("/proc/sys/kernel/hostname").exists() else socket.gethostname()


def test_host_command_uses_host_init_namespaces():
    cmd = host_command("nsenter", ["/bin/bash", "-s"])
    assert cmd[:3] == ["nsenter", "--target", "1"]
    assert {"--mount", "--uts", "--ipc", "--net", "--pid"} <= set(cmd)
    assert cmd[-2:] == ["/bin/bash", "-s"]
    assert host_command("direct", ["x"]) == ["x"]


def test_refuses_when_pid1_is_the_container(tmp_path):
    for pid in ("1", "self"):
        (tmp_path / pid / "ns").mkdir(parents=True)
        os.symlink("mnt:[4026531840]", tmp_path / pid / "ns" / "mnt")
    with pytest.raises(ApplyError, match="land in the container"):
        check_host_context("nsenter", proc=tmp_path)


def test_accepts_host_pid1(tmp_path):
    for pid, ns in (("1", "mnt:[1]"), ("self", "mnt:[2]")):
        (tmp_path / pid / "ns").mkdir(parents=True)
        os.symlink(ns, tmp_path / pid / "ns" / "mnt")
    check_host_context("nsenter", proc=tmp_path)
    check_host_context("direct", proc=tmp_path / "missing")  # direct mode needs no namespace check


def test_select_requires_explicit_rules():
    plan = {"scripts": [{"rule_id": RULE + "a", "path": "a"}]}
    with pytest.raises(ApplyError):
        select_scripts(plan, None, False)
    chosen, missing = select_scripts(plan, ["a", "nope"], False)
    assert [c["rule_id"] for c in chosen] == [RULE + "a"]
    assert missing == [RULE + "nope"]


def test_wrong_hostname_applies_nothing(plan, tmp_path):
    plan_path, marker = plan
    with pytest.raises(ApplyError, match="does not match"):
        apply_plan(plan_path, tmp_path, confirm_host="definitely-not-this-host", apply_all=True, mode="direct")
    assert not marker.exists()


def test_apply_stops_on_failure(plan, tmp_path):
    plan_path, marker = plan
    run = apply_plan(plan_path, tmp_path, confirm_host=hostname(), apply_all=True, mode="direct")
    assert [r.returncode for r in run.results] == [0, 3]
    assert run.skipped == [RULE + "ok_two"]
    assert marker.read_text() == "one\n"
    log = json.loads((tmp_path / "apply-log.json").read_text())
    assert log["summary"] == {"applied": 1, "failed": 1, "skipped": 1}


def test_apply_keep_going_and_path_fallback(plan, tmp_path):
    plan_path, marker = plan
    data = json.loads(plan_path.read_text())
    for e in data["scripts"]:  # paths as a container would have recorded them
        e["path"] = "/out/remediation/scripts/" + Path(e["path"]).name
    plan_path.write_text(json.dumps(data))
    run = apply_plan(plan_path, tmp_path, confirm_host=hostname(), apply_all=True, keep_going=True, mode="direct")
    assert [r.returncode for r in run.results] == [0, 3, 0]
    assert marker.read_text() == "one\ntwo\n"
