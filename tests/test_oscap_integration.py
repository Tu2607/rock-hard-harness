"""Runs the real oscap binary when it is installed; skipped otherwise."""

import shutil
from pathlib import Path

import pytest

from rockhard import oscap
from rockhard.parsers import parse_oval_results

FIX = Path(__file__).parent / "fixtures"

pytestmark = pytest.mark.skipif(shutil.which("oscap") is None, reason="oscap not installed")


def test_eval_oval_round_trip(tmp_path):
    run = oscap.eval_oval(FIX / "sample-oval-definitions.xml", tmp_path)
    assert run.ok, Path(run.log).read_text()
    report = parse_oval_results(run.results)
    assert report.definitions_evaluated == 5


def test_probe_env_points_at_root(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/hostname").write_text("target\n")
    env = oscap.probe_env(tmp_path)
    assert env["OSCAP_PROBE_ROOT"] == str(tmp_path.resolve())
    assert env["OSCAP_EVALUATION_TARGET"] == f"chroot://{tmp_path.resolve()}"
    assert env["OSCAP_PROBE_PRIMARY_HOST_NAME"] == "target"
    assert "OSCAP_PROBE_ROOT" not in oscap.probe_env("/")
