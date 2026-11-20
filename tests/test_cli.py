import json
from pathlib import Path

from rockhard.cli import main

FIX = Path(__file__).parent / "fixtures"


def run(capsys, *argv):
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_detect(tmp_path, capsys):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=rhel\nVERSION_ID=9.4\n")
    code, out = run(capsys, "detect", "--root", str(tmp_path))
    assert code == 0
    assert out["os"]["id"] == "rhel"
    assert out["content"]["products"] == ["rhel9"]


def test_errors_are_json(tmp_path, capsys):
    code, out = run(capsys, "detect", "--root", str(tmp_path))
    assert code == 1
    assert out["type"] == "OSDetectionError"


def test_parse_commands(capsys):
    code, out = run(capsys, "parse", "compliance", str(FIX / "ubuntu2004-stig-arf.xml"))
    assert code == 0 and out["summary"]["automatable"] == 2
    code, out = run(capsys, "parse", "cve", str(FIX / "sample-oval-results.xml"))
    assert code == 0 and out["unique_cves"] == 4
