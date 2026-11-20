"""Thin wrapper around the ``oscap`` command line tool.

Scans of a mounted host root use the same mechanism as ``oscap-chroot``:
OpenSCAP probes read files relative to ``OSCAP_PROBE_ROOT`` instead of the
container's own filesystem. Nothing here writes to the target root.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

# oscap exit codes: 0 = everything passed, 2 = at least one rule failed,
# anything else is an error.
OK_EXIT_CODES = (0, 2)


class OscapError(RuntimeError):
    pass


@dataclass
class ScanRun:
    command: list[str]
    returncode: int
    results: str
    report: str
    log: str

    @property
    def ok(self) -> bool:
        return self.returncode in OK_EXIT_CODES

    def to_dict(self) -> dict:
        return asdict(self)


def oscap_binary() -> str:
    binary = os.environ.get("ROCKHARD_OSCAP", "oscap")
    if shutil.which(binary) is None:
        raise OscapError(f"oscap binary not found: {binary}")
    return binary


# Below this version the dpkginfo probe crashes (SIGSEGV) or returns nothing
# when OSCAP_PROBE_ROOT points at a mounted root. Observed with 1.3.9.
MIN_VERSION_DPKG_ROOT = (1, 4, 0)


def oscap_version() -> tuple[int, ...]:
    out = subprocess.run([oscap_binary(), "--version"], capture_output=True, text=True, check=False).stdout
    m = re.search(r"\(oscap\)\s+(\d+(?:\.\d+)+)", out)
    if not m:
        raise OscapError("could not read oscap version")
    return tuple(int(x) for x in m.group(1).split("."))


def compatibility_warnings(version: tuple[int, ...], os_family: tuple[str, ...], root: str | Path) -> list[str]:
    """Known problems with this oscap version for this target."""
    warnings = []
    mounted = str(Path(root).resolve()) != "/"
    if mounted and {"debian", "ubuntu"} & set(os_family) and version < MIN_VERSION_DPKG_ROOT:
        warnings.append(
            f"oscap {'.'.join(map(str, version))} cannot read dpkg packages from a mounted root "
            f"(package checks will be wrong or crash); use oscap >= {'.'.join(map(str, MIN_VERSION_DPKG_ROOT))}, "
            "e.g. the rock-hard-harness container"
        )
    return warnings


def probe_env(root: str | Path, os_version: str = "") -> dict[str, str]:
    """Environment that points OpenSCAP probes at ``root`` (oscap-chroot style)."""
    env = dict(os.environ)
    root = str(Path(root).resolve())
    if root == "/":
        return env
    env.update(
        {
            "OSCAP_PROBE_ROOT": root,
            "OSCAP_EVALUATION_TARGET": f"chroot://{root}",
            "OSCAP_PROBE_OS_NAME": platform.system(),
            "OSCAP_PROBE_OS_VERSION": os_version or platform.release(),
            "OSCAP_PROBE_ARCHITECTURE": platform.machine(),
        }
    )
    hostname = Path(root, "etc/hostname")
    if hostname.is_file():
        env["OSCAP_PROBE_PRIMARY_HOST_NAME"] = hostname.read_text(errors="replace").strip()
    return env


def _run(cmd: list[str], env: dict[str, str] | None, log_path: Path | None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    if log_path is not None:
        log_path.write_text(f"$ {' '.join(cmd)}\n\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}")
    return proc


def list_profiles(datastream: str | Path) -> dict[str, str]:
    proc = _run([oscap_binary(), "info", "--profiles", str(datastream)], None, None)
    if proc.returncode != 0:
        raise OscapError(proc.stderr.strip() or f"oscap info failed on {datastream}")
    profiles = {}
    for line in proc.stdout.splitlines():
        pid, _, title = line.partition(":")
        if pid.startswith("xccdf_"):
            profiles[pid] = title
    return profiles


def eval_xccdf(
    datastream: str | Path,
    profile: str,
    out_dir: str | Path,
    root: str | Path = "/",
    rules: list[str] | None = None,
    tailoring: str | Path | None = None,
) -> ScanRun:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    arf, report, log = out / "compliance-arf.xml", out / "compliance-report.html", out / "compliance-oscap.log"
    cmd = [oscap_binary(), "xccdf", "eval", "--profile", profile, "--results-arf", str(arf), "--report", str(report)]
    if tailoring:
        cmd += ["--tailoring-file", str(tailoring)]
    for rule in rules or ():
        cmd += ["--rule", rule]
    cmd.append(str(datastream))
    proc = _run(cmd, probe_env(root), log)
    return ScanRun(cmd, proc.returncode, str(arf), str(report), str(log))


def eval_oval(feed: str | Path, out_dir: str | Path, root: str | Path = "/") -> ScanRun:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    results, report, log = out / "cve-oval-results.xml", out / "cve-report.html", out / "cve-oscap.log"
    cmd = [oscap_binary(), "oval", "eval", "--results", str(results), "--report", str(report), str(feed)]
    proc = _run(cmd, probe_env(root), log)
    # `oscap oval eval` exits 0 whether or not definitions are true.
    return ScanRun(cmd, proc.returncode, str(results), str(report), str(log))


def generate_bash_fix(arf: str | Path, result_id: str) -> str:
    """Bash remediation for every failed rule in an ARF/XCCDF result.

    The script is generated, never executed.
    """
    cmd = [oscap_binary(), "xccdf", "generate", "fix", "--fix-type", "bash", "--result-id", result_id, str(arf)]
    proc = _run(cmd, None, None)
    if proc.returncode != 0:
        raise OscapError(proc.stderr.strip() or "oscap xccdf generate fix failed")
    return proc.stdout
