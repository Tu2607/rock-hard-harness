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


# OpenSCAP's rpm probes read the database from /usr/lib/sysimage/rpm whenever
# that directory exists under the target root, and from /var/lib/rpm
# otherwise (rpm-helper.c, set_rpm_db_path). EL8/EL9 keep the real database in
# /var/lib/rpm, and some of them (Oracle Linux 9 images, for one) also carry a
# small leftover database in /usr/lib/sysimage/rpm. oscap then sees almost no
# packages and the whole profile comes back "notapplicable".
RPMDB_SYSIMAGE = "usr/lib/sysimage/rpm"
RPMDB_VAR = "var/lib/rpm"


def _rpm_dbpath_from_macros(root: Path) -> str | None:
    """The target's own %_dbpath, relative to its root, if it declares one."""
    macros = root / "usr/lib/rpm/macros"
    try:
        text = macros.read_text(errors="replace")
    except OSError:
        return None
    m = re.search(r"^%_dbpath\s+(\S+)", text, re.M)
    if not m:
        return None
    value = m.group(1).replace("%{_var}", "/var").replace("%{_usr}", "/usr").replace("%{_prefix}", "/usr")
    return value.strip("/") if "%" not in value else None


def rpmdb_shadowed(root: str | Path) -> bool:
    """True when oscap would read a different rpm database than the target's rpm.

    That happens when the target uses /var/lib/rpm but also has a separate
    /usr/lib/sysimage/rpm directory, which oscap always prefers.
    """
    root = Path(root)
    sysimage, var = root / RPMDB_SYSIMAGE, root / RPMDB_VAR
    if not sysimage.is_dir() or not var.is_dir():
        return False
    try:
        if sysimage.resolve() == var.resolve():
            return False  # one is a symlink to the other (Fedora, EL10)
    except OSError:
        return False
    return _rpm_dbpath_from_macros(root) == RPMDB_VAR


def compatibility_warnings(version: tuple[int, ...], os_family: tuple[str, ...], root: str | Path) -> list[str]:
    """Known problems with this oscap version for this target."""
    warnings = []
    mounted = str(Path(root).resolve()) != "/"
    if mounted and rpmdb_shadowed(root):
        warnings.append(
            f"{Path(root) / RPMDB_SYSIMAGE} exists but this OS keeps its rpm database in /{RPMDB_VAR}; "
            "oscap will read the wrong database and most rules will come back notapplicable. "
            f"Bind /{RPMDB_VAR} read-only over /{RPMDB_SYSIMAGE} in the target (rockhard-container does this)"
        )
    if mounted and {"debian", "ubuntu"} & set(os_family) and version < MIN_VERSION_DPKG_ROOT:
        warnings.append(
            f"oscap {'.'.join(map(str, version))} cannot read dpkg packages from a mounted root "
            f"(package checks will be wrong or crash); use oscap >= {'.'.join(map(str, MIN_VERSION_DPKG_ROOT))}, "
            "e.g. the rock-hard-harness container"
        )
    return warnings


def applicability_warning(counts: dict[str, int], datastream: str | Path, os_name: str) -> str | None:
    """Warn when a compliance scan evaluated nothing.

    Seen on Rocky Linux with the RHEL fallback datastream: the content's
    platform check does not match the OS, every rule is notapplicable, and
    the scan looks clean.
    """
    if any(n for r, n in counts.items() if r not in ("notapplicable", "notselected")):
        return None
    return (
        f"no rule was evaluated: every selected rule is notapplicable. {Path(datastream).name} does not "
        f"recognise this OS ({os_name}), so this result says nothing about compliance"
    )


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
