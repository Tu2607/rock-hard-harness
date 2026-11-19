"""Apply reviewed remediation scripts to the host.

Scanning never changes the host. Applying is a separate, explicitly gated
step: the caller names the rules to apply (or ``--all``) and confirms the
host's hostname.

Where the scripts run (``ROCKHARD_APPLY_MODE``):

* ``nsenter`` (the container's apply mode): the container runs privileged
  with the host's PID namespace, and each script runs through
  ``nsenter --target 1`` in the mount, UTS, IPC, network and PID namespaces
  of the host's init. Files, packages, ``systemctl``, ``sysctl`` and
  ``modprobe`` all act on the host, not the container.
* ``direct``: ``rockhard`` itself runs on the host (no container); scripts
  run with the host's own ``bash``.

Before the first script, ``/etc`` on the host is archived to the output
directory so configuration changes can be rolled back by hand.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

MODES = ("nsenter", "direct")
SCRIPT_TIMEOUT = 1800
NSENTER = ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--"]


class ApplyError(RuntimeError):
    pass


@dataclass
class ScriptResult:
    rule_id: str
    path: str
    returncode: int
    stdout: str
    stderr: str
    seconds: float


@dataclass
class ApplyRun:
    mode: str
    host: str
    backup: str
    results: list[ScriptResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = {
            "applied": sum(r.returncode == 0 for r in self.results),
            "failed": sum(r.returncode != 0 for r in self.results),
            "skipped": len(self.skipped),
        }
        return d


def apply_mode() -> str:
    mode = os.environ.get("ROCKHARD_APPLY_MODE", "direct")
    if mode not in MODES:
        raise ApplyError(f"ROCKHARD_APPLY_MODE must be one of {MODES}, got {mode!r}")
    return mode


def host_command(mode: str, argv: list[str]) -> list[str]:
    return [*NSENTER, *argv] if mode == "nsenter" else list(argv)


def check_host_context(mode: str, proc: Path = Path("/proc")) -> None:
    """Refuse to apply unless commands will really run in the host's namespaces.

    In ``nsenter`` mode, PID 1 must be the host's init, not this container's
    entrypoint. If the container was started without ``--pid=host``, PID 1
    shares our mount namespace and every change would land in the container.
    """
    if mode != "nsenter":
        return
    try:
        pid1_mnt = os.readlink(proc / "1" / "ns" / "mnt")
        self_mnt = os.readlink(proc / "self" / "ns" / "mnt")
    except OSError as e:
        raise ApplyError(f"cannot inspect namespaces ({e}); the apply container must run privileged with --pid=host") from e
    if pid1_mnt == self_mnt:
        raise ApplyError(
            "PID 1 shares this container's mount namespace, so changes would land in the container, "
            "not the host. Start the apply container with --pid=host and --privileged."
        )


def _run(mode: str, argv: list[str], stdin: str | None = None, timeout: int = SCRIPT_TIMEOUT, text: bool = True):
    return subprocess.run(host_command(mode, argv), input=stdin, capture_output=True, text=text, timeout=timeout, check=False)


def host_hostname(mode: str) -> str:
    proc = _run(mode, ["cat", "/proc/sys/kernel/hostname"], timeout=30)
    if proc.returncode != 0:
        raise ApplyError(f"cannot read host hostname: {proc.stderr.strip()}")
    return proc.stdout.strip()


def backup_etc(mode: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"etc-{time.strftime('%Y%m%dT%H%M%S')}.tar.gz"
    proc = _run(mode, ["tar", "--numeric-owner", "-czf", "-", "-C", "/", "etc"], timeout=600, text=False)
    # tar exits 1 when files change while being read; the archive is still usable.
    if proc.returncode not in (0, 1) or not proc.stdout:
        raise ApplyError(f"backup of /etc failed: {proc.stderr.decode(errors='replace').strip()}")
    dest.write_bytes(proc.stdout)
    dest.chmod(0o600)
    return dest


def select_scripts(plan: dict, rule_ids: list[str] | None, apply_all: bool) -> tuple[list[dict], list[str]]:
    """Scripts to run, and requested rules that have no script."""
    scripts = plan.get("scripts", [])
    if apply_all:
        return scripts, []
    if not rule_ids:
        raise ApplyError("name the rules to apply with --rule, or pass --all")
    wanted = {r if r.startswith("xccdf_") else f"xccdf_org.ssgproject.content_rule_{r}" for r in rule_ids}
    chosen = [s for s in scripts if s["rule_id"] in wanted]
    missing = sorted(wanted - {s["rule_id"] for s in chosen})
    return chosen, missing


def _script_path(recorded: str, plan_path: Path) -> Path:
    """The plan records paths as seen by whoever wrote it (container or host).
    Fall back to the scripts/ directory next to the plan."""
    path = Path(recorded)
    if path.is_file():
        return path
    fallback = plan_path.parent / "scripts" / path.name
    if fallback.is_file():
        return fallback
    raise ApplyError(f"script not found: {recorded}")


def apply_plan(
    plan_path: str | Path,
    out_dir: str | Path,
    confirm_host: str,
    rule_ids: list[str] | None = None,
    apply_all: bool = False,
    keep_going: bool = False,
    mode: str | None = None,
) -> ApplyRun:
    mode = mode or apply_mode()
    plan = json.loads(Path(plan_path).read_text())
    chosen, missing = select_scripts(plan, rule_ids, apply_all)
    if not chosen:
        raise ApplyError("nothing to apply" + (f"; no script for: {', '.join(missing)}" if missing else ""))

    check_host_context(mode)
    host = host_hostname(mode)
    if confirm_host != host:
        raise ApplyError(f"--confirm-host {confirm_host!r} does not match this host ({host!r}); nothing applied")

    out = Path(out_dir)
    run = ApplyRun(mode=mode, host=host, backup=str(backup_etc(mode, out / "backup")), skipped=missing)
    log_path = out / "apply-log.json"
    for i, entry in enumerate(chosen):
        script = _script_path(entry["path"], Path(plan_path)).read_text()
        start = time.monotonic()
        try:
            proc = _run(mode, ["/bin/bash", "-s"], stdin=script)
            rc, so, se = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            rc, so, se = 124, "", f"timed out after {SCRIPT_TIMEOUT}s"
        run.results.append(ScriptResult(entry["rule_id"], entry["path"], rc, so[-4000:], se[-4000:], round(time.monotonic() - start, 2)))
        log_path.write_text(json.dumps(run.to_dict(), indent=2))
        if rc != 0 and not keep_going:
            run.skipped += [e["rule_id"] for e in chosen[i + 1 :]]
            break
    log_path.write_text(json.dumps(run.to_dict(), indent=2))
    return run
