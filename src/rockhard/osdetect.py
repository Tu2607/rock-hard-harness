"""Detect the operating system of a target root filesystem.

The scanner runs inside a container with the host's root mounted read-only
(by default at ``/host``), so detection reads ``os-release`` relative to that
root rather than the container's own ``/etc``.
"""

from __future__ import annotations

import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path

OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")


class OSDetectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class OSInfo:
    id: str
    version_id: str
    id_like: tuple[str, ...] = field(default_factory=tuple)
    version_codename: str = ""
    pretty_name: str = ""

    @property
    def major(self) -> str:
        return self.version_id.split(".", 1)[0]

    @property
    def family(self) -> tuple[str, ...]:
        """The OS id followed by its ID_LIKE ancestors, most specific first."""
        return (self.id, *self.id_like)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id_like"] = list(self.id_like)
        return d


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release(5) content into a dict. Quoting follows shell rules."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        try:
            parts = shlex.split(value, posix=True)
        except ValueError:
            parts = [value.strip("\"'")]
        values[key.strip()] = parts[0] if parts else ""
    return values


def detect_os(root: str | Path = "/") -> OSInfo:
    root = Path(root)
    for rel in OS_RELEASE_PATHS:
        path = root / rel
        if path.is_file():
            data = parse_os_release(path.read_text(encoding="utf-8", errors="replace"))
            break
    else:
        raise OSDetectionError(f"no os-release found under {root}")

    os_id = data.get("ID", "").lower()
    if not os_id:
        raise OSDetectionError(f"os-release under {root} has no ID")

    codename = data.get("VERSION_CODENAME", "") or data.get("UBUNTU_CODENAME", "")
    return OSInfo(
        id=os_id,
        version_id=data.get("VERSION_ID", ""),
        id_like=tuple(data.get("ID_LIKE", "").lower().split()),
        version_codename=codename.lower(),
        pretty_name=data.get("PRETTY_NAME", ""),
    )
