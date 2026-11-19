"""Map a detected OS to SCAP content: the SSG datastream, the STIG profile,
and the vendor OVAL vulnerability feed.

Everything distro-specific lives in this file so it is easy to review and
extend. Datastream names follow SCAP Security Guide (ComplianceAsCode)
naming: ``ssg-<product>-ds.xml``.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from .osdetect import OSInfo

DEFAULT_CONTENT_DIR = "/usr/share/xml/scap/ssg/content"
STIG_PROFILE = "xccdf_org.ssgproject.content_profile_stig"


class UnsupportedOSError(RuntimeError):
    pass


@dataclass(frozen=True)
class OvalFeed:
    url: str
    vendor: str
    note: str = ""

    @property
    def filename(self) -> str:
        """Decompressed local filename for the feed."""
        name = self.url.rsplit("/", 1)[-1]
        for ext in (".bz2", ".gz", ".xz"):
            if name.endswith(ext):
                return name[: -len(ext)]
        return name


@dataclass(frozen=True)
class ContentSelection:
    products: tuple[str, ...]  # SSG product candidates, best first
    datastream: str | None  # resolved path, or None if not found
    profile: str
    oval_feed: OvalFeed | None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["products"] = list(self.products)
        return d


def content_dir() -> Path:
    return Path(os.environ.get("ROCKHARD_CONTENT_DIR", DEFAULT_CONTENT_DIR))


def ssg_products(info: OSInfo) -> tuple[str, ...]:
    """SSG product names to try for this OS, most specific first."""
    major = info.major
    ver_nodot = info.version_id.replace(".", "")
    i = info.id
    if i == "rhel":
        return (f"rhel{major}",)
    if i == "centos":
        # CentOS Stream 9+ has its own product; 7/8 are classic CentOS.
        return (f"cs{major}", f"centos{major}", f"rhel{major}") if int(major or 0) >= 9 else (f"centos{major}", f"rhel{major}")
    if i in ("almalinux", "rocky"):
        return (f"{i}{major}", f"rhel{major}")
    if i == "ol":
        return (f"ol{major}",)
    if i == "fedora":
        return ("fedora",)
    if i == "ubuntu":
        return (f"ubuntu{ver_nodot}",)
    if i == "debian":
        return (f"debian{major}",)
    if i in ("sles", "sled", "sle-micro"):
        return (f"sle{major}",)
    if i.startswith("opensuse"):
        return ("opensuse",)
    if i == "amzn":
        return (f"al{major}",)
    # Fall back on ID_LIKE: e.g. an RHEL rebuild we do not know by name.
    for like in info.id_like:
        if like in ("rhel", "fedora") and major:
            return (f"rhel{major}",)
    raise UnsupportedOSError(f"no SSG content mapping for {info.id} {info.version_id}")


def oval_feed(info: OSInfo) -> OvalFeed | None:
    """Vendor OVAL vulnerability feed for this OS, or None if there is none."""
    major = info.major
    code = info.version_codename
    i = info.id
    if i == "rhel" or (i == "centos" and major in ("7", "8")):
        return OvalFeed(
            f"https://security.access.redhat.com/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2",
            "redhat",
            "CentOS uses the RHEL feed; package signatures differ, so treat results as advisory."
            if i == "centos"
            else "",
        )
    if i == "almalinux":
        return OvalFeed(f"https://security.almalinux.org/oval/org.almalinux.alsa-{major}.xml.bz2", "almalinux")
    if i == "ol":
        return OvalFeed(f"https://linux.oracle.com/security/oval/com.oracle.elsa-ol{major}.xml.bz2", "oracle")
    if i == "ubuntu" and code:
        return OvalFeed(f"https://security-metadata.canonical.com/oval/com.ubuntu.{code}.cve.oval.xml.bz2", "ubuntu")
    if i == "debian" and code:
        return OvalFeed(f"https://www.debian.org/security/oval/oval-definitions-{code}.xml.bz2", "debian")
    if i == "sles":
        sp = info.version_id.split(".", 1)[1] if "." in info.version_id else ""
        name = f"suse.linux.enterprise.server.{major}" + (f"-sp{sp}" if sp and sp != "0" else "")
        return OvalFeed(f"https://ftp.suse.com/pub/projects/security/oval/{name}.xml.gz", "suse")
    if i == "opensuse-leap":
        return OvalFeed(
            f"https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.{info.version_id}.xml.gz", "suse"
        )
    return None


def select_content(info: OSInfo, directory: Path | None = None, profile: str | None = None) -> ContentSelection:
    directory = directory or content_dir()
    products = ssg_products(info)
    datastream = None
    for product in products:
        candidate = directory / f"ssg-{product}-ds.xml"
        if candidate.is_file():
            datastream = str(candidate)
            break
    return ContentSelection(
        products=products,
        datastream=datastream,
        profile=profile or STIG_PROFILE,
        oval_feed=oval_feed(info),
    )
