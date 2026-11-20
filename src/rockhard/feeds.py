"""Download and cache vendor OVAL feeds.

Fetching is a separate step from scanning so the scan container can run
with networking disabled.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import time
import urllib.request
from pathlib import Path

from .catalog import OvalFeed

DEFAULT_CACHE = "/var/cache/rockhard/feeds"
DEFAULT_MAX_AGE = 24 * 3600

_DECOMPRESSORS = {".bz2": bz2.open, ".gz": gzip.open, ".xz": lzma.open}


def cache_dir() -> Path:
    return Path(os.environ.get("ROCKHARD_FEED_CACHE", DEFAULT_CACHE))


def cached_path(feed: OvalFeed, directory: Path | None = None) -> Path:
    return (directory or cache_dir()) / feed.filename


def decompress(src: Path, dest: Path) -> Path:
    opener = _DECOMPRESSORS.get(src.suffix)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with (opener(src, "rb") if opener else open(src, "rb")) as fin, open(tmp, "wb") as fout:
        shutil.copyfileobj(fin, fout, length=1 << 20)
    tmp.replace(dest)
    return dest


def fetch(feed: OvalFeed, directory: Path | None = None, max_age: int = DEFAULT_MAX_AGE, force: bool = False) -> Path:
    """Return a local, decompressed copy of ``feed``, downloading if stale."""
    directory = directory or cache_dir()
    directory.mkdir(parents=True, exist_ok=True)
    dest = cached_path(feed, directory)
    if not force and dest.is_file() and time.time() - dest.stat().st_mtime < max_age:
        return dest

    # Keep the compression suffix on the download so decompress() picks the codec.
    raw = directory / (".download-" + feed.url.rsplit("/", 1)[-1])
    req = urllib.request.Request(feed.url, headers={"User-Agent": "rock-hard-harness"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, open(raw, "wb") as out:
            shutil.copyfileobj(resp, out, length=1 << 20)
        return decompress(raw, dest)
    finally:
        raw.unlink(missing_ok=True)
