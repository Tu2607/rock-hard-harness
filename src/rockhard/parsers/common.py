from __future__ import annotations

import re
from pathlib import Path

from lxml import etree

_WS = re.compile(r"\s+")


def load_xml(path: str | Path) -> etree._ElementTree:
    """Parse untrusted scanner/feed XML: no entity expansion, no network.

    ``huge_tree`` is required because ARF files embed the whole datastream
    and vendor OVAL feeds run to hundreds of megabytes.
    """
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True, remove_blank_text=True)
    return etree.parse(str(path), parser)


def text_of(el) -> str:
    """Flattened, whitespace-normalised text of an element (HTML markup dropped)."""
    if el is None:
        return ""
    return _WS.sub(" ", "".join(el.itertext())).strip()
