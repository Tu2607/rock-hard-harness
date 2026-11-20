"""Parse ``oscap oval eval --results`` output into normalised CVE findings.

Works across vendor feeds (Red Hat, Ubuntu, Debian, SUSE, Oracle,
AlmaLinux): CVE ids are taken from ``reference[@source='CVE']`` and from
the ``advisory/cve`` extension elements that Red Hat, Ubuntu and SUSE use.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .common import load_xml, text_of

RES = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"

FINDING_CLASSES = ("vulnerability", "patch")
DESCRIPTION_LIMIT = 1500

_SEVERITY_MAP = {
    "critical": "critical",
    "important": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "negligible": "low",
}


def normalise_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.strip().lower(), "unknown") if raw else "unknown"


@dataclass
class CveRef:
    id: str
    severity: str = ""  # vendor's own wording (impact / priority)
    cvss3: str = ""
    url: str = ""


@dataclass
class CveFinding:
    definition_id: str
    oval_class: str
    title: str
    severity: str  # normalised: critical | high | medium | low | unknown
    vendor_severity: str
    cves: list[CveRef] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)  # RHSA-..., USN-..., DSA-...
    references: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # criteria that evaluated true
    description: str = ""


@dataclass
class CveReport:
    generator: str
    feed_timestamp: str
    definitions_evaluated: int
    counts: dict[str, int]
    findings: list[CveFinding]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = dict(Counter(f.severity for f in self.findings))
        d["unique_cves"] = len({c.id for f in self.findings for c in f.cves})
        return d


def _cves(meta) -> list[CveRef]:
    found: dict[str, CveRef] = {}
    adv = meta.find(DEF + "advisory")
    if adv is not None:
        for el in adv.iter():
            if not isinstance(el.tag, str) or el.tag.rsplit("}", 1)[-1] != "cve":
                continue
            cid = (el.text or "").strip()
            if cid:
                found[cid] = CveRef(
                    id=cid,
                    severity=el.get("impact") or el.get("priority") or "",
                    cvss3=el.get("cvss3") or el.get("cvss_vector") or el.get("cvss_score") or "",
                    url=el.get("href") or "",
                )
    for ref in meta.iterfind(DEF + "reference"):
        if (ref.get("source") or "").upper() == "CVE":
            cid = ref.get("ref_id", "").strip()
            if not cid:
                continue
            if cid not in found:
                found[cid] = CveRef(id=cid, url=ref.get("ref_url") or "")
            elif not found[cid].url:
                found[cid].url = ref.get("ref_url") or ""
    return list(found.values())


def _vendor_severity(meta, cves: list[CveRef]) -> str:
    adv = meta.find(DEF + "advisory")
    if adv is not None:
        sev = next((e for e in adv.iter() if isinstance(e.tag, str) and e.tag.rsplit("}", 1)[-1] == "severity"), None)
        if sev is not None and (sev.text or "").strip():
            return sev.text.strip()
    # Fall back to the worst per-CVE rating.
    order = ["critical", "important", "high", "moderate", "medium", "low", "negligible"]
    ratings = [c.severity.lower() for c in cves if c.severity.lower() in order]
    return min(ratings, key=order.index) if ratings else ""


def _true_criteria(criteria, test_results: dict[str, str]) -> list[str]:
    if criteria is None:
        return []
    out = []
    for crit in criteria.iter(DEF + "criterion"):
        if test_results.get(crit.get("test_ref", "")) == "true":
            comment = crit.get("comment", "").strip()
            if comment and comment not in out:
                out.append(comment)
    return out


def parse_oval_results(path: str | Path, include_classes: tuple[str, ...] = FINDING_CLASSES) -> CveReport:
    root = load_xml(path).getroot()

    system = root.find(f"{RES}results/{RES}system")
    if system is None:
        raise ValueError(f"{path}: not an OVAL results document")

    def_results = {d.get("definition_id"): d.get("result", "") for d in system.iterfind(f"{RES}definitions/{RES}definition")}
    test_results = {t.get("test_id"): t.get("result", "") for t in system.iterfind(f"{RES}tests/{RES}test")}

    defs_doc = root.find(DEF + "oval_definitions")
    generator = ""
    timestamp = ""
    if defs_doc is not None:
        gen = defs_doc.find(DEF + "generator")
        if gen is not None:
            timestamp = (gen.findtext("{http://oval.mitre.org/XMLSchema/oval-common-5}timestamp") or "").strip()
            generator = (gen.findtext("{http://oval.mitre.org/XMLSchema/oval-common-5}product_name") or "").strip()

    counts = Counter(def_results.values())
    findings: list[CveFinding] = []
    for definition in (defs_doc.iter(DEF + "definition") if defs_doc is not None else ()):
        did = definition.get("id", "")
        cls = definition.get("class", "")
        if def_results.get(did) != "true" or cls not in include_classes:
            continue
        meta = definition.find(DEF + "metadata")
        if meta is None:
            continue
        cves = _cves(meta)
        vendor_sev = _vendor_severity(meta, cves)
        advisories, refs = [], []
        for ref in meta.iterfind(DEF + "reference"):
            if (ref.get("source") or "").upper() != "CVE" and ref.get("ref_id"):
                advisories.append(ref.get("ref_id"))
            if ref.get("ref_url"):
                refs.append(ref.get("ref_url"))
        desc = text_of(meta.find(DEF + "description"))
        findings.append(
            CveFinding(
                definition_id=did,
                oval_class=cls,
                title=text_of(meta.find(DEF + "title")),
                severity=normalise_severity(vendor_sev),
                vendor_severity=vendor_sev,
                cves=cves,
                advisories=advisories,
                references=refs,
                evidence=_true_criteria(definition.find(DEF + "criteria"), test_results),
                description=desc[:DESCRIPTION_LIMIT] + ("…" if len(desc) > DESCRIPTION_LIMIT else ""),
            )
        )

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    findings.sort(key=lambda f: (rank[f.severity], f.definition_id))
    return CveReport(
        generator=generator,
        feed_timestamp=timestamp,
        definitions_evaluated=len(def_results),
        counts=dict(counts),
        findings=findings,
    )
