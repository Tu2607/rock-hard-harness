"""Parse XCCDF 1.2 results (plain or wrapped in an ARF report) into
normalised compliance findings."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .common import load_xml, text_of

XCCDF = "http://checklists.nist.gov/xccdf/1.2"
X = f"{{{XCCDF}}}"
SH_FIX = "urn:xccdf:fix:script:sh"

# Results that need attention, and how each one is categorised before
# remediation scripts are generated.
NEEDS_REVIEW = ("error", "unknown", "notchecked")
NON_PASSING = ("fail", *NEEDS_REVIEW)


@dataclass
class RuleFinding:
    rule_id: str
    title: str
    result: str
    severity: str
    category: str  # automatable | manual | review | none
    stig_ids: list[str] = field(default_factory=list)
    srg_ids: list[str] = field(default_factory=list)
    cci: list[str] = field(default_factory=list)
    idents: list[str] = field(default_factory=list)  # CCE etc.
    has_sh_fix: bool = False
    fix: dict[str, str] = field(default_factory=dict)  # complexity/disruption/reboot/strategy
    description: str = ""
    rationale: str = ""

    @property
    def short_id(self) -> str:
        return self.rule_id.removeprefix("xccdf_org.ssgproject.content_rule_")


@dataclass
class ComplianceReport:
    benchmark_id: str
    benchmark_title: str
    benchmark_version: str
    profile: str
    test_result_id: str
    start_time: str
    end_time: str
    score: float | None
    counts: dict[str, int]
    findings: list[RuleFinding]

    def failed(self) -> list[RuleFinding]:
        return [f for f in self.findings if f.result == "fail"]

    def to_dict(self, include_passing: bool = False) -> dict:
        d = asdict(self)
        if not include_passing:
            d["findings"] = [asdict(f) for f in self.findings if f.result in NON_PASSING]
        by_category = Counter(f.category for f in self.findings if f.result in NON_PASSING)
        d["summary"] = {
            "automatable": by_category.get("automatable", 0),
            "manual": by_category.get("manual", 0),
            "review": by_category.get("review", 0),
        }
        return d


def _categorise(result: str, has_fix: bool) -> str:
    if result == "fail":
        return "automatable" if has_fix else "manual"
    if result in NEEDS_REVIEW:
        return "review"
    return "none"


def _references(rule) -> tuple[list[str], list[str], list[str]]:
    stig, srg, cci = [], [], []
    for el in (*rule.iterfind(X + "reference"), *rule.iterfind(X + "ident")):
        value = (el.text or "").strip()
        source = (el.get("href") or "") + (el.get("system") or "")
        if not value:
            continue
        if value.startswith("CCI-"):
            cci.append(value)
        elif "cyber.mil" not in source:
            continue
        elif value.startswith("SRG-"):
            srg.append(value)
        elif not value.startswith("SV-"):  # SV-...r..._rule are vuln-rule ids, not STIG ids
            stig.append(value)
    return stig, srg, cci


def parse_xccdf_results(path: str | Path, result_id: str | None = None) -> ComplianceReport:
    root = load_xml(path).getroot()

    test_results = list(root.iter(X + "TestResult"))
    if not test_results:
        raise ValueError(f"{path}: no XCCDF TestResult found")
    if result_id:
        matches = [t for t in test_results if t.get("id") == result_id]
        if not matches:
            raise ValueError(f"{path}: no TestResult with id {result_id}")
        tr = matches[0]
    else:
        tr = test_results[-1]

    rules = {}
    for rule in root.iter(X + "Rule"):
        rules.setdefault(rule.get("id"), rule)

    bench_ref = tr.find(X + "benchmark")
    bench_id = bench_ref.get("id", "") if bench_ref is not None else ""
    benchmark = next((b for b in root.iter(X + "Benchmark") if not bench_id or b.get("id") == bench_id), None)

    findings: list[RuleFinding] = []
    counts: Counter[str] = Counter()
    for rr in tr.iterfind(X + "rule-result"):
        rid = rr.get("idref", "")
        result = rr.findtext(X + "result", "").strip()
        counts[result] += 1
        rule = rules.get(rid)
        title = desc = rationale = ""
        stig = srg = cci = []
        idents: list[str] = []
        fix_attrs: dict[str, str] = {}
        has_fix = False
        if rule is not None:
            title = text_of(rule.find(X + "title"))
            desc = text_of(rule.find(X + "description"))
            rationale = text_of(rule.find(X + "rationale"))
            stig, srg, cci = _references(rule)
            idents = [
                (i.text or "").strip()
                for i in rule.iterfind(X + "ident")
                if (i.text or "").strip() and not (i.text or "").startswith("CCI-")
            ]
            sh = next((f for f in rule.iterfind(X + "fix") if f.get("system") == SH_FIX), None)
            if sh is not None:
                has_fix = True
                fix_attrs = {k: sh.get(k) for k in ("complexity", "disruption", "reboot", "strategy") if sh.get(k)}
        findings.append(
            RuleFinding(
                rule_id=rid,
                title=title,
                result=result,
                severity=rr.get("severity") or (rule.get("severity") if rule is not None else "") or "unknown",
                category=_categorise(result, has_fix),
                stig_ids=stig,
                srg_ids=srg,
                cci=cci,
                idents=idents,
                has_sh_fix=has_fix,
                fix=fix_attrs,
                description=desc,
                rationale=rationale,
            )
        )

    score_el = tr.find(X + "score")
    profile_el = tr.find(X + "profile")
    return ComplianceReport(
        benchmark_id=bench_id,
        benchmark_title=text_of(benchmark.find(X + "title")) if benchmark is not None else "",
        benchmark_version=(benchmark.findtext(X + "version") or "").strip() if benchmark is not None else "",
        profile=profile_el.get("idref", "") if profile_el is not None else "",
        test_result_id=tr.get("id", ""),
        start_time=tr.get("start-time", ""),
        end_time=tr.get("end-time", ""),
        score=float(score_el.text) if score_el is not None and score_el.text else None,
        counts=dict(counts),
        findings=findings,
    )
