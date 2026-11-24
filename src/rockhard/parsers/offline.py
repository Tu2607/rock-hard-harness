"""Find the rules a mounted-root scan could not really evaluate.

With ``OSCAP_PROBE_ROOT`` set (the container scans the host's root mounted
at /host), OpenSCAP turns off the probes that have no offline mode. Their
objects come back flagged ``not applicable`` and the OVAL logic quietly
drops them: a rule gated on one is reported ``notapplicable``, which reads
as "does not concern this host" when the truth is "not checked".

This walks the OVAL results embedded in an ARF report, generically (no rule
names): skipped object -> tests -> definitions (following extend_definition)
-> the XCCDF rules whose check or platform uses them.
"""

from __future__ import annotations

from collections import defaultdict

OVAL_DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
OVAL_RES = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
OVAL_SC = "{http://oval.mitre.org/XMLSchema/oval-system-characteristics-5}"
CPE_LANG = "{http://cpe.mitre.org/language/2.0}"
X = "{http://checklists.nist.gov/xccdf/1.2}"

# OpenSCAP probes with no offline (mounted root) support, by OVAL object
# type. From openscap src/OVAL/probes/probe-table.c and each probe's
# *_offline_mode_supported(); uname and interface read the kernel and the
# network namespace, which a chroot cannot redirect.
OFFLINE_UNSUPPORTED = {
    "uname_object": "uname",
    "interface_object": "interface",
    "inetlisteningservers_object": "inetlisteningservers",
    "iflisteners_object": "iflisteners",
    "routingtable_object": "routingtable",
    "process_object": "process",
}
_SKIPPED_FLAGS = ("not applicable", "not collected")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def skipped_definitions(root) -> dict[str, set[str]]:
    """OVAL definition id -> offline-unsupported probes it depends on."""
    object_type: dict[str, str] = {}
    test_objects: dict[str, set[str]] = defaultdict(set)
    def_tests: dict[str, set[str]] = defaultdict(set)
    def_extends: dict[str, set[str]] = defaultdict(set)
    skipped_objects: set[str] = set()

    for results in root.iter(OVAL_RES + "oval_results"):
        defs = results.find(OVAL_DEF + "oval_definitions")
        if defs is None:
            continue
        for section in defs:
            if not isinstance(section.tag, str):
                continue
            name = _local(section.tag)
            if name == "objects":
                for obj in section:
                    if isinstance(obj.tag, str) and obj.get("id"):
                        object_type[obj.get("id")] = _local(obj.tag)
            elif name == "tests":
                for test in section:
                    if not isinstance(test.tag, str) or not test.get("id"):
                        continue
                    for child in test:
                        if isinstance(child.tag, str) and child.get("object_ref"):
                            test_objects[test.get("id")].add(child.get("object_ref"))
            elif name == "definitions":
                for d in section.iterfind(OVAL_DEF + "definition"):
                    did = d.get("id")
                    for c in d.iter(OVAL_DEF + "criterion"):
                        def_tests[did].add(c.get("test_ref"))
                    for e in d.iter(OVAL_DEF + "extend_definition"):
                        def_extends[did].add(e.get("definition_ref"))
        for co in results.iter(OVAL_SC + "object"):
            if co.get("flag") in _SKIPPED_FLAGS and object_type.get(co.get("id")) in OFFLINE_UNSUPPORTED:
                skipped_objects.add(co.get("id"))

    if not skipped_objects:
        return {}

    memo: dict[str, set[str]] = {}

    def probes_for(did: str, stack: frozenset = frozenset()) -> set[str]:
        if did in memo:
            return memo[did]
        found = set()
        for tid in def_tests.get(did, ()):
            for oid in test_objects.get(tid, ()):
                if oid in skipped_objects:
                    found.add(OFFLINE_UNSUPPORTED[object_type[oid]])
        for ext in def_extends.get(did, ()):
            if ext not in stack:
                found |= probes_for(ext, stack | {did})
        memo[did] = found
        return found

    return {did: p for did in set(def_tests) | set(def_extends) if (p := probes_for(did))}


def _definition_results(root) -> dict[str, str]:
    results: dict[str, str] = {}
    for d in root.iter(OVAL_RES + "definition"):
        if d.get("definition_id") and d.get("result"):
            results[d.get("definition_id")] = d.get("result")
    return results


def _platform_value(test, def_results: dict[str, str]) -> bool | None:
    """Three-valued CPE logical-test: True, False, or None (not evaluated)."""
    values = []
    for child in test:
        if not isinstance(child.tag, str):
            continue
        name = _local(child.tag)
        if name == "logical-test":
            values.append(_platform_value(child, def_results))
        elif name == "check-fact-ref":
            r = def_results.get(child.get("id-ref"))
            values.append(True if r == "true" else False if r == "false" else None)
    if test.get("operator", "AND").upper() == "OR":
        value = True if True in values else None if None in values else False
    else:
        value = False if False in values else None if None in values else True
    if value is not None and test.get("negate", "false") == "true":
        value = not value
    return value


def offline_gaps(root) -> dict[str, list[str]]:
    """XCCDF rule id -> offline-unsupported probes its check or platform needs."""
    by_def = skipped_definitions(root)
    if not by_def:
        return {}
    platform_gaps: dict[str, set[str]] = {}
    for p in root.iter(CPE_LANG + "platform"):
        probes = set()
        for ref in p.iter(CPE_LANG + "check-fact-ref"):
            probes |= by_def.get(ref.get("id-ref"), set())
        if probes:
            platform_gaps["#" + p.get("id")] = probes

    gaps: dict[str, list[str]] = {}
    for rule in root.iter(X + "Rule"):
        probes: set[str] = set()
        node = rule
        while node is not None and node.tag in (X + "Rule", X + "Group"):
            for plat in node.iterfind(X + "platform"):
                probes |= platform_gaps.get(plat.get("idref"), set())
            node = node.getparent()
        for ref in rule.iter(X + "check-content-ref"):
            probes |= by_def.get(ref.get("name"), set())
        if probes:
            gaps[rule.get("id")] = sorted(probes)
    return gaps


def not_really_applicable(root) -> set[str]:
    """Rules reported ``notapplicable`` only because a probe was skipped.

    A rule is genuinely not applicable when one of its platforms (its own or
    an enclosing group's) evaluated false, e.g. no kernel installed. When
    none did and a platform or the check itself could not be evaluated for
    lack of an offline probe, the rule was never checked.
    """
    gaps = offline_gaps(root)
    if not gaps:
        return set()
    def_results = _definition_results(root)
    platforms = {"#" + p.get("id"): p for p in root.iter(CPE_LANG + "platform")}
    out = set()
    for rule in root.iter(X + "Rule"):
        rid = rule.get("id")
        if rid not in gaps:
            continue
        values = []
        node = rule
        while node is not None and node.tag in (X + "Rule", X + "Group"):
            for plat in node.iterfind(X + "platform"):
                p = platforms.get(plat.get("idref"))
                test = p.find(CPE_LANG + "logical-test") if p is not None else None
                if test is not None:
                    values.append(_platform_value(test, def_results))
            node = node.getparent()
        if False in values:
            continue  # a platform ruled it out on its own
        checks = [def_results.get(r.get("name")) for r in rule.iter(X + "check-content-ref")]
        if None in values or any(c not in ("true", "false") for c in checks if c is not None):
            out.add(rid)
    return out
