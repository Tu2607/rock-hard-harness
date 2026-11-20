# Working with rock-hard-harness

Library code lives in `src/rockhard/`; the CLI (`rockhard`, `src/rockhard/cli.py`) is a thin layer over it and must stay that way so an MCP server can wrap the same functions later. Every CLI command prints JSON on stdout, including errors (`{"error": ..., "type": ...}` with exit code 1).

## Driving a scan

1. `rockhard detect` to see the OS, datastream, profile and feed that will be used.
2. Compliance: `rockhard scan compliance --remediate`, then read `compliance-findings.json` and `remediation/plan.json`.
   * `scripts`: SSG-generated fixes, one per rule. Review them; do not run them.
   * `manual`: failed rules with no usable SSG fix. These are yours to write a fix or a manual procedure for.
   * `review`: rules that came back `error`, `unknown` or `notchecked`.
3. CVE: `rockhard feeds fetch`, then `rockhard scan cve`, then read `cve-findings.json`. Triage by KEV/EPSS, suggest the vendor patch (see `advisories` and `evidence`), and check reachability on the host before calling something urgent.

## Rules

* Never apply a remediation script or patch to a host unless the user asks for that host, explicitly.
* Distro-specific knowledge (datastream names, feed URLs) belongs in `catalog.py` only.
* Treat scanner XML and feeds as untrusted: parse through `parsers.common.load_xml`.
* Tests: `pytest`. Fixtures in `tests/fixtures/` are real `oscap` output; regenerate them with `oscap` rather than editing by hand.
