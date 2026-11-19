"""``rockhard`` command line: every command prints JSON on stdout so Claude
(or any other caller) can consume it directly."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, catalog, feeds, oscap, remediate
from .osdetect import OSDetectionError, detect_os
from .parsers import parse_oval_results, parse_xccdf_results


class CLIError(RuntimeError):
    pass


def _emit(data: dict) -> None:
    json.dump(data, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _write(out: Path, name: str, data: dict) -> str:
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    path.write_text(json.dumps(data, indent=2, default=str))
    return str(path)


def _resolve(args):
    info = detect_os(args.root)
    sel = catalog.select_content(info, profile=getattr(args, "profile", None))
    return info, sel


def cmd_detect(args) -> dict:
    info, sel = _resolve(args)
    return {"root": args.root, "os": info.to_dict(), "content": sel.to_dict(), "content_dir": str(catalog.content_dir())}


def cmd_feeds_fetch(args) -> dict:
    if args.url:
        feed = catalog.OvalFeed(args.url, "custom")
    else:
        info, sel = _resolve(args)
        if sel.oval_feed is None:
            raise CLIError(f"no known OVAL feed for {info.id} {info.version_id}; pass --url")
        feed = sel.oval_feed
    path = feeds.fetch(feed, force=args.force)
    return {"feed": feed.url, "vendor": feed.vendor, "path": str(path), "note": feed.note}


def cmd_scan_compliance(args) -> dict:
    info, sel = _resolve(args)
    datastream = args.datastream or sel.datastream
    if not datastream:
        raise CLIError(
            f"no SSG datastream for {info.id} {info.version_id} in {catalog.content_dir()} "
            f"(looked for: {', '.join('ssg-%s-ds.xml' % p for p in sel.products)}); pass --datastream"
        )
    profiles = oscap.list_profiles(datastream)
    if sel.profile not in profiles:
        raise CLIError(
            f"profile {sel.profile} is not in {datastream}. Available: " + (", ".join(sorted(profiles)) or "none")
        )
    out = Path(args.out)
    run = oscap.eval_xccdf(datastream, sel.profile, out, root=args.root, rules=args.rule, tailoring=args.tailoring)
    if not run.ok:
        raise CLIError(f"oscap failed with exit code {run.returncode}; see {run.log}")
    report = parse_xccdf_results(run.results)
    data = report.to_dict(include_passing=args.all)
    result = {
        "track": "compliance",
        "os": info.to_dict(),
        "datastream": datastream,
        "scan": run.to_dict(),
        "findings_file": _write(out, "compliance-findings.json", data),
        "summary": data["summary"],
        "counts": data["counts"],
    }
    if args.remediate:
        plan = remediate.build_plan(report, run.results, out / "remediation")
        result["remediation"] = {"plan": str(out / "remediation" / "plan.json"), **plan.to_dict()["summary"]}
    return result


def cmd_scan_cve(args) -> dict:
    info, sel = _resolve(args)
    if args.feed:
        feed_path = Path(args.feed)
    elif sel.oval_feed is not None:
        feed_path = feeds.cached_path(sel.oval_feed)
        if not feed_path.is_file():
            raise CLIError(f"feed not cached at {feed_path}; run `rockhard feeds fetch` first or pass --feed")
    else:
        raise CLIError(f"no known OVAL feed for {info.id} {info.version_id}; pass --feed")
    out = Path(args.out)
    run = oscap.eval_oval(feed_path, out, root=args.root)
    if not run.ok:
        raise CLIError(f"oscap failed with exit code {run.returncode}; see {run.log}")
    data = parse_oval_results(run.results).to_dict()
    return {
        "track": "cve",
        "os": info.to_dict(),
        "feed": str(feed_path),
        "scan": run.to_dict(),
        "findings_file": _write(out, "cve-findings.json", data),
        "summary": data["summary"],
        "unique_cves": data["unique_cves"],
    }


def cmd_parse_compliance(args) -> dict:
    return parse_xccdf_results(args.file, result_id=args.result_id).to_dict(include_passing=args.all)


def cmd_parse_cve(args) -> dict:
    return parse_oval_results(args.file).to_dict()


def cmd_remediate(args) -> dict:
    report = parse_xccdf_results(args.file, result_id=args.result_id)
    return remediate.build_plan(report, args.file, args.out).to_dict()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rockhard", description="OpenSCAP harness for STIG compliance and CVE scanning.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def with_root(sp):
        sp.add_argument("--root", default=os.environ.get("ROCKHARD_ROOT", "/"), help="target root filesystem (default: $ROCKHARD_ROOT or /)")
        return sp

    def with_out(sp):
        sp.add_argument("--out", default=os.environ.get("ROCKHARD_OUT", "rockhard-out"), help="output directory")
        return sp

    sp = with_root(sub.add_parser("detect", help="detect the target OS and the SCAP content that matches it"))
    sp.add_argument("--profile")
    sp.set_defaults(func=cmd_detect)

    fp = sub.add_parser("feeds", help="manage vendor OVAL feeds").add_subparsers(dest="feeds_cmd", required=True)
    sp = with_root(fp.add_parser("fetch", help="download the OVAL feed for the target OS"))
    sp.add_argument("--url", help="fetch this feed instead of the detected one")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_feeds_fetch)

    scan = sub.add_parser("scan", help="run a scan").add_subparsers(dest="track", required=True)
    sp = with_out(with_root(scan.add_parser("compliance", help="evaluate the STIG profile")))
    sp.add_argument("--datastream", help="override the detected SSG datastream")
    sp.add_argument("--profile", help=f"XCCDF profile id (default: {catalog.STIG_PROFILE})")
    sp.add_argument("--tailoring", help="XCCDF tailoring file")
    sp.add_argument("--rule", action="append", help="evaluate only this rule (repeatable)")
    sp.add_argument("--all", action="store_true", help="include passing rules in the findings file")
    sp.add_argument("--remediate", action="store_true", help="also write per-rule remediation scripts (never applied)")
    sp.set_defaults(func=cmd_scan_compliance)

    sp = with_out(with_root(scan.add_parser("cve", help="evaluate the vendor OVAL feed")))
    sp.add_argument("--feed", help="path to an OVAL definitions file (default: cached feed for the detected OS)")
    sp.set_defaults(func=cmd_scan_cve)

    parse = sub.add_parser("parse", help="parse existing scan results").add_subparsers(dest="kind", required=True)
    sp = parse.add_parser("compliance", help="parse XCCDF / ARF results")
    sp.add_argument("file")
    sp.add_argument("--result-id")
    sp.add_argument("--all", action="store_true")
    sp.set_defaults(func=cmd_parse_compliance)
    sp = parse.add_parser("cve", help="parse OVAL results")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_parse_cve)

    sp = with_out(sub.add_parser("remediate", help="write per-rule remediation scripts from ARF results"))
    sp.add_argument("file")
    sp.add_argument("--result-id")
    sp.set_defaults(func=cmd_remediate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _emit(args.func(args))
        return 0
    except (CLIError, OSDetectionError, catalog.UnsupportedOSError, oscap.OscapError, ValueError, OSError) as e:
        _emit({"error": str(e), "type": type(e).__name__})
        return 1


if __name__ == "__main__":
    sys.exit(main())
