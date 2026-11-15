"""Command line interface.

Usage:
    mailsentry audit <export-file> [--format json|csv]
                     [--org-domain example.com] [--out DIR]
    mailsentry patterns

Exit codes for ``audit``: 2 if any critical finding, 1 if any high
finding (and no critical), 0 otherwise.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detectors import PATTERNS, audit_records
from .parsers import load_export
from .report import build_report, exit_code_for, write_reports


def _infer_format(path: Path, explicit):
    if explicit:
        return explicit
    suffix = path.suffix.lower().lstrip(".")
    if suffix in ("json", "csv"):
        return suffix
    raise SystemExit(f"cannot infer format from {path.name!r}; pass --format json|csv")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mailsentry",
                                     description="Audit mailbox rule exports for hidden forwarding / exfiltration patterns.")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser("audit", help="audit an offline rule export")
    audit_p.add_argument("export_file")
    audit_p.add_argument("--format", choices=["json", "csv"], default=None)
    audit_p.add_argument("--org-domain", default=None,
                         help="organisation domain; overrides the export's org_domain")
    audit_p.add_argument("--out", default="mailsentry-report",
                         help="output directory for report.md / report.json")

    sub.add_parser("patterns", help="list the detection patterns")

    args = parser.parse_args(argv)

    if args.command == "patterns":
        for pid, name, severity in PATTERNS:
            print(f"{pid}  [{severity}]  {name}  (MITRE T1114.003)")
        return 0

    path = Path(args.export_file)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 3
    fmt = _infer_format(path, args.format)
    try:
        records, export_org = load_export(path.read_text(encoding="utf-8"), fmt)
    except (ValueError, KeyError) as exc:
        print(f"error: could not parse {path}: {exc}", file=sys.stderr)
        return 3
    org_domain = (args.org_domain or export_org or "").lower()
    if not org_domain:
        print("error: no organisation domain — pass --org-domain or include "
              "\"org_domain\" in the export", file=sys.stderr)
        return 3

    findings = audit_records(records, org_domain)
    report = build_report(findings, org_domain, str(path), len(records))
    json_path, md_path = write_reports(report, args.out)
    s = report["summary"]
    print(f"audited {len(records)} record(s) from {path} (org domain: {org_domain})")
    print(f"findings: {s['total']} (critical: {s['critical']}, high: {s['high']}, "
          f"medium: {s['medium']}, low: {s['low']})")
    print(f"wrote {md_path} and {json_path}")
    return exit_code_for(findings)


if __name__ == "__main__":
    raise SystemExit(main())
