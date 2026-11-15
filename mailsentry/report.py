"""Report generation: Markdown + JSON, always with remediation per finding."""
from __future__ import annotations

import json
from pathlib import Path

from .models import SEVERITY_ORDER


def summarise(findings) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts


def build_report(findings, org_domain: str, source: str, records_count: int) -> dict:
    ordered = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.mailbox, f.pattern_id))
    return {
        "tool": "mailsentry",
        "version": "0.1.0",
        "source": source,
        "org_domain": org_domain,
        "records_audited": records_count,
        "summary": summarise(findings),
        "findings": [f.to_dict() for f in ordered],
    }


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# MailSentry audit report",
        "",
        f"- Source: `{report['source']}`",
        f"- Organisation domain: `{report['org_domain']}`",
        f"- Records audited: {report['records_audited']}",
        f"- Findings: {s['total']} "
        f"(critical: {s['critical']}, high: {s['high']}, medium: {s['medium']}, low: {s['low']})",
        "",
        "All patterns map to MITRE ATT&CK T1114.003 (Email Forwarding Rule) "
        "unless noted otherwise in a finding.",
        "",
    ]
    if not report["findings"]:
        lines += ["No findings. No rule in this export matched a detection pattern.", ""]
    for f in report["findings"]:
        lines += [
            f"## [{f['severity'].upper()}] {f['pattern_id']} — {f['pattern_name']}",
            "",
            f"- Mailbox: `{f['mailbox']}` ({f['provider']})",
            f"- Rule: `{f['rule_name']}` (id: `{f['rule_id']}`)",
            f"- MITRE ATT&CK: {f['mitre']}",
            f"- Evidence: {f['evidence']}",
            "",
            f["explanation"],
            "",
            f"**Remediation:** {f['remediation']}",
            "",
        ]
    return "\n".join(lines)


def write_reports(report: dict, out_dir) -> tuple:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "report.json"
    md_path = out / "report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def exit_code_for(findings) -> int:
    """2 = any critical, 1 = any high, 0 = otherwise."""
    sevs = {f.severity for f in findings}
    if "critical" in sevs:
        return 2
    if "high" in sevs:
        return 1
    return 0
