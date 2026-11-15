import json

from conftest import EXAMPLES
from mailsentry.cli import main
from mailsentry.detectors import audit_records
from mailsentry.parsers import load_export
from mailsentry.report import build_report, exit_code_for, render_markdown, write_reports


def _report_for(name):
    records, org = load_export((EXAMPLES / name).read_text(encoding="utf-8"), "json")
    findings = audit_records(records, org)
    return build_report(findings, org, name, len(records)), findings


def test_report_files_exist_and_contain_remediation(tmp_path):
    report, _findings = _report_for("google_malicious.json")
    json_path, md_path = write_reports(report, tmp_path)
    assert json_path.is_file() and md_path.is_file()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["total"] > 0
    assert all(f["remediation"] for f in data["findings"])
    md = md_path.read_text(encoding="utf-8")
    assert "Remediation:" in md
    assert "MS-" in md
    assert "alice@example.com" in md


def test_markdown_render_zero_findings():
    report, findings = _report_for("google_benign.json")
    assert findings == []
    assert "No findings" in render_markdown(report)


def test_exit_code_thresholds():
    _report, malicious = _report_for("microsoft_malicious.json")
    assert exit_code_for(malicious) == 2  # critical present
    _r2, benign = _report_for("microsoft_benign.json")
    assert exit_code_for(benign) == 0


def test_cli_audit_malicious_exit_code_and_reports(tmp_path):
    code = main(["audit", str(EXAMPLES / "google_malicious.json"),
                 "--org-domain", "example.com", "--out", str(tmp_path)])
    assert code == 2
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["critical"] >= 1
    assert (tmp_path / "report.md").is_file()


def test_cli_audit_benign_exit_zero(tmp_path):
    code = main(["audit", str(EXAMPLES / "microsoft_benign.json"),
                 "--out", str(tmp_path)])
    assert code == 0
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 0


def test_cli_audit_csv_format_flag(tmp_path):
    code = main(["audit", str(EXAMPLES / "rules_malicious.csv"),
                 "--format", "csv", "--org-domain", "example.com",
                 "--out", str(tmp_path)])
    assert code == 2


def test_cli_missing_file_returns_3(tmp_path):
    assert main(["audit", str(tmp_path / "nope.json")]) == 3


def test_cli_patterns_command(capsys):
    assert main(["patterns"]) == 0
    out = capsys.readouterr().out
    assert "MS-001" in out and "MS-012" in out
