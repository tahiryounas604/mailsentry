from conftest import load_example
from mailsentry.detectors import PATTERNS, audit_records

ALL_PATTERN_IDS = {pid for pid, _name, _sev in PATTERNS}
ORG = "example.com"


def _all_malicious_records():
    records = []
    for name in ("google_malicious.json", "microsoft_malicious.json", "rules_malicious.csv"):
        recs, _ = load_example(name)
        records.extend(recs)
    return records


def _all_benign_records():
    records = []
    for name in ("google_benign.json", "microsoft_benign.json", "rules_benign.csv"):
        recs, _ = load_example(name)
        records.extend(recs)
    return records


def test_every_pattern_fires_on_malicious_fixtures():
    findings = audit_records(_all_malicious_records(), ORG)
    fired = {f.pattern_id for f in findings}
    missing = ALL_PATTERN_IDS - fired
    assert missing == set(), f"patterns that never fired: {missing}"
    assert len(ALL_PATTERN_IDS) == 12


def test_each_pattern_fires_at_least_once_individually():
    findings = audit_records(_all_malicious_records(), ORG)
    for pid in sorted(ALL_PATTERN_IDS):
        assert any(f.pattern_id == pid for f in findings), pid


def test_benign_fixtures_have_zero_high_or_critical():
    findings = audit_records(_all_benign_records(), ORG)
    bad = [f for f in findings if f.severity in ("high", "critical")]
    assert bad == []


def test_benign_fixtures_have_zero_findings_at_all():
    findings = audit_records(_all_benign_records(), ORG)
    assert findings == []


def test_findings_carry_remediation_and_mitre():
    findings = audit_records(_all_malicious_records(), ORG)
    assert findings
    for f in findings:
        assert f.remediation.strip()
        assert f.explanation.strip()
        assert f.mitre == "T1114.003"
        assert f.mailbox
        assert f.severity in ("critical", "high", "medium", "low")


def test_csv_malicious_fixture_alone_fires_key_patterns():
    records, _ = load_example("rules_malicious.csv")
    fired = {f.pattern_id for f in audit_records(records, ORG)}
    assert {"MS-003", "MS-004", "MS-007", "MS-009"} <= fired
