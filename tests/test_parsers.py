from conftest import load_example
from mailsentry.parsers import load_export, parse_csv_text, parse_json_data


def test_google_json_parser():
    records, org = load_example("google_malicious.json")
    assert org == "example.com"
    assert len(records) == 8  # 1 account forwarding + 7 filters
    acct = [r for r in records if r.kind == "account_forwarding"][0]
    assert acct.provider == "google"
    assert acct.forward_to == ["alice-backup@examp1e.com"]
    fwd = [r for r in records if r.rule_id == "g-f1"][0]
    assert fwd.mailbox == "alice@example.com"
    assert fwd.forward_to == ["alice.personal@gmail.com"]


def test_microsoft_json_parser():
    records, org = load_example("microsoft_malicious.json")
    assert org == "example.com"
    assert len(records) == 5  # 1 smtp forwarding + 4 inbox rules
    smtp = [r for r in records if r.kind == "account_forwarding"][0]
    assert smtp.provider == "microsoft"
    assert smtp.forward_to == ["bob-copy@outside-smtp.net"]
    sweep = [r for r in records if r.rule_id == "m-r2"][0]
    assert sweep.is_sweep is True
    hidden = [r for r in records if r.rule_id == "m-r1"][0]
    assert hidden.hidden is True


def test_google_benign_json_parser_disables_forwarding():
    records, _ = load_example("google_benign.json")
    acct = [r for r in records if r.kind == "account_forwarding"][0]
    assert acct.enabled is False
    assert acct.forward_to == []


def test_csv_parser_both_providers():
    records, _ = load_example("rules_malicious.csv")
    providers = {r.provider for r in records}
    assert providers == {"microsoft", "google"}
    acct = [r for r in records if r.kind == "account_forwarding"][0]
    assert acct.forward_to == ["heidi@outside-heidi.net"]
    bcc = [r for r in records if r.rule_id == "c-r1"][0]
    assert bcc.copy_to == ["spy@outside-spy.com"]
    assert bcc.delete is True
    assert "wire" in bcc.condition_keywords


def test_csv_parser_semicolon_lists_and_booleans():
    header = (
        "provider,mailbox,rule_id,rule_name,kind,enabled,hidden,is_sweep,"
        "condition_keywords,forward_to,redirect_to,bcc_to,delete,mark_as_read,"
        "move_to_folder,skip_inbox,account_forwarding_address,prior_relationship_domains"
    )
    fields = ["google", "x@example.com", "r1", "Multi", "rule", "yes", "false",
              "false", "hello", "a@outside.com;b@outside.net", "", "", "true",
              "false", "", "false", "", "outside.com"]
    assert len(fields) == len(header.split(","))
    text = header + "\n" + ",".join(fields) + "\n"
    records, _ = parse_csv_text(text)
    assert records[0].enabled is True
    assert records[0].forward_to == ["a@outside.com", "b@outside.net"]
    assert records[0].prior_relationship_domains == ["outside.com"]


def test_single_mailbox_json_shape_and_prior_absent_is_none():
    data = {
        "provider": "google",
        "mailbox": "solo@example.com",
        "filters": [{"id": "s1", "name": "Solo",
                     "criteria": {"query": "hi"},
                     "actions": {"forward_to": ["a@outside.com"]}}],
    }
    records, org = parse_json_data(data)
    assert org is None
    assert len(records) == 1
    assert records[0].prior_relationship_domains is None


def test_load_export_rejects_bad_format():
    try:
        load_export("{}", "xml")
    except ValueError as exc:
        assert "unsupported format" in str(exc)
    else:
        raise AssertionError("expected ValueError")
