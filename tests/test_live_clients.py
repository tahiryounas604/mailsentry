"""Live clients are placeholders: tests mock the transport, no network."""
import pytest

from mailsentry.live.gmail_client import GmailClientPlaceholder
from mailsentry.live.graph_client import GraphClientPlaceholder

GOOGLE_PAYLOAD = {
    "provider": "google",
    "mailboxes": [{"mailbox": "a@example.com",
                   "filters": [{"id": "1", "name": "F",
                                "criteria": {"query": "hi"},
                                "actions": {"forward_to": ["x@outside.com"]}}]}],
}

MS_PAYLOAD = {
    "provider": "microsoft",
    "mailboxes": [{"mailbox": "b@example.com",
                   "inbox_rules": [{"id": "2", "name": "R",
                                    "conditions": {"subject_contains": ["hi"]},
                                    "actions": {"redirect_to": ["y@outside.com"]}}]}],
}


def test_gmail_client_with_mocked_transport():
    client = GmailClientPlaceholder(transport=lambda: GOOGLE_PAYLOAD)
    records = client.fetch_records()
    assert len(records) == 1
    assert records[0].forward_to == ["x@outside.com"]


def test_graph_client_with_mocked_transport():
    client = GraphClientPlaceholder(transport=lambda: MS_PAYLOAD)
    records = client.fetch_records()
    assert len(records) == 1
    assert records[0].redirect_to == ["y@outside.com"]


def test_gmail_client_without_transport_raises():
    with pytest.raises(RuntimeError, match="not exercised"):
        GmailClientPlaceholder().fetch_records()


def test_graph_client_without_transport_raises():
    with pytest.raises(RuntimeError, match="not exercised"):
        GraphClientPlaceholder().fetch_records()
