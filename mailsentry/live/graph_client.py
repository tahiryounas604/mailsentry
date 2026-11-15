"""Placeholder Microsoft Graph client — NOT exercised against live APIs.

A real implementation would call Graph endpoints for mailbox settings
and message rules. In v0.1 this class only accepts an injected
``transport`` callable (used by unit tests with a mock) that returns an
export-shaped dict as documented for the offline Microsoft JSON format;
the parsed records are then identical to an offline import.
"""
from __future__ import annotations

from ..parsers import parse_json_data


class GraphClientPlaceholder:
    def __init__(self, transport=None):
        # transport: callable() -> dict (export-shaped payload)
        self._transport = transport

    def fetch_records(self):
        if self._transport is None:
            raise RuntimeError(
                "live Microsoft Graph mode is not configured and was not exercised "
                "in v0.1; export inbox rules from Exchange and audit the file offline")
        payload = self._transport()
        records, _org = parse_json_data(payload)
        return records
