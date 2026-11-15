"""Unified data model.

Every supported export format (Google Workspace / Gmail, Microsoft 365 /
Exchange, JSON or CSV) is normalised into :class:`AuditRecord` objects.
Detectors only ever see this unified shape, never a provider-specific one.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class AuditRecord:
    """One auditable thing: an inbox rule/filter, or an account-level
    forwarding setting (``kind == "account_forwarding"``)."""

    provider: str  # "google" | "microsoft" | "csv" source provider value
    mailbox: str
    kind: str = "rule"  # "rule" | "account_forwarding"
    rule_id: str = ""
    name: str = ""
    enabled: bool = True
    hidden: bool = False
    is_sweep: bool = False
    # Searchable condition text (subjects, queries, senders, keywords),
    # lower-cased by the parsers.
    condition_text: str = ""
    condition_keywords: list = field(default_factory=list)
    # Actions
    forward_to: list = field(default_factory=list)
    redirect_to: list = field(default_factory=list)
    copy_to: list = field(default_factory=list)  # BCC / CC / copy recipients
    delete: bool = False
    mark_as_read: bool = False
    move_to_folder: Optional[str] = None  # folder or Gmail label
    skip_inbox: bool = False
    # Domains the mailbox owner has a recorded prior relationship with,
    # as supplied by the export. None = the export did not carry this
    # field at all (detector MS-011 then stays silent); [] = the field
    # was present and empty (no prior relationship recorded).
    prior_relationship_domains: Optional[list] = None

    def all_recipients(self) -> list:
        out = []
        for group in (self.forward_to, self.redirect_to, self.copy_to):
            for addr in group:
                if addr not in out:
                    out.append(addr)
        return out

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    pattern_id: str  # e.g. "MS-001"
    pattern_name: str
    severity: str  # "critical" | "high" | "medium" | "low"
    mailbox: str
    provider: str
    rule_id: str
    rule_name: str
    explanation: str
    remediation: str
    evidence: str = ""
    mitre: str = "T1114.003"

    def to_dict(self) -> dict:
        return asdict(self)


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
