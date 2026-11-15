"""Offline import parsers for mailbox rule exports.

Accepted shapes are documented in the README. In short:

JSON (Google)::
    {"provider": "google", "org_domain": "example.com",
     "mailboxes": [{"mailbox": "a@example.com",
                    "forwarding": {"enabled": true,
                                   "email_address": "x@other.com",
                                   "prior_relationship_domains": []},
                    "filters": [{"id": "...", "name": "...", "enabled": true,
                                 "criteria": {"query": "...", "from": "...",
                                              "subject": "...", "has_words": "..."},
                                 "actions": {"forward_to": [...], "bcc_to": [...],
                                             "delete": false, "mark_read": false,
                                             "skip_inbox": false,
                                             "add_label": "Finance"},
                                 "prior_relationship_domains": [...]}]}]}

JSON (Microsoft 365)::
    {"provider": "microsoft", "org_domain": "example.com",
     "mailboxes": [{"mailbox": "b@example.com",
                    "smtp_forwarding": {"enabled": true,
                                        "smtp_address": "x@other.com",
                                        "prior_relationship_domains": []},
                    "inbox_rules": [{"id": "...", "name": "...", "enabled": true,
                                     "hidden": false, "is_sweep": false,
                                     "conditions": {"subject_contains": [...],
                                                    "body_contains": [...],
                                                    "from": [...]},
                                     "actions": {"forward_to": [...],
                                                 "redirect_to": [...],
                                                 "bcc_to": [...], "delete": false,
                                                 "mark_as_read": false,
                                                 "move_to_folder": "Archive"},
                                     "prior_relationship_domains": [...]}]}]}

A single-mailbox object (``{"mailbox": ..., "filters"/"inbox_rules": [...]}``)
and a bare list of mailbox objects are also accepted.

CSV: one row per rule, columns documented in the README; multiple
addresses/domains inside one cell are separated by ``;``.
"""
from __future__ import annotations

import csv
import io
import json

from .models import AuditRecord

_TRUE = {"true", "yes", "1", "y", "on"}


def _bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in _TRUE


def _addr_list(value) -> list:
    if not value:
        return []
    if isinstance(value, str):
        parts = value.replace(",", ";").split(";")
        return [p.strip() for p in parts if p.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


def _text_blob(*parts) -> str:
    chunks = []
    for part in parts:
        if not part:
            continue
        if isinstance(part, (list, tuple)):
            chunks.extend(str(p) for p in part)
        elif isinstance(part, dict):
            chunks.extend(str(v) for v in part.values())
        else:
            chunks.append(str(part))
    return " ".join(chunks).lower()


def _prior(obj: dict):
    """Return the prior-relationship list if the key exists, else None."""
    if "prior_relationship_domains" not in obj:
        return None
    val = obj.get("prior_relationship_domains")
    if val is None:
        return None
    if isinstance(val, str):
        return [v.strip().lower() for v in val.replace(",", ";").split(";") if v.strip()]
    return [str(v).strip().lower() for v in val if str(v).strip()]


# ---------------------------------------------------------------- Google

def _google_filter(mailbox: str, f: dict) -> AuditRecord:
    criteria = f.get("criteria") or {}
    actions = f.get("actions") or {}
    keywords = _text_blob(criteria.get("query"), criteria.get("has_words"),
                          criteria.get("subject"), criteria.get("from"))
    return AuditRecord(
        provider="google",
        mailbox=mailbox,
        kind="rule",
        rule_id=str(f.get("id", "")),
        name=str(f.get("name", "") or f.get("id", "")),
        enabled=_bool(f.get("enabled"), default=True),
        hidden=_bool(f.get("hidden")),
        condition_text=keywords,
        condition_keywords=[w for w in keywords.split() if w],
        forward_to=_addr_list(actions.get("forward_to") or actions.get("forwardTo")),
        redirect_to=_addr_list(actions.get("redirect_to")),
        copy_to=_addr_list(actions.get("bcc_to") or actions.get("cc_to") or actions.get("copy_to")),
        delete=_bool(actions.get("delete")),
        mark_as_read=_bool(actions.get("mark_read") or actions.get("mark_as_read")),
        move_to_folder=actions.get("move_to_folder") or actions.get("add_label"),
        skip_inbox=_bool(actions.get("skip_inbox") or actions.get("skipInbox")),
        prior_relationship_domains=_prior(f),
    )


def _google_mailbox(mb: dict) -> list:
    mailbox = str(mb.get("mailbox") or mb.get("email") or "")
    records = []
    fwd = mb.get("forwarding") or {}
    if fwd:
        addr = fwd.get("email_address") or fwd.get("address") or ""
        enabled = _bool(fwd.get("enabled"))
        records.append(AuditRecord(
            provider="google", mailbox=mailbox, kind="account_forwarding",
            rule_id="account-forwarding", name="Account forwarding setting",
            enabled=enabled,
            forward_to=_addr_list(addr) if (enabled and addr) else [],
            prior_relationship_domains=_prior(fwd),
        ))
    for f in mb.get("filters") or []:
        records.append(_google_filter(mailbox, f))
    return records


# ------------------------------------------------------------- Microsoft

def _ms_rule(mailbox: str, r: dict) -> AuditRecord:
    cond = r.get("conditions") or {}
    actions = r.get("actions") or {}
    keywords = _text_blob(cond.get("subject_contains"), cond.get("body_contains"),
                          cond.get("keywords"), cond.get("from"), r.get("name") if r.get("is_sweep") else "")
    name = str(r.get("name", "") or r.get("id", ""))
    return AuditRecord(
        provider="microsoft",
        mailbox=mailbox,
        kind="rule",
        rule_id=str(r.get("id", "")),
        name=name,
        enabled=_bool(r.get("enabled"), default=True),
        hidden=_bool(r.get("hidden")),
        is_sweep=_bool(r.get("is_sweep")) or name.lower().startswith("sweep"),
        condition_text=keywords,
        condition_keywords=[w for w in keywords.split() if w],
        forward_to=_addr_list(actions.get("forward_to") or actions.get("forwardTo")),
        redirect_to=_addr_list(actions.get("redirect_to") or actions.get("redirectTo")),
        copy_to=_addr_list(actions.get("bcc_to") or actions.get("cc_to") or actions.get("copy_to")),
        delete=_bool(actions.get("delete")),
        mark_as_read=_bool(actions.get("mark_as_read") or actions.get("mark_read")),
        move_to_folder=actions.get("move_to_folder"),
        skip_inbox=_bool(actions.get("skip_inbox")),
        prior_relationship_domains=_prior(r),
    )


def _ms_mailbox(mb: dict) -> list:
    mailbox = str(mb.get("mailbox") or mb.get("email") or "")
    records = []
    smtp = mb.get("smtp_forwarding") or mb.get("forwarding") or {}
    if smtp:
        addr = smtp.get("smtp_address") or smtp.get("email_address") or smtp.get("address") or ""
        enabled = _bool(smtp.get("enabled"))
        records.append(AuditRecord(
            provider="microsoft", mailbox=mailbox, kind="account_forwarding",
            rule_id="smtp-forwarding", name="Mailbox SMTP forwarding setting",
            enabled=enabled,
            forward_to=_addr_list(addr) if (enabled and addr) else [],
            prior_relationship_domains=_prior(smtp),
        ))
    for r in mb.get("inbox_rules") or mb.get("rules") or []:
        records.append(_ms_rule(mailbox, r))
    return records


# -------------------------------------------------------------- dispatch

def parse_json_data(data) -> tuple:
    """Return (records, org_domain_or_None)."""
    if isinstance(data, list):
        mailboxes, provider, org = data, None, None
    elif isinstance(data, dict):
        provider = str(data.get("provider", "")).lower() or None
        org = data.get("org_domain")
        if "mailboxes" in data:
            mailboxes = data["mailboxes"]
        elif "mailbox" in data:
            mailboxes = [data]
        else:
            raise ValueError("JSON export has no 'mailboxes' list and no 'mailbox' object")
    else:
        raise ValueError("JSON export must be an object or a list")
    records = []
    for mb in mailboxes:
        mb_provider = str(mb.get("provider", provider or "")).lower()
        if mb_provider in ("microsoft", "m365", "exchange", "office365"):
            records.extend(_ms_mailbox(mb))
        elif mb_provider in ("google", "gmail", "workspace"):
            records.extend(_google_mailbox(mb))
        else:  # infer from shape
            if "inbox_rules" in mb or "smtp_forwarding" in mb:
                records.extend(_ms_mailbox(mb))
            else:
                records.extend(_google_mailbox(mb))
    return records, org


def load_json(text: str) -> tuple:
    return parse_json_data(json.loads(text))


CSV_COLUMNS = [
    "provider", "mailbox", "rule_id", "rule_name", "kind", "enabled", "hidden",
    "is_sweep", "condition_keywords", "forward_to", "redirect_to", "bcc_to",
    "delete", "mark_as_read", "move_to_folder", "skip_inbox",
    "account_forwarding_address", "prior_relationship_domains",
]


def parse_csv_text(text: str) -> tuple:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ValueError("CSV export is empty")
    records, org = [], None
    for row in reader:
        # Tolerate ragged rows: DictReader puts surplus fields under the
        # None key as a list — drop them rather than crashing.
        row = {(k or "").strip(): (v or "").strip()
               for k, v in row.items() if k is not None and isinstance(v, str)}
        kind = (row.get("kind") or "rule").lower()
        prior = None
        if "prior_relationship_domains" in row:
            # Column exists in the documented CSV shape; an empty cell
            # means "no prior relationship recorded" ([]), not "unknown".
            prior = [v.strip().lower() for v in row["prior_relationship_domains"].split(";") if v.strip()]
        rec = AuditRecord(
            provider=(row.get("provider") or "csv").lower(),
            mailbox=row.get("mailbox", ""),
            kind="account_forwarding" if kind == "account_forwarding" else "rule",
            rule_id=row.get("rule_id", ""),
            name=row.get("rule_name", ""),
            enabled=_bool(row.get("enabled"), default=True),
            hidden=_bool(row.get("hidden")),
            is_sweep=_bool(row.get("is_sweep")),
            condition_text=row.get("condition_keywords", "").lower(),
            condition_keywords=[w for w in row.get("condition_keywords", "").lower().split() if w],
            forward_to=_addr_list(row.get("forward_to", "")),
            redirect_to=_addr_list(row.get("redirect_to", "")),
            copy_to=_addr_list(row.get("bcc_to", "")),
            delete=_bool(row.get("delete")),
            mark_as_read=_bool(row.get("mark_as_read")),
            move_to_folder=row.get("move_to_folder") or None,
            skip_inbox=_bool(row.get("skip_inbox")),
            prior_relationship_domains=prior,
        )
        if rec.kind == "account_forwarding":
            addr = row.get("account_forwarding_address", "")
            rec.forward_to = _addr_list(addr) if (rec.enabled and addr) else []
        records.append(rec)
    return records, org


def load_export(text: str, fmt: str) -> tuple:
    """Load export text in the given format ('json' or 'csv')."""
    if fmt == "json":
        return load_json(text)
    if fmt == "csv":
        return parse_csv_text(text)
    raise ValueError(f"unsupported format: {fmt!r} (expected 'json' or 'csv')")
