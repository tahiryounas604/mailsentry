"""Detection patterns for hidden forwarding / inbox-rule exfiltration.

Each pattern is a named rule mapped to MITRE ATT&CK T1114.003
(Email Collection: Email Forwarding Rule). Patterns are deliberately
independent: one malicious rule can (and often should) fire several
patterns, because each pattern is a separate remediation conversation.
"""
from __future__ import annotations

from .domains import domain_of, is_external, is_free_webmail, is_lookalike
from .models import AuditRecord, Finding

FINANCE_KEYWORDS = {
    "invoice", "invoices", "payment", "payments", "wire", "wires", "bank",
    "banking", "payroll", "billing", "refund", "remittance", "ach", "swift",
    "salary", "tax", "w-2", "w2", "purchase-order", "po-number",
}

PATTERNS = [
    ("MS-001", "External auto-forwarding", "high"),
    ("MS-002", "Redirect to external address", "high"),
    ("MS-003", "BCC/copy to external address", "high"),
    ("MS-004", "Finance-keyword rule that deletes or hides mail", "critical"),
    ("MS-005", "Mark-as-read + move-to-folder hiding rule", "medium"),
    ("MS-006", "Forwarding to lookalike / typosquat domain", "critical"),
    ("MS-007", "Account-level SMTP forwarding to external address", "critical"),
    ("MS-008", "Sweep-style automatic move/delete rule", "medium"),
    ("MS-009", "Forwarding to free webmail provider", "high"),
    ("MS-010", "Disabled or hidden rule with forwarding actions", "medium"),
    ("MS-011", "Forwarding to domain with no recorded prior relationship", "medium"),
    ("MS-012", "Forward-and-delete rule (exfiltrate then erase)", "critical"),
]

_REMEDIATION = {
    "MS-001": "Remove the forwarding action unless there is a documented business need; if there is, restrict it to an approved internal/partner address and alert on future changes.",
    "MS-002": "Remove the redirect action immediately — redirected mail leaves no copy in the mailbox, so also review Sent/Deleted items and audit logs for what was already redirected.",
    "MS-003": "Remove the BCC/copy recipient; check audit logs for how long the copy was active and which messages matched the rule's conditions.",
    "MS-004": "Disable the rule now, preserve a copy for investigation, and notify Finance: search the mailbox and audit logs for finance mail the owner never saw, and verify no payment details were changed.",
    "MS-005": "Review the rule with the mailbox owner; if it was not created by them, disable it and check the destination folder/label for mail hidden from the owner.",
    "MS-006": "Treat as likely impersonation/exfiltration: remove the recipient, block the lookalike domain at the mail gateway, and consider registering or monitoring the typosquat domain.",
    "MS-007": "Clear the account-level forwarding address (Google Admin / Exchange mailbox settings), force a password reset and session revocation, and review sign-in logs for compromise.",
    "MS-008": "Confirm the sweep rule with the owner; sweep rules act on all matching mail automatically, so verify the destination folder and retention before deleting the rule.",
    "MS-009": "Remove the free-webmail recipient. Personal webmail is outside organisational retention/DLP; if forwarding is genuinely needed, use a managed address instead.",
    "MS-010": "Delete dormant forwarding rules rather than leaving them disabled/hidden — a disabled rule can be silently re-enabled after an account compromise. Investigate who created it.",
    "MS-011": "Verify the recipient domain with the mailbox owner and your vendor/partner records. If no relationship can be confirmed, remove the forwarding action and treat the rule as suspicious.",
    "MS-012": "Disable the rule immediately and preserve it as evidence: forward-and-delete is a classic exfiltration-plus-cleanup pattern. Review audit logs for the rule's full active period.",
}


def _finding(rec: AuditRecord, pid: str, name: str, severity: str,
             explanation: str, evidence: str) -> Finding:
    return Finding(
        pattern_id=pid, pattern_name=name, severity=severity,
        mailbox=rec.mailbox, provider=rec.provider,
        rule_id=rec.rule_id, rule_name=rec.name,
        explanation=explanation, remediation=_REMEDIATION[pid],
        evidence=evidence,
    )


def _external(addresses, org_domain):
    return [a for a in addresses if is_external(a, org_domain)]


def audit_record(rec: AuditRecord, org_domain: str) -> list:
    findings = []
    org = (org_domain or "").lower()
    is_rule = rec.kind == "rule"

    ext_forward = _external(rec.forward_to, org)
    ext_redirect = _external(rec.redirect_to, org)
    ext_copy = _external(rec.copy_to, org)
    all_ext = _external(rec.all_recipients(), org)

    hides = rec.delete or rec.mark_as_read or bool(rec.move_to_folder) or rec.skip_inbox
    finance_hits = sorted(FINANCE_KEYWORDS.intersection(
        set(rec.condition_keywords) | set(rec.condition_text.replace(",", " ").split())))

    if is_rule and ext_forward:
        findings.append(_finding(
            rec, "MS-001", "External auto-forwarding", "high",
            "Rule automatically forwards matching mail to an address outside the organisation domain. This is the classic T1114.003 persistence/exfiltration pattern.",
            f"forward_to={', '.join(ext_forward)}"))
    if is_rule and ext_redirect:
        findings.append(_finding(
            rec, "MS-002", "Redirect to external address", "high",
            "Rule redirects matching mail to an external address. Unlike forwarding, a redirect typically leaves no copy in the owner's mailbox, so the owner may never know the mail existed.",
            f"redirect_to={', '.join(ext_redirect)}"))
    if is_rule and ext_copy:
        findings.append(_finding(
            rec, "MS-003", "BCC/copy to external address", "high",
            "Rule silently copies (BCC/CC) matching mail to an external address, giving an outsider an ongoing copy of the mailbox's mail.",
            f"copy_to={', '.join(ext_copy)}"))
    if finance_hits and hides:
        findings.append(_finding(
            rec, "MS-004", "Finance-keyword rule that deletes or hides mail", "critical",
            "Rule matches finance-related keywords and also deletes or hides matching mail. This pattern is used in business-email-compromise to hide invoice/payment fraud from the mailbox owner.",
            f"keywords={', '.join(finance_hits)}; delete={rec.delete}, mark_as_read={rec.mark_as_read}, move_to_folder={rec.move_to_folder}, skip_inbox={rec.skip_inbox}"))
    if is_rule and rec.mark_as_read and rec.move_to_folder:
        findings.append(_finding(
            rec, "MS-005", "Mark-as-read + move-to-folder hiding rule", "medium",
            "Rule marks matching mail as read and moves it out of the inbox. Even without forwarding, this hides mail from the owner and is a common companion to fraud rules.",
            f"move_to_folder={rec.move_to_folder}"))
    lookalikes = [a for a in all_ext if is_lookalike(a, org)]
    if lookalikes:
        findings.append(_finding(
            rec, "MS-006", "Forwarding to lookalike / typosquat domain", "critical",
            "Mail is sent to a domain that is a close lookalike/typosquat of the organisation domain — a strong indicator of deliberate impersonation or exfiltration rather than a legitimate partner.",
            f"lookalike_recipients={', '.join(lookalikes)}; org_domain={org}"))
    if rec.kind == "account_forwarding" and ext_forward:
        findings.append(_finding(
            rec, "MS-007", "Account-level SMTP forwarding to external address", "critical",
            "Account-level (SMTP) forwarding is set to an external address, so ALL incoming mail — not just rule matches — is copied outside the organisation.",
            f"forward_to={', '.join(ext_forward)}"))
    if is_rule and (rec.is_sweep or "sweep" in rec.name.lower()) and (rec.move_to_folder or rec.delete):
        findings.append(_finding(
            rec, "MS-008", "Sweep-style automatic move/delete rule", "medium",
            "Sweep-style rule automatically moves or deletes all matching mail on an ongoing basis. Sweep rules are easy to overlook and can quietly hide a whole category of mail.",
            f"move_to_folder={rec.move_to_folder}; delete={rec.delete}"))
    webmail = [a for a in all_ext if is_free_webmail(a)]
    if webmail:
        findings.append(_finding(
            rec, "MS-009", "Forwarding to free webmail provider", "high",
            "Mail is sent to a free webmail provider address, which sits outside organisational retention, DLP and e-discovery controls.",
            f"webmail_recipients={', '.join(webmail)}"))
    if is_rule and (not rec.enabled or rec.hidden) and rec.all_recipients():
        sev = "high" if rec.hidden else "medium"
        findings.append(_finding(
            rec, "MS-010", "Disabled or hidden rule with forwarding actions", sev,
            "A disabled or hidden rule still carries forwarding/copy actions. Dormant rules are a known persistence trick: they attract no attention until silently re-enabled.",
            f"enabled={rec.enabled}; hidden={rec.hidden}; recipients={', '.join(rec.all_recipients())}"))
    if rec.prior_relationship_domains is not None and all_ext:
        unknown = [a for a in all_ext
                   if domain_of(a) not in rec.prior_relationship_domains]
        if unknown:
            findings.append(_finding(
                rec, "MS-011", "Forwarding to domain with no recorded prior relationship", "medium",
                "Mail is sent to an external domain that does not appear in the export's prior-relationship field for this mailbox/rule, so there is no recorded business relationship justifying the flow.",
                f"unknown_recipients={', '.join(unknown)}; prior_relationship_domains={', '.join(rec.prior_relationship_domains) or '(none recorded)'}"))
    if is_rule and rec.forward_to and rec.delete:
        findings.append(_finding(
            rec, "MS-012", "Forward-and-delete rule (exfiltrate then erase)", "critical",
            "Rule forwards mail and then deletes the original — exfiltration combined with cleanup, leaving the owner with no trace in the mailbox.",
            f"forward_to={', '.join(rec.forward_to)}; delete=True"))
    return findings


def audit_records(records, org_domain: str) -> list:
    findings = []
    for rec in records:
        findings.extend(audit_record(rec, org_domain))
    findings.sort(key=lambda f: (f.mailbox, f.pattern_id))
    return findings
