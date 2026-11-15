# MailSentry

Self-hosted auditor for hidden email forwarding and inbox-rule
exfiltration — the patterns behind MITRE ATT&CK **T1114.003
(Email Collection: Email Forwarding Rule)**.

Attackers who compromise a mailbox rarely change the password. They add
a quiet forwarding rule, a BCC copy, or an account-level SMTP forward —
then read (and hide) the victim's mail for months. MailSentry audits
**offline exports** of mailbox rules and forwarding settings from
Google Workspace / Gmail and Microsoft 365 / Exchange, flags twelve
concrete patterns, and writes a Markdown + JSON report with a severity,
an explanation, and a concrete remediation step for every finding.

No mail is read. No live mailbox is touched. You export the rules, you
run the audit on your own machine.

## Features

- **Offline-first**: audits exported rule/filter and forwarding data —
  nothing is sent anywhere, no account credentials are needed.
- **Two providers, two formats**: Google Workspace / Gmail filters and
  forwarding settings, and Microsoft 365 / Exchange inbox rules and
  mailbox SMTP forwarding, each in documented JSON and CSV shapes.
- **12 named detection patterns** (table below), each mapped to
  MITRE ATT&CK T1114.003, each with its own remediation guidance.
- **Lookalike / typosquat detection**: Levenshtein distance, homoglyph
  normalisation ( `examp1e.com` ), transpositions, same-SLD/different-TLD,
  and brand-padding domains ( `example-secure.com` ).
- **Reports**: `report.md` for humans, `report.json` for tooling —
  severity per finding, the mailbox and rule involved, evidence,
  explanation, and remediation.
- **Scriptable CLI** with severity-based exit codes (see below).
- **Pure Python standard library** — no third-party dependencies for
  the core tool.

## Install

Python 3.11 or 3.12. Standard library only.

```bash
git clone https://github.com/tahiryounas604/mailsentry.git
cd mailsentry
pip install .
# or just run it in place:
python3 -m mailsentry --help
```

## Usage

```bash
# Audit an export (format inferred from .json / .csv extension)
mailsentry audit examples/google_malicious.json --org-domain example.com --out ./out

# Explicit format and output directory
mailsentry audit rules.csv --format csv --org-domain example.com --out ./out

# List the detection patterns
mailsentry patterns
```

`--org-domain` is the organisation's primary mail domain. Anything
sent to a domain that is neither this domain nor a sub-domain of it
counts as *external*. If the JSON export carries an `org_domain`
field it is used when `--org-domain` is omitted; CSV exports have no
org-domain field, so `--org-domain` is required for them.

Exit codes for `audit`:

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings (medium/low/none may exist) |
| 1 | At least one **high** finding, no critical |
| 2 | At least one **critical** finding |
| 3 | Input error (missing file, unparseable export, no org domain) |

## Detection patterns

| ID | Pattern | Default severity |
|----|---------|------------------|
| MS-001 | External auto-forwarding | High |
| MS-002 | Redirect to external address (leaves no copy) | High |
| MS-003 | BCC/copy to external address | High |
| MS-004 | Finance-keyword rule (invoice/payment/wire/bank/…) that deletes or hides mail | Critical |
| MS-005 | Mark-as-read + move-to-folder hiding rule | Medium |
| MS-006 | Forwarding to a lookalike / typosquat domain | Critical |
| MS-007 | Account-level SMTP forwarding to an external address | Critical |
| MS-008 | Sweep-style automatic move/delete rule | Medium |
| MS-009 | Forwarding to a free webmail provider (Gmail, ProtonMail, …) | High |
| MS-010 | Disabled or hidden rule that still carries forwarding actions | Medium (High if hidden) |
| MS-011 | Forwarding to a domain with no recorded prior relationship | Medium |
| MS-012 | Forward-and-delete rule (exfiltrate, then erase the original) | Critical |

One rule can fire several patterns — each pattern is a separate
remediation conversation. MS-011 only fires when the export actually
carries a `prior_relationship_domains` field for the rule/mailbox
(see export shapes); when the field is absent, MailSentry stays
silent rather than guessing.

## Accepted export shapes

Example files for every shape live in [`examples/`](examples/):
`google_malicious.json`, `microsoft_malicious.json`,
`google_benign.json`, `microsoft_benign.json`, `rules_malicious.csv`,
`rules_benign.csv`.

### Google Workspace / Gmail — JSON

```json
{
  "provider": "google",
  "org_domain": "example.com",
  "mailboxes": [
    {
      "mailbox": "alice@example.com",
      "forwarding": {
        "enabled": true,
        "email_address": "alice-backup@other.com",
        "prior_relationship_domains": []
      },
      "filters": [
        {
          "id": "g-f1", "name": "My filter", "enabled": true,
          "criteria": {"query": "invoice", "from": "", "subject": "", "has_words": "wire"},
          "actions": {
            "forward_to": ["x@other.com"], "bcc_to": [],
            "delete": false, "mark_read": false,
            "skip_inbox": false, "add_label": "Finance"
          },
          "prior_relationship_domains": ["partner.com"]
        }
      ]
    }
  ]
}
```

A single-mailbox object (`{"mailbox": ..., "filters": [...]}`) and a
bare list of mailbox objects are also accepted.

### Microsoft 365 / Exchange — JSON

```json
{
  "provider": "microsoft",
  "org_domain": "example.com",
  "mailboxes": [
    {
      "mailbox": "bob@example.com",
      "smtp_forwarding": {
        "enabled": true,
        "smtp_address": "bob-copy@other.com",
        "prior_relationship_domains": []
      },
      "inbox_rules": [
        {
          "id": "m-r1", "name": "My rule", "enabled": true,
          "hidden": false, "is_sweep": false,
          "conditions": {"subject_contains": ["invoice"], "body_contains": [], "from": []},
          "actions": {
            "forward_to": [], "redirect_to": [], "bcc_to": [],
            "delete": false, "mark_as_read": false, "move_to_folder": "Archive"
          },
          "prior_relationship_domains": ["partner.com"]
        }
      ]
    }
  ]
}
```

Notes: a rule whose name starts with `Sweep` is treated as a sweep
rule even if `is_sweep` is omitted. Gmail's `add_label` counts as the
move target for the mark-as-read + move hiding pattern (MS-005).

### CSV (both providers)

One row per rule (or per account-forwarding setting), with this header:

```
provider,mailbox,rule_id,rule_name,kind,enabled,hidden,is_sweep,condition_keywords,forward_to,redirect_to,bcc_to,delete,mark_as_read,move_to_folder,skip_inbox,account_forwarding_address,prior_relationship_domains
```

- `kind` is `rule` or `account_forwarding`; for the latter, put the
  forwarding address in `account_forwarding_address`.
- Booleans accept `true/false/yes/no/1/0`.
- Multiple addresses or domains in one cell are separated by `;`.
- `condition_keywords` is a space-separated keyword list (used by the
  finance-keyword pattern).
- An empty `prior_relationship_domains` cell means "field present,
  no prior relationship recorded" — MS-011 can fire. (In JSON, omit
  the key entirely to mean "unknown".)

## Architecture

```
mailsentry/
├── models.py     # unified AuditRecord / Finding dataclasses
├── parsers.py    # Google JSON, Microsoft JSON, and CSV -> AuditRecord
├── domains.py    # external check, free-webmail list, lookalike detection
├── detectors.py  # the 12 patterns (MS-001 … MS-012) + remediation text
├── report.py     # report.md / report.json generation, exit-code policy
├── cli.py        # `mailsentry audit` / `mailsentry patterns`
└── live/         # OPTIONAL placeholder API clients — see Honest limits
examples/         # documented fixture exports (malicious + benign)
tests/            # pytest suite (parsers, detectors, domains, report, CLI, live stubs)
```

Parsers normalise every input into the same `AuditRecord` shape, so
detectors never see provider-specific data.

## Tests

```bash
python -m pytest -q
```

The suite covers: both JSON parsers and the CSV parser (Google +
Microsoft shapes), lookalike-domain unit tests, a malicious fixture
set that must trigger **every one of the 12 patterns**, a benign
fixture set that must produce zero findings, report generation
(files exist, findings and remediation present), CLI exit codes, and
the live-client placeholders with **mocked** transports.

## Honest limits

- **Offline import is the product.** MailSentry audits what your
  export contains. If a provider export omits a rule type, a hidden
  flag, or the prior-relationship field, the corresponding pattern
  cannot fire — MS-011 in particular stays silent when the field is
  absent, by design.
- **Live API mode was NOT exercised.** The `mailsentry/live/` modules
  are documented placeholders: they accept an injected transport
  callable and are covered only by unit tests with mocked transports.
  No Gmail / Admin SDK or Microsoft Graph call has ever been made by
  this code, and no claim is made that the placeholder shapes match
  the real APIs' responses.
- **Heuristics, not verdicts.** A flagged rule may be legitimate
  (an approved partner forward, a real sweep rule the owner created).
  MailSentry surfaces and explains; a human decides. Conversely, a
  clean report means "no exported rule matched these 12 patterns",
  not "this mailbox is uncompromised" — transport rules at the tenant
  level, delegate access, OAuth grants, and mail clients are out of
  scope for v0.1.
- **Lookalike detection is approximate.** It uses edit distance ≤ 2
  on the second-level label plus homoglyph and brand-padding checks.
  It will miss creative typosquats and can flag short org domains
  more aggressively; check the evidence line in each finding.
- **Finance-keyword list is fixed** in v0.1 (invoice, payment, wire,
  bank, payroll, billing, refund, remittance, ACH, SWIFT, salary,
  tax, W-2, …) and matched against the rule's exported condition
  text only — not against message content, which MailSentry never sees.
- **v0.1** — tested only against the documented fixture shapes in
  `examples/`, not against exports produced by real Google/Microsoft
  admin tooling. If your export tool emits a different shape, adapt
  it to the documented shape first.

## Author

Tahir Younas — Tytechlabs — https://www.linkedin.com/in/tahiryounas604

## License

GPL-3.0 — see [LICENSE](LICENSE).
