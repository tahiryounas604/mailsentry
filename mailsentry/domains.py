"""Domain helpers: external checks, free-webmail list, lookalike detection.

Pure standard library. Lookalike detection uses Levenshtein distance on
the second-level domain label, prefix/suffix containment, and a small
homoglyph normalisation (0->o, 1->l, rn->m, vv->w).
"""
from __future__ import annotations

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com",
    "aol.com", "protonmail.com", "proton.me", "pm.me", "icloud.com",
    "me.com", "mail.com", "gmx.com", "gmx.net", "yandex.com", "yandex.ru",
    "qq.com", "163.com", "126.com", "zoho.com", "zohomail.com",
    "tutanota.com", "tuta.com", "fastmail.com", "mail.ru", "bk.ru",
    "inbox.com", "hushmail.com", "rediffmail.com",
}

_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"))


def domain_of(address: str) -> str:
    """Extract the lower-cased domain from an email address (or bare domain)."""
    addr = (address or "").strip().lower()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    return addr.strip("<> .,;")


def sld(domain: str) -> str:
    """Second-level label: 'mail.example.co.uk' -> 'example' (best effort)."""
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def is_external(address_or_domain: str, org_domain: str) -> bool:
    """True when the domain is neither the org domain nor a sub-domain of it."""
    d = domain_of(address_or_domain)
    org = (org_domain or "").strip().lower()
    if not d:
        return False
    if not org:
        return True
    return not (d == org or d.endswith("." + org))


def is_free_webmail(address_or_domain: str) -> bool:
    return domain_of(address_or_domain) in FREE_WEBMAIL_DOMAINS


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _homoglyph_normalise(text: str) -> str:
    out = text
    for src, dst in _HOMOGLYPHS:
        out = out.replace(src, dst)
    return out


def is_lookalike(address_or_domain: str, org_domain: str) -> bool:
    """True when an *external* domain is suspiciously close to the org domain.

    Catches: 1-2 edit typosquats (exampl.com), transpositions (exmaple.com,
    distance 2), homoglyph swaps (examp1e.com), and brand-plus-padding
    domains (example-secure.com, secure-example.net, examplecorp.com).
    """
    d = domain_of(address_or_domain)
    org = (org_domain or "").strip().lower()
    if not d or not org or not is_external(d, org):
        return False
    target_sld, org_sld = sld(d), sld(org)
    if not target_sld or not org_sld or target_sld == org_sld:
        # Same SLD under a different TLD (example.net vs example.com) is
        # itself a classic typosquat.
        return target_sld == org_sld and d != org
    if _homoglyph_normalise(target_sld) == _homoglyph_normalise(org_sld):
        return True
    if levenshtein(target_sld, org_sld) <= 2:
        return True
    # Brand padding: org SLD appears inside the target SLD with extra text.
    if org_sld in target_sld and len(target_sld) - len(org_sld) <= 8:
        return True
    return False
