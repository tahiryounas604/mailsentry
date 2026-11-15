import pytest

from mailsentry.domains import is_external, is_free_webmail, is_lookalike, levenshtein

ORG = "example.com"


@pytest.mark.parametrize("domain", [
    "exampl.com",          # missing letter
    "examplee.com",        # extra letter
    "exmaple.com",         # transposition
    "examp1e.com",         # homoglyph 1 -> l
    "example.net",         # same SLD, different TLD
    "example-secure.com",  # brand padding
    "secure-example.net",  # brand padding
    "examplecorp.com",     # brand padding
])
def test_lookalike_domains_detected(domain):
    assert is_lookalike(domain, ORG) is True
    assert is_lookalike(f"user@{domain}", ORG) is True


@pytest.mark.parametrize("domain", [
    "example.com",           # the org domain itself is not external
    "mail.example.com",      # sub-domain of the org
    "gmail.com",
    "partner-vendor.com",
    "microsoft.com",
    "totally-unrelated.org",
])
def test_non_lookalike_domains(domain):
    assert is_lookalike(domain, ORG) is False


def test_is_external():
    assert is_external("a@example.com", ORG) is False
    assert is_external("a@sub.example.com", ORG) is False
    assert is_external("a@other.com", ORG) is True
    assert is_external("other.com", ORG) is True


def test_free_webmail():
    assert is_free_webmail("x@gmail.com") is True
    assert is_free_webmail("x@protonmail.com") is True
    assert is_free_webmail("x@example.com") is False
    assert is_free_webmail("x@partner.com") is False


def test_levenshtein_basics():
    assert levenshtein("example", "example") == 0
    assert levenshtein("exampl", "example") == 1
    assert levenshtein("", "abc") == 3
    assert levenshtein("kitten", "sitting") == 3
