#!/usr/bin/env python3
"""
test_domain_regex.py — pin RFC 1123 conformance of DOMAIN_RE.

The DOMAIN_RE pattern is shared by build_metadata.py,
validate_manual_sources.py, and the three discovery agents. A previous
incarnation enforced "no leading/trailing hyphen" on every label EXCEPT
the TLD, which silently accepted strings like `foo.-bar` and `foo.bar-`.
These cases never appear in legitimate input, but the regex was advertised
as RFC-strict and the gap was misleading.

This file pins the corrected behaviour for both copies of the regex
(_source_parser.py for the script layer, _common.py for the discovery
agent layer) so a future refactor cannot silently re-loosen them.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "discovery_agents"))

import _source_parser  # noqa: E402
import _common         # noqa: E402


VALID_CASES = [
    "example.com",
    "a.bb",
    "foo.x-y-z",
    "a-1.b-2.com",
    "sub.domain.example.com",
    "test.xn--fiqs8s",        # punycode IDN domain
]

# Things that previously slipped through DOMAIN_RE because the TLD pattern
# was looser than other labels.
INVALID_TLD_BOUNDARY_CASES = [
    "foo.-bar",
    "foo.bar-",
    "foo.-baz-",
]

# Other invalid shapes that must stay rejected.
INVALID_OTHER_CASES = [
    "",
    "foo",                    # no dot
    "foo.a",                  # TLD too short (single char)
    "-foo.com",               # leading hyphen overall
    "foo-.com",               # non-TLD label trailing hyphen
    ".com",                   # empty label
    "foo..com",               # empty internal label
    "FOO.COM",                # uppercase — DOMAIN_RE is intentionally lowercase
                              # (callers .lower() before matching)
]


def _check_both(domain):
    return (
        bool(_source_parser.DOMAIN_RE.match(domain)),
        bool(_common.DOMAIN_RE.match(domain)),
    )


class TestDomainRegexValid(unittest.TestCase):
    def test_valid_examples(self):
        for d in VALID_CASES:
            a, b = _check_both(d)
            self.assertTrue(a, f"_source_parser rejected valid: {d!r}")
            self.assertTrue(b, f"_common rejected valid: {d!r}")


class TestDomainRegexTldBoundary(unittest.TestCase):
    """Previously-accepted cases that should now be rejected.

    These are the regressions ChatGPT flagged during external review:
    DOMAIN_RE billed itself as RFC-strict but allowed hyphens at the
    edges of the TLD label. Pinning rejection here prevents accidental
    re-loosening in a future refactor.
    """
    def test_leading_hyphen_in_tld_rejected(self):
        a, b = _check_both("foo.-bar")
        self.assertFalse(a)
        self.assertFalse(b)

    def test_trailing_hyphen_in_tld_rejected(self):
        a, b = _check_both("foo.bar-")
        self.assertFalse(a)
        self.assertFalse(b)

    def test_both_sides_hyphen_in_tld_rejected(self):
        a, b = _check_both("foo.-baz-")
        self.assertFalse(a)
        self.assertFalse(b)


class TestDomainRegexInvalid(unittest.TestCase):
    def test_invalid_other(self):
        for d in INVALID_OTHER_CASES:
            a, b = _check_both(d)
            self.assertFalse(a, f"_source_parser accepted invalid: {d!r}")
            self.assertFalse(b, f"_common accepted invalid: {d!r}")


class TestRegexIdentity(unittest.TestCase):
    """The agent layer must re-export the script layer's regex object —
    not a copy, not a parallel definition. This used to require a parity
    test across two independent compiled patterns; now it is a literal
    `is` check.
    """
    def test_agent_layer_reexports_script_layer(self):
        self.assertIs(
            _common.DOMAIN_RE,
            _source_parser.DOMAIN_RE,
            "_common.DOMAIN_RE must be the same object as _source_parser.DOMAIN_RE "
            "(re-exported, not duplicated)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
