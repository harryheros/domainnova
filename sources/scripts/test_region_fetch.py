#!/usr/bin/env python3
"""
Unit tests for Step 4: ipnova multi-region CIDR fetch + lookup + ip_to_bucket.

Covers:
  - _parse_cidr_text: comment/blank skipping, invalid CIDR drop
  - _count_cidr_lines: matches what sanity check sees
  - _fetch_one_region_cidrs: success, HTTP failure, sanity-check fuse
  - fetch_region_cidrs: orchestration, partial degradation
  - build_region_lookup + ip_to_bucket: precedence CN > HK > MO > TW

The HTTP layer is mocked — no real network calls.

Run from repo root:
    python sources/scripts/test_region_fetch.py
"""
from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from build_domains import (  # noqa: E402
    _parse_cidr_text,
    _count_cidr_lines,
    _fetch_one_region_cidrs,
    fetch_region_cidrs,
    build_region_lookup,
    ip_to_bucket,
)


def _mk_resp(text: str, status: int = 200) -> MagicMock:
    """Build a mock requests.Response."""
    r = MagicMock()
    r.text = text
    r.status_code = status
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f"HTTP {status}")
    else:
        r.raise_for_status.return_value = None
    return r


def _big_cidr_blob(prefix: int, n: int) -> str:
    """Generate n distinct /32 CIDRs in a single /16 — easily exceeds the
    50-line sanity threshold without colliding across test cases."""
    lines = [f"10.{prefix}.{i // 256}.{i % 256}/32" for i in range(n)]
    return "\n".join(lines) + "\n"


class TestParseCidrText(unittest.TestCase):
    def test_basic(self):
        nets = _parse_cidr_text("1.0.0.0/24\n2.0.0.0/16\n")
        self.assertEqual([str(n) for n in nets], ["1.0.0.0/24", "2.0.0.0/16"])

    def test_skips_blank_and_comment(self):
        text = "# header\n\n1.0.0.0/24\n  # indented comment\n\n2.0.0.0/16\n"
        nets = _parse_cidr_text(text)
        self.assertEqual(len(nets), 2)

    def test_drops_invalid(self):
        text = "1.0.0.0/24\nnot-a-cidr\n999.999.0.0/16\n2.0.0.0/16\n"
        nets = _parse_cidr_text(text)
        self.assertEqual(len(nets), 2)

    def test_empty_input(self):
        self.assertEqual(_parse_cidr_text(""), [])

    def test_strict_false_allows_host_bits(self):
        # ipnova may emit non-canonical CIDRs; strict=False should accept
        nets = _parse_cidr_text("1.2.3.4/24\n")
        self.assertEqual(len(nets), 1)


class TestCountCidrLines(unittest.TestCase):
    def test_counts_only_data_lines(self):
        text = "# header\n\n1.0.0.0/24\n# c\n2.0.0.0/16\n\n"
        self.assertEqual(_count_cidr_lines(text), 2)

    def test_empty(self):
        self.assertEqual(_count_cidr_lines(""), 0)

    def test_invalid_lines_still_count(self):
        # Sanity check counts data-shaped lines BEFORE parsing — invalid
        # CIDRs that look like data still pass the fuse, then get dropped.
        text = "not-a-cidr\nalso-not\nstill-not\n"
        self.assertEqual(_count_cidr_lines(text), 3)


class TestFetchOneRegion(unittest.TestCase):
    def test_success(self):
        text = _big_cidr_blob(0, 100)
        session = MagicMock()
        session.get.return_value = _mk_resp(text)
        nets = _fetch_one_region_cidrs(session, "HK", "http://x")
        self.assertEqual(len(nets), 100)

    def test_http_failure_returns_empty(self):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("boom")
        nets = _fetch_one_region_cidrs(session, "HK", "http://x")
        self.assertEqual(nets, [])

    def test_http_500_returns_empty(self):
        session = MagicMock()
        session.get.return_value = _mk_resp("", status=500)
        nets = _fetch_one_region_cidrs(session, "HK", "http://x")
        self.assertEqual(nets, [])

    def test_sanity_fuse_below_threshold(self):
        # 49 lines < IPNOVA_MIN_LINES (50) → empty
        text = _big_cidr_blob(0, 49)
        session = MagicMock()
        session.get.return_value = _mk_resp(text)
        nets = _fetch_one_region_cidrs(session, "HK", "http://x")
        self.assertEqual(nets, [])

    def test_sanity_fuse_at_threshold(self):
        # exactly 50 lines → passes
        text = _big_cidr_blob(0, 50)
        session = MagicMock()
        session.get.return_value = _mk_resp(text)
        nets = _fetch_one_region_cidrs(session, "HK", "http://x")
        self.assertEqual(len(nets), 50)

    def test_sanity_fuse_truncated_response(self):
        # Simulates a partial 502: only header + 3 lines
        text = "# ipnova HK CIDRs\n1.0.0.0/24\n2.0.0.0/24\n3.0.0.0/24\n"
        session = MagicMock()
        session.get.return_value = _mk_resp(text)
        nets = _fetch_one_region_cidrs(session, "HK", "http://x")
        self.assertEqual(nets, [])


class TestFetchRegionCidrs(unittest.TestCase):
    def test_all_four_buckets_returned(self):
        session = MagicMock()
        session.get.return_value = _mk_resp(_big_cidr_blob(0, 100))
        result = fetch_region_cidrs(session)
        self.assertEqual(set(result.keys()), {"CN", "HK", "MO", "TW"})
        for bucket in ("CN", "HK", "MO", "TW"):
            self.assertEqual(len(result[bucket]), 100)

    def test_partial_degradation_does_not_abort(self):
        # CN ok, HK truncated, MO ok, TW network failure
        responses = {
            "CN": _mk_resp(_big_cidr_blob(1, 200)),
            "HK": _mk_resp("1.0.0.0/24\n"),  # < 50 lines
            "MO": _mk_resp(_big_cidr_blob(3, 60)),
            "TW": None,  # raises
        }

        def fake_get(url, timeout=None, **kw):
            for bucket in responses:
                if url.endswith(f"/{bucket}.txt"):
                    r = responses[bucket]
                    if r is None:
                        raise requests.ConnectionError("simulated")
                    return r
            raise AssertionError(f"unexpected URL: {url}")

        session = MagicMock()
        session.get.side_effect = fake_get
        result = fetch_region_cidrs(session)
        self.assertEqual(len(result["CN"]), 200)
        self.assertEqual(result["HK"], [])  # sanity-degraded
        self.assertEqual(len(result["MO"]), 60)
        self.assertEqual(result["TW"], [])  # network-degraded

    def test_total_outage_returns_all_empty(self):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("offline")
        result = fetch_region_cidrs(session)
        self.assertEqual(result, {"CN": [], "HK": [], "MO": [], "TW": []})


class TestRegionLookupAndIpToBucket(unittest.TestCase):
    def setUp(self):
        self.lookup = build_region_lookup({
            "CN": [ipaddress.IPv4Network("1.0.0.0/24")],
            "HK": [ipaddress.IPv4Network("2.0.0.0/16")],
            "MO": [ipaddress.IPv4Network("3.0.0.0/16")],
            "TW": [ipaddress.IPv4Network("4.0.0.0/16")],
        })

    def test_cn_match(self):
        self.assertEqual(ip_to_bucket("1.0.0.5", self.lookup), "CN")

    def test_hk_match(self):
        self.assertEqual(ip_to_bucket("2.0.5.5", self.lookup), "HK")

    def test_mo_match(self):
        self.assertEqual(ip_to_bucket("3.0.5.5", self.lookup), "MO")

    def test_tw_match(self):
        self.assertEqual(ip_to_bucket("4.0.5.5", self.lookup), "TW")

    def test_unmatched_returns_empty(self):
        self.assertEqual(ip_to_bucket("9.9.9.9", self.lookup), "")

    def test_invalid_ip_returns_empty(self):
        self.assertEqual(ip_to_bucket("not-an-ip", self.lookup), "")

    def test_empty_string_returns_empty(self):
        self.assertEqual(ip_to_bucket("", self.lookup), "")

    def test_empty_lookup_for_bucket_skipped(self):
        # If a bucket was degraded to empty, ip_to_bucket should silently
        # skip it and try the next bucket.
        partial = build_region_lookup({
            "CN": [],  # degraded
            "HK": [ipaddress.IPv4Network("1.0.0.0/24")],
            "MO": [],
            "TW": [],
        })
        self.assertEqual(ip_to_bucket("1.0.0.5", partial), "HK")

    def test_precedence_cn_over_hk_when_overlap(self):
        # Defensive: if CIDR tables overlap (shouldn't happen with ipnova
        # in practice), CN wins by precedence.
        overlapping = build_region_lookup({
            "CN": [ipaddress.IPv4Network("5.0.0.0/24")],
            "HK": [ipaddress.IPv4Network("5.0.0.0/24")],
            "MO": [],
            "TW": [],
        })
        self.assertEqual(ip_to_bucket("5.0.0.5", overlapping), "CN")

    def test_all_empty_lookup(self):
        empty = build_region_lookup({"CN": [], "HK": [], "MO": [], "TW": []})
        self.assertEqual(ip_to_bucket("1.0.0.1", empty), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
