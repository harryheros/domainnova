#!/usr/bin/env python3
"""
test_provider_lookup.py — correctness + regression guard for the ASN lookup
fast path used by detect_provider().

The original detect_provider() iterated _cidr_asn_map.items() linearly and
re-parsed IPv4Network for every (ip, cidr) pair. For a typical build
(1500 domains × ~3 IPs × hundreds of CIDRs), that's millions of throwaway
IPv4Network allocations per run. We replaced that with a prefix-bucketed
sorted lookup using bisect (same shape as build_cidr_lookup()), giving
O(prefix_len_count * log n) instead of O(n) per IP.

These tests pin:
  1. correctness — same answers as the old linear scan
  2. longest-prefix wins when CIDRs overlap (a real ipnova v3.2 case)
  3. the fast lookup actually returns None outside any CIDR (no false hits)
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains as bd  # noqa: E402


class TestBuildAsnLookup(unittest.TestCase):
    def test_simple_lookup(self):
        cidr_asn = {"8.0.0.0/8": 3356, "47.74.0.0/15": 45102}
        lookup = bd._build_asn_lookup(cidr_asn)
        self.assertEqual(bd._lookup_asn_for_ip("8.8.8.8", lookup), 3356)
        self.assertEqual(bd._lookup_asn_for_ip("47.74.1.1", lookup), 45102)
        self.assertIsNone(bd._lookup_asn_for_ip("1.1.1.1", lookup))

    def test_longest_prefix_wins(self):
        # Overlapping CIDRs: a /20 nested inside a /16. The more specific
        # /20 should win for addresses inside it, but the /16 should still
        # cover the rest of the /16.
        cidr_asn = {
            "10.0.0.0/16":  4134,    # broad
            "10.0.16.0/20": 37963,   # specific, inside the /16
        }
        lookup = bd._build_asn_lookup(cidr_asn)
        # Inside the /20
        self.assertEqual(bd._lookup_asn_for_ip("10.0.16.5", lookup), 37963)
        self.assertEqual(bd._lookup_asn_for_ip("10.0.31.255", lookup), 37963)
        # Inside the /16 but outside the /20
        self.assertEqual(bd._lookup_asn_for_ip("10.0.0.1", lookup), 4134)
        self.assertEqual(bd._lookup_asn_for_ip("10.0.255.1", lookup), 4134)

    def test_invalid_cidr_silently_skipped(self):
        # build phase should never raise on garbage cidr strings — those
        # rows in IPNova data.json that fail to parse are dropped, the
        # rest still work.
        cidr_asn = {"junk": 1, "8.0.0.0/8": 3356}
        lookup = bd._build_asn_lookup(cidr_asn)
        self.assertEqual(bd._lookup_asn_for_ip("8.8.8.8", lookup), 3356)

    def test_invalid_ip_returns_none(self):
        cidr_asn = {"8.0.0.0/8": 3356}
        lookup = bd._build_asn_lookup(cidr_asn)
        self.assertIsNone(bd._lookup_asn_for_ip("not-an-ip", lookup))
        self.assertIsNone(bd._lookup_asn_for_ip("", lookup))

    def test_empty_lookup_returns_none(self):
        self.assertIsNone(bd._lookup_asn_for_ip("8.8.8.8", {}))

    def test_boundary_addresses(self):
        # First and last host of a /24
        cidr_asn = {"192.0.2.0/24": 64500}
        lookup = bd._build_asn_lookup(cidr_asn)
        self.assertEqual(bd._lookup_asn_for_ip("192.0.2.0",   lookup), 64500)
        self.assertEqual(bd._lookup_asn_for_ip("192.0.2.255", lookup), 64500)
        self.assertIsNone(bd._lookup_asn_for_ip("192.0.3.0", lookup))


class TestDetectProviderFastPath(unittest.TestCase):
    """detect_provider() integration tests against the fast lookup."""

    def setUp(self):
        # Save & swap module-level state so we don't pollute other tests
        self._orig_map = bd._cidr_asn_map
        self._orig_lookup = bd._cidr_asn_lookup

    def tearDown(self):
        bd._cidr_asn_map = self._orig_map
        bd._cidr_asn_lookup = self._orig_lookup

    def _install(self, cidr_asn):
        bd._cidr_asn_map = cidr_asn
        bd._cidr_asn_lookup = bd._build_asn_lookup(cidr_asn)

    def test_alibaba_match(self):
        self._install({"8.152.0.0/15": 37963})
        name, masked = bd.detect_provider(["8.152.0.1"])
        self.assertEqual(name, "Alibaba Cloud")
        self.assertEqual(masked, 0)

    def test_global_cdn_marks_masked(self):
        # AS13335 = Cloudflare in GLOBAL_CDN_ASNS
        self._install({"104.16.0.0/13": 13335})
        name, masked = bd.detect_provider(["104.16.1.1"])
        self.assertEqual(name, "Cloudflare")
        self.assertEqual(masked, 1)

    def test_unknown_ip_returns_empty(self):
        self._install({"8.152.0.0/15": 37963})
        name, masked = bd.detect_provider(["1.1.1.1"])
        self.assertEqual(name, "")
        self.assertEqual(masked, 0)

    def test_empty_lookup_falls_back_to_static_prefix_hint(self):
        # Empty lookup forces the legacy IP-prefix heuristic branch
        bd._cidr_asn_map = {}
        bd._cidr_asn_lookup = {}
        name, masked = bd.detect_provider(["47.74.5.5"])
        # 47.x is in the static fallback table for Alibaba
        self.assertEqual(name, "Alibaba Cloud")

    def test_empty_ip_list(self):
        self._install({"8.152.0.0/15": 37963})
        self.assertEqual(bd.detect_provider([]), ("", 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
