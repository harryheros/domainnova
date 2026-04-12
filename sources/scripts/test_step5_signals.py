#!/usr/bin/env python3
"""
Unit tests for Step 5: build_region_signals + process_domain integration.

The critical guarantee Step 5 must prove:
  build_region_signals(ips, region_lookup_with_only_CN) is BYTE-EQUIVALENT to
  the legacy build_dns_signal(ips, cn_lookup) for all four return fields it
  shares (dns_cn, dns_cn_count, dns_total, matched_cidr).

If that holds, no existing CN domain can change score or sticky behavior as a
result of Step 5 — the only new thing is per_ip_buckets and the bucket field.

Run from repo root:
    python sources/scripts/test_step5_signals.py
"""
from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_domains import (  # noqa: E402
    build_dns_signal,
    build_region_signals,
    build_cidr_lookup,
    build_region_lookup,
    process_domain,
    DomainRecord,
)


def _make_cn_only_lookup():
    nets = [
        ipaddress.IPv4Network("1.0.0.0/24"),
        ipaddress.IPv4Network("2.0.0.0/16"),
    ]
    cn_lookup = build_cidr_lookup(nets)
    region_lookup = build_region_lookup({
        "CN": nets,
        "HK": [],
        "MO": [],
        "TW": [],
    })
    return cn_lookup, region_lookup


def _make_multi_region_lookup():
    return build_region_lookup({
        "CN": [ipaddress.IPv4Network("1.0.0.0/24")],
        "HK": [ipaddress.IPv4Network("2.0.0.0/16")],
        "MO": [ipaddress.IPv4Network("3.0.0.0/16")],
        "TW": [ipaddress.IPv4Network("4.0.0.0/16")],
    })


class TestEquivalenceWithLegacy(unittest.TestCase):
    """build_region_signals must produce identical legacy fields when the
    region lookup contains only CN data."""

    def setUp(self):
        self.cn_lookup, self.region_lookup = _make_cn_only_lookup()

    def assert_equiv(self, ips):
        legacy = build_dns_signal(ips, self.cn_lookup)
        per_ip, dns_cn, cn_count, dns_total, matched = \
            build_region_signals(ips, self.region_lookup)
        self.assertEqual(
            (dns_cn, cn_count, dns_total, matched),
            legacy,
            f"divergence on ips={ips}",
        )

    def test_empty(self):
        self.assert_equiv([])

    def test_all_cn(self):
        self.assert_equiv(["1.0.0.5", "1.0.0.6", "2.0.5.5"])

    def test_no_cn(self):
        self.assert_equiv(["8.8.8.8", "9.9.9.9"])

    def test_mixed_60_pct_threshold_exact(self):
        # 3 CN out of 5 → exactly 0.6 → dns_cn=1
        self.assert_equiv(["1.0.0.1", "1.0.0.2", "1.0.0.3", "8.8.8.8", "9.9.9.9"])

    def test_mixed_below_threshold(self):
        # 2 CN out of 5 → 0.4 → dns_cn=0
        self.assert_equiv(["1.0.0.1", "1.0.0.2", "8.8.8.8", "9.9.9.9", "9.9.9.10"])

    def test_with_invalid_ips(self):
        # invalid IPs are counted in dns_total but not ipv4_total
        self.assert_equiv(["1.0.0.1", "not-an-ip", "1.0.0.2"])

    def test_dedup_matched_cidrs(self):
        # multiple IPs in same CIDR → matched_cidr dedup
        self.assert_equiv(["1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4"])

    def test_matched_cidr_cap_at_5(self):
        # Many distinct CIDRs hit — matched should cap at 5
        nets = [ipaddress.IPv4Network(f"10.{i}.0.0/16") for i in range(10)]
        cn_lookup = build_cidr_lookup(nets)
        region_lookup = build_region_lookup({"CN": nets, "HK": [], "MO": [], "TW": []})
        ips = [f"10.{i}.0.1" for i in range(10)]
        legacy = build_dns_signal(ips, cn_lookup)
        _, dns_cn, cn_count, dns_total, matched = build_region_signals(ips, region_lookup)
        self.assertEqual((dns_cn, cn_count, dns_total, matched), legacy)
        self.assertEqual(len(matched.split("|")), 5)


class TestPerIpBuckets(unittest.TestCase):
    """The new field: per_ip_buckets is positionally aligned with `ips`."""

    def setUp(self):
        self.region_lookup = _make_multi_region_lookup()

    def test_alignment_with_invalid_ip(self):
        ips = ["1.0.0.5", "not-an-ip", "2.0.0.5", "9.9.9.9"]
        per_ip, *_ = build_region_signals(ips, self.region_lookup)
        self.assertEqual(per_ip, ["CN", "", "HK", ""])

    def test_all_four_buckets_represented(self):
        per_ip, *_ = build_region_signals(
            ["1.0.0.1", "2.0.0.1", "3.0.0.1", "4.0.0.1"], self.region_lookup
        )
        self.assertEqual(per_ip, ["CN", "HK", "MO", "TW"])

    def test_empty_ips(self):
        per_ip, *_ = build_region_signals([], self.region_lookup)
        self.assertEqual(per_ip, [])

    def test_dns_cn_only_counts_cn_bucket(self):
        # 3 HK + 1 CN → dns_cn=0 (only 25% CN)
        _, dns_cn, cn_count, _, _ = build_region_signals(
            ["1.0.0.1", "2.0.0.1", "2.0.0.2", "2.0.0.3"], self.region_lookup
        )
        self.assertEqual(dns_cn, 0)
        self.assertEqual(cn_count, 1)


class TestProcessDomainStickyBucket(unittest.TestCase):
    """Sticky fallback must restore bucket from previous run (PROPOSAL §6.1)."""

    def setUp(self):
        _, self.region_lookup = _make_cn_only_lookup()

    def test_sticky_restores_bucket(self):
        prev = DomainRecord(
            domain="example.com", dns_cn=1, dns_cn_count=2, dns_total=2,
            registrar_cn=0, registrant_cn=0, cn_tld=0, score=80,
            resolved_ips="1.0.0.1|1.0.0.2", matched_cidr="1.0.0.0/24",
            source="extended", updated="2026-04-01T00:00:00Z", sticky=0,
            bucket="HK",  # previous run put this in HK
        )

        # Stub resolve_domain to return [] (simulate DNS flake)
        import build_domains as bd
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: []
        try:
            rec = process_domain(
                "example.com", "extended", session=None,
                region_lookup=self.region_lookup,
                updated="2026-04-11T00:00:00Z",
                previous={"example.com": prev},
            )
        finally:
            bd.resolve_domain = original

        self.assertEqual(rec.sticky, 1)
        self.assertEqual(rec.bucket, "HK")  # bucket sticky-restored
        self.assertEqual(rec.score, 80)     # score also restored

    def test_no_sticky_when_resolution_succeeds(self):
        # Successful resolution → fresh bucket from decide_bucket
        import build_domains as bd
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: ["1.0.0.5", "1.0.0.6"]
        try:
            rec = process_domain(
                "example.com", "extended", session=None,
                region_lookup=self.region_lookup,
                updated="2026-04-11T00:00:00Z",
                previous=None,
            )
        finally:
            bd.resolve_domain = original

        self.assertEqual(rec.sticky, 0)
        self.assertEqual(rec.bucket, "CN")  # 2 CN IPs + dns_cn boost
        self.assertEqual(rec.dns_cn, 1)

    def test_unresolvable_no_previous_yields_empty_bucket(self):
        import build_domains as bd
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: []
        try:
            rec = process_domain(
                "example.com", "extended", session=None,
                region_lookup=self.region_lookup,
                updated="2026-04-11T00:00:00Z",
                previous=None,
            )
        finally:
            bd.resolve_domain = original

        self.assertEqual(rec.sticky, 0)
        self.assertEqual(rec.bucket, "")
        self.assertEqual(rec.score, 0)

    def test_seed_hk_source_forces_bucket_even_with_cn_ips(self):
        # Integration: source=seed_hk overrides everything
        import build_domains as bd
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: ["1.0.0.1", "1.0.0.2"]
        try:
            rec = process_domain(
                "example.hk", "seed_hk", session=None,
                region_lookup=self.region_lookup,
                updated="2026-04-11T00:00:00Z",
            )
        finally:
            bd.resolve_domain = original

        self.assertEqual(rec.bucket, "HK")  # forced by seed
        # Score still reflects CN IP signal (score path unchanged)
        self.assertGreaterEqual(rec.score, 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
