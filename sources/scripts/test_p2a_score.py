#!/usr/bin/env python3
"""
Unit tests for P2.A: multi-region scoring model.

Covers:
  - score_record_for_bucket() — all buckets, all code paths
  - score_record() wrapper equivalence with score_record_for_bucket("CN", ...)
  - build_region_signals() region_dns_flags: all four flags computed correctly
  - process_domain() integration: HK/MO/TW scoring, seed-force, sticky path
  - CSV schema backward compat: old 14-column CSV loads with dns_hk/mo/tw = 0
  - CN equivalence: score_record_for_bucket("CN", ...) == legacy score_record(...)

Run from repo root:
    python sources/scripts/test_p2a_score.py
"""
from __future__ import annotations

import csv
import io
import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_domains import (  # noqa: E402
    DomainRecord,
    build_cidr_lookup,
    build_region_lookup,
    build_region_signals,
    load_previous_rows,
    process_domain,
    score_record,
    score_record_for_bucket,
    _tld_flag_for_bucket,
    INCLUDE_THRESHOLD,
    DNS_WEIGHT,
    CN_TLD_WEIGHT,
    XX_TLD_WEIGHT,
    CN_TLD_FALLBACK_SCORE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_multi_region_lookup():
    return build_region_lookup({
        "CN": [ipaddress.IPv4Network("1.0.0.0/24")],
        "HK": [ipaddress.IPv4Network("2.0.0.0/16")],
        "MO": [ipaddress.IPv4Network("3.0.0.0/16")],
        "TW": [ipaddress.IPv4Network("4.0.0.0/16")],
    })


# ---------------------------------------------------------------------------
# Tests: score_record_for_bucket — CN path
# ---------------------------------------------------------------------------

class TestScoreRecordForBucketCN(unittest.TestCase):
    """CN path must be byte-identical to the old score_record() when
    registrar_cn=0 and registrant_cn=0."""

    def test_cn_dns_only(self):
        self.assertEqual(score_record_for_bucket("CN", 1, 0), DNS_WEIGHT)  # 60

    def test_cn_dns_and_tld(self):
        self.assertEqual(
            score_record_for_bucket("CN", 1, 1),
            DNS_WEIGHT + CN_TLD_WEIGHT,  # 70
        )

    def test_cn_tld_fallback(self):
        # TLD alone triggers fallback for CN
        self.assertEqual(score_record_for_bucket("CN", 0, 1), CN_TLD_FALLBACK_SCORE)

    def test_cn_no_signal(self):
        self.assertEqual(score_record_for_bucket("CN", 0, 0), 0)


# ---------------------------------------------------------------------------
# Tests: score_record_for_bucket — HK/MO/TW paths
# ---------------------------------------------------------------------------

class TestScoreRecordForBucketHKMOTW(unittest.TestCase):
    """HK/MO/TW paths: dns required, no TLD fallback."""

    def _check_bucket(self, bucket):
        # dns=1, tld=0 → 60
        self.assertEqual(score_record_for_bucket(bucket, 1, 0), DNS_WEIGHT)
        # dns=1, tld=1 → 80
        self.assertEqual(score_record_for_bucket(bucket, 1, 1), DNS_WEIGHT + XX_TLD_WEIGHT)
        # dns=0, tld=1 → 0 (no TLD fallback for non-CN)
        self.assertEqual(score_record_for_bucket(bucket, 0, 1), 0)
        # dns=0, tld=0 → 0
        self.assertEqual(score_record_for_bucket(bucket, 0, 0), 0)

    def test_hk(self):
        self._check_bucket("HK")

    def test_mo(self):
        self._check_bucket("MO")

    def test_tw(self):
        self._check_bucket("TW")

    def test_unknown_bucket_returns_zero(self):
        self.assertEqual(score_record_for_bucket("", 1, 1), 0)
        self.assertEqual(score_record_for_bucket("XX", 1, 1), 0)


# ---------------------------------------------------------------------------
# Tests: score_record wrapper equivalence
# ---------------------------------------------------------------------------

class TestScoreRecordWrapperEquivalence(unittest.TestCase):
    """score_record(dns_cn, 0, 0, cn_tld) must equal
    score_record_for_bucket('CN', dns_cn, cn_tld) for all combinations."""

    def _check(self, dns_cn, cn_tld):
        expected = score_record_for_bucket("CN", dns_cn, cn_tld)
        got = score_record(dns_cn, 0, 0, cn_tld)
        self.assertEqual(got, expected,
                         f"mismatch dns_cn={dns_cn} cn_tld={cn_tld}: "
                         f"wrapper={got} direct={expected}")

    def test_all_combinations(self):
        for dns_cn in (0, 1):
            for cn_tld in (0, 1):
                self._check(dns_cn, cn_tld)

    def test_registrar_registrant_ignored(self):
        # Passing non-zero registrar/registrant must not change outcome
        # (they are P3 scope and intentionally dropped)
        self.assertEqual(
            score_record(1, 1, 1, 0),
            score_record_for_bucket("CN", 1, 0),
        )


# ---------------------------------------------------------------------------
# Tests: _tld_flag_for_bucket
# ---------------------------------------------------------------------------

class TestTLDFlagForBucket(unittest.TestCase):

    def test_cn_tld(self):
        self.assertEqual(_tld_flag_for_bucket("example.cn", "CN"), 1)

    def test_cn_tld_unicode(self):
        # .xn--fiqs8s is a CN TLD
        self.assertEqual(_tld_flag_for_bucket("example.xn--fiqs8s", "CN"), 1)

    def test_hk_tld(self):
        self.assertEqual(_tld_flag_for_bucket("example.hk", "HK"), 1)

    def test_mo_tld(self):
        self.assertEqual(_tld_flag_for_bucket("example.mo", "MO"), 1)

    def test_tw_tld(self):
        self.assertEqual(_tld_flag_for_bucket("example.tw", "TW"), 1)

    def test_mismatch(self):
        # .hk domain but bucket=CN → 0
        self.assertEqual(_tld_flag_for_bucket("example.hk", "CN"), 0)

    def test_empty_bucket(self):
        self.assertEqual(_tld_flag_for_bucket("example.hk", ""), 0)

    def test_com_tld(self):
        self.assertEqual(_tld_flag_for_bucket("example.com", "HK"), 0)


# ---------------------------------------------------------------------------
# Tests: build_region_signals — region_dns_flags
# ---------------------------------------------------------------------------

class TestBuildRegionSignalsFlags(unittest.TestCase):

    def setUp(self):
        self.lookup = _make_multi_region_lookup()

    def test_cn_majority(self):
        # 3 CN out of 3 → dns_cn=1, dns_hk=0
        _, flags, _, _, _ = build_region_signals(
            ["1.0.0.1", "1.0.0.2", "1.0.0.3"], self.lookup
        )
        self.assertEqual(flags["CN"], 1)
        self.assertEqual(flags["HK"], 0)

    def test_hk_majority(self):
        # 3 HK out of 3 → dns_hk=1, dns_cn=0
        _, flags, _, _, _ = build_region_signals(
            ["2.0.0.1", "2.0.0.2", "2.0.0.3"], self.lookup
        )
        self.assertEqual(flags["HK"], 1)
        self.assertEqual(flags["CN"], 0)
        self.assertEqual(flags["MO"], 0)
        self.assertEqual(flags["TW"], 0)

    def test_tw_majority(self):
        _, flags, _, _, _ = build_region_signals(
            ["4.0.0.1", "4.0.0.2", "4.0.0.3"], self.lookup
        )
        self.assertEqual(flags["TW"], 1)

    def test_below_60pct_threshold(self):
        # 2 HK out of 5 = 40% → dns_hk=0
        _, flags, _, _, _ = build_region_signals(
            ["2.0.0.1", "2.0.0.2", "8.8.8.8", "9.9.9.9", "9.9.9.10"], self.lookup
        )
        self.assertEqual(flags["HK"], 0)

    def test_exactly_60pct_threshold(self):
        # 3 HK out of 5 = 60% → dns_hk=1
        _, flags, _, _, _ = build_region_signals(
            ["2.0.0.1", "2.0.0.2", "2.0.0.3", "8.8.8.8", "9.9.9.9"], self.lookup
        )
        self.assertEqual(flags["HK"], 1)

    def test_empty_ips(self):
        _, flags, _, _, _ = build_region_signals([], self.lookup)
        self.assertEqual(flags, {"CN": 0, "HK": 0, "MO": 0, "TW": 0})

    def test_cn_flag_equals_legacy_dns_cn(self):
        """region_dns_flags["CN"] must equal legacy dns_cn for all inputs."""
        from build_domains import build_dns_signal
        cn_only_lookup = build_region_lookup({
            "CN": [ipaddress.IPv4Network("1.0.0.0/24")],
            "HK": [], "MO": [], "TW": [],
        })
        cn_cidr_lookup = build_cidr_lookup([ipaddress.IPv4Network("1.0.0.0/24")])
        test_cases = [
            [],
            ["1.0.0.1"],
            ["1.0.0.1", "1.0.0.2", "1.0.0.3"],
            ["8.8.8.8", "9.9.9.9"],
            ["1.0.0.1", "1.0.0.2", "8.8.8.8", "9.9.9.9", "9.9.9.10"],
            ["1.0.0.1", "not-an-ip"],
        ]
        for ips in test_cases:
            legacy_dns_cn, *_ = build_dns_signal(ips, cn_cidr_lookup)
            _, flags, *_ = build_region_signals(ips, cn_only_lookup)
            self.assertEqual(
                flags["CN"], legacy_dns_cn,
                f"CN flag mismatch on ips={ips}",
            )


# ---------------------------------------------------------------------------
# Tests: process_domain integration — HK/MO/TW scoring
# ---------------------------------------------------------------------------

class TestProcessDomainP2A(unittest.TestCase):

    def setUp(self):
        self.lookup = _make_multi_region_lookup()

    def _run(self, domain, source, ips):
        import build_domains as bd
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: ips
        try:
            return process_domain(
                domain, source, session=None,
                region_lookup=self.lookup,
                updated="2026-04-21",
            )
        finally:
            bd.resolve_domain = original

    def test_hk_ips_no_tld(self):
        # 3 HK IPs, .com TLD → bucket=HK, dns_hk=1, score=60
        rec = self._run("example.com", "extended", ["2.0.0.1", "2.0.0.2", "2.0.0.3"])
        self.assertEqual(rec.bucket, "HK")
        self.assertEqual(rec.dns_hk, 1)
        self.assertEqual(rec.score, DNS_WEIGHT)       # 60
        self.assertGreaterEqual(rec.score, INCLUDE_THRESHOLD)  # qualifies for dist

    def test_hk_ips_with_hk_tld(self):
        # 3 HK IPs, .hk TLD → bucket=HK, score=80
        rec = self._run("example.hk", "extended", ["2.0.0.1", "2.0.0.2", "2.0.0.3"])
        self.assertEqual(rec.bucket, "HK")
        self.assertEqual(rec.dns_hk, 1)
        self.assertEqual(rec.score, DNS_WEIGHT + XX_TLD_WEIGHT)  # 80

    def test_tw_ips_with_tw_tld(self):
        rec = self._run("example.tw", "extended", ["4.0.0.1", "4.0.0.2", "4.0.0.3"])
        self.assertEqual(rec.bucket, "TW")
        self.assertEqual(rec.dns_tw, 1)
        self.assertEqual(rec.score, DNS_WEIGHT + XX_TLD_WEIGHT)  # 80

    def test_hk_tld_only_no_ips_match_scores_zero(self):
        # .hk TLD but IPs resolve to non-HK → dns_hk=0 → score=0 (no fallback)
        rec = self._run("example.hk", "extended", ["8.8.8.8", "9.9.9.9", "8.8.4.4"])
        self.assertEqual(rec.dns_hk, 0)
        self.assertEqual(rec.score, 0)

    def test_mixed_hk_us_below_threshold(self):
        # 2 HK + 3 other = 40% HK → dns_hk=0 → score=0
        rec = self._run("example.com", "extended",
                        ["2.0.0.1", "2.0.0.2", "8.8.8.8", "9.9.9.9", "9.9.9.10"])
        self.assertEqual(rec.dns_hk, 0)
        self.assertEqual(rec.score, 0)

    def test_seed_hk_forces_score_100(self):
        # seed_hk with CN IPs → bucket=HK (forced), score=100 (forced)
        rec = self._run("example.hk", "seed_hk", ["1.0.0.1", "1.0.0.2"])
        self.assertEqual(rec.bucket, "HK")
        self.assertEqual(rec.score, 100)
        self.assertEqual(rec.dns_hk, 0)  # IPs are CN, not HK

    def test_cn_path_unchanged(self):
        # 3 CN IPs, .com TLD → bucket=CN, score=60 (same as P1)
        rec = self._run("example.com", "extended", ["1.0.0.1", "1.0.0.2", "1.0.0.3"])
        self.assertEqual(rec.bucket, "CN")
        self.assertEqual(rec.dns_cn, 1)
        self.assertEqual(rec.score, DNS_WEIGHT)

    def test_cn_path_with_cn_tld(self):
        # 3 CN IPs, .cn TLD → score=70 (same as P1: DNS_WEIGHT + CN_TLD_WEIGHT)
        rec = self._run("example.cn", "extended", ["1.0.0.1", "1.0.0.2", "1.0.0.3"])
        self.assertEqual(rec.bucket, "CN")
        self.assertEqual(rec.score, DNS_WEIGHT + CN_TLD_WEIGHT)  # 70

    def test_mo_ips_qualify(self):
        rec = self._run("example.mo", "extended", ["3.0.0.1", "3.0.0.2", "3.0.0.3"])
        self.assertEqual(rec.bucket, "MO")
        self.assertEqual(rec.dns_mo, 1)
        self.assertGreaterEqual(rec.score, INCLUDE_THRESHOLD)

    def test_new_fields_present_in_record(self):
        rec = self._run("example.hk", "extended", ["2.0.0.1", "2.0.0.2", "2.0.0.3"])
        # All three new fields must exist and be integers
        self.assertIsInstance(rec.dns_hk, int)
        self.assertIsInstance(rec.dns_mo, int)
        self.assertIsInstance(rec.dns_tw, int)


# ---------------------------------------------------------------------------
# Tests: sticky path preserves dns_hk/mo/tw
# ---------------------------------------------------------------------------

class TestStickyPreservesNewFields(unittest.TestCase):

    def test_sticky_restores_dns_hk(self):
        lookup = _make_multi_region_lookup()
        prev = DomainRecord(
            domain="sticky.hk", dns_cn=0, dns_cn_count=0, dns_total=3,
            registrar_cn=0, registrant_cn=0, cn_tld=0, score=80,
            resolved_ips="2.0.0.1|2.0.0.2|2.0.0.3",
            matched_cidr="",
            source="extended", updated="2026-04-01", sticky=0,
            bucket="HK",
            dns_hk=1, dns_mo=0, dns_tw=0,
        )

        import build_domains as bd
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: []
        try:
            rec = process_domain(
                "sticky.hk", "extended", session=None,
                region_lookup=lookup,
                updated="2026-04-21",
                previous={"sticky.hk": prev},
            )
        finally:
            bd.resolve_domain = original

        self.assertEqual(rec.sticky, 1)
        self.assertEqual(rec.dns_hk, 1)
        self.assertEqual(rec.score, 80)
        self.assertEqual(rec.bucket, "HK")


# ---------------------------------------------------------------------------
# Tests: CSV schema backward compatibility
# ---------------------------------------------------------------------------

class TestCSVSchemaBackwardCompat(unittest.TestCase):
    """Old 14-column CSV (without dns_hk/mo/tw) must load without error,
    with the three new fields defaulting to 0."""

    OLD_CSV = (
        "domain,dns_cn,dns_cn_count,dns_total,registrar_cn,registrant_cn,"
        "cn_tld,score,resolved_ips,matched_cidr,source,updated,sticky,bucket\n"
        "example.com,1,2,2,0,0,0,60,1.0.0.1|1.0.0.2,1.0.0.0/24,extended,2026-04-01,0,CN\n"
        "baidu.com,1,3,3,0,0,0,60,1.0.0.3|1.0.0.4|1.0.0.5,1.0.0.0/24,seed,2026-04-01,0,CN\n"
    )

    def test_old_csv_loads_new_fields_default_zero(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                        delete=False, encoding="utf-8") as f:
            f.write(self.OLD_CSV)
            tmppath = Path(f.name)
        try:
            result = load_previous_rows(tmppath)
        finally:
            os.unlink(tmppath)

        self.assertIn("example.com", result)
        rec = result["example.com"]
        self.assertEqual(rec.dns_hk, 0)
        self.assertEqual(rec.dns_mo, 0)
        self.assertEqual(rec.dns_tw, 0)
        self.assertEqual(rec.dns_cn, 1)  # existing field unaffected


# ---------------------------------------------------------------------------
# Tests: P2.A equivalence — CN domain scores must not change
# ---------------------------------------------------------------------------

class TestP2AEquivalence(unittest.TestCase):
    """
    P2.A safety net: any domain that would have scored X under P1 via the
    score_record(dns_cn, 0, 0, cn_tld) path must score identically under
    score_record_for_bucket("CN", dns_cn, cn_tld).
    """

    def test_equivalence_exhaustive(self):
        for dns_cn in (0, 1):
            for cn_tld in (0, 1):
                old = score_record(dns_cn, 0, 0, cn_tld)
                new = score_record_for_bucket("CN", dns_cn, cn_tld)
                self.assertEqual(old, new,
                    f"P2.A CN equivalence broken: dns_cn={dns_cn} cn_tld={cn_tld} "
                    f"old={old} new={new}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
