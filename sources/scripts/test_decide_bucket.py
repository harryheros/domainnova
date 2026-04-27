#!/usr/bin/env python3
"""
Unit tests for decide_bucket() — P1 multi-region bucket assignment (v1.1).

Simplified signature: decide_bucket(domain, source, ip_buckets, dns_cn)

ip_buckets is a list of pre-resolved bucket labels (one per IP), produced by
ip_to_bucket() against the ipnova region CIDR lookup. Each element is one of
"CN" | "HK" | "MO" | "TW" | "" (empty = IP not in any region table).

Covers PROPOSAL §2.2 decision tree:
  Rule 1: seed forced assignment
  Rule 3: per-IP voting from ipnova-derived bucket labels
  Rule 4: dns_cn boosts CN by +2
  Rule 5: TLD +1 vote
  Rule 6: majority + tie-break CN > HK > MO > TW

Run from repo root:
    python sources/scripts/test_decide_bucket.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_domains import decide_bucket  # noqa: E402


class TestSeedForcing(unittest.TestCase):
    """Rule 1: seed_xx sources force the bucket regardless of IP signals."""

    def test_seed_hk_forces_hk_even_with_cn_ips(self):
        self.assertEqual(
            decide_bucket("example.hk", "seed_hk", ["CN", "CN"], dns_cn=1),
            "HK",
        )

    def test_seed_tw_forces_tw_with_no_signals(self):
        self.assertEqual(
            decide_bucket("example.tw", "seed_tw", [], dns_cn=0),
            "TW",
        )

    def test_seed_mo_forces_mo(self):
        self.assertEqual(
            decide_bucket("example.mo", "seed_mo", [""], dns_cn=0),
            "MO",
        )

    def test_legacy_seed_forces_cn(self):
        # P1 fix v2: mainland seed is now symmetric with seed_hk/mo/tw.
        # Even without IP/TLD/dns_cn signal, source=seed forces bucket=CN.
        self.assertEqual(
            decide_bucket("example.com", "seed", [], dns_cn=0),
            "CN",
        )

    def test_legacy_seed_with_cn_signal_becomes_cn(self):
        self.assertEqual(
            decide_bucket("example.com", "seed", ["CN"], dns_cn=1),
            "CN",
        )

    def test_unknown_source_uses_voting(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK"], dns_cn=0),
            "HK",
        )


class TestIpBucketVoting(unittest.TestCase):
    """Rule 3: ipnova-derived per-IP bucket labels are the primary signal."""

    def test_single_hk_ip(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK"], dns_cn=0),
            "HK",
        )

    def test_single_tw_ip(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["TW"], dns_cn=0),
            "TW",
        )

    def test_single_mo_ip(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["MO"], dns_cn=0),
            "MO",
        )

    def test_single_cn_ip(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["CN"], dns_cn=0),
            "CN",
        )

    def test_majority_hk_over_empty(self):
        # 2 HK + 1 unmatched (empty) → HK
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK", "HK", ""], dns_cn=0),
            "HK",
        )

    def test_all_empty_unclassified(self):
        # All IPs are non-region (US/JP/SG etc.) → empty strings → unclassified
        self.assertEqual(
            decide_bucket("example.com", "extended", ["", "", ""], dns_cn=0),
            "",
        )

    def test_invalid_label_ignored(self):
        # Defensive: anything not in REGION_BUCKETS is silently dropped
        self.assertEqual(
            decide_bucket("example.com", "extended", ["XX", "??", "HK"], dns_cn=0),
            "HK",
        )


class TestDnsCnBoost(unittest.TestCase):
    """Rule 4: dns_cn=1 adds +2 to CN."""

    def test_dns_cn_boost_outweighs_single_hk_ip(self):
        # 1 HK (1 pt) vs dns_cn (2 pts) → CN
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK"], dns_cn=1),
            "CN",
        )

    def test_dns_cn_alone_yields_cn(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", [], dns_cn=1),
            "CN",
        )

    def test_two_hk_vs_dns_cn_tie_cn_wins(self):
        # 2 HK (2 pts) vs dns_cn (2 pts) → tie → CN by tie-break
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK", "HK"], dns_cn=1),
            "CN",
        )

    def test_three_hk_beats_dns_cn(self):
        # 3 HK (3 pts) > dns_cn (2 pts) → HK
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK", "HK", "HK"], dns_cn=1),
            "HK",
        )


class TestTldVoting(unittest.TestCase):
    """Rule 5: TLD adds +1 vote to its matching bucket."""

    def test_cn_tld_alone_yields_cn(self):
        self.assertEqual(
            decide_bucket("example.cn", "extended", [], dns_cn=0),
            "CN",
        )

    def test_hk_tld_breaks_tie_with_unmatched(self):
        # 1 unmatched IP + .hk TLD (+1 HK) → HK
        self.assertEqual(
            decide_bucket("example.hk", "extended", [""], dns_cn=0),
            "HK",
        )

    def test_tw_tld_alone(self):
        self.assertEqual(
            decide_bucket("foo.tw", "extended", [], dns_cn=0),
            "TW",
        )

    def test_mo_tld_alone(self):
        self.assertEqual(
            decide_bucket("foo.mo", "extended", [], dns_cn=0),
            "MO",
        )

    def test_uppercase_domain_normalized(self):
        self.assertEqual(
            decide_bucket("EXAMPLE.CN", "extended", [], dns_cn=0),
            "CN",
        )

    def test_tld_only_matches_one_bucket(self):
        # .com.cn should match .cn and only .cn
        self.assertEqual(
            decide_bucket("foo.com.cn", "extended", [], dns_cn=0),
            "CN",
        )


class TestTieBreak(unittest.TestCase):
    """Rule 6: tie-break order CN > HK > MO > TW."""

    def test_hk_vs_tw_tie_hk_wins(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK", "TW"], dns_cn=0),
            "HK",
        )

    def test_mo_vs_tw_tie_mo_wins(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["MO", "TW"], dns_cn=0),
            "MO",
        )

    def test_hk_vs_mo_tie_hk_wins(self):
        self.assertEqual(
            decide_bucket("example.com", "extended", ["HK", "MO"], dns_cn=0),
            "HK",
        )

    def test_three_way_tie_cn_wins(self):
        # 1 HK + 1 MO + 1 TW + .cn TLD (+1 CN) → all 1 → CN by tie-break
        self.assertEqual(
            decide_bucket("example.cn", "extended", ["HK", "MO", "TW"], dns_cn=0),
            "CN",
        )


class TestUnclassified(unittest.TestCase):
    """Empty / pure-unmatched signals → unclassified."""

    def test_empty_everything(self):
        self.assertEqual(decide_bucket("example.com", "extended", [], dns_cn=0), "")

    def test_only_empty_strings(self):
        self.assertEqual(
            decide_bucket("example.com", "discovery", ["", "", ""], dns_cn=0),
            "",
        )


class TestRealisticScenarios(unittest.TestCase):
    """End-to-end realistic cases."""

    def test_alibaba_cn(self):
        # All IPs in ipnova CN.txt, dns_cn=1
        self.assertEqual(
            decide_bucket("aliyun.com", "extended", ["CN", "CN"], dns_cn=1),
            "CN",
        )

    def test_hk_seed_with_cn_mirror(self):
        # Seed forces HK regardless of where IPs land
        self.assertEqual(
            decide_bucket("hktdc.com", "seed_hk", ["CN", "CN"], dns_cn=1),
            "HK",
        )

    def test_taiwan_university(self):
        self.assertEqual(
            decide_bucket("ntu.edu.tw", "extended", ["TW"], dns_cn=0),
            "TW",
        )

    def test_global_cdn_with_mixed_pops_cn_wins(self):
        # 1 HK PoP + 1 CN PoP, CN-CIDR majority → CN (curated CIDR is decisive)
        self.assertEqual(
            decide_bucket(
                "global-cdn.example", "extended",
                ["HK", "CN"], dns_cn=1,
            ),
            "CN",
        )

    def test_offshore_hosted_dot_cn_domain(self):
        # .cn domain hosted on US infrastructure → empty IPs, but TLD wins
        self.assertEqual(
            decide_bucket("foo.cn", "extended", ["", ""], dns_cn=0),
            "CN",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
