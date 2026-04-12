#!/usr/bin/env python3
"""
Unit tests for the P1 fix patch:
  1. load_all_sources loads seed_hk/mo/tw with priority above legacy seed
  2. process_domain forces score=100 for region seed sources
  3. write_dist_buckets uses lenient filter for non-CN buckets

Run from repo root:
    python sources/scripts/test_p1_fix.py
"""
from __future__ import annotations

import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains as bd  # noqa: E402
from build_domains import (  # noqa: E402
    load_all_sources,
    process_domain,
    write_dist_buckets,
    build_region_lookup,
    DomainRecord,
    INCLUDE_THRESHOLD,
)


def _make_repo(seed=None, hk=None, mo=None, tw=None, extended=None, discovery=None):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    (root / "sources" / "manual").mkdir(parents=True)
    (root / "data").mkdir()

    def _write(name, lines):
        (root / "sources" / "manual" / name).write_text(
            "\n".join(lines or []) + "\n", encoding="utf-8"
        )
    _write("seed.txt",      seed or [])
    _write("seed_hk.txt",   hk or [])
    _write("seed_mo.txt",   mo or [])
    _write("seed_tw.txt",   tw or [])
    _write("extended.txt",  extended or [])
    _write("discovery.txt", discovery or [])
    return tmp, root


def _hk_lookup():
    return build_region_lookup({
        "CN": [ipaddress.IPv4Network("1.0.0.0/16")],
        "HK": [ipaddress.IPv4Network("2.0.0.0/16")],
        "MO": [ipaddress.IPv4Network("3.0.0.0/16")],
        "TW": [ipaddress.IPv4Network("4.0.0.0/16")],
    })


class TestLoadAllSourcesRegionSeeds(unittest.TestCase):
    def test_loads_all_four_seed_files(self):
        tmp, root = _make_repo(
            seed=["mainland.cn"],
            hk=["alipay.hk", "jd.hk"],
            mo=["macau1.mo"],
            tw=["taiwan1.tw"],
        )
        try:
            result = dict(load_all_sources(root))
        finally:
            tmp.cleanup()
        self.assertEqual(result["mainland.cn"], "seed")
        self.assertEqual(result["alipay.hk"],   "seed_hk")
        self.assertEqual(result["jd.hk"],       "seed_hk")
        self.assertEqual(result["macau1.mo"],   "seed_mo")
        self.assertEqual(result["taiwan1.tw"],  "seed_tw")

    def test_region_seed_priority_over_legacy_seed(self):
        # If alipay.hk somehow appears in BOTH seed.txt and seed_hk.txt,
        # the HK assignment must win.
        tmp, root = _make_repo(
            seed=["alipay.hk", "other.cn"],
            hk=["alipay.hk"],
        )
        try:
            result = dict(load_all_sources(root))
        finally:
            tmp.cleanup()
        self.assertEqual(result["alipay.hk"], "seed_hk")
        self.assertEqual(result["other.cn"],  "seed")

    def test_region_seed_priority_over_extended(self):
        tmp, root = _make_repo(
            hk=["foo.hk"],
            extended=["foo.hk", "other.com"],
        )
        try:
            result = dict(load_all_sources(root))
        finally:
            tmp.cleanup()
        self.assertEqual(result["foo.hk"],   "seed_hk")
        self.assertEqual(result["other.com"], "extended")

    def test_empty_region_seeds_no_crash(self):
        tmp, root = _make_repo(seed=["only.cn"])
        try:
            result = dict(load_all_sources(root))
        finally:
            tmp.cleanup()
        self.assertEqual(result, {"only.cn": "seed"})


class TestProcessDomainRegionSeedScore(unittest.TestCase):
    def setUp(self):
        self.lookup = _hk_lookup()
        self._orig = bd.resolve_domain

    def tearDown(self):
        bd.resolve_domain = self._orig

    def test_seed_hk_with_no_ips_still_score_100(self):
        # alipay.hk fails to resolve → would normally score 0 → would be filtered
        bd.resolve_domain = lambda d, s: []
        rec = process_domain("alipay.hk", "seed_hk", session=None,
                             region_lookup=self.lookup, updated="now")
        self.assertEqual(rec.bucket, "HK")
        self.assertEqual(rec.score, 100)

    def test_seed_hk_with_hk_ips_score_100(self):
        bd.resolve_domain = lambda d, s: ["2.0.0.5"]
        rec = process_domain("alipay.hk", "seed_hk", session=None,
                             region_lookup=self.lookup, updated="now")
        self.assertEqual(rec.bucket, "HK")
        self.assertEqual(rec.score, 100)

    def test_seed_mo_score_100(self):
        bd.resolve_domain = lambda d, s: []
        rec = process_domain("foo.mo", "seed_mo", session=None,
                             region_lookup=self.lookup, updated="now")
        self.assertEqual(rec.bucket, "MO")
        self.assertEqual(rec.score, 100)

    def test_seed_tw_score_100(self):
        bd.resolve_domain = lambda d, s: []
        rec = process_domain("foo.tw", "seed_tw", session=None,
                             region_lookup=self.lookup, updated="now")
        self.assertEqual(rec.bucket, "TW")
        self.assertEqual(rec.score, 100)

    def test_legacy_cn_seed_NOT_overridden(self):
        # Mainland seed must still earn its score normally so seed_health_check
        # has a real signal to detect drift.
        bd.resolve_domain = lambda d, s: []
        rec = process_domain("foo.com", "seed", session=None,
                             region_lookup=self.lookup, updated="now")
        # No IPs, no .cn TLD → score=0 (unchanged from pre-patch behavior)
        self.assertEqual(rec.score, 0)

    def test_extended_source_NOT_overridden(self):
        bd.resolve_domain = lambda d, s: []
        rec = process_domain("foo.com", "extended", session=None,
                             region_lookup=self.lookup, updated="now")
        self.assertEqual(rec.score, 0)


def _rec(domain, bucket, score=80, source="extended"):
    return DomainRecord(
        domain=domain, dns_cn=int(bucket == "CN"), dns_cn_count=0, dns_total=1,
        registrar_cn=0, registrant_cn=0, cn_tld=0, score=score,
        resolved_ips="", matched_cidr="", source=source, updated="now",
        sticky=0, bucket=bucket,
    )


class TestWriteDistBucketsLenientFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self.tmp.name) / "dist"

    def tearDown(self):
        self.tmp.cleanup()

    def _read(self, name):
        return [
            ln for ln in (self.dist / name).read_text().splitlines()
            if ln and not ln.startswith("#")
        ]

    def test_hk_bucket_accepts_zero_score(self):
        rows = [_rec("alipay.hk", "HK", score=0)]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read("domains_hk.txt"), ["alipay.hk"])

    def test_cn_bucket_still_threshold_filtered(self):
        rows = [
            _rec("good.cn", "CN", score=INCLUDE_THRESHOLD),
            _rec("bad.cn",  "CN", score=0),
        ]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read("domains_cn.txt"), ["good.cn"])

    def test_mo_tw_buckets_lenient(self):
        rows = [
            _rec("foo.mo", "MO", score=0),
            _rec("foo.tw", "TW", score=10),
        ]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read("domains_mo.txt"), ["foo.mo"])
        self.assertEqual(self._read("domains_tw.txt"), ["foo.tw"])

    def test_unclassified_still_excluded_from_all(self):
        rows = [_rec("nope.com", "", score=100)]
        write_dist_buckets(self.dist, rows)
        for b in ("cn", "hk", "mo", "tw"):
            self.assertEqual(self._read(f"domains_{b}.txt"), [])


class TestEndToEndAlipayHk(unittest.TestCase):
    """Reproduces the exact failure mode observed on the cloud build:
    seed_hk.txt contains alipay.hk, but domains_hk.txt was empty."""

    def test_alipay_hk_lands_in_dist(self):
        tmp, root = _make_repo(
            seed=["mainland.cn"],
            hk=["alipay.hk", "jd.hk", "tmall.hk"],
        )
        sources = dict(load_all_sources(root))
        self.assertEqual(sources.get("alipay.hk"), "seed_hk")

        # Simulate process_domain with no resolved IPs (worst-case)
        original = bd.resolve_domain
        bd.resolve_domain = lambda d, s: []
        try:
            rec = process_domain(
                "alipay.hk", "seed_hk", session=None,
                region_lookup=_hk_lookup(), updated="now",
            )
        finally:
            bd.resolve_domain = original
            tmp.cleanup()

        # The combined contract: bucket=HK, score=100, dist accepts it
        self.assertEqual(rec.bucket, "HK")
        self.assertEqual(rec.score, 100)

        with tempfile.TemporaryDirectory() as d:
            dist = Path(d) / "dist"
            counts = write_dist_buckets(dist, [rec])
            self.assertEqual(counts["hk"], 1)
            content = (dist / "domains_hk.txt").read_text()
            self.assertIn("alipay.hk", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
