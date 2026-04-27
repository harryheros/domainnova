#!/usr/bin/env python3
"""
Unit tests for Step 6: write_dist_buckets + write_stats buckets section.

Run from repo root:
    python sources/scripts/test_step6_dist.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_domains import (  # noqa: E402
    write_dist_buckets,
    write_stats,
    DomainRecord,
    INCLUDE_THRESHOLD,
)


def _rec(domain: str, bucket: str, score: int = 80, source: str = "extended") -> DomainRecord:
    return DomainRecord(
        domain=domain, dns_cn=int(bucket == "CN"), dns_cn_count=0, dns_total=1,
        registrar_cn=0, registrant_cn=0, cn_tld=0, score=score,
        resolved_ips="", matched_cidr="", source=source, updated="2026-04-11T00:00:00Z",
        sticky=0, bucket=bucket,
    )


class TestWriteDistBuckets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self.tmp.name) / "dist"

    def tearDown(self):
        self.tmp.cleanup()

    def _read_domains(self, name: str) -> list[str]:
        path = self.dist / name
        lines = path.read_text(encoding="utf-8").splitlines()
        return [ln for ln in lines if ln and not ln.startswith("#")]

    def test_creates_all_four_files(self):
        rows = [_rec("a.cn", "CN"), _rec("b.hk", "HK")]
        write_dist_buckets(self.dist, rows)
        for name in ("domains_cn.txt", "domains_hk.txt", "domains_mo.txt", "domains_tw.txt"):
            self.assertTrue((self.dist / name).exists(), f"missing {name}")

    def test_empty_bucket_still_has_header(self):
        rows = [_rec("only.cn", "CN")]
        write_dist_buckets(self.dist, rows)
        mo_text = (self.dist / "domains_mo.txt").read_text(encoding="utf-8")
        self.assertIn("# DomainNova - MO domains", mo_text)
        self.assertIn("# Count: 0", mo_text)
        self.assertEqual(self._read_domains("domains_mo.txt"), [])

    def test_routing_per_bucket(self):
        rows = [
            _rec("a.cn", "CN"), _rec("b.cn", "CN"),
            _rec("c.hk", "HK"),
            _rec("d.tw", "TW"),
        ]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read_domains("domains_cn.txt"), ["a.cn", "b.cn"])
        self.assertEqual(self._read_domains("domains_hk.txt"), ["c.hk"])
        self.assertEqual(self._read_domains("domains_mo.txt"), [])
        self.assertEqual(self._read_domains("domains_tw.txt"), ["d.tw"])

    def test_alphabetical_sort(self):
        rows = [_rec("z.cn", "CN"), _rec("a.cn", "CN"), _rec("m.cn", "CN")]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read_domains("domains_cn.txt"), ["a.cn", "m.cn", "z.cn"])

    def test_threshold_filtering(self):
        rows = [
            _rec("good.cn", "CN", score=INCLUDE_THRESHOLD),
            _rec("gray.cn", "CN", score=INCLUDE_THRESHOLD - 1),
            _rec("bad.cn",  "CN", score=0),
        ]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read_domains("domains_cn.txt"), ["good.cn"])

    def test_unclassified_excluded(self):
        rows = [_rec("classified.cn", "CN"), _rec("unknown.com", "")]
        write_dist_buckets(self.dist, rows)
        self.assertEqual(self._read_domains("domains_cn.txt"), ["classified.cn"])
        for b in ("hk", "mo", "tw"):
            self.assertEqual(self._read_domains(f"domains_{b}.txt"), [])

    def test_returns_counts(self):
        rows = [_rec("a.cn", "CN"), _rec("b.cn", "CN"), _rec("c.hk", "HK")]
        counts = write_dist_buckets(self.dist, rows)
        self.assertEqual(counts, {"cn": 2, "hk": 1, "mo": 0, "tw": 0})

    def test_mutual_exclusion_invariant(self):
        # PROPOSAL §7.1.2: 4 dist files must be pairwise disjoint
        rows = [
            _rec("a.cn", "CN"), _rec("b.cn", "CN"),
            _rec("c.hk", "HK"), _rec("d.hk", "HK"),
            _rec("e.mo", "MO"),
            _rec("f.tw", "TW"), _rec("g.tw", "TW"),
        ]
        write_dist_buckets(self.dist, rows)
        sets = {b: set(self._read_domains(f"domains_{b}.txt"))
                for b in ("cn", "hk", "mo", "tw")}
        keys = list(sets)
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                self.assertEqual(
                    sets[keys[i]] & sets[keys[j]], set(),
                    f"intersection between {keys[i]} and {keys[j]}",
                )

    def test_legacy_domains_txt_removed_if_present(self):
        self.dist.mkdir(parents=True)
        legacy = self.dist / "domains.txt"
        legacy.write_text("stale\n", encoding="utf-8")
        write_dist_buckets(self.dist, [_rec("a.cn", "CN")])
        self.assertFalse(legacy.exists(), "legacy dist/domains.txt should be removed")


class TestWriteStatsBuckets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "stats.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def test_buckets_section_present(self):
        rows = [_rec("a.cn", "CN"), _rec("b.hk", "HK")]
        write_stats(self.path, rows, extra={}, bucket_counts={"cn": 1, "hk": 1, "mo": 0, "tw": 0})
        data = self._read()
        self.assertIn("buckets", data)
        for b in ("cn", "hk", "mo", "tw", "unclassified"):
            self.assertIn(b, data["buckets"])

    def test_dist_domains_is_total_across_buckets(self):
        # PROPOSAL v1.1 §5.3: dist_domains = sum across all four buckets
        rows = [_rec("a.cn", "CN"), _rec("b.cn", "CN"), _rec("c.hk", "HK"), _rec("d.tw", "TW")]
        write_stats(self.path, rows, extra={},
                    bucket_counts={"cn": 2, "hk": 1, "mo": 0, "tw": 1})
        data = self._read()
        self.assertEqual(data["dist_domains"], 4)
        self.assertEqual(data["buckets"]["cn"]["included"], 2)
        self.assertEqual(data["buckets"]["hk"]["included"], 1)
        self.assertEqual(data["buckets"]["tw"]["included"], 1)

    def test_unclassified_count(self):
        rows = [_rec("a.cn", "CN"), _rec("nope.com", ""), _rec("nada.com", "")]
        write_stats(self.path, rows, extra={},
                    bucket_counts={"cn": 1, "hk": 0, "mo": 0, "tw": 0})
        data = self._read()
        self.assertEqual(data["buckets"]["unclassified"], 2)

    def test_gray_band_per_bucket(self):
        rows = [
            _rec("good.cn", "CN", score=INCLUDE_THRESHOLD),
            _rec("gray.cn", "CN", score=40),
            _rec("good.hk", "HK", score=INCLUDE_THRESHOLD),
        ]
        write_stats(self.path, rows, extra={},
                    bucket_counts={"cn": 1, "hk": 1, "mo": 0, "tw": 0})
        data = self._read()
        self.assertEqual(data["buckets"]["cn"]["gray"], 1)
        self.assertEqual(data["buckets"]["cn"]["total"], 2)
        self.assertEqual(data["buckets"]["hk"]["gray"], 0)
        self.assertEqual(data["buckets"]["hk"]["total"], 1)

    def test_extra_kwargs_preserved(self):
        write_stats(self.path, [], extra={"sticky_retained": 3, "workers": 20},
                    bucket_counts={"cn": 0, "hk": 0, "mo": 0, "tw": 0})
        data = self._read()
        self.assertEqual(data["sticky_retained"], 3)
        self.assertEqual(data["workers"], 20)

    def test_works_without_bucket_counts_kwarg(self):
        # Backward-compat fallback path: derive from rows
        rows = [_rec("a.cn", "CN"), _rec("b.hk", "HK")]
        write_stats(self.path, rows, extra={})
        data = self._read()
        self.assertEqual(data["buckets"]["cn"]["included"], 1)
        self.assertEqual(data["buckets"]["hk"]["included"], 1)
        self.assertEqual(data["dist_domains"], 2)

    def test_stats_matches_dist_invariant(self):
        # PROPOSAL §8.6: stats.buckets.{b}.included must equal write_dist_buckets output
        rows = [
            _rec("a.cn", "CN"), _rec("b.cn", "CN"),
            _rec("c.hk", "HK"),
            _rec("d.tw", "TW"),
            _rec("nope.com", ""),
        ]
        tmp = tempfile.TemporaryDirectory()
        try:
            dist = Path(tmp.name) / "dist"
            counts = write_dist_buckets(dist, rows)
            write_stats(self.path, rows, extra={}, bucket_counts=counts)
            data = self._read()
            for b in ("cn", "hk", "mo", "tw"):
                self.assertEqual(
                    data["buckets"][b]["included"], counts[b],
                    f"stats/dist mismatch for {b}",
                )
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
