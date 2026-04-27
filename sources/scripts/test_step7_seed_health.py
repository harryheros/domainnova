#!/usr/bin/env python3
"""
Unit tests for Step 7: seed_health_check + _classify_health.

Run from repo root:
    python sources/scripts/test_step7_seed_health.py
"""
from __future__ import annotations

import ipaddress
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains as bd  # noqa: E402
from build_domains import (  # noqa: E402
    _classify_health,
    seed_health_check,
    build_region_lookup,
)


def _make_lookup():
    """Build a region lookup whose CIDRs map distinct /16s to each bucket."""
    return build_region_lookup({
        "CN": [ipaddress.IPv4Network("1.0.0.0/16")],
        "HK": [ipaddress.IPv4Network("2.0.0.0/16")],
        "MO": [ipaddress.IPv4Network("3.0.0.0/16")],
        "TW": [ipaddress.IPv4Network("4.0.0.0/16")],
    })


class TestClassifyHealth(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(_classify_health(1.0), "ok")
        self.assertEqual(_classify_health(0.6), "ok")
        self.assertEqual(_classify_health(0.95), "ok")

    def test_warn(self):
        self.assertEqual(_classify_health(0.5), "warn")
        self.assertEqual(_classify_health(0.3), "warn")
        self.assertEqual(_classify_health(0.59), "warn")

    def test_error(self):
        self.assertEqual(_classify_health(0.0), "error")
        self.assertEqual(_classify_health(0.1), "error")
        self.assertEqual(_classify_health(0.299), "error")


class _FakeRepo:
    """Minimal disposable repo with a populated sources/manual/ directory."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "sources" / "manual").mkdir(parents=True)
        (self.root / "data").mkdir()

    def write_seed(self, filename: str, domains: list):
        path = self.root / "sources" / "manual" / filename
        path.write_text("\n".join(domains) + "\n", encoding="utf-8")

    def cleanup(self):
        self.tmp.cleanup()


def _stub_resolver(mapping: dict):
    """Returns a function suitable for monkey-patching bd.resolve_domain.
    `mapping` maps domain -> list[str] of IPs (or [] for unresolvable)."""
    def _impl(domain, session):
        return mapping.get(domain, [])
    return _impl


class TestSeedHealthCheck(unittest.TestCase):
    def setUp(self):
        self.repo = _FakeRepo()
        self.lookup = _make_lookup()
        self._orig_resolve = bd.resolve_domain

    def tearDown(self):
        bd.resolve_domain = self._orig_resolve
        self.repo.cleanup()

    def test_all_consistent(self):
        self.repo.write_seed("seed_cn.txt",    [f"cn{i}.example" for i in range(10)])
        self.repo.write_seed("seed_hk.txt", [f"hk{i}.example" for i in range(5)])
        self.repo.write_seed("seed_mo.txt", [f"mo{i}.example" for i in range(5)])
        self.repo.write_seed("seed_tw.txt", [f"tw{i}.example" for i in range(5)])

        mapping = {}
        for i in range(10): mapping[f"cn{i}.example"] = ["1.0.0.5"]
        for i in range(5):  mapping[f"hk{i}.example"] = ["2.0.0.5"]
        for i in range(5):  mapping[f"mo{i}.example"] = ["3.0.0.5"]
        for i in range(5):  mapping[f"tw{i}.example"] = ["4.0.0.5"]
        bd.resolve_domain = _stub_resolver(mapping)

        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(42))
        for fname in ("seed_cn.txt", "seed_hk.txt", "seed_mo.txt", "seed_tw.txt"):
            entry = payload["results"][fname]
            self.assertEqual(entry["status"], "ok", f"{fname}: {entry}")
            self.assertEqual(entry["rate"], 1.0)

    def test_warn_threshold(self):
        # 5 HK domains, 2 resolve to HK and 3 to CN -> rate 0.4 -> warn
        self.repo.write_seed("seed_cn.txt",    ["a", "b", "c"])
        self.repo.write_seed("seed_hk.txt", ["h1", "h2", "h3", "h4", "h5"])
        self.repo.write_seed("seed_mo.txt", ["m1", "m2", "m3"])
        self.repo.write_seed("seed_tw.txt", ["t1", "t2", "t3"])

        mapping = {
            "a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"],
            "h1": ["2.0.0.1"], "h2": ["2.0.0.2"],
            "h3": ["1.0.0.10"], "h4": ["1.0.0.11"], "h5": ["1.0.0.12"],
            "m1": ["3.0.0.1"], "m2": ["3.0.0.2"], "m3": ["3.0.0.3"],
            "t1": ["4.0.0.1"], "t2": ["4.0.0.2"], "t3": ["4.0.0.3"],
        }
        bd.resolve_domain = _stub_resolver(mapping)

        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        hk = payload["results"]["seed_hk.txt"]
        self.assertEqual(hk["sampled"], 5)
        self.assertEqual(hk["consistent"], 2)
        self.assertAlmostEqual(hk["rate"], 0.4, places=4)
        self.assertEqual(hk["status"], "warn")

    def test_error_threshold(self):
        # 5 TW domains, only 1 in TW -> rate 0.2 -> error
        self.repo.write_seed("seed_cn.txt",    ["a", "b", "c"])
        self.repo.write_seed("seed_hk.txt", ["h1", "h2", "h3"])
        self.repo.write_seed("seed_mo.txt", ["m1", "m2", "m3"])
        self.repo.write_seed("seed_tw.txt", ["t1", "t2", "t3", "t4", "t5"])

        mapping = {
            "a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"],
            "h1": ["2.0.0.1"], "h2": ["2.0.0.2"], "h3": ["2.0.0.3"],
            "m1": ["3.0.0.1"], "m2": ["3.0.0.2"], "m3": ["3.0.0.3"],
            "t1": ["4.0.0.1"],
            "t2": ["1.0.0.99"], "t3": ["1.0.0.98"], "t4": ["1.0.0.97"], "t5": ["1.0.0.96"],
        }
        bd.resolve_domain = _stub_resolver(mapping)

        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        tw = payload["results"]["seed_tw.txt"]
        self.assertEqual(tw["consistent"], 1)
        self.assertAlmostEqual(tw["rate"], 0.2, places=4)
        self.assertEqual(tw["status"], "error")

    def test_skipped_when_too_few_domains(self):
        # < 3 domains -> skipped
        self.repo.write_seed("seed_cn.txt",    ["a", "b", "c"])
        self.repo.write_seed("seed_hk.txt", ["only_one"])
        self.repo.write_seed("seed_mo.txt", [])
        self.repo.write_seed("seed_tw.txt", ["t1", "t2", "t3"])
        bd.resolve_domain = _stub_resolver({"a": ["1.0.0.1"], "b": ["1.0.0.2"],
                                            "c": ["1.0.0.3"], "t1": ["4.0.0.1"],
                                            "t2": ["4.0.0.2"], "t3": ["4.0.0.3"]})
        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        self.assertEqual(payload["results"]["seed_hk.txt"]["status"], "skipped")
        self.assertEqual(payload["results"]["seed_mo.txt"]["status"], "skipped")
        self.assertEqual(payload["results"]["seed_cn.txt"]["status"], "ok")

    def test_skipped_when_zero_resolved(self):
        # All resolve attempts fail -> skipped (not error)
        self.repo.write_seed("seed_cn.txt",    ["a", "b", "c"])
        self.repo.write_seed("seed_hk.txt", ["h1", "h2", "h3", "h4", "h5"])
        self.repo.write_seed("seed_mo.txt", ["m1", "m2", "m3"])
        self.repo.write_seed("seed_tw.txt", ["t1", "t2", "t3"])
        # HK domains all fail to resolve
        mapping = {"a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"],
                   "m1": ["3.0.0.1"], "m2": ["3.0.0.2"], "m3": ["3.0.0.3"],
                   "t1": ["4.0.0.1"], "t2": ["4.0.0.2"], "t3": ["4.0.0.3"]}
        bd.resolve_domain = _stub_resolver(mapping)
        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        self.assertEqual(payload["results"]["seed_hk.txt"]["status"], "skipped")

    def test_resolve_exception_does_not_abort(self):
        self.repo.write_seed("seed_cn.txt",    ["a", "b", "c"])
        self.repo.write_seed("seed_hk.txt", ["h1", "h2", "h3"])
        self.repo.write_seed("seed_mo.txt", ["m1", "m2", "m3"])
        self.repo.write_seed("seed_tw.txt", ["t1", "t2", "t3"])

        def boom_resolver(domain, session):
            if domain.startswith("h"):
                raise ConnectionError("simulated DoH outage")
            return {"a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"],
                    "m1": ["3.0.0.1"], "m2": ["3.0.0.2"], "m3": ["3.0.0.3"],
                    "t1": ["4.0.0.1"], "t2": ["4.0.0.2"], "t3": ["4.0.0.3"]}.get(domain, [])
        bd.resolve_domain = boom_resolver

        # Must not raise
        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        self.assertEqual(payload["results"]["seed_hk.txt"]["status"], "skipped")
        self.assertEqual(payload["results"]["seed_cn.txt"]["status"], "ok")

    def test_missing_seed_file_skipped(self):
        # Only seed_cn.txt exists; HK/MO/TW files missing entirely
        self.repo.write_seed("seed_cn.txt", ["a", "b", "c"])
        bd.resolve_domain = _stub_resolver({"a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"]})
        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        self.assertEqual(payload["results"]["seed_hk.txt"]["status"], "skipped")
        self.assertEqual(payload["results"]["seed_mo.txt"]["status"], "skipped")
        self.assertEqual(payload["results"]["seed_tw.txt"]["status"], "skipped")

    def test_writes_seed_health_json(self):
        self.repo.write_seed("seed_cn.txt", ["a", "b", "c"])
        bd.resolve_domain = _stub_resolver({"a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"]})
        seed_health_check(self.repo.root, self.lookup, session=None,
                          rng=random.Random(0))
        out = self.repo.root / "data" / "seed_health.json"
        self.assertTrue(out.exists())
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("checked_at", data)
        self.assertIn("results", data)
        self.assertEqual(set(data["results"].keys()),
                         {"seed_cn.txt", "seed_hk.txt", "seed_mo.txt", "seed_tw.txt"})

    def test_sample_size_caps_at_20(self):
        # 100 CN domains -> sample only 20
        domains = [f"d{i}" for i in range(100)]
        self.repo.write_seed("seed_cn.txt", domains)
        for fname in ("seed_hk.txt", "seed_mo.txt", "seed_tw.txt"):
            self.repo.write_seed(fname, ["x1", "x2", "x3"])
        mapping = {d: ["1.0.0.1"] for d in domains}
        for x in ("x1", "x2", "x3"):
            mapping[x] = ["2.0.0.1"]  # HK
        bd.resolve_domain = _stub_resolver(mapping)
        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        self.assertEqual(payload["results"]["seed_cn.txt"]["sampled"], 20)
        self.assertEqual(payload["results"]["seed_cn.txt"]["consistent"], 20)

    def test_payload_structure_matches_spec(self):
        # PROPOSAL §4.3: results entry has region/sampled/consistent/rate/status
        self.repo.write_seed("seed_cn.txt", ["a", "b", "c"])
        bd.resolve_domain = _stub_resolver({"a": ["1.0.0.1"], "b": ["1.0.0.2"], "c": ["1.0.0.3"]})
        payload = seed_health_check(self.repo.root, self.lookup, session=None,
                                    rng=random.Random(0))
        cn = payload["results"]["seed_cn.txt"]
        self.assertEqual(set(cn.keys()), {"region", "sampled", "consistent", "rate", "status"})
        self.assertEqual(cn["region"], "CN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
