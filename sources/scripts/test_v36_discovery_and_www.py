"""v3.6: full discovery evaluation, www fallback, discovery intake filter."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "discovery_agents"))

import build_domains as bd  # noqa: E402
import _common  # noqa: E402


class TestWwwFallback(unittest.TestCase):
    def setUp(self):
        self._orig = bd._resolve_name
        bd._www_fallback_hits.clear()

    def tearDown(self):
        bd._resolve_name = self._orig
        bd._www_fallback_hits.clear()

    def _stub(self, table):
        calls = []

        def fake(name, session):
            calls.append(name)
            return list(table.get(name, []))
        bd._resolve_name = fake
        return calls

    def test_bare_name_resolves_no_www_query(self):
        calls = self._stub({"example.cn": ["1.2.3.4"]})
        self.assertEqual(bd.resolve_domain_detail("example.cn", object()), (["1.2.3.4"], "example.cn"))
        self.assertEqual(calls, ["example.cn"])
        self.assertNotIn("example.cn", bd._www_fallback_hits)

    def test_falls_back_to_www(self):
        # e.g. soumu.go.jp has no address record, www.soumu.go.jp does
        calls = self._stub({"www.soumu.go.jp": ["203.0.113.5"]})
        ips, name = bd.resolve_domain_detail("soumu.go.jp", object())
        self.assertEqual((ips, name), (["203.0.113.5"], "www.soumu.go.jp"))
        self.assertEqual(calls, ["soumu.go.jp", "www.soumu.go.jp"])
        self.assertIn("soumu.go.jp", bd._www_fallback_hits)
        self.assertEqual(bd.resolve_domain("soumu.go.jp", object()), ["203.0.113.5"])

    def test_no_double_www_and_no_wildcards(self):
        calls = self._stub({})
        self.assertEqual(bd.resolve_domain_detail("www.dead.example", object()), ([], ""))
        self.assertEqual(calls, ["www.dead.example"])
        calls.clear()
        bd.resolve_domain_detail("*.wild.example", object())
        self.assertNotIn("www.*.wild.example", calls)

    def test_dead_domain_returns_empty(self):
        self._stub({})
        self.assertEqual(bd.resolve_domain("gone.example", object()), [])


class TestFullDiscoveryEvaluation(unittest.TestCase):
    def test_every_discovery_domain_is_loaded_and_offset_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manual = root / "sources" / "manual"
            manual.mkdir(parents=True)
            for name in ("seed_cn", "seed_hk", "seed_mo", "seed_tw", "seed_jp", "seed_kr", "seed_sg"):
                (manual / f"{name}.txt").write_text("", encoding="utf-8")
            (manual / "extended.txt").write_text("ext.example\n", encoding="utf-8")
            disc = [f"d{i}.example" for i in range(700)]
            (manual / "discovery.txt").write_text("\n".join(disc) + "\n", encoding="utf-8")
            (root / "data").mkdir()
            state = root / "data" / "discovery_stats.json"
            state.write_text(json.dumps({"discovery_offset": 300, "hit_counts": {"d1.example": 2}}), encoding="utf-8")

            first = dict(bd.load_all_sources(root))
            second = dict(bd.load_all_sources(root))
            n = sum(1 for v in first.values() if v == "discovery")
            self.assertEqual(n, 700, "all discovery domains must be checked every run")
            self.assertEqual(first, second, "two runs must load the same domains")
            saved = json.loads(state.read_text(encoding="utf-8"))
            self.assertNotIn("discovery_offset", saved)
            self.assertEqual(saved["hit_counts"], {"d1.example": 2}, "promotion counters must be kept")

    def test_no_sampling_constant_left(self):
        self.assertFalse(hasattr(bd, "DISCOVERY_SAMPLE"))


class TestDiscoveryIntake(unittest.TestCase):
    def test_capacity_matches_between_build_and_agents(self):
        self.assertEqual(bd.DISCOVERY_MAX, _common.DISCOVERY_MAX)
        self.assertGreaterEqual(_common.DISCOVERY_MAX, 5000)

    def test_filter_candidates(self):
        known = {"example.cn", "baidu.com", "gov.cn"}
        got = _common.filter_candidates(
            ["WWW.Foo.com.", "news.example.cn", "hzfc.gov.cn", "foo.com", "bar.net",
             "google.com", "bad_domain", "www.baidu.com", "nodot"], known)
        self.assertEqual(got, ["foo.com", "bar.net"])

    def test_is_covered(self):
        self.assertTrue(_common.is_covered("a.b.example.cn", {"example.cn"}))
        self.assertTrue(_common.is_covered("example.cn", {"example.cn"}))
        self.assertFalse(_common.is_covered("example.cn", {"cn"}), "a bare TLD never covers")
        self.assertFalse(_common.is_covered("other.cn", {"example.cn"}))

    def test_load_existing_includes_every_seed_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manual = root / "sources" / "manual"
            manual.mkdir(parents=True)
            (manual / "seed_jp.txt").write_text("# c\nsoumu.go.jp\n", encoding="utf-8")
            (manual / "extended.txt").write_text("ext.example\n", encoding="utf-8")
            self.assertEqual(_common.load_existing(root), {"soumu.go.jp", "ext.example"})


if __name__ == "__main__":
    unittest.main()
