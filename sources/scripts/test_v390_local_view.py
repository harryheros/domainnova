"""
v3.9.0: the regional view, on trial (_local_view.py).

Domains with a regional hint are asked again as a client in their own
region; an answer counts only past the guards (foreign edges of global
services, global CDNs, the build's own view, answers that follow the
asker), and only after two weeks in a row. Nothing is published from it:
the build records the result in stats.json and QUALITY.md.

The world below stands in for DNS: answers depend on the client subnet.
"""
import ipaddress
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _local_view as lv  # noqa: E402
import build_domains  # noqa: E402
import build_quality_report as qr  # noqa: E402

RANGES = {
    "HK": "203.0.0.0/16",     # HK ranges
    "SG": "198.18.0.0/16",    # SG ranges
    "TW": "100.64.0.0/16",
}
SUBNETS = {"HK": "203.0.0.0/24", "SG": "198.18.0.0/24", "TW": "100.64.0.0/24"}


def bucket(ip):
    for r, n in RANGES.items():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(n):
            return r
    return ""


# name -> {subnet: [ips]}; "*" answers every subnet
WORLD = {
    # hosted in Hong Kong: the same address for everyone
    "origin.com.hk": {"*": ["203.0.5.10"]},
    # HK users to HK, everyone else to a CDN outside every region
    "geo.com.hk": {SUBNETS["HK"]: ["203.0.6.10"], "*": ["192.0.2.10"]},
    # a CDN with a node in every region: follows the asker
    "cdn-customer.com.hk": {SUBNETS["HK"]: ["203.0.7.10"], SUBNETS["SG"]: ["198.18.7.10"],
                            "*": ["192.0.2.20"]},
    # lands on the node where the global services answer HK clients
    "edge-user.com.hk": {SUBNETS["HK"]: ["203.0.9.20"], "*": ["192.0.2.30"]},
    "cdnmasked.com.hk": {SUBNETS["HK"]: ["203.0.8.10"], "*": ["192.0.2.40"]},
    "elsewhere.com.hk": {"*": ["192.0.2.50"]},
    # controls: a global service with an edge in every region
    "www.google.com": {SUBNETS["HK"]: ["203.0.9.1"], SUBNETS["SG"]: ["198.18.9.1"],
                       SUBNETS["TW"]: ["100.64.9.1"], "*": ["192.0.2.1"]},
}


def resolve(name, subnet):
    entry = WORLD.get(name, {})
    return entry.get(subnet, entry.get("*", []))


def provider(ips):
    return ("Akamai", 1) if "203.0.8.10" in ips else ("", 0)


def classify(name, region="HK", cn_bucket="", cn_score=0, edges=None):
    edges = edges if edges is not None else {"HK": frozenset({"203.0.9.0/24"})}
    return lv.classify(name, region, cn_bucket, cn_score, SUBNETS, edges, resolve, bucket, provider)


def row(domain, source="discovery", bucket_="", score=0):
    return SimpleNamespace(domain=domain, source=source, bucket=bucket_, score=score)


class Verdicts(unittest.TestCase):
    def test_hosted_in_the_region(self):
        self.assertEqual(classify("origin.com.hk"), "local")

    def test_local_answer_only_for_local_clients_still_counts(self):
        # elsewhere it goes to a CDN outside every region: it does not follow the asker
        self.assertEqual(classify("geo.com.hk"), "local")

    def test_cdn_with_a_node_in_every_region_is_stopped(self):
        self.assertEqual(classify("cdn-customer.com.hk"), "follows-asker")

    def test_foreign_edge_is_stopped(self):
        self.assertEqual(classify("edge-user.com.hk"), "foreign-edge")

    def test_global_cdn_is_stopped(self):
        self.assertEqual(classify("cdnmasked.com.hk"), "cdn")

    def test_not_local_and_unresolved(self):
        self.assertEqual(classify("elsewhere.com.hk"), "not-local")
        self.assertEqual(classify("nothing.com.hk"), "unresolved")

    def test_the_builds_own_placement_elsewhere_wins(self):
        self.assertEqual(classify("origin.com.hk", cn_bucket="CN", cn_score=70), "cn-view-elsewhere")
        # a placement below the threshold is no placement
        self.assertEqual(classify("origin.com.hk", cn_bucket="CN", cn_score=0), "local")


class Pieces(unittest.TestCase):
    def test_hint_region(self):
        self.assertEqual(lv.hint_region("a.com", "seed_hk"), "HK")
        self.assertEqual(lv.hint_region("a.com.tw", "discovery"), "TW")
        self.assertEqual(lv.hint_region("a.cn", "seed_cn"), "")   # CN keeps the build's view
        self.assertEqual(lv.hint_region("a.com", "extended"), "")

    def test_region_subnets_are_stable_and_inside_the_region(self):
        cidrs = {"HK": [ipaddress.ip_network("43.240.0.0/22"), ipaddress.ip_network("103.1.0.0/16")],
                 "MO": [ipaddress.ip_network("60.246.0.0/26")], "CN": [ipaddress.ip_network("1.0.0.0/8")]}
        subs = lv.region_subnets(cidrs)
        self.assertEqual(subs["HK"], "103.1.0.0/24")
        self.assertEqual(subs["MO"], "60.246.0.0/24")
        self.assertNotIn("CN", subs)
        self.assertEqual(lv.region_subnets(cidrs), subs)

    def test_foreign_edges_per_region(self):
        edges = lv.foreign_edges(SUBNETS, resolve, bucket)
        self.assertIn("203.0.9.0/24", edges["HK"])
        self.assertIn("198.18.9.0/24", edges["SG"])
        self.assertNotIn("192.0.2.0/24", edges["HK"])

    def test_two_weeks_in_a_row(self):
        s = lv.update_state({}, {("a.hk", "HK"): "local"}, "2026-W48")
        self.assertEqual(s["a.hk"]["weeks"], ["2026-W48"])
        s = lv.update_state(s, {("a.hk", "HK"): "local"}, "2026-W48")   # same week again
        self.assertEqual(s["a.hk"]["weeks"], ["2026-W48"])
        s = lv.update_state(s, {("a.hk", "HK"): "local"}, "2026-W49")
        self.assertEqual(s["a.hk"]["weeks"], ["2026-W48", "2026-W49"])

    def test_any_other_verdict_starts_over(self):
        s = {"a.hk": {"region": "HK", "weeks": ["2026-W48"]}}
        self.assertEqual(lv.update_state(s, {("a.hk", "HK"): "follows-asker"}, "2026-W49"), {})
        self.assertEqual(lv.update_state(s, {}, "2026-W49"), {})   # not checked this week

    def test_another_region_starts_over(self):
        s = {"a.hk": {"region": "HK", "weeks": ["2026-W48"]}}
        self.assertEqual(lv.update_state(s, {("a.hk", "SG"): "local"}, "2026-W49")["a.hk"]["weeks"],
                         ["2026-W49"])


class Run(unittest.TestCase):
    def rows(self):
        return [row("origin.com.hk", "seed_hk", "HK", 100),       # calibration
                row("geo.com.hk"),                                # would be added
                row("cdn-customer.com.hk"),
                row("edge-user.com.hk"),
                row("placed.com.hk", "discovery", "HK", 60),       # already in HK
                row("plain.com")]                                  # no hint

    def test_report_and_rows_untouched(self):
        rows = self.rows()
        before = [vars(r).copy() for r in rows]
        report, state = lv.run(rows, SUBNETS, resolve, bucket, provider, {}, "2026-W48")
        self.assertEqual([vars(r) for r in rows], before)
        self.assertEqual(report["mode"], "shadow")
        self.assertEqual(report["seeds"], {"HK": {"checked": 1, "local": 1}})
        self.assertEqual(report["checked"], 4)
        self.assertEqual(report["verdicts"], {"local": 1, "follows-asker": 1, "foreign-edge": 1})
        self.assertEqual(report["would_add"], {})          # one week only
        self.assertEqual(report["pending"], {"HK": 1})
        self.assertNotIn("origin.com.hk", state)            # seeds are never "added"
        report, state = lv.run(rows, SUBNETS, resolve, bucket, provider, state, "2026-W49")
        self.assertEqual(report["would_add"], {"HK": ["geo.com.hk"]})

    def test_controls_do_not_pass(self):
        report, _ = lv.run(self.rows(), SUBNETS, resolve, bucket, provider, {}, "2026-W48")
        self.assertEqual(report["controls"]["passed"], 0)
        self.assertEqual(report["controls"]["checked"], len(lv.CONTROLS) * len(SUBNETS))

    def test_a_control_that_gets_through_is_reported(self):
        world = dict(WORLD)
        world["www.apple.com"] = {"*": ["203.0.50.1"]}   # answers from HK to everyone
        with patch.dict(WORLD, world):
            report, _ = lv.run(self.rows(), SUBNETS, resolve, bucket, provider, {}, "2026-W48")
        self.assertIn("www.apple.com@HK", report["controls"]["passed_names"])

    def test_no_ranges_no_trial(self):
        report, state = lv.run(self.rows(), {}, resolve, bucket, provider, {"x": 1}, "2026-W48")
        self.assertIn("skipped", report)
        self.assertEqual(state, {"x": 1})


class Build(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "data").mkdir()
        (self.root / "data" / "discovery_stats.json").write_text(json.dumps({"keep": 1}))

    def test_skipped_when_public_resolvers_are_off(self):
        with patch.object(build_domains, "PUBLIC_DOH", False):
            report = build_domains.run_local_view(self.root, [], {}, {})
        self.assertIn("skipped", report)

    def test_streaks_kept_with_the_pipeline_state(self):
        cidrs = {r: [ipaddress.ip_network(n)] for r, n in RANGES.items()}
        lookup = build_domains.build_region_lookup(cidrs)
        rows = [build_domains.DomainRecord(
            domain="geo.com.hk", dns_cn=0, dns_cn_count=0, dns_total=1, registrar_cn=0,
            registrant_cn=0, cn_tld=0, score=0, resolved_ips="192.0.2.10", matched_cidr="",
            source="discovery", updated="2026-11-23")]
        subnets = lv.region_subnets(cidrs)
        world = {"geo.com.hk": {subnets["HK"]: ["203.0.6.10"], "*": ["192.0.2.10"]}}

        def fake(name, subnet, session=None):
            e = world.get(name, {})
            return e.get(subnet, e.get("*", []))

        with patch.object(build_domains, "PUBLIC_DOH", True), \
             patch.object(build_domains, "resolve_public_with_subnet", side_effect=fake), \
             patch.object(build_domains, "log"):
            report = build_domains.run_local_view(self.root, rows, cidrs, lookup, week="2026-W48")
        stats = json.loads((self.root / "data" / "discovery_stats.json").read_text())
        self.assertEqual(stats["keep"], 1)
        self.assertEqual(stats["local_view"]["geo.com.hk"]["weeks"], ["2026-W48"])
        self.assertEqual(report["pending"], {"HK": 1})

    def test_subnet_query_goes_to_public_resolvers_with_that_subnet(self):
        seen = []

        def do_resolve(name, upstream, session):
            seen.append((name, upstream, build_domains.random_ecs_subnet()))
            return ["203.0.5.10"] if upstream == build_domains.SUBNET_UPSTREAMS[-1] else []

        with patch.object(build_domains, "_do_resolve", side_effect=do_resolve):
            ips = build_domains.resolve_public_with_subnet("a.com.hk", "203.0.0.0/24", object())
        self.assertEqual(ips, ["203.0.5.10"])
        self.assertEqual({s for _, _, s in seen}, {"203.0.0.0/24"})
        self.assertNotIn("https://cloudflare-dns.com/dns-query", {u for _, u, _ in seen})
        # afterwards the build's own subnets are back
        self.assertIn(build_domains.random_ecs_subnet(), build_domains.ECS_SUBNETS)

    def test_www_is_tried(self):
        def do_resolve(name, upstream, session):
            return ["203.0.5.10"] if name == "www.a.com.hk" else []

        with patch.object(build_domains, "_do_resolve", side_effect=do_resolve):
            self.assertEqual(build_domains.resolve_public_with_subnet("a.com.hk", "203.0.0.0/24", object()),
                             ["203.0.5.10"])


class QualityPage(unittest.TestCase):
    def test_trial_section(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "data").mkdir()
        (root / "data" / "stats.json").write_text(json.dumps({"local_view": {
            "mode": "shadow", "seeds": {"HK": {"checked": 120, "local": 60}},
            "controls": {"checked": 114, "passed": 0, "passed_names": []},
            "verdicts": {"local": 3, "follows-asker": 40},
            "would_add": {"HK": ["geo.com.hk"]}, "pending": {"SG": 2}, "required_weeks": 2}}))
        page = qr.build(root)
        self.assertIn("## Regional view (trial, not published)", page)
        self.assertIn("| HK | 120 | 60 | 50.0% |", page)
        self.assertIn("0 of 114 checks passed the guards (should be 0)", page)
        self.assertIn("HK 1 (waiting: SG 2)", page)
        self.assertIn("`geo.com.hk`", page)

    def test_no_section_without_the_trial(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        self.assertNotIn("Regional view", qr.build(root))


if __name__ == "__main__":
    unittest.main()
