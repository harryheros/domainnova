"""
v3.8.0: global services' in-country edges are not regional evidence.

Some global companies serve users in a region from addresses inside it (Google's
edge in China is registered to a Chinese company and sits in IPNova's CN list
until IPNova 4.1.1). A domain of such a service resolves "in region" for the
region's users and would be published there: googletagmanager.com and
googleoptimize.com reached the CN list that way.

Each build resolves a few sentinel domains of global companies; the /24s their
in-region answers land in are foreign edges, except /24s that a seed domain
also uses (a shared CDN serves real regional sites too). A non-seed domain
that reaches 60% in its region only by counting foreign-edge addresses is not
published.
"""
import inspect
import ipaddress
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains as bd  # noqa: E402

LOOKUP = bd.build_region_lookup({
    "CN": [ipaddress.ip_network("203.208.32.0/19"), ipaddress.ip_network("1.2.3.0/24"),
           ipaddress.ip_network("5.5.5.0/24")],
    "HK": [], "MO": [], "TW": [], "JP": [], "KR": [], "SG": [],
})


def row(domain, source, ips, bucket="CN", score=60):
    return bd.DomainRecord(
        domain=domain, dns_cn=1, dns_cn_count=len(ips), dns_total=len(ips), registrar_cn=0,
        registrant_cn=0, cn_tld=0, score=score, resolved_ips="|".join(ips),
        matched_cidr="", source=source, updated="2026-11-19", bucket=bucket)


class ResolveEdges(unittest.TestCase):
    def test_in_region_answers_become_slash24s(self):
        answers = {"www.googletagmanager.com": ["203.208.40.66", "8.8.8.8"],
                   "www.linkedin.com": ["1.2.3.9"]}
        with patch.object(bd, "resolve_domain", side_effect=lambda d, s: answers.get(d, [])), \
             patch.object(bd, "FOREIGN_SENTINELS", tuple(answers)):
            edges = bd.resolve_foreign_edges(LOOKUP)
        self.assertEqual(edges, {"203.208.40.0/24", "1.2.3.0/24"})  # 8.8.8.8: not in a region

    def test_sentinels_are_first_party_services_not_cdns(self):
        for d in bd.FOREIGN_SENTINELS:
            for cdn in ("akamai", "cloudflare", "fastly", "cloudfront", "edgekey", "azureedge"):
                self.assertNotIn(cdn, d)
        self.assertIn("www.googletagmanager.com", bd.FOREIGN_SENTINELS)


class Filter(unittest.TestCase):
    def setUp(self):
        self.rows = [
            row("seed.cn", "seed_cn", ["1.2.3.5"], score=100),
            row("googleoptimize.com", "discovery", ["203.208.40.66", "203.208.40.67"]),
            row("mixed.com", "extended", ["203.208.40.66", "5.5.5.5"]),
            row("shared-cdn.cn", "discovery", ["1.2.3.6"]),
            row("plain.cn", "discovery", ["5.5.5.6"]),
            row("google-seed.cn", "seed_cn", ["203.208.40.70"], score=100),
            row("unresolved.cn", "discovery", [], score=60),
        ]
        # google-seed.cn would make 203.208.40.0/24 "shared"; drop it for the main case
        self.edges = {"203.208.40.0/24", "1.2.3.0/24"}

    def test_demotes_only_foreign_edge_domains(self):
        rows = [r for r in self.rows if r.domain != "google-seed.cn"]
        demoted, foreign = bd.apply_foreign_edge_filter(rows, self.edges, LOOKUP)
        self.assertEqual(foreign, {"203.208.40.0/24"})  # 1.2.3.0/24 is used by a seed
        self.assertEqual(sorted(demoted), ["googleoptimize.com", "mixed.com"])
        score = {r.domain: r.score for r in rows}
        self.assertEqual(score["googleoptimize.com"], 0)
        self.assertEqual(score["mixed.com"], 0)  # 1 of 2 addresses left: 50% < 60%
        self.assertEqual(score["shared-cdn.cn"], 60)
        self.assertEqual(score["plain.cn"], 60)
        self.assertEqual(score["seed.cn"], 100)

    def test_seeds_are_never_demoted_and_mark_shared_networks(self):
        demoted, foreign = bd.apply_foreign_edge_filter(self.rows, self.edges, LOOKUP)
        self.assertEqual(foreign, set())
        self.assertEqual(demoted, [])

    def test_no_edges_no_change(self):
        demoted, foreign = bd.apply_foreign_edge_filter(self.rows, set(), LOOKUP)
        self.assertEqual((demoted, foreign), ([], set()))

    def test_build_applies_the_filter_before_lifecycle_and_dist(self):
        src = inspect.getsource(bd.build)
        self.assertIn("resolve_foreign_edges(", src)
        f = src.index("apply_foreign_edge_filter(")
        self.assertLess(f, src.index("manage_discovery_lifecycle("))
        self.assertLess(f, src.index("write_dist_buckets("))
        self.assertIn('"foreign_edge"', src)


if __name__ == "__main__":
    unittest.main()
