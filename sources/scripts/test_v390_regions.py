"""
v3.9.0: discovery looks for the smaller regions too.

Until 3.8 the IP-neighbor agent resolved only seed_cn.txt and kept only
addresses in IPNova's CN ranges, so every reverse-IP query (about 50 a
week, all the free quota allows) went to CN servers; HK, MO, SG and TW
grew only through link crawl, whose budget was taken first by .cn names.

- ip-neighbor shares its 50 queries between regions (REGION_SLOTS), each
  resolving its own seeds (with the build's client subnet) and keeping
  only addresses in its own IPNova ranges; slots a region cannot fill
  go to the others, and the queries alternate between regions so one
  region cannot spend the whole budget of new domains.
- link crawl reads a rotating slice of the HK, MO, SG and TW seeds every
  week besides the general slice, and queues regional ccTLDs scarcest
  first (.mo, .sg, .hk, .tw before .jp, .kr, .cn).
"""
import ipaddress
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "discovery_agents"))

import agent_ip_neighbor as ipn  # noqa: E402
import agent_link_crawl as lc  # noqa: E402

REPO = HERE.parents[1]

NETS = {
    "CN": ["1.0.1.0/24", "36.0.0.0/12"],
    "HK": ["43.240.0.0/22", "103.1.0.0/16"],
    "MO": ["60.246.0.0/16"],
    "SG": ["8.128.0.0/16"],
    "TW": ["1.160.0.0/12"],
    "JP": ["1.72.0.0/13"],
}


def nets(region):
    return [ipaddress.IPv4Network(n) for n in NETS.get(region, [])]


class Slots(unittest.TestCase):
    def test_slots_cover_the_query_budget(self):
        self.assertEqual(sum(ipn.REGION_SLOTS.values()), ipn.MAX_IPS_PER_RUN)

    def test_small_regions_get_slots(self):
        for r in ("HK", "MO", "SG", "TW"):
            self.assertGreater(ipn.REGION_SLOTS.get(r, 0), 0, r)
        self.assertLess(ipn.REGION_SLOTS["CN"], ipn.MAX_IPS_PER_RUN / 2)

    def test_regions_are_known_buckets(self):
        import constants
        self.assertLessEqual(set(ipn.REGION_SLOTS), set(constants.REGION_CIDR_URLS))


class SameViewAsTheBuild(unittest.TestCase):
    def test_every_region_is_resolved_with_the_builds_client_subnet(self):
        asked = []

        def resolve(domain, session, subnet=ipn.ECS_SUBNET):
            asked.append(subnet)
            return []

        with patch.object(ipn, "resolve_to_ipv4", side_effect=resolve):
            ipn.pick_ips({"HK": ["b.hk"], "SG": ["c.sg"]}, {"HK": nets("HK"), "SG": nets("SG")}, None)
        self.assertEqual(asked, [ipn.ECS_SUBNET, ipn.ECS_SUBNET])


class PickIPs(unittest.TestCase):
    """Which addresses are queried, from which region's seeds."""

    def pick(self, seeds, answers, slots, total):
        asked = []

        def resolve(domain, session, subnet=ipn.ECS_SUBNET):
            asked.append((domain, subnet))
            return answers.get(domain, [])

        with patch.object(ipn, "resolve_to_ipv4", side_effect=resolve), \
             patch.object(ipn, "REGION_SLOTS", slots), \
             patch.object(ipn, "MAX_IPS_PER_RUN", total):
            picked = ipn.pick_ips(seeds, {r: nets(r) for r in slots}, None)
        return picked, asked

    def test_each_region_keeps_only_its_own_addresses(self):
        seeds = {"CN": ["a.cn"], "HK": ["b.hk"]}
        answers = {"a.cn": ["1.0.1.5", "8.8.8.8"], "b.hk": ["103.1.2.3", "1.0.1.6"]}
        picked, asked = self.pick(seeds, answers, {"CN": 2, "HK": 2}, 4)
        self.assertIn(("CN", "1.0.1.5"), picked)
        self.assertIn(("HK", "103.1.2.3"), picked)
        self.assertNotIn(("HK", "1.0.1.6"), picked)          # a CN address of an HK seed
        self.assertNotIn("8.8.8.8", [ip for _, ip in picked])

    def test_queries_alternate_between_regions(self):
        seeds = {"CN": [f"s{i}.cn" for i in range(3)], "SG": [f"s{i}.sg" for i in range(3)]}
        answers = {f"s{i}.cn": [f"1.0.1.{i + 1}"] for i in range(3)}
        answers |= {f"s{i}.sg": [f"8.128.0.{i + 1}"] for i in range(3)}
        picked, _ = self.pick(seeds, answers, {"CN": 3, "SG": 3}, 6)
        self.assertEqual([r for r, _ in picked], ["CN", "SG"] * 3)

    def test_unused_slots_go_to_other_regions(self):
        seeds = {"CN": [f"s{i}.cn" for i in range(5)], "MO": ["only.mo"]}
        answers = {f"s{i}.cn": [f"1.0.1.{i + 1}"] for i in range(5)}
        answers["only.mo"] = ["60.246.1.1"]
        picked, _ = self.pick(seeds, answers, {"CN": 2, "MO": 3}, 5)
        self.assertEqual(len(picked), 5)
        self.assertEqual(sum(1 for r, _ in picked if r == "MO"), 1)
        self.assertEqual(sum(1 for r, _ in picked if r == "CN"), 4)

    def test_never_more_than_the_budget(self):
        seeds = {"CN": [f"s{i}.cn" for i in range(9)]}
        answers = {f"s{i}.cn": [f"1.0.1.{i + 1}", f"1.0.1.{i + 100}"] for i in range(9)}
        picked, _ = self.pick(seeds, answers, {"CN": 4}, 4)
        self.assertEqual(len(picked), 4)
        self.assertEqual(len(set(picked)), 4)


class RunAllRegions(unittest.TestCase):
    def test_run_reads_every_regions_seeds_and_writes_their_neighbours(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_cn.txt").write_text("a.cn\n", encoding="utf-8")
        (manual / "seed_hk.txt").write_text("# HK\nb.com.hk\n", encoding="utf-8")
        (manual / "seed_mo.txt").write_text("c.mo\n", encoding="utf-8")
        (manual / "discovery.txt").write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")
        answers = {"a.cn": ["1.0.1.5"], "b.com.hk": ["103.1.2.3"], "c.mo": ["60.246.1.1"]}
        neighbours = {"1.0.1.5": ["sib-cn.cn"], "103.1.2.3": ["sib-hk.com.hk"],
                      "60.246.1.1": ["sib-mo.com.mo"]}
        with patch.object(ipn, "fetch_region_cidrs", side_effect=lambda s, r: nets(r)), \
             patch.object(ipn, "resolve_to_ipv4",
                          side_effect=lambda d, s, subnet=ipn.ECS_SUBNET: answers.get(d, [])), \
             patch.object(ipn, "reverse_ip_lookup", side_effect=lambda ip, s: neighbours[ip]), \
             patch.object(ipn, "make_session"), \
             patch.object(ipn.time, "sleep"), patch("builtins.print"):
            ipn.run(root)
        text = (manual / "discovery.txt").read_text(encoding="utf-8")
        for d in ("sib-cn.cn", "sib-hk.com.hk", "sib-mo.com.mo"):
            self.assertIn(f"\n{d}\n", text)
        self.assertIn("# --- ip-neighbor:103.1.2.3 ", text)

    def test_a_region_whose_ranges_fail_to_load_is_skipped(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_cn.txt").write_text("a.cn\n", encoding="utf-8")
        (manual / "seed_hk.txt").write_text("b.com.hk\n", encoding="utf-8")
        (manual / "discovery.txt").write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")

        def fetch(session, region):
            if region == "HK":
                raise OSError("502")
            return nets(region)

        with patch.object(ipn, "fetch_region_cidrs", side_effect=fetch), \
             patch.object(ipn, "resolve_to_ipv4",
                          side_effect=lambda d, s, subnet=ipn.ECS_SUBNET: {"a.cn": ["1.0.1.5"]}.get(d, [])), \
             patch.object(ipn, "reverse_ip_lookup", side_effect=lambda ip, s: ["sib-cn.cn"]), \
             patch.object(ipn, "make_session"), \
             patch.object(ipn.time, "sleep"), patch("builtins.print"):
            ipn.run(root)
        self.assertIn("sib-cn.cn", (manual / "discovery.txt").read_text(encoding="utf-8"))


class LinkCrawl(unittest.TestCase):
    def test_scarcest_regional_tlds_first(self):
        ordered = lc.prioritise(["a.com", "b.cn", "c.com.mo", "d.com.hk", "e.jp", "f.sg", "g.tw", "h.kr"])
        self.assertEqual(ordered, ["c.com.mo", "f.sg", "d.com.hk", "g.tw", "e.jp", "h.kr", "b.cn", "a.com"])

    def test_focus_seeds_are_read_every_week(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_cn.txt").write_text("".join(f"c{i:03}.cn\n" for i in range(200)), encoding="utf-8")
        (manual / "seed_hk.txt").write_text("".join(f"h{i:02}.hk\n" for i in range(30)), encoding="utf-8")
        (manual / "seed_sg.txt").write_text("s1.sg\n", encoding="utf-8")
        (manual / "extended.txt").write_text("", encoding="utf-8")
        (manual / "discovery.txt").write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")
        read = []

        def crawl(session, site):
            read.append(site)
            return []

        with patch.object(lc, "crawl_site", side_effect=crawl), \
             patch.object(lc, "make_session"), patch("builtins.print"):
            lc.run(root, pages=20, week=0, focus_pages=10)
            first = list(read)
            read.clear()
            lc.run(root, pages=20, week=1, focus_pages=10)
        focus = [s for s in first if s.endswith((".hk", ".sg"))]
        self.assertGreaterEqual(len(focus), 10)
        self.assertEqual(len(first), 20)
        self.assertEqual(len(set(first)), 20)
        # the next week continues with other focus sites
        self.assertFalse(set(focus) & {s for s in read if s.endswith((".hk", ".sg"))})

    def test_full_crawl_still_reads_every_site_once(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_cn.txt").write_text("a.cn\nb.cn\n", encoding="utf-8")
        (manual / "seed_hk.txt").write_text("h.hk\n", encoding="utf-8")
        (manual / "discovery.txt").write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")
        read = []
        with patch.object(lc, "crawl_site", side_effect=lambda s, site: read.append(site) or []), \
             patch.object(lc, "make_session"), patch("builtins.print"):
            lc.run(root, all_sites=True)
        self.assertEqual(sorted(read), ["a.cn", "b.cn", "h.hk"])


if __name__ == "__main__":
    unittest.main()
