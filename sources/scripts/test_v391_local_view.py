"""
v3.9.1: the regional view asks from each region's main consumer ISP.

The first build of the trial asked each region from the first /24 of its
largest IPNova range. For SG that was a cloud provider's 43.0.0.0/9, whose
addresses are used worldwide, and for HK a transit operator's
63.216.0.0/13: geographic DNS did not place those clients in the region,
and 2 of 73 SG seeds were found in SG. A block of the region's main
consumer ISP is used instead, when IPNova still has it in the region.

The report also says why seeds were not found, so the next build shows
which guard stops them instead of leaving it to guesswork.
"""
import ipaddress
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _local_view as lv  # noqa: E402
import build_quality_report as qr  # noqa: E402
from test_v390_local_view import SUBNETS, bucket, provider, resolve, row  # noqa: E402


def nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


class Subnets(unittest.TestCase):
    def test_the_consumer_isp_not_the_largest_range(self):
        cidrs = {"HK": nets("63.216.0.0/13", "113.252.0.0/14", "118.140.0.0/14"),
                 "SG": nets("43.0.0.0/9", "8.128.0.0/10", "116.14.0.0/15"),
                 "JP": nets("133.0.0.0/9", "126.0.0.0/11")}
        subs = lv.region_subnets(cidrs)
        self.assertEqual(subs["HK"], "113.252.0.0/24")
        self.assertEqual(subs["SG"], "116.14.0.0/24")
        self.assertEqual(subs["JP"], "126.0.0.0/24")

    def test_the_largest_range_when_ipnova_no_longer_has_it(self):
        cidrs = {"HK": nets("63.216.0.0/13", "103.1.0.0/16")}
        self.assertEqual(lv.region_subnets(cidrs)["HK"], "63.216.0.0/24")

    def test_every_consumer_block_is_one_region_only(self):
        blocks = [ipaddress.ip_network(b) for b in lv.CONSUMER_BLOCKS.values()]
        self.assertEqual(set(lv.CONSUMER_BLOCKS), set(lv.REGIONS))
        for i, a in enumerate(blocks):
            for b in blocks[i + 1:]:
                self.assertFalse(a.overlaps(b), (a, b))

    def test_the_report_says_where_each_region_was_asked_from(self):
        subs = dict(SUBNETS, SG="116.14.0.0/24")
        report, _ = lv.run([], subs, resolve, bucket, provider, {}, "2026-W48")
        self.assertEqual(report["subnet_kind"]["SG"], "consumer ISP")
        self.assertEqual(report["subnet_kind"]["HK"], "largest range")


class WhySeedsWereNotFound(unittest.TestCase):
    def test_verdicts_and_examples_per_region(self):
        rows = [row("origin.com.hk", "seed_hk", "HK", 100),      # found
                row("elsewhere.com.hk", "seed_hk", "", 0),       # not-local
                row("cdn-customer.com.hk", "seed_hk", "", 0),    # follows-asker
                row("nowhere.com.hk", "seed_hk", "", 0),         # unresolved
                row("geo.com.hk")]                               # not a seed
        report, _ = lv.run(rows, SUBNETS, resolve, bucket, provider, {}, "2026-W48")
        self.assertEqual(report["seeds"], {"HK": {"checked": 4, "local": 1}})
        self.assertEqual(report["seed_verdicts"],
                         {"HK": {"not-local": 1, "follows-asker": 1, "unresolved": 1}})
        self.assertEqual(report["seed_examples"]["HK"]["not-local"], ["elsewhere.com.hk"])

    def test_at_most_five_examples(self):
        rows = [row(f"x{i}.com.hk", "seed_hk") for i in range(9)]   # all unresolved
        report, _ = lv.run(rows, SUBNETS, resolve, bucket, provider, {}, "2026-W48")
        self.assertEqual(report["seed_verdicts"]["HK"], {"unresolved": 9})
        self.assertEqual(len(report["seed_examples"]["HK"]["unresolved"]), 5)


class QualityPage(unittest.TestCase):
    def page(self, lv_report):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "data").mkdir()
        (root / "data" / "stats.json").write_text(json.dumps({"local_view": lv_report}))
        return qr.build(root)

    def test_why_not_found_and_where_asked_from(self):
        text = self.page({
            "mode": "shadow",
            "subnets": {"HK": "113.252.0.0/24", "SG": "43.0.0.0/24"},
            "subnet_kind": {"HK": "consumer ISP", "SG": "largest range"},
            "seeds": {"HK": {"checked": 10, "local": 6}, "SG": {"checked": 5, "local": 0}},
            "seed_verdicts": {"HK": {"not-local": 3, "follows-asker": 1},
                              "SG": {"not-local": 5}},
            "controls": {"checked": 2, "passed": 0},
        })
        self.assertIn("| Region | Seeds checked | Found in region | Share | Not found: why |", text)
        self.assertIn("| HK | 10 | 6 | 60.0% | `not-local` 3, `follows-asker` 1 |", text)
        self.assertIn("- Asked from: HK `113.252.0.0/24`, SG `43.0.0.0/24` "
                      "(SG: largest IPNova range, no consumer ISP block)", text)


if __name__ == "__main__":
    unittest.main()
