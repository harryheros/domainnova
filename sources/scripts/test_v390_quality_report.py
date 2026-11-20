"""
v3.9.0: data/QUALITY.md, the public data-quality page.

Built at the end of every build from dist/, domains_metadata.csv,
stats.json, seed_health.json and removed.csv, so its numbers are the
build's own; it carries no clock of its own, so an unchanged build leaves
it unchanged.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_quality_report as qr  # noqa: E402

REPO = HERE.parents[1]


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        write(self.root, "dist/domains_cn.txt",
              "# DomainNova - CN domains\n# Count: 3\nseed.cn\next.com\nfound.com\n")
        write(self.root, "dist/domains_hk.txt", "# header\nseed.hk\nmystery.hk\n")
        write(self.root, "data/domains_metadata.csv",
              "domain,source,section,ecosystem,entity,category,origin,origin_detail\n"
              "seed.cn,seed_cn,,,,,manual,\n"
              "ext.com,extended,,,,,ct-logs,%.cn\n"
              "found.com,discovery,,,,,link-crawl,a.cn\n"
              "seed.hk,seed_hk,,,,,manual,\n"
              "notpublished.com,discovery,,,,,ip-neighbor,1.2.3.4\n")
        write(self.root, "data/stats.json", json.dumps({
            "generated_at": "2026-11-23T02:40:00Z",
            "resolver": {"own": 8, "public": 1, "fallback": 0, "unresolved": 1},
            "foreign_edge": {"networks": ["203.0.113.0/24"], "demoted": ["edge.example"]},
            "auto_promoted": 4, "sticky_retained": 2,
        }))
        write(self.root, "data/seed_health.json", json.dumps({"results": {
            "seed_hk.txt": {"region": "HK", "sampled": 20, "resolved": 20, "consistent": 14, "status": "ok"},
            "seed_cn.txt": {"region": "CN", "sampled": 20, "resolved": 19, "consistent": 19, "status": "ok"},
        }}))
        write(self.root, "sources/manual/removed.csv",
              "domain,origin,origin_detail,reason,removed\n"
              "a.example,ip-neighbor,1.2.3.4,shared-host,2026-11-18\n"
              "b.example,ip-neighbor,1.2.3.4,shared-host,2026-11-18\n"
              "x.big.cn,ct-logs,q,covered-by:big.cn,2026-11-18\n"
              "www.r.cn,ct-logs,q,reduced-to:r.cn,2026-11-18\n")
        self.page = qr.build(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def row(self, first_cell: str) -> list[str]:
        for line in self.page.splitlines():
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and cells[0] == first_cell:
                return cells
        self.fail(f"no row {first_cell!r} in:\n{self.page}")

    def test_published_counts_by_region_and_tier(self):
        self.assertEqual(self.row("CN"), ["CN", "3", "1", "1", "1"])
        self.assertEqual(self.row("HK")[:3], ["HK", "2", "1"])
        self.assertEqual(self.row("**All**")[1], "**5**")

    def test_origin_counts_only_published_domains(self):
        self.assertEqual(self.row("`manual`")[1:], ["2", "40.0%"])
        self.assertEqual(self.row("`ip-neighbor`")[1], "0")   # notpublished.com is not in dist
        self.assertEqual(self.row("`unknown`")[1], "1")       # mystery.hk has no metadata row

    def test_resolver_shares(self):
        self.assertEqual(self.row("`own`")[1:], ["8", "80.0%"])

    def test_foreign_edge_and_lifecycle(self):
        self.assertIn("`203.0.113.0/24`", self.page)
        self.assertIn("`edge.example`", self.page)
        self.assertEqual(self.row("Promoted from discovery to extended")[1], "4")

    def test_seed_health_in_region_order(self):
        self.assertLess(self.page.index("| CN | 20 | 19 |"), self.page.index("| HK | 20 | 20 |"))

    def test_removed_by_reason(self):
        self.assertIn("3 were removed and 1 replaced", self.page)
        self.assertEqual(self.row("`shared-host`")[2], "2")

    def test_build_time(self):
        self.assertIn("- Build: 2026-11-23T02:40:00Z\n", self.page)

    def test_same_inputs_same_page(self):
        self.assertEqual(qr.build(self.root), self.page)

    def test_missing_inputs_do_not_break_the_page(self):
        empty = Path(tempfile.mkdtemp())
        try:
            page = qr.build(empty)
        finally:
            shutil.rmtree(empty)
        self.assertIn("# DomainNova data quality", page)
        self.assertIn("No seed check in this build.", page)


class Repository(unittest.TestCase):
    def test_page_is_published(self):
        # Not compared with a fresh build: a hand edit of removed.csv between
        # builds must not fail the weekly run, which rewrites the page anyway.
        page = (REPO / "data" / "QUALITY.md").read_text(encoding="utf-8")
        self.assertTrue(page.startswith("# DomainNova data quality\n"))

    def test_workflow_builds_it_after_metadata(self):
        wf = (REPO / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")
        self.assertIn("python sources/scripts/build_quality_report.py", wf)
        self.assertLess(wf.index("build_metadata.py --all"), wf.index("build_quality_report.py"))
        self.assertLess(wf.index("build_quality_report.py"), wf.index("git add data/"))

    def test_readme_links_it(self):
        self.assertIn("(data/QUALITY.md)", (REPO / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
