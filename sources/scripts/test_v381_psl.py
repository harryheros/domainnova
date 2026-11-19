"""
v3.8.1: registrable names come from the Public Suffix List.

3.8.0 reduced names with a hand-written table that covered only a few
ccTLDs, so `abc.com.my` became `com.my`, and a name under a shared-hosting
suffix (`sakura.ne.jp`) or a free subdomain service the table did not know
(`ccwu.cc`) became that suffix. Two of them were published (com.my in SG,
sakura.ne.jp in JP).

- _psl implements the PSL algorithm (rules, wildcards, exceptions, both
  sections) on the copy in sources/third_party/.
- _quality.registrable() follows it; a public suffix itself is junk
  ("public-suffix"), and so is a name under a suffix of the PSL's private
  section ("free-subdomain"): those are names the suffix's owner hands out.
- The discovery agents, the promotion check and clean_agent_domains.py all
  go through _quality, and the data no longer holds such names.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "discovery_agents"))

import _common  # noqa: E402
import _provenance as prov  # noqa: E402
import _psl  # noqa: E402
import _quality as q  # noqa: E402
import agent_link_crawl as lc  # noqa: E402
import build_domains  # noqa: E402
import clean_agent_domains as clean  # noqa: E402

REPO = HERE.parents[1]


class PublicSuffixList(unittest.TestCase):
    def test_list_is_loaded_with_both_sections(self):
        icann, private = _psl.rule_counts()
        self.assertGreater(icann, 5000)
        self.assertGreater(private, 2000)

    def test_public_suffix(self):
        cases = {
            "www.example.com": "com",
            "abc.com.my": "com.my",
            "news.sina.com.cn": "com.cn",
            "x.bj.cn": "bj.cn",
            "foo.sakura.ne.jp": "sakura.ne.jp",   # private section
            "a.b.c.kawasaki.jp": "c.kawasaki.jp",  # *.kawasaki.jp
            "www.city.kawasaki.jp": "kawasaki.jp",  # !city.kawasaki.jp
            "example.unknowntld": "unknowntld",    # implicit "*" rule
        }
        for host, suffix in cases.items():
            self.assertEqual(_psl.public_suffix(host), suffix, host)

    def test_icann_only(self):
        self.assertEqual(_psl.public_suffix("foo.sakura.ne.jp", private=False), "ne.jp")

    def test_idn_rules_match_punycode(self):
        # 公司.cn is a suffix; names in the data are in ASCII (xn--) form
        self.assertTrue(_psl.is_public_suffix("xn--55qx5d.cn"))
        self.assertEqual(_psl.public_suffix("example.xn--fiqs8s"), "xn--fiqs8s")  # .中国

    def test_private_suffix(self):
        self.assertEqual(_psl.private_suffix("shop.myshopify.com"), "myshopify.com")
        self.assertEqual(_psl.private_suffix("myshopify.com"), "myshopify.com")
        self.assertIsNone(_psl.private_suffix("abc.com.my"))
        self.assertIsNone(_psl.private_suffix("shopify.com"))


class Registrable(unittest.TestCase):
    def test_other_countries(self):
        r = q.registrable
        self.assertEqual(r("www.streetdirectory.com.my"), "streetdirectory.com.my")
        self.assertEqual(r("abc.com.br"), "abc.com.br")
        self.assertEqual(r("x.y.example.com.tr"), "example.com.tr")
        self.assertEqual(r("uni.edu.my"), "uni.edu.my")
        self.assertIsNone(r("com.my"))
        self.assertIsNone(r("com.br"))
        self.assertIsNone(r("ac.ae"))

    def test_wildcards_and_exceptions(self):
        r = q.registrable
        self.assertEqual(r("www.city.nagoya.jp"), "city.nagoya.jp")
        self.assertEqual(r("www.city.sapporo.jp"), "city.sapporo.jp")
        self.assertIsNone(r("ward.nagoya.jp"))  # *.nagoya.jp

    def test_private_section_suffixes_are_not_names(self):
        r = q.registrable
        for suffix in ("sakura.ne.jp", "ccwu.cc", "myshopify.com", "github.io"):
            self.assertIsNone(r(suffix), suffix)
        self.assertEqual(r("www.foo.sakura.ne.jp"), "foo.sakura.ne.jp")

    def test_region_names_unchanged(self):
        r = q.registrable
        for host, reg in {"news.sina.com.cn": "sina.com.cn", "www.beijing.gov.cn": "beijing.gov.cn",
                          "shop.example.co.jp": "example.co.jp", "img.third.com.hk": "third.com.hk",
                          "a.b.naver.com": "naver.com", "x.gov.sg": "x.gov.sg",
                          "m.example.com.tw": "example.com.tw", "w.example.co.kr": "example.co.kr",
                          "w.example.com.mo": "example.com.mo"}.items():
            self.assertEqual(r(host), reg, host)


class Junk(unittest.TestCase):
    def test_public_suffixes_are_junk(self):
        for d in ("com.my", "sakura.ne.jp", "googleapis.com", "myshopify.com", "com.br",
                  "com.tr", "edu.my", "ac.ae", "ccwu.cc", "ward.nagoya.jp"):
            self.assertEqual(q.junk_reason(d), "public-suffix", d)

    def test_names_under_private_suffixes_are_free_subdomains(self):
        for d in ("lifecells.ccwu.cc", "foo.sakura.ne.jp", "shop.myshopify.com"):
            self.assertEqual(q.junk_reason(d), "free-subdomain", d)

    def test_real_names_still_pass(self):
        for d in ("streetdirectory.com.my", "city.nagoya.jp", "sina.com.cn", "naver.com",
                  "sakura.ad.jp", "shopify.com", "taobao.com"):
            self.assertIsNone(q.junk_reason(d), d)


class Agents(unittest.TestCase):
    def test_filter_candidates(self):
        got = _common.filter_candidates(
            ["www.streetdirectory.com.my", "abc.sakura.ne.jp", "com.br", "www.city.nagoya.jp",
             "shop.myshopify.com", "x.y.ccwu.cc"], set())
        self.assertEqual(got, ["streetdirectory.com.my", "city.nagoya.jp"])

    def test_link_crawl_uses_the_list(self):
        self.assertIs(lc.registrable, q.registrable)


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.manual = self.root / "sources" / "manual"
        self.manual.mkdir(parents=True)
        (self.manual / "seed_cn.txt").write_text("gov.cn\nseed.cn\n", encoding="utf-8")

    def test_public_suffixes_removed_manual_kept(self):
        (self.manual / "extended.txt").write_text(
            "# DomainNova - Extended Domains\nccwu.cc\nedu.tw\nkeep.cn\n", encoding="utf-8")
        (prov.path(self.root)).write_text(
            "domain,origin,origin_detail,nominated\n"
            "ccwu.cc,ip-neighbor,111.63.65.103,2026-06-16\n"
            "edu.tw,manual,added by hand,2026-03-28\n"
            "keep.cn,ct-logs,%.cn,2026-07-01\n", encoding="utf-8")
        (self.manual / "discovery.txt").write_text(
            "# DomainNova - Discovery Layer\n\n"
            "# --- link-crawl:streetdirectory.com 2026-11-19 ---\ncom.my\nfine.com.my\n\n"
            "# --- link-crawl:yuncha.com 2026-11-19 ---\nsakura.ne.jp\n", encoding="utf-8")
        summary = clean.clean(self.root, today="2026-11-20")
        self.assertEqual(summary["by_reason"], {"public-suffix": 3})
        ext = (self.manual / "extended.txt").read_text(encoding="utf-8")
        self.assertNotIn("ccwu.cc", ext)
        self.assertIn("edu.tw", ext)  # curated by hand: never touched
        disc = (self.manual / "discovery.txt").read_text(encoding="utf-8")
        self.assertNotIn("\ncom.my\n", disc)
        self.assertIn("fine.com.my", disc)
        self.assertNotIn("sakura.ne.jp", disc)
        self.assertNotIn("yuncha.com", disc)  # its section is empty now
        self.assertNotIn("ccwu.cc", prov.path(self.root).read_text(encoding="utf-8"))
        removed = (self.manual / "removed.csv").read_text(encoding="utf-8")
        self.assertIn("com.my,link-crawl,streetdirectory.com,public-suffix,2026-11-20", removed)
        self.assertIn("ccwu.cc,ip-neighbor,111.63.65.103,public-suffix,2026-11-20", removed)
        # a second run changes nothing
        self.assertEqual(clean.clean(self.root, today="2026-11-21")["removed"], 0)


class Data(unittest.TestCase):
    """The committed data holds no agent-nominated public suffix."""

    def test_no_public_suffix_from_agents(self):
        manual = REPO / "sources" / "manual"
        origins = {**prov.discovery_sections(manual / "discovery.txt"), **prov.load(REPO)}
        bad = []
        for name in ("extended.txt", "discovery.txt"):
            for line in (manual / name).read_text(encoding="utf-8").splitlines():
                d = line.strip().lower()
                if not d or d.startswith("#"):
                    continue
                if origins.get(d, ("manual",))[0] == "manual":
                    continue
                if q.junk_reason(d) or q.registrable(d) != d:
                    bad.append(d)
        self.assertEqual(bad, [])


class Build(unittest.TestCase):
    """A discovery name purged as junk is not published by the same build
    (3.8.0 purged it from discovery.txt but still wrote it to dist/ once)."""

    def test_purged_name_not_published(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "discovery.txt").write_text(
            "# DomainNova - Discovery Layer\n\n# --- link-crawl:x.com 2026-11-16 ---\n"
            "com.my\nreal.com.sg\n", encoding="utf-8")
        (manual / "extended.txt").write_text("# DomainNova - Extended Domains\n", encoding="utf-8")
        rows = [build_domains.DomainRecord(
            domain=d, dns_cn=0, dns_cn_count=0, dns_total=1, registrar_cn=0, registrant_cn=0,
            cn_tld=0, score=100, resolved_ips="1.0.1.1", matched_cidr="1.0.1.0/24",
            source="discovery", updated="2026-11-16", bucket="SG") for d in ("com.my", "real.com.sg")]
        with patch.object(build_domains, "log"):
            purged, _ = build_domains.manage_discovery_lifecycle(root, rows, week="2026-W47")
            build_domains.write_dist_buckets(root / "dist", rows)
        self.assertEqual(purged, ["com.my"])
        sg = (root / "dist" / "domains_sg.txt").read_text(encoding="utf-8").splitlines()
        self.assertIn("real.com.sg", sg)
        self.assertNotIn("com.my", sg)


if __name__ == "__main__":
    unittest.main()
