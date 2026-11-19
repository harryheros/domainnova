"""
v3.8.0: what the discovery agents may nominate and what may be promoted.

- Candidates are reduced to their registrable name (a.b.example.cn ->
  example.cn) and junk is refused: names under free subdomain services,
  adult and gambling sites, numeric throwaway names (_quality.junk_reason).
- The IP-neighbor agent skips shared-hosting IPs, whose neighbours are
  hundreds of unrelated sites.
- Discovery streaks count at most one run per ISO week, so several manual
  runs in one week cannot promote a domain early; a junk or non-registrable
  discovery domain is purged, never promoted.
- clean_agent_domains.py applies the same rules to the existing data.
"""
import csv
import datetime as dt
import json
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
import _quality as q  # noqa: E402
import agent_ip_neighbor as ipn  # noqa: E402
import build_domains  # noqa: E402
import clean_agent_domains as clean  # noqa: E402


class JunkReason(unittest.TestCase):
    def test_junk(self):
        cases = {
            "llsstt.dpdns.org": "free-subdomain",
            "ae.zdrgs.kurl.cc": "free-subdomain",
            "home.3322.org": "free-subdomain",
            "intranet.javsee.cc": "adult-gambling",
            "lecaiwang.live": "adult-gambling",
            "bet365.com": "adult-gambling",
            "lucky.casino": "adult-gambling",
            "0026.cc": "numeric-throwaway",
            "8686868.vip": "numeric-throwaway",
            "1.805188.vip": "numeric-throwaway",
            "0001000.xyz": "numeric-throwaway",
            "01083531111.com": "numeric-throwaway",
        }
        for d, why in cases.items():
            self.assertEqual(q.junk_reason(d), why, d)

    def test_real_names_pass(self):
        for d in ("10086.cn", "163.net", "12321.cn", "127.net", "1234567.com.cn",
                  "12309.gov.cn", "java.com", "alphabet.com", "better.com",
                  "betterment.com", "sussex.ac.uk", "h3c.com.cn", "chinaunicom.com.cn",
                  "dpdns.org.cn", "taobao.com", "qq.com", "58.com", "4399.com"):
            self.assertIsNone(q.junk_reason(d), d)

    def test_registrable(self):
        self.assertEqual(q.registrable("news.sina.com.cn"), "sina.com.cn")
        self.assertEqual(q.registrable("a.b.example.com"), "example.com")
        self.assertEqual(q.registrable("city.osaka.lg.jp"), "osaka.lg.jp")
        self.assertIsNone(q.registrable("com.cn"))


class FilterCandidates(unittest.TestCase):
    def test_reduces_to_registrable_and_drops_junk(self):
        got = _common.filter_candidates(
            ["0757jiafa.cn.alibaba.com", "res-img1.huaweicloud.com", "www.example.cn",
             "x.dpdns.org", "ww12.javsee.cc", "0066000.cc", "a.example.cn",
             "jd.com--vip999--huodong.example", "news.known.cn"],
            {"known.cn"})
        self.assertEqual(got, ["alibaba.com", "huaweicloud.com", "example.cn"])


class GlobalServices(unittest.TestCase):
    def test_google_optimize_is_excluded(self):
        # the full crawl placed it in CN (an in-country edge for CN users)
        self.assertEqual(_common.filter_candidates(["www.googleoptimize.com"], set()), [])

    def test_not_in_discovery(self):
        disc = (HERE.parents[1] / "sources" / "manual" / "discovery.txt").read_text(encoding="utf-8")
        self.assertNotIn("\ngoogleoptimize.com\n", disc)


class SharedHost(unittest.TestCase):
    def test_is_shared_host(self):
        few = ["www.h3c.com.cn", "h3c.com.cn", "h3c.com", "mail.h3c.com"]
        self.assertFalse(ipn.is_shared_host(few))
        many = [f"site{i}.com" for i in range(ipn.SHARED_HOST_MIN)]
        self.assertTrue(ipn.is_shared_host(many))
        # many subdomains of one organisation are not shared hosting
        self.assertFalse(ipn.is_shared_host([f"h{i}.alibaba.com" for i in range(100)]))

    def test_run_skips_shared_host(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_cn.txt").write_text("seed.cn\n", encoding="utf-8")
        (manual / "discovery.txt").write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")
        neighbours = {"1.1.1.1": [f"farm{i}.com" for i in range(40)],
                      "2.2.2.2": ["sibling.cn", "www.sibling.cn"]}
        with patch.object(ipn, "fetch_cn_cidrs", return_value=[]), \
             patch.object(ipn, "resolve_to_ipv4", return_value=["1.1.1.1", "2.2.2.2"]), \
             patch.object(ipn, "is_cn_ip", return_value=True), \
             patch.object(ipn, "reverse_ip_lookup", side_effect=lambda ip, s: neighbours[ip]), \
             patch.object(ipn, "make_session"), \
             patch.object(ipn.time, "sleep"):
            ipn.run(root)
        text = (manual / "discovery.txt").read_text(encoding="utf-8")
        self.assertIn("sibling.cn", text)
        self.assertNotIn("farm", text)


def _record(domain, bucket="CN", score=100):
    return build_domains.DomainRecord(
        domain=domain, dns_cn=1, dns_cn_count=1, dns_total=1, registrar_cn=0,
        registrant_cn=0, cn_tld=0, score=score, resolved_ips="1.0.1.1",
        matched_cidr="1.0.1.0/24", source="discovery", updated="2026-11-16", bucket=bucket)


class WeeklyLifecycle(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.manual = self.root / "sources" / "manual"
        self.manual.mkdir(parents=True)
        (self.manual / "discovery.txt").write_text(
            "# DomainNova - Discovery Layer\n\n# --- ip-neighbor:9.9.9.9 2026-11-02 ---\n"
            "steady.cn\n8686868.vip\nsub.steady2.cn\n", encoding="utf-8")
        (self.manual / "extended.txt").write_text("# DomainNova - Extended Domains\n", encoding="utf-8")
        p = patch.object(build_domains, "log")
        p.start()
        self.addCleanup(p.stop)

    def run_week(self, week, domains=("steady.cn",)):
        return build_domains.manage_discovery_lifecycle(
            self.root, [_record(d) for d in domains], week=week)

    def test_same_week_runs_count_once(self):
        for _ in range(build_domains.PROMOTE_AFTER_PASSES + 2):
            _, promoted = self.run_week("2026-W47")
            self.assertEqual(promoted, [])
        stats = json.loads((self.root / "data" / "discovery_stats.json").read_text())
        self.assertEqual(stats["hit_counts"]["steady.cn"], 1)

    def test_promotes_after_distinct_weeks(self):
        weeks = [f"2026-W{n}" for n in range(44, 44 + build_domains.PROMOTE_AFTER_PASSES)]
        for w in weeks[:-1]:
            self.assertEqual(self.run_week(w)[1], [])
            self.assertEqual(self.run_week(w)[1], [])  # second run, same week
        self.assertEqual(self.run_week(weeks[-1])[1], ["steady.cn"])

    def test_junk_and_subdomains_are_purged_not_promoted(self):
        stats = {"hit_counts": {"8686868.vip": 9, "sub.steady2.cn": 9}}
        (self.root / "data").mkdir()
        (self.root / "data" / "discovery_stats.json").write_text(json.dumps(stats))
        purged, promoted = self.run_week("2026-W47", ("8686868.vip", "sub.steady2.cn"))
        self.assertEqual(promoted, [])
        self.assertEqual(sorted(purged), ["8686868.vip", "sub.steady2.cn"])
        self.assertNotIn("8686868.vip", (self.manual / "discovery.txt").read_text())

    def test_dead_domain_removal_still_works(self):
        # detect_dead_domains shares the stats file; a confirmed dead
        # discovery domain is removed without error.
        (self.root / "data").mkdir(exist_ok=True)
        (self.root / "data" / "discovery_stats.json").write_text(
            json.dumps({"dead_streak": {"steady.cn": build_domains.DEAD_STREAK_THRESHOLD - 1}}))
        row = _record("steady.cn")
        row.dns_total = 0
        with patch.object(build_domains, "_query_ns_record", return_value=False):
            removed = build_domains.detect_dead_domains(self.root, [row], session=None)
        self.assertEqual(removed, ["steady.cn"])
        self.assertNotIn("steady.cn", (self.manual / "discovery.txt").read_text())

    def test_iso_week(self):
        self.assertEqual(build_domains.iso_week(dt.date(2026, 11, 18)), "2026-W47")
        self.assertEqual(build_domains.iso_week(dt.date(2027, 1, 1)), "2026-W53")


class Cleanup(unittest.TestCase):
    """clean_agent_domains.py on a small repo."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        m = self.root / "sources" / "manual"
        m.mkdir(parents=True)
        (m / "seed_cn.txt").write_text("# seed\nalibaba.com\n", encoding="utf-8")
        farm = [f"farm{i}.com" for i in range(25)]
        (m / "extended.txt").write_text(
            "# Broadly-used mainland CN domains. How each was found: provenance.csv\n"
            "mine.cn\n1.805188.vip\nintranet.javsee.cc\n0757jiafa.cn.alibaba.com\n"
            "abs.anheng.com.cn\nmail.anheng.com.cn\nllsstt.dpdns.org\nh3c.com.cn\n"
            + "\n".join(farm) + "\n", encoding="utf-8")
        (m / "discovery.txt").write_text(
            "# DomainNova - Discovery Layer\n\n# --- ip-neighbor:7.7.7.7 2026-11-15 ---\n"
            "0026.cc\nbbs.newsite.cn\nok.cn\n", encoding="utf-8")
        rows = [("mine.cn", "manual", "added by hand", "2026-01-01"),
                ("1.805188.vip", "ip-neighbor", "122.14.229.58", "2026-11-15"),
                ("intranet.javsee.cc", "ip-neighbor", "5.5.5.5", "2026-11-02"),
                ("0757jiafa.cn.alibaba.com", "ip-neighbor", "6.6.6.6", "2026-11-02"),
                ("abs.anheng.com.cn", "ct-logs", "%.com.cn", "2026-10-26"),
                ("mail.anheng.com.cn", "ct-logs", "%.com.cn", "2026-10-27"),
                ("llsstt.dpdns.org", "ip-neighbor", "6.6.6.6", "2026-11-02"),
                ("h3c.com.cn", "ip-neighbor", "60.191.123.44", "2026-11-15")]
        rows += [(d, "ip-neighbor", "211.100.61.67", "2026-11-02") for d in farm]
        prov.record(self.root, rows)
        self.summary = clean.clean(self.root, today="2026-11-19")

    def lines(self, name):
        return [l for l in (self.root / "sources" / "manual" / name).read_text().splitlines()
                if l and not l.startswith("#")]

    def test_extended(self):
        self.assertEqual(sorted(self.lines("extended.txt")),
                         ["anheng.com.cn", "h3c.com.cn", "mine.cn"])

    def test_discovery(self):
        self.assertEqual(self.lines("discovery.txt"), ["newsite.cn", "ok.cn"])
        # the header stays, so the reduced name keeps its nomination
        self.assertEqual(prov.discovery_sections(self.root / "sources/manual/discovery.txt")["newsite.cn"][0],
                         "ip-neighbor")

    def test_provenance_follows(self):
        reg = prov.load(self.root)
        self.assertEqual(sorted(reg), ["anheng.com.cn", "h3c.com.cn", "mine.cn"])
        self.assertEqual(reg["anheng.com.cn"], ("ct-logs", "%.com.cn", "2026-10-26"))

    def test_removed_log(self):
        rows = list(csv.DictReader((self.root / "sources/manual/removed.csv").open()))
        why = {r["domain"]: r["reason"] for r in rows}
        self.assertEqual(why["1.805188.vip"], "numeric-throwaway")
        self.assertEqual(why["intranet.javsee.cc"], "adult-gambling")
        self.assertEqual(why["llsstt.dpdns.org"], "free-subdomain")
        self.assertEqual(why["farm3.com"], "shared-host")
        self.assertEqual(why["0757jiafa.cn.alibaba.com"], "covered-by:alibaba.com")
        self.assertEqual(why["mail.anheng.com.cn"], "covered-by:anheng.com.cn")
        self.assertEqual(why["0026.cc"], "numeric-throwaway")
        self.assertNotIn("mine.cn", why)
        self.assertTrue(all(r["removed"] == "2026-11-19" for r in rows))
        self.assertEqual(rows[0].keys(), {"domain", "origin", "origin_detail", "reason", "removed"})

    def test_registrable_name_after_its_subdomain_is_not_listed_twice(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        m = root / "sources" / "manual"
        m.mkdir(parents=True)
        (m / "extended.txt").write_text("# x\n# ===== Auto-promoted 2026-04-10 =====\n"
                                        "bbs.site.cn\nsite.cn\n", encoding="utf-8")
        prov.record(root, [("bbs.site.cn", "ct-logs", "%.cn", "2026-04-01"),
                           ("site.cn", "ip-neighbor", "1.2.3.4", "2026-04-02")])
        clean.clean(root, today="2026-11-19")
        self.assertEqual([l for l in (m / "extended.txt").read_text().splitlines()
                          if not l.startswith("#")], ["site.cn"])
        self.assertEqual(prov.load(root)["site.cn"], ("ip-neighbor", "1.2.3.4", "2026-04-02"))

    def test_manual_untouched_and_idempotent(self):
        before = (self.root / "sources/manual/extended.txt").read_text()
        again = clean.clean(self.root, today="2026-11-20")
        self.assertEqual((self.root / "sources/manual/extended.txt").read_text(), before)
        self.assertEqual(again["removed"], 0)


if __name__ == "__main__":
    unittest.main()
