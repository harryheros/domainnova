"""
v3.8.0: every published domain carries where it came from.

- origin: who first nominated the domain (manual curation, the CT-log or
  IP-neighbor discovery agents, or a historical upstream list), kept in
  sources/manual/provenance.csv and written into data/domains_metadata.*.
- resolver: which resolver tier answered for it in this build (our own
  resolver, a public ECS resolver, or the last-resort fallback), recorded in
  data/domains.csv and counted in data/stats.json.
"""
import csv
import importlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _provenance as prov  # noqa: E402
import build_domains  # noqa: E402
import build_metadata  # noqa: E402

DISCOVERY = """# DomainNova - Discovery Layer

# --- ct-logs:%.cn 2026-10-26 ---
alpha.cn
beta.cn

# --- ip-neighbor:120.48.6.179 2026-11-02 ---
gamma.com

# --- upstream:felixonmars-accelerated 2026-04-11 ---
delta.com
"""


class Tags(unittest.TestCase):
    def test_parse_tag(self):
        self.assertEqual(prov.parse_tag("ct-logs:%.cn"), ("ct-logs", "%.cn"))
        self.assertEqual(prov.parse_tag("ip-neighbor:120.48.6.179"), ("ip-neighbor", "120.48.6.179"))
        self.assertEqual(prov.parse_tag("upstream:felixonmars-accelerated"),
                         ("dnsmasq-china-list", "accelerated-domains"))
        self.assertEqual(prov.parse_tag("upstream:v2fly-cn"), ("upstream-list", "v2fly-cn"))
        self.assertEqual(prov.parse_tag("something-new"), ("something-new", ""))

    def test_discovery_sections(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "discovery.txt"
            p.write_text(DISCOVERY + "\nUntagged.CN\n", encoding="utf-8")
            got = prov.discovery_sections(p)
        self.assertEqual(got["alpha.cn"], ("ct-logs", "%.cn", "2026-10-26"))
        self.assertEqual(got["gamma.com"], ("ip-neighbor", "120.48.6.179", "2026-11-02"))
        self.assertEqual(got["delta.com"], ("dnsmasq-china-list", "accelerated-domains", "2026-04-11"))
        # still under the last header: the header applies until the next one
        self.assertEqual(got["untagged.cn"], ("dnsmasq-china-list", "accelerated-domains", "2026-04-11"))

    def test_untagged_before_any_header(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "discovery.txt"
            p.write_text("# DomainNova - Discovery Layer\nearly.cn\n", encoding="utf-8")
            self.assertEqual(prov.discovery_sections(p)["early.cn"], ("unknown", "", ""))


class Registry(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "sources" / "manual").mkdir(parents=True)

    def test_record_first_nomination_wins_and_file_is_sorted(self):
        prov.record(self.root, [("b.cn", "ct-logs", "%.cn", "2026-10-26"),
                                ("a.cn", "ip-neighbor", "1.2.3.4", "2026-11-02")])
        prov.record(self.root, [("b.cn", "ip-neighbor", "5.6.7.8", "2026-11-09")])
        rows = list(csv.DictReader(prov.path(self.root).open(encoding="utf-8")))
        self.assertEqual([r["domain"] for r in rows], ["a.cn", "b.cn"])
        self.assertEqual(rows[1]["origin"], "ct-logs")
        self.assertEqual(rows[1]["nominated"], "2026-10-26")
        self.assertEqual(prov.load(self.root)["a.cn"], ("ip-neighbor", "1.2.3.4", "2026-11-02"))

    def test_load_missing_file(self):
        self.assertEqual(prov.load(self.root), {})


def _record(domain, source="discovery", bucket="CN", score=100):
    return build_domains.DomainRecord(
        domain=domain, dns_cn=1, dns_cn_count=1, dns_total=1, registrar_cn=0,
        registrant_cn=0, cn_tld=0, score=score, resolved_ips="1.0.1.1",
        matched_cidr="1.0.1.0/24", source=source, updated="2026-11-16", bucket=bucket)


class Promotion(unittest.TestCase):
    def test_promoted_domains_keep_their_nomination(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        manual = root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "discovery.txt").write_text(DISCOVERY, encoding="utf-8")
        (manual / "extended.txt").write_text("# DomainNova - Extended Domains\nold.cn\n", encoding="utf-8")
        (root / "data").mkdir()
        hits = {d: build_domains.PROMOTE_AFTER_PASSES - 1 for d in ("alpha.cn", "gamma.com")}
        (root / "data" / "discovery_stats.json").write_text(json.dumps({"hit_counts": hits}), encoding="utf-8")
        with patch.object(build_domains, "log"):
            _, promoted = build_domains.manage_discovery_lifecycle(
                root, [_record("alpha.cn"), _record("gamma.com"), _record("beta.cn", score=0)])
        self.assertEqual(sorted(promoted), ["alpha.cn", "gamma.com"])
        reg = prov.load(root)
        self.assertEqual(reg["alpha.cn"], ("ct-logs", "%.cn", "2026-10-26"))
        self.assertEqual(reg["gamma.com"], ("ip-neighbor", "120.48.6.179", "2026-11-02"))
        self.assertNotIn("beta.cn", reg)
        self.assertNotIn("alpha.cn", (manual / "discovery.txt").read_text(encoding="utf-8"))


class Metadata(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        manual = self.root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_hk.txt").write_text("# DomainNova - Seed Domains (Hong Kong)\nhk.example.hk\n", encoding="utf-8")
        (manual / "extended.txt").write_text(
            "# DomainNova - Extended Domains\nold.cn\nalpha.cn\nnobody.cn\n", encoding="utf-8")
        (manual / "discovery.txt").write_text(DISCOVERY, encoding="utf-8")
        prov.record(self.root, [("old.cn", "manual", "2026-03-27 list", "2026-03-27")])
        seeds = {k: manual / f"{k}.txt" for k in build_metadata.SEED_FILES}
        self.patches = [
            patch.object(build_metadata, "ROOT", self.root),
            patch.object(build_metadata, "SEED_FILES", seeds),
            patch.object(build_metadata, "EXTENDED_FILE", manual / "extended.txt"),
            patch.object(build_metadata, "DISCOVERY_FILE", manual / "discovery.txt"),
        ]
        for name in ("OUT_JSON", "OUT_YAML", "OUT_CSV", "OUT_STATS", "OUT_VALIDATION"):
            self.patches.append(patch.object(build_metadata, name,
                                             self.root / "data" / getattr(build_metadata, name).name))
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_every_tier_has_an_origin(self):
        with patch("builtins.print"):
            build_metadata.run(write_all=True)
        rows = {r["domain"]: r for r in csv.DictReader((self.root / "data" / "domains_metadata.csv").open(encoding="utf-8"))}
        self.assertEqual((rows["hk.example.hk"]["source"], rows["hk.example.hk"]["origin"]), ("seed_hk", "manual"))
        self.assertEqual((rows["old.cn"]["origin"], rows["old.cn"]["origin_detail"]), ("manual", "2026-03-27 list"))
        self.assertEqual(rows["nobody.cn"]["origin"], "unknown")
        # a discovery domain is listed with its agent; one also in extended counts as extended
        self.assertEqual((rows["beta.cn"]["source"], rows["beta.cn"]["origin"]), ("discovery", "ct-logs"))
        self.assertEqual(rows["alpha.cn"]["source"], "extended")
        stats = json.loads((self.root / "data" / "metadata_stats.json").read_text(encoding="utf-8"))
        self.assertEqual(stats["by_origin"]["ct-logs"], 1)  # beta.cn; alpha.cn is extended without a registry row
        meta_json = json.loads((self.root / "data" / "domains_metadata.json").read_text(encoding="utf-8"))
        self.assertIn("origin", meta_json[0])


class ResolverTier(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"DOMAINNOVA_DOH_URL": "https://dns.example/ecs-x",
                                           "DOMAINNOVA_PUBLIC_DOH": "on"})
        self.env.start()
        self.bd = importlib.reload(build_domains)
        self.addCleanup(self.env.stop)
        self.addCleanup(importlib.reload, build_domains)

    def tier_for(self, own, public, fallback):
        bd = self.bd
        def do_resolve(domain, upstream, session):
            return fallback if upstream in bd.DOH_FALLBACKS else public
        with patch.object(bd, "_resolve_rescue_detail", return_value=(own, bool(own))), \
             patch.object(bd, "_do_resolve", side_effect=do_resolve), \
             patch.object(bd, "log"):
            rec = bd.process_domain("example.cn", "extended", object(), {}, "2026-11-16")
        return rec.resolver

    def test_tiers(self):
        self.assertEqual(self.tier_for(["1.0.1.1"], [], []), "own")
        self.assertEqual(self.tier_for([], ["1.0.1.1"], []), "public")
        self.assertEqual(self.tier_for([], [], ["1.0.1.1"]), "fallback")
        self.assertEqual(self.tier_for([], [], []), "")

    def test_tier_does_not_leak_between_domains(self):
        self.assertEqual(self.tier_for([], ["1.0.1.1"], []), "public")
        self.assertEqual(self.tier_for([], [], []), "")

    def test_sticky_row_has_no_tier(self):
        bd = self.bd
        prev = {"example.cn": _record("example.cn", source="extended")}
        prev["example.cn"].resolver = "own"
        with patch.object(bd, "_resolve_rescue_detail", return_value=([], True)), \
             patch.object(bd, "_do_resolve", return_value=[]), patch.object(bd, "log"):
            rec = bd.process_domain("example.cn", "extended", object(), {}, "2026-11-16", prev)
        self.assertEqual((rec.sticky, rec.resolver), (1, ""))

    def test_stats_and_csv_roundtrip(self):
        bd = self.bd
        rows = [_record("a.cn"), _record("b.cn"), _record("c.cn"), _record("d.cn")]
        for r, t in zip(rows, ["own", "own", "public", ""], strict=True):
            r.resolver = t
        with tempfile.TemporaryDirectory() as d:
            bd.write_stats(Path(d) / "stats.json", rows, {})
            stats = json.loads((Path(d) / "stats.json").read_text(encoding="utf-8"))
            self.assertEqual(stats["resolver"], {"own": 2, "public": 1, "fallback": 0, "unresolved": 1})
            bd.write_csv(Path(d) / "domains.csv", rows)
            self.assertEqual(bd.load_previous_rows(Path(d) / "domains.csv")["c.cn"].resolver, "public")
            # an old domains.csv without the column still loads
            old = Path(d) / "old.csv"
            old.write_text("domain,dns_cn,score,source,updated\nx.cn,1,100,extended,2026-11-09\n", encoding="utf-8")
            self.assertEqual(bd.load_previous_rows(old)["x.cn"].resolver, "")


class Workflow(unittest.TestCase):
    def test_ci_commits_the_registry(self):
        """Promotions write provenance.csv; CI must commit it with extended.txt."""
        wf = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")
        add = wf[wf.index("git add"):wf.index("git commit")]
        for rel in ("sources/manual/extended.txt", "sources/manual/discovery.txt", "sources/manual/provenance.csv"):
            self.assertIn(rel, add)


if __name__ == "__main__":
    unittest.main()
