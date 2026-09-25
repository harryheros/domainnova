#!/usr/bin/env python3
"""
test_v35_fixes.py — regression tests for the DomainNova v3.5.0 fixes.

  - Quad9 is queried in RFC 8484 wire format (its JSON API was retired)
  - Rescue DoH circuit breaker stops a dead rescue node from stalling builds
  - Dead-domain check: only NXDOMAIN is "dead" (subdomains / CNAMEs are alive)
  - Provider detection falls through to heuristics on an IPNova lookup miss
  - CT agent: seed-anchored queries only, results filtered to the seed
  - IP-neighbor agent: no HTML scraping; stops when quota is exhausted
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sources" / "scripts"))
sys.path.insert(0, str(ROOT / "sources" / "discovery_agents"))

import build_domains as bd  # noqa: E402
import agent_ct_logs as ct  # noqa: E402
import agent_ip_neighbor as ipn  # noqa: E402


class _Resp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text
        self.content = b""

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _Session:
    """Records GET calls and replies with a fixed response."""

    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return self.resp


# ---------------------------------------------------------------------------
class TestQuad9WireMode(unittest.TestCase):
    def test_quad9_uses_wire_google_uses_json(self):
        quad9 = "https://dns11.quad9.net/dns-query"
        with mock.patch.object(bd, "_resolve_via_wire", return_value=(True, ["1.2.3.4"])) as w, \
             mock.patch.object(bd, "_resolve_via_json", return_value=(True, ["5.6.7.8"])) as j:
            self.assertEqual(bd._do_resolve("example.cn", quad9, None), ["1.2.3.4"])
            self.assertEqual(w.call_count, 1)
            self.assertEqual(j.call_count, 0)
            self.assertEqual(bd._do_resolve("example.cn", "https://dns.google/resolve", None), ["5.6.7.8"])
            self.assertEqual(j.call_count, 1)

    def test_every_upstream_has_a_mode(self):
        for up in bd.DOH_PRIMARIES + bd.DOH_FALLBACKS:
            self.assertIn(bd.DOH_MODE.get(up), ("json", "wire"), up)

    def test_wire_roundtrip_with_ecs(self):
        q = bd._encode_dns_wire_query("example.cn", ecs_subnet="219.141.140.0/24")
        self.assertEqual(struct.unpack(">H", q[10:12])[0], 1)  # ARCOUNT=1 (OPT)
        # Build a minimal response: header + question + one A answer (pointer name)
        qname = b"\x07example\x02cn\x00"
        header = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        question = qname + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        self.assertEqual(bd._decode_dns_wire_answer(header + question + answer), ["1.2.3.4"])


# ---------------------------------------------------------------------------
class TestRescueBreaker(unittest.TestCase):
    def setUp(self):
        self._saved = (bd._rescue_mode, bd._rescue_consecutive_failures, bd._rescue_disabled)
        bd._rescue_mode = None
        bd._rescue_consecutive_failures = 0
        bd._rescue_disabled = False

    def tearDown(self):
        bd._rescue_mode, bd._rescue_consecutive_failures, bd._rescue_disabled = self._saved

    def test_dead_rescue_is_disabled_after_threshold(self):
        with mock.patch.object(bd, "_resolve_via_json", return_value=(False, [])) as j, \
             mock.patch.object(bd, "_resolve_via_wire", return_value=(False, [])) as w, \
             mock.patch.object(bd, "log"):
            for _ in range(bd.RESCUE_MAX_CONSECUTIVE_FAILURES + 20):
                self.assertEqual(bd._resolve_rescue("x.cn", None), [])
            self.assertTrue(bd._rescue_disabled)
            # No further network attempts once tripped
            self.assertEqual(j.call_count, bd.RESCUE_MAX_CONSECUTIVE_FAILURES)
            self.assertEqual(w.call_count, bd.RESCUE_MAX_CONSECUTIVE_FAILURES)

    def test_success_resets_streak(self):
        results = [(False, [])] * (bd.RESCUE_MAX_CONSECUTIVE_FAILURES - 1) + [(True, ["1.1.1.1"])]
        with mock.patch.object(bd, "_resolve_via_json", side_effect=results + [(True, [])] * 50), \
             mock.patch.object(bd, "_resolve_via_wire", return_value=(False, [])), \
             mock.patch.object(bd, "log"):
            for _ in range(len(results)):
                bd._resolve_rescue("x.cn", None)
        self.assertFalse(bd._rescue_disabled)
        self.assertEqual(bd._rescue_consecutive_failures, 0)

    def test_nxdomain_is_not_a_transport_failure(self):
        bd._rescue_mode = "json"
        with mock.patch.object(bd, "_resolve_via_json", return_value=(True, [])), \
             mock.patch.object(bd, "log"):
            for _ in range(bd.RESCUE_MAX_CONSECUTIVE_FAILURES * 2):
                bd._resolve_rescue("gone.cn", None)
        self.assertFalse(bd._rescue_disabled)


# ---------------------------------------------------------------------------
class TestDeadDomainCheck(unittest.TestCase):
    def _alive(self, payload, status=200):
        with mock.patch.object(bd.time, "sleep"):
            return bd._query_ns_record("x.example.cn", _Session(_Resp(status, payload)))

    def test_subdomain_noerror_without_ns_is_alive(self):
        # Typical subdomain answer: NOERROR, no Answer, SOA in Authority.
        self.assertTrue(self._alive({"Status": 0, "Authority": [{"type": 6}]}))

    def test_cname_answer_is_alive(self):
        self.assertTrue(self._alive({"Status": 0, "Answer": [{"type": 5}]}))

    def test_nxdomain_is_dead(self):
        self.assertFalse(self._alive({"Status": 3}))

    def test_servfail_and_http_errors_play_safe(self):
        self.assertTrue(self._alive({"Status": 2}))
        self.assertTrue(self._alive(None, status=500))


# ---------------------------------------------------------------------------
class TestProviderFallThrough(unittest.TestCase):
    def setUp(self):
        self._orig = bd._cidr_asn_lookup
        # A loaded lookup that doesn't cover the IPs under test (the common
        # case since IPNova only attaches ASNs to BGP-supplement CIDRs).
        bd._cidr_asn_lookup = bd._build_asn_lookup({"8.152.0.0/15": 37963})

    def tearDown(self):
        bd._cidr_asn_lookup = self._orig

    def test_lookup_hit_still_wins(self):
        self.assertEqual(bd.detect_provider(["8.152.1.1"]), ("Alibaba Cloud", 0))

    def test_miss_falls_back_to_prefix_hint(self):
        self.assertEqual(bd.detect_provider(["47.97.1.1"]), ("Alibaba Cloud", 0))

    def test_global_cdn_detected_despite_loaded_lookup(self):
        self.assertEqual(bd.detect_provider(["104.16.1.1"]), ("Cloudflare", 1))

    def test_unknown_stays_empty(self):
        self.assertEqual(bd.detect_provider(["1.1.1.1"]), ("", 0))


# ---------------------------------------------------------------------------
class TestCtAgent(unittest.TestCase):
    def test_queries_are_seed_anchored_only(self):
        qs = ct.build_queries(ROOT)
        self.assertTrue(qs)
        self.assertLessEqual(len(qs), ct.MAX_QUERIES_PER_RUN)
        for q in qs:
            self.assertTrue(q.startswith("%."), q)
            parent = q[2:]
            self.assertIn(".", parent, f"whole-TLD wildcard is not allowed: {q}")
            self.assertNotIn(parent, [t.lstrip(".") for t in ct.CN_TLDS])

    def test_results_filtered_to_parent(self):
        payload = [
            {"name_value": "a.example.cn\n*.b.example.cn\nexample.cn"},
            {"name_value": "www.xiaomi--kursk.online\nexample.cn.evil.com"},
        ]
        sess = _Session(_Resp(200, payload))
        got = sorted(ct.query_crtsh("%.example.cn", sess))
        self.assertEqual(got, ["a.example.cn", "b.example.cn", "example.cn"])
        params = sess.calls[0][1]["params"]
        self.assertEqual(params.get("exclude"), "expired")


# ---------------------------------------------------------------------------
class TestIpNeighborAgent(unittest.TestCase):
    def test_no_key_means_no_viewdns_request(self):
        sess = _Session(_Resp(200, {}))
        with mock.patch.object(ipn, "VIEWDNS_APIKEY", ""):
            self.assertIsNone(ipn.viewdns_lookup("1.2.3.4", sess))
        self.assertEqual(sess.calls, [])

    def test_quota_exhausted_raises_without_key(self):
        sess = _Session(_Resp(200, None, text="API count exceeded - Increase Quota"))
        with mock.patch.object(ipn, "VIEWDNS_APIKEY", ""), mock.patch("builtins.print"):
            with self.assertRaises(ipn.QuotaExhausted):
                ipn.reverse_ip_lookup("1.2.3.4", sess)
        # exactly one request (HackerTarget), no scraping fallback
        self.assertEqual(len(sess.calls), 1)
        self.assertIn("hackertarget", sess.calls[0][0])

    def test_source_has_no_html_scraping(self):
        src = (ROOT / "sources" / "discovery_agents" / "agent_ip_neighbor.py").read_text()
        self.assertNotIn("https://viewdns.info/reverseip", src)


if __name__ == "__main__":
    unittest.main()
